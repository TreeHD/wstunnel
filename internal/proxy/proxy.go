// Package proxy 提供上游 SOCKS5 / HTTP CONNECT 鏈接。
//
// 對外只暴露 DialTarget,呼叫者不需要關心 upstream 是否啟用、
// 走哪種協定。upstream 啟用時走代理,否則 fallback 直連(dnsx.DialContextSmart)。
package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"wstunnel/internal/config"
	"wstunnel/internal/dnsx"
)

// Settings 是當前上游代理設定的快照(避免每次 dial 都拿鎖)。
type Settings struct {
	Enabled  bool
	RawURL   string
	Parsed   *url.URL
	Username string
	Password string
}

// CurrentSettings 從 config singleton 讀取目前生效的上游設定。
func CurrentSettings() Settings {
	c := config.Get()
	c.Lock.RLock()
	enabled := c.UpstreamProxyEnabled
	raw := strings.TrimSpace(c.UpstreamProxyURL)
	c.Lock.RUnlock()

	if !enabled || raw == "" {
		return Settings{Enabled: false}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Settings{Enabled: false}
	}
	s := Settings{Enabled: true, RawURL: raw, Parsed: u}
	if u.User != nil {
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	return s
}

// DialTarget 是所有出站 TCP 連線的統一入口。
// 啟用 upstream 時把連線委託給代理(由代理負責 DNS 與實際撥號);
// 否則走 dnsx.DialContextSmart 直連。
func DialTarget(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	s := CurrentSettings()
	if !s.Enabled {
		return dnsx.DialContextSmart(ctx, addr, timeout)
	}
	return DialVia(ctx, s, addr, timeout)
}

// DialVia 依據 scheme 分派到 SOCKS5 或 HTTP CONNECT(供測試 endpoint 用)。
func DialVia(ctx context.Context, s Settings, target string, timeout time.Duration) (net.Conn, error) {
	scheme := strings.ToLower(s.Parsed.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, s, target, timeout)
	case "http":
		return dialHTTP(ctx, s, target, timeout, false)
	case "https":
		return nil, fmt.Errorf("upstream scheme %q not supported (try http or socks5)", scheme)
	default:
		return nil, fmt.Errorf("unknown upstream proxy scheme: %q", scheme)
	}
}

// dialSOCKS5 連到 SOCKS5 proxy 並使用 USER/PASS(0x02) 或無認證(0x00)。
// 把 hostname 用 atyp=0x03 (FQDN) 帶過去,讓上游解析,避免本地 DNS 干擾。
func dialSOCKS5(ctx context.Context, s Settings, target string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("upstream socks5: invalid target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("upstream socks5: invalid port %q", portStr)
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", s.Parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream socks5: dial %s: %w", s.Parsed.Host, err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	authMethods := []byte{0x00}
	if s.Username != "" || s.Password != "" {
		authMethods = []byte{0x02, 0x00}
	}

	hello := []byte{0x05, byte(len(authMethods))}
	hello = append(hello, authMethods...)
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: hello write: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: hello read: %w", err)
	}
	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: bad version %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
		// no-auth ok
	case 0x02:
		if err := socks5UserPass(conn, s.Username, s.Password); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, errors.New("upstream socks5: server rejected all auth methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: unsupported method 0x%02X", resp[1])
	}

	if len(host) > 255 {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: hostname too long")
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xFF))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: connect write: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: connect read: %w", err)
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: connect failed, REP=0x%02X (%s)", head[1], socks5RepText(head[1]))
	}
	switch head[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 16+2))
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5UserPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("upstream socks5: user/pass too long")
	}
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, []byte(user)...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, []byte(pass)...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("upstream socks5: auth write: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("upstream socks5: auth read: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("upstream socks5: auth rejected (status=0x%02X)", resp[1])
	}
	return nil
}

func socks5RepText(rep byte) string {
	switch rep {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	}
	return "unknown"
}

// dialHTTP 連到 HTTP proxy 並送 CONNECT 請求。
func dialHTTP(ctx context.Context, s Settings, target string, timeout time.Duration, useTLS bool) (net.Conn, error) {
	if useTLS {
		return nil, errors.New("upstream https proxy not implemented")
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", s.Parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream http: dial %s: %w", s.Parsed.Host, err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&sb, "Host: %s\r\n", target)
	fmt.Fprintf(&sb, "User-Agent: wstunnel-go\r\n")
	if s.Username != "" || s.Password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(s.Username + ":" + s.Password))
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", token)
	}
	sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream http: CONNECT write: %w", err)
	}

	statusLine, err := readHTTPLine(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream http: status read: %w", err)
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "2") {
		conn.Close()
		return nil, fmt.Errorf("upstream http: CONNECT rejected: %s", strings.TrimSpace(statusLine))
	}

	for {
		line, err := readHTTPLine(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream http: header read: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// readHTTPLine 讀一行 \r\n 結尾的文字(不使用 bufio,避免吞掉 CONNECT 之後的資料)。
func readHTTPLine(conn net.Conn) (string, error) {
	var buf []byte
	one := make([]byte, 1)
	for {
		_, err := conn.Read(one)
		if err != nil {
			return "", err
		}
		buf = append(buf, one[0])
		if len(buf) >= 2 && buf[len(buf)-2] == '\r' && buf[len(buf)-1] == '\n' {
			return string(buf[:len(buf)-2]), nil
		}
		if len(buf) > 8192 {
			return "", errors.New("http header line too long")
		}
	}
}

// HealthCheck 啟動時測試上游 proxy 是否可達。
func HealthCheck() {
	s := CurrentSettings()
	if !s.Enabled {
		log.Printf("UPSTREAM: ⏸  disabled (direct dial)")
		return
	}

	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", s.Parsed.Host)
	if err != nil {
		log.Printf("UPSTREAM HEALTH-CHECK: ❌ proxy %s NOT reachable — %v", s.Parsed.Host, err)
		log.Printf("UPSTREAM HEALTH-CHECK:    所有出站連線會失敗,請從後台修正設定或先停用 upstream")
		return
	}
	conn.Close()

	authNote := "no auth"
	if s.Username != "" {
		authNote = fmt.Sprintf("auth user=%q", s.Username)
	}
	log.Printf("UPSTREAM: ✅ enabled — scheme=%s host=%s %s",
		strings.ToLower(s.Parsed.Scheme), s.Parsed.Host, authNote)
}

// RedactURL 把 URL 中的密碼換成 *** 用於 log。
//
// 不能用 url.URL.String() 因為它會把 * 做 percent-encode 變 %2A。
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	user := u.User.Username()
	if _, hasPass := u.User.Password(); !hasPass {
		return raw
	}
	scheme := u.Scheme
	if scheme != "" {
		scheme += "://"
	}
	tail := u.Host
	if u.Path != "" {
		tail += u.Path
	}
	if u.RawQuery != "" {
		tail += "?" + u.RawQuery
	}
	return fmt.Sprintf("%s%s:***@%s", scheme, user, tail)
}
