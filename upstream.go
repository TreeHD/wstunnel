// upstream.go — 上游 SOCKS5 / HTTP Proxy 鏈接
//
// 職責：
//   * 讓 wstunnel 把所有 SSH Tunnel 內走出來的 TCP 流量
//     再轉發給一個帶 Auth 的上游 SOCKS5 或 HTTP Proxy
//   * dialTarget 是統一的出口:upstream 啟用走代理,未啟用 fallback 直連
//   * 解析 host 的責任:啟用 upstream 時交給上游(remote DNS resolution),
//     未啟用時走本地 dns.go 的 resolver chain
//
// 為什麼不走 golang.org/x/net/proxy?
//   * 該套件對 HTTP CONNECT proxy 沒有原生支援,要自己包
//   * 我們需要對 timeout / Basic Auth header / SOCKS5 USER-PASS 子協商有完整控制
//   * 直接手刻 ~150 行可避免新增依賴
package main

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
)

// upstreamConfig 是當前上游代理設定的快照(避免每次 dial 都拿鎖)
type upstreamConfig struct {
	enabled  bool
	rawURL   string
	parsed   *url.URL
	username string
	password string
}

// getUpstreamConfig 讀取目前生效的 upstream 設定
func getUpstreamConfig() upstreamConfig {
	globalConfig.lock.RLock()
	enabled := globalConfig.UpstreamProxyEnabled
	raw := strings.TrimSpace(globalConfig.UpstreamProxyURL)
	globalConfig.lock.RUnlock()

	if !enabled || raw == "" {
		return upstreamConfig{enabled: false}
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return upstreamConfig{enabled: false}
	}

	cfg := upstreamConfig{enabled: true, rawURL: raw, parsed: u}
	if u.User != nil {
		cfg.username = u.User.Username()
		cfg.password, _ = u.User.Password()
	}
	return cfg
}

// dialTarget 是所有出站 TCP 連線的統一入口
// 啟用 upstream 時把連線委託給代理(由代理負責 DNS 與實際撥號);否則走 dns.go 直連。
func dialTarget(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	cfg := getUpstreamConfig()
	if !cfg.enabled {
		return dialContextSmart(ctx, addr, timeout)
	}
	return dialViaUpstream(ctx, cfg, addr, timeout)
}

// dialViaUpstream 依據 scheme 分派到 SOCKS5 或 HTTP CONNECT
func dialViaUpstream(ctx context.Context, cfg upstreamConfig, target string, timeout time.Duration) (net.Conn, error) {
	scheme := strings.ToLower(cfg.parsed.Scheme)
	switch scheme {
	case "socks5", "socks5h":
		return dialViaSOCKS5(ctx, cfg, target, timeout)
	case "http":
		return dialViaHTTP(ctx, cfg, target, timeout, false)
	case "https":
		// TLS 至代理本身,目前未實作(罕用)
		return nil, fmt.Errorf("upstream scheme %q not supported (try http or socks5)", scheme)
	default:
		return nil, fmt.Errorf("unknown upstream proxy scheme: %q", scheme)
	}
}

// dialViaSOCKS5 連到 SOCKS5 proxy 並使用 USER/PASS(0x02) 或無認證(0x00)
//
// 把 hostname 用 atyp=0x03 (FQDN) 帶過去,讓上游解析,避免本地 DNS 干擾。
func dialViaSOCKS5(ctx context.Context, cfg upstreamConfig, target string, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("upstream socks5: invalid target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("upstream socks5: invalid port %q", portStr)
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream socks5: dial %s: %w", cfg.parsed.Host, err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	authMethods := []byte{0x00} // 預設 no-auth
	if cfg.username != "" || cfg.password != "" {
		authMethods = []byte{0x02, 0x00} // 優先 USER/PASS,允許退到 no-auth
	}

	// 階段 1:method negotiation
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
		if err := socks5UserPass(conn, cfg.username, cfg.password); err != nil {
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

	// 階段 2:CONNECT 請求(用 FQDN atyp=0x03)
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

	// 讀 4 byte header,再依 atyp 讀後面位址
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: connect read: %w", err)
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream socks5: connect failed, REP=0x%02X (%s)", head[1], socks5RepText(head[1]))
	}
	// 把回應後面剩下的 BND.ADDR + PORT 讀掉(資料量依 atyp 變)
	switch head[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03: // FQDN
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 0x04: // IPv6
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

// dialViaHTTP 連到 HTTP proxy 並送 CONNECT 請求
// useTLS=true 表示對 proxy 本身做 TLS(目前未實作)
func dialViaHTTP(ctx context.Context, cfg upstreamConfig, target string, timeout time.Duration, useTLS bool) (net.Conn, error) {
	if useTLS {
		return nil, errors.New("upstream https proxy not implemented")
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("upstream http: dial %s: %w", cfg.parsed.Host, err)
	}
	conn.SetDeadline(time.Now().Add(timeout))

	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&sb, "Host: %s\r\n", target)
	fmt.Fprintf(&sb, "User-Agent: wstunnel-go\r\n")
	if cfg.username != "" || cfg.password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(cfg.username + ":" + cfg.password))
		fmt.Fprintf(&sb, "Proxy-Authorization: Basic %s\r\n", token)
	}
	sb.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")

	if _, err := conn.Write([]byte(sb.String())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream http: CONNECT write: %w", err)
	}

	// 讀 status line
	statusLine, err := readHTTPLine(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream http: status read: %w", err)
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "2") {
		// 把剩下的 header 也讀完免得殘留資料(失敗了反正要關 conn)
		conn.Close()
		return nil, fmt.Errorf("upstream http: CONNECT rejected: %s", strings.TrimSpace(statusLine))
	}

	// 讀掉所有 header 直到空行
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

// readHTTPLine 讀一行 \r\n 結尾的文字(不使用 bufio,避免吞掉 CONNECT 之後的資料)
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

// upstreamHealthCheck 啟動時測試上游 proxy 是否可達
func upstreamHealthCheck() {
	cfg := getUpstreamConfig()
	if !cfg.enabled {
		log.Printf("UPSTREAM: ⏸  disabled (direct dial)")
		return
	}

	// 試對 proxy 本身做一次 TCP 連線(不做完整握手,避免造成無謂的對外查詢)
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial("tcp", cfg.parsed.Host)
	if err != nil {
		log.Printf("UPSTREAM HEALTH-CHECK: ❌ proxy %s NOT reachable — %v", cfg.parsed.Host, err)
		log.Printf("UPSTREAM HEALTH-CHECK:    所有出站連線會失敗,請從後台修正設定或先停用 upstream")
		return
	}
	conn.Close()

	authNote := "no auth"
	if cfg.username != "" {
		authNote = fmt.Sprintf("auth user=%q", cfg.username)
	}
	log.Printf("UPSTREAM: ✅ enabled — scheme=%s host=%s %s",
		strings.ToLower(cfg.parsed.Scheme), cfg.parsed.Host, authNote)
}

// redactProxyURL 把 URL 中的密碼換成 *** 用於 log,避免敏感資料外洩
//
// 不能用 url.URL.String() 因為它會把 * 做 percent-encode 變 %2A,所以手動拼接。
func redactProxyURL(raw string) string {
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
