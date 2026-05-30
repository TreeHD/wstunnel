// Package dnsx 提供 DNS 解析子系統。
//
// 設計目標:
//   1. 多 DNS 伺服器 failover(設定值支援逗號分隔)
//   2. UDP 失敗自動退回 TCP(規避 UDP/53 被擋)
//   3. 啟動健檢,把問題提早暴露在 log
//   4. 解析失敗時印出足夠細節讓使用者排障(分類 NXDOMAIN/SERVFAIL/...)
//   5. DialContextSmart 把「DNS 失敗」與「TCP 失敗」分開回報
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wstunnel/internal/config"
)

// state 為 DNS 子系統的執行期狀態,用 atomic.Pointer 實現零鎖切換。
type state struct {
	resolver *net.Resolver
	servers  []string // 解析後的 DNS server 清單,每筆皆為 "ip:port"
	rawCfg   string   // 用於比對是否需要 rebuild
}

var (
	statePtr      atomic.Pointer[state]
	rebuildMu     sync.Mutex
	healthOnce    sync.Once
)

// Init 在程式啟動初期呼叫一次,建立預設 resolver。
func Init() {
	Rebuild()
}

// Rebuild 從 config.Get().DNSServer 重新建構 resolver。
// 設定變更後也會被呼叫。
func Rebuild() {
	rebuildMu.Lock()
	defer rebuildMu.Unlock()

	c := config.Get()
	c.Lock.RLock()
	raw := strings.TrimSpace(c.DNSServer)
	c.Lock.RUnlock()

	if cur := statePtr.Load(); cur != nil && cur.rawCfg == raw {
		return
	}

	servers := parseServers(raw)
	st := &state{
		servers: servers,
		rawCfg:  raw,
	}

	if len(servers) == 0 {
		st.resolver = &net.Resolver{PreferGo: true}
	} else {
		st.resolver = &net.Resolver{
			PreferGo: true,
			Dial:     buildDialFunc(servers),
		}
	}
	statePtr.Store(st)

	if len(servers) == 0 {
		log.Printf("DNS: resolver rebuilt — using container default (/etc/resolv.conf)")
	} else {
		log.Printf("DNS: resolver rebuilt — servers=%v (UDP first, TCP fallback)", servers)
	}
}

// parseServers 把使用者輸入(逗號或空白分隔)標準化成 "ip:port" 列表。
func parseServers(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(p); err != nil {
			if strings.Count(p, ":") >= 2 && !strings.HasPrefix(p, "[") {
				p = "[" + p + "]"
			}
			p = p + ":53"
		}
		out = append(out, p)
	}
	return out
}

// buildDialFunc 回傳用於 net.Resolver.Dial 的函式;同 server 先 UDP 後 TCP。
func buildDialFunc(servers []string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		var lastErr error
		for _, srv := range servers {
			for _, proto := range []string{"udp", "tcp"} {
				dialer := net.Dialer{Timeout: 3 * time.Second}
				conn, err := dialer.DialContext(ctx, proto, srv)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
		}
		if lastErr == nil {
			lastErr = errors.New("no DNS servers configured")
		}
		return nil, fmt.Errorf("all DNS servers failed: %w", lastErr)
	}
}

// Resolver 取得當前 resolver;若尚未初始化則 lazy init。
func Resolver() *net.Resolver {
	if s := statePtr.Load(); s != nil {
		return s.resolver
	}
	Rebuild()
	return statePtr.Load().resolver
}

// Servers 取得目前生效的 DNS server 清單(udpgw fallback 等地方會用到)。
func Servers() []string {
	if s := statePtr.Load(); s != nil {
		return s.servers
	}
	return nil
}

// NewDialer 建立帶有正確 resolver 的 net.Dialer。
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:  timeout,
		Resolver: Resolver(),
	}
}

// DialContextSmart 對 host:port 進行解析 + 撥號,並把「DNS 失敗」與「TCP 失敗」分開回報。
// 純 IP 直接撥號;hostname 先解析,IPv4 優先,逐一嘗試。
func DialContextSmart(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	if ip := net.ParseIP(host); ip != nil {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "tcp", addr)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := Resolver().LookupIPAddr(resolveCtx, host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS lookup returned no results for %q", host)
	}

	sortIPv4First(ips)

	d := net.Dialer{Timeout: timeout}
	var lastErr error
	for _, ip := range ips {
		dst := net.JoinHostPort(ip.IP.String(), port)
		conn, err := d.DialContext(ctx, "tcp", dst)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("connect failed after DNS resolved %d IPs for %q: %w", len(ips), host, lastErr)
}

func sortIPv4First(ips []net.IPAddr) {
	for i := 0; i < len(ips); i++ {
		if ips[i].IP.To4() != nil {
			continue
		}
		for j := i + 1; j < len(ips); j++ {
			if ips[j].IP.To4() != nil {
				ips[i], ips[j] = ips[j], ips[i]
				break
			}
		}
	}
}

// HealthCheck 啟動時對設定的 DNS server 做一次測試查詢,結果寫入 log。
func HealthCheck() {
	healthOnce.Do(func() {
		st := statePtr.Load()
		if st == nil {
			return
		}

		const probe = "cloudflare.com"
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		start := time.Now()
		ips, err := st.resolver.LookupIPAddr(ctx, probe)
		elapsed := time.Since(start)

		if err != nil {
			log.Printf("DNS HEALTH-CHECK: ❌ FAILED — probe=%s err=%v elapsed=%v", probe, err, elapsed)
			log.Printf("DNS HEALTH-CHECK: 提示:請檢查 docker-compose.yml 的 dns: 區塊或 DNS_SERVER 環境變數")
			if len(st.servers) == 0 {
				log.Printf("DNS HEALTH-CHECK: 目前未設定自訂 DNS,正在使用容器 /etc/resolv.conf")
			} else {
				log.Printf("DNS HEALTH-CHECK: 設定中的 DNS servers: %v", st.servers)
			}
			return
		}

		ipStrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.IP.String())
			if len(ipStrs) >= 3 {
				break
			}
		}
		log.Printf("DNS HEALTH-CHECK: ✅ OK — probe=%s ips=%v elapsed=%v", probe, ipStrs, elapsed)
	})
}

// ClassifyError 把錯誤分類,方便 log 給使用者看的中文訊息。
// 回傳 (kind, hint);kind 為短代號,hint 為人類可讀提示。
func ClassifyError(err error) (kind string, hint string) {
	if err == nil {
		return "", ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "NXDOMAIN"):
		return "NXDOMAIN", "域名不存在或上游 DNS 拒答"
	case strings.Contains(msg, "server misbehaving"):
		return "SERVFAIL", "上游 DNS 回 SERVFAIL,可能 DNS 伺服器設定錯誤"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "TIMEOUT", "DNS 查詢逾時,可能 UDP 53 被防火牆擋;考慮換 DNS 或啟用 TCP fallback"
	case strings.Contains(msg, "connection refused"):
		return "REFUSED", "DNS 連線被拒,伺服器位址可能錯誤或服務未啟動"
	case strings.Contains(msg, "DNS lookup failed"):
		return "LOOKUP", "DNS 查詢失敗(請見上層錯誤訊息)"
	default:
		return "OTHER", "其他錯誤"
	}
}
