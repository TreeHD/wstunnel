// dns.go — DNS 解析子系統
//
// 設計目標：
//   1. 集中所有 DNS 解析邏輯（SSH direct-tcpip / SOCKS5 / HTTP Proxy 共用）
//   2. 多 DNS 伺服器 failover（DNSServer 可填多個，逗號分隔）
//   3. UDP 失敗自動退回 TCP（DNS over TCP 規避 UDP 被 ISP/防火牆截斷）
//   4. 啟動時自我健檢，把問題提早暴露在 log
//   5. 解析失敗時印出足夠細節讓使用者排障
//
// 此檔取代 main.go 原先的 newResolver / newDialer。
package main

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
)

// dnsState 為當前 DNS 子系統的執行期狀態。
// 透過 atomic 指標實現「設定變更時零鎖切換」。
type dnsState struct {
	resolver *net.Resolver
	servers  []string // 解析後的 DNS server 清單，每筆皆為 "ip:port"；空 slice 代表使用 /etc/resolv.conf
	rawCfg   string   // 用於比對是否需要 rebuild
}

var (
	dnsStatePtr   atomic.Pointer[dnsState]
	dnsRebuildMu  sync.Mutex // 序列化 rebuild，避免重入
	dnsHealthOnce sync.Once  // 啟動健檢只跑一次
)

// initDNS 在程式啟動初期呼叫一次，建立預設 resolver。
func initDNS() {
	rebuildResolver()
}

// rebuildResolver 從 globalConfig.DNSServer 重新建構 resolver。
// 設定變更（管理後台 /api/settings POST）後也會被呼叫。
func rebuildResolver() {
	dnsRebuildMu.Lock()
	defer dnsRebuildMu.Unlock()

	globalConfig.lock.RLock()
	raw := strings.TrimSpace(globalConfig.DNSServer)
	globalConfig.lock.RUnlock()

	if cur := dnsStatePtr.Load(); cur != nil && cur.rawCfg == raw {
		return // 沒變化
	}

	servers := parseDNSServers(raw)
	state := &dnsState{
		servers: servers,
		rawCfg:  raw,
	}

	if len(servers) == 0 {
		// 使用容器 /etc/resolv.conf；CGO_ENABLED=0 時 Go 也能解析
		state.resolver = &net.Resolver{PreferGo: true}
	} else {
		state.resolver = &net.Resolver{
			PreferGo: true,
			Dial:     buildDialFunc(servers),
		}
	}
	dnsStatePtr.Store(state)

	if len(servers) == 0 {
		log.Printf("DNS: resolver rebuilt — using container default (/etc/resolv.conf)")
	} else {
		log.Printf("DNS: resolver rebuilt — servers=%v (UDP first, TCP fallback)", servers)
	}
}

// parseDNSServers 把使用者輸入（逗號或空白分隔）標準化成 "ip:port" 列表。
// 例如 "8.8.8.8, 1.1.1.1:53" → ["8.8.8.8:53", "1.1.1.1:53"]
func parseDNSServers(raw string) []string {
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
			// 沒帶 port → 補 :53
			// 注意：IPv6 純地址要先包 [ ]
			if strings.Count(p, ":") >= 2 && !strings.HasPrefix(p, "[") {
				p = "[" + p + "]"
			}
			p = p + ":53"
		}
		out = append(out, p)
	}
	return out
}

// buildDialFunc 回傳用於 net.Resolver.Dial 的函式。
// 行為：依序嘗試每個 server；同一 server 先 UDP 後 TCP；任一成功即回。
func buildDialFunc(servers []string) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// 忽略 net 套件傳入的 address（那是從 /etc/resolv.conf 推出來的）
		// 我們堅持用設定中的 servers
		var lastErr error
		for _, srv := range servers {
			// 先 UDP（快），失敗再 TCP（可繞過 UDP 被擋）
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

// resolver 取得當前 resolver；若尚未初始化則 lazy init。
func resolver() *net.Resolver {
	if s := dnsStatePtr.Load(); s != nil {
		return s.resolver
	}
	rebuildResolver()
	return dnsStatePtr.Load().resolver
}

// newDialer 建立帶有正確 resolver 的 net.Dialer。
// 此函式取代原 main.go 中的同名函式。
func newDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout:  timeout,
		Resolver: resolver(),
	}
}

// dialContextSmart 對 host:port 進行解析 + 撥號，並把「DNS 失敗」與「TCP 失敗」分開回報。
// 這對於排查「IP 直連通、走 DNS 不通」的情境特別有用：
// 一看 log 就知道究竟是 NXDOMAIN/SERVFAIL 還是 connection refused/timeout。
func dialContextSmart(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// 純 IP 直接撥號，不走 DNS
	if ip := net.ParseIP(host); ip != nil {
		d := net.Dialer{Timeout: timeout}
		return d.DialContext(ctx, "tcp", addr)
	}

	// 解析 hostname → IPs
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	ips, err := resolver().LookupIPAddr(resolveCtx, host)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS lookup returned no results for %q", host)
	}

	// 依序嘗試（IPv4 優先，因 NPV 客戶端多為 IPv4-only 上行）
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

// sortIPv4First 把 IPv4 排在 IPv6 前面（in-place）。
// NPV 客戶端通常無 IPv6 上行，IPv4 優先可避免無謂的 IPv6 timeout。
func sortIPv4First(ips []net.IPAddr) {
	for i := 0; i < len(ips); i++ {
		if ips[i].IP.To4() != nil {
			continue
		}
		// 找後面第一個 IPv4 換上來
		for j := i + 1; j < len(ips); j++ {
			if ips[j].IP.To4() != nil {
				ips[i], ips[j] = ips[j], ips[i]
				break
			}
		}
	}
}

// dnsHealthCheck 啟動時對設定的 DNS server 各做一次測試查詢。
// 把結果輸出到 log，方便管理者立即知道「DNS 是否真的能用」。
func dnsHealthCheck() {
	dnsHealthOnce.Do(func() {
		state := dnsStatePtr.Load()
		if state == nil {
			return
		}

		// 用 cloudflare.com 當測試標的：穩定、TTL 短、分散全球
		const probe = "cloudflare.com"
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		start := time.Now()
		ips, err := state.resolver.LookupIPAddr(ctx, probe)
		elapsed := time.Since(start)

		if err != nil {
			log.Printf("DNS HEALTH-CHECK: ❌ FAILED — probe=%s err=%v elapsed=%v", probe, err, elapsed)
			log.Printf("DNS HEALTH-CHECK: 提示：請檢查 docker-compose.yml 的 dns: 區塊或 DNS_SERVER 環境變數")
			if len(state.servers) == 0 {
				log.Printf("DNS HEALTH-CHECK: 目前未設定自訂 DNS，正在使用容器 /etc/resolv.conf")
			} else {
				log.Printf("DNS HEALTH-CHECK: 設定中的 DNS servers: %v", state.servers)
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

// classifyDNSError 把錯誤分類，方便 log 給使用者看的中文訊息。
// 回傳 (kind, hint)；kind 為短代號，hint 為人類可讀提示。
func classifyDNSError(err error) (kind string, hint string) {
	if err == nil {
		return "", ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "NXDOMAIN"):
		return "NXDOMAIN", "域名不存在或上游 DNS 拒答"
	case strings.Contains(msg, "server misbehaving"):
		return "SERVFAIL", "上游 DNS 回 SERVFAIL，可能 DNS 伺服器設定錯誤"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "TIMEOUT", "DNS 查詢逾時，可能 UDP 53 被防火牆擋；考慮換 DNS 或啟用 TCP fallback"
	case strings.Contains(msg, "connection refused"):
		return "REFUSED", "DNS 連線被拒，伺服器位址可能錯誤或服務未啟動"
	case strings.Contains(msg, "DNS lookup failed"):
		return "LOOKUP", "DNS 查詢失敗（請見上層錯誤訊息）"
	default:
		return "OTHER", "其他錯誤"
	}
}
