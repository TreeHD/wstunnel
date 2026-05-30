// udpgw.go — UDPGW (BadVPN tun2socks) 協定攔截器
//
// 背景:
//   NPV Tunnel 等 SSH-based VPN 客戶端透過 UDPGW 把 UDP 包(含 DNS)封裝成
//   TCP 訊框,經由 SSH direct-tcpip channel 送到 udpgw-server。
//   舊架構完全依賴 sidecar 的 udpgw-server 處理所有 UDP,當 udpgw 進程死掉、
//   或機房擋 UDP/53 出站時,DNS 就會 NXDOMAIN。
//
// 本檔做的事:
//   1. 攔截目的地為 udpgw 的 SSH direct-tcpip channel
//   2. 解析 UDPGW frame
//   3. 對 DNS 查詢(port 53)由 wstunnel 自己解析(走 dns.go 的 resolver chain)
//   4. 非 DNS 流量透明轉發給真實 udpgw 進程,維持其他 UDP App 可用
//
// UDPGW Frame 格式 (參考 BadVPN udpgw_protocol.h):
//   [2 bytes length, LE]
//   [1 byte flags]
//   [2 bytes conid, LE]
//   [4 or 16 bytes addr][2 bytes port, BE]
//   [N bytes payload]
//   length = 1 + 2 + addr_len + 2 + N
//
// Flags:
//   0x01 KEEPALIVE  0x02 REBIND  0x04 DNS  0x08 IPv6
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	udpgwFlagKeepalive = 0x01
	udpgwFlagRebind    = 0x02
	udpgwFlagDNS       = 0x04
	udpgwFlagIPv6      = 0x08

	// 預設 udpgw 監聽 port (與 entrypoint.sh 中 udpgw -l 0.0.0.0:7300 一致)
	defaultUDPGWPort = 7300

	// DNS 查詢逾時
	udpgwDNSTimeout = 5 * time.Second

	// 單個 frame 上限保護(防惡意流量)
	udpgwMaxFrameLen = 65535
)

// 全域 UDPGW 統計,用於觀測
var (
	udpgwSessions     atomic.Int64
	udpgwDNSIntercept atomic.Int64
	udpgwDNSSuccess   atomic.Int64
	udpgwDNSFailed    atomic.Int64
	udpgwBytesUp      atomic.Uint64
	udpgwBytesDown    atomic.Uint64
)

// udpgwFrame 解析後的單一 UDPGW 訊框
type udpgwFrame struct {
	flags   uint8
	conid   uint16
	dstIP   net.IP
	dstPort uint16
	payload []byte
}

func (f *udpgwFrame) isKeepalive() bool { return f.flags&udpgwFlagKeepalive != 0 }
func (f *udpgwFrame) isIPv6() bool      { return f.flags&udpgwFlagIPv6 != 0 }
func (f *udpgwFrame) isDNS() bool {
	// 兩種判斷方式: 顯式 DNS flag 或 dstPort==53
	return f.flags&udpgwFlagDNS != 0 || f.dstPort == 53
}

// isUDPGWTarget 判斷一個 SSH direct-tcpip 的目的地是否指向本機的 udpgw
// 接受 "127.0.0.1", "localhost", "::1" + port == 7300 (或 globalConfig 設定值)
func isUDPGWTarget(host string, port uint32) bool {
	if int(port) != getUDPGWPort() {
		return false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0":
		return true
	}
	return false
}

// getUDPGWPort 從 globalConfig 取得 udpgw port,預設 7300
func getUDPGWPort() int {
	globalConfig.lock.RLock()
	p := globalConfig.UDPGWPort
	globalConfig.lock.RUnlock()
	if p <= 0 {
		return defaultUDPGWPort
	}
	return p
}

// readUDPGWFrame 從 reader 讀取一個完整的 UDPGW frame
func readUDPGWFrame(r io.Reader) (*udpgwFrame, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint16(lenBuf[:])
	if length < 3 {
		return nil, fmt.Errorf("udpgw: frame too short (%d)", length)
	}
	if int(length) > udpgwMaxFrameLen {
		return nil, fmt.Errorf("udpgw: frame too large (%d)", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	f := &udpgwFrame{
		flags: body[0],
		conid: binary.LittleEndian.Uint16(body[1:3]),
	}
	pos := 3

	if f.isKeepalive() {
		// keepalive 沒有 addr/payload
		return f, nil
	}

	if f.isIPv6() {
		if int(length) < pos+18 {
			return nil, errors.New("udpgw: ipv6 frame underflow")
		}
		f.dstIP = make(net.IP, 16)
		copy(f.dstIP, body[pos:pos+16])
		pos += 16
	} else {
		if int(length) < pos+6 {
			return nil, errors.New("udpgw: ipv4 frame underflow")
		}
		f.dstIP = make(net.IP, 4)
		copy(f.dstIP, body[pos:pos+4])
		pos += 4
	}
	f.dstPort = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	f.payload = body[pos:]
	return f, nil
}

// writeUDPGWFrame 將 frame 寫回 writer (整段一次寫入,呼叫者需自行加鎖)
func writeUDPGWFrame(w io.Writer, f *udpgwFrame) error {
	addrLen := 4
	if f.isIPv6() {
		addrLen = 16
	}
	bodyLen := 1 + 2 + addrLen + 2 + len(f.payload)
	if f.isKeepalive() {
		bodyLen = 3 // 只有 flags + conid
	}
	if bodyLen > udpgwMaxFrameLen {
		return fmt.Errorf("udpgw: outgoing frame too large (%d)", bodyLen)
	}

	buf := make([]byte, 2+bodyLen)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(bodyLen))
	buf[2] = f.flags
	binary.LittleEndian.PutUint16(buf[3:5], f.conid)
	pos := 5

	if !f.isKeepalive() {
		if f.isIPv6() {
			ip := f.dstIP.To16()
			if ip == nil {
				return errors.New("udpgw: invalid ipv6 dst")
			}
			copy(buf[pos:pos+16], ip)
			pos += 16
		} else {
			ip := f.dstIP.To4()
			if ip == nil {
				return errors.New("udpgw: invalid ipv4 dst")
			}
			copy(buf[pos:pos+4], ip)
			pos += 4
		}
		binary.BigEndian.PutUint16(buf[pos:pos+2], f.dstPort)
		pos += 2
		copy(buf[pos:], f.payload)
	}

	_, err := w.Write(buf)
	return err
}

// safeChannelWriter 包裝 ssh.Channel 的並行寫入(DNS goroutine 與上行轉發互不衝突)
type safeChannelWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *safeChannelWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// handleUDPGWChannel 接管一條目的地為 udpgw 的 SSH direct-tcpip channel
//
// 流程:
//   1. 解析每個 frame
//   2. DNS frame -> 走 wstunnel resolver,自己回應
//   3. 其他 frame -> 透明轉發給本機 udpgw 進程
//   4. udpgw 回來的 frame 直接轉回 SSH channel
func handleUDPGWChannel(ch ssh.Channel, remoteAddr net.Addr, username string) {
	udpgwSessions.Add(1)
	defer udpgwSessions.Add(-1)

	log.Printf("UDPGW: session start user='%s' from %s", username, remoteAddr)
	defer log.Printf("UDPGW: session end user='%s' from %s", username, remoteAddr)

	defer ch.Close()

	// 嘗試連到本機真實 udpgw 進程
	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", getUDPGWPort()), 3*time.Second)
	if err != nil {
		log.Printf("UDPGW: ⚠️  cannot reach local udpgw process at 127.0.0.1:%d: %v "+
			"— DNS will still work via interception, but other UDP traffic will be dropped",
			getUDPGWPort(), err)
		// 即使 udpgw 不可用也繼續,因為我們可以攔截 DNS
		upstream = nil
	}
	if upstream != nil {
		defer upstream.Close()
	}

	chWriter := &safeChannelWriter{w: ch}

	// 上行: SSH -> (filter) -> udpgw
	// 下行: udpgw -> SSH (純轉發)
	var wg sync.WaitGroup

	if upstream != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// udpgw -> SSH 純轉發,無需 frame 解析
			buf := make([]byte, 32*1024)
			for {
				n, err := upstream.Read(buf)
				if n > 0 {
					if _, werr := chWriter.Write(buf[:n]); werr != nil {
						return
					}
					udpgwBytesDown.Add(uint64(n))
				}
				if err != nil {
					return
				}
			}
		}()
	}

	// SSH -> filter -> udpgw  (主迴圈,結束就關 session)
	for {
		f, err := readUDPGWFrame(ch)
		if err != nil {
			if err != io.EOF {
				// 讀錯誤通常代表 client 斷線,降級成 debug
				// log.Printf("UDPGW: read frame err: %v", err)
			}
			break
		}

		// 統計
		udpgwBytesUp.Add(uint64(len(f.payload)))

		// 分流
		if f.isKeepalive() {
			// keepalive 直接往 udpgw 塞,讓它維持狀態(若 udpgw 不在則丟掉)
			if upstream != nil {
				if err := writeUDPGWFrame(upstream, f); err != nil {
					break
				}
			}
			continue
		}

		if f.isDNS() {
			// 攔截 DNS 自己解
			udpgwDNSIntercept.Add(1)
			go interceptDNSFrame(f, chWriter, username)
			continue
		}

		// 其他 UDP -> 透明轉給 udpgw
		if upstream == nil {
			// udpgw 不在,丟棄並 log(限頻)
			continue
		}
		if err := writeUDPGWFrame(upstream, f); err != nil {
			break
		}
	}

	// 確保下行 goroutine 也結束
	if upstream != nil {
		upstream.Close()
	}
	wg.Wait()
}

// interceptDNSFrame 攔截 DNS 查詢,使用 wstunnel resolver chain 解析後回包
//
// 策略:
//   1. 先試 frame 中的原始 dst (例如 client 設定的 8.8.8.8:53),5 秒逾時
//   2. 失敗則改用 globalConfig.DNSServer 解析(走 dns.go 的多 server failover + UDP→TCP)
//   3. 全部失敗則記錯誤,不回應 (client 會自己 timeout)
func interceptDNSFrame(f *udpgwFrame, chWriter *safeChannelWriter, username string) {
	if len(f.payload) < 12 {
		// DNS header 至少 12 bytes
		return
	}

	// 嘗試原始 dst
	respPayload, source, err := dnsForwardOriginal(f)
	if err != nil {
		// 退到設定的 DNS server
		respPayload, source, err = dnsForwardConfigured(f.payload)
	}

	if err != nil {
		udpgwDNSFailed.Add(1)
		log.Printf("UDPGW DNS: ❌ user='%s' dst=%s:%d FAILED — %v",
			username, f.dstIP, f.dstPort, err)
		return
	}

	udpgwDNSSuccess.Add(1)

	resp := &udpgwFrame{
		flags:   f.flags, // 保留 DNS / IPv6 等 flag
		conid:   f.conid,
		dstIP:   f.dstIP,
		dstPort: f.dstPort,
		payload: respPayload,
	}
	if err := writeUDPGWFrame(chWriter, resp); err != nil {
		if !isBenignNetError(err) {
			log.Printf("UDPGW DNS: write reply failed for user='%s': %v", username, err)
		}
		return
	}

	logUDPGWDNSSuccess(source)
}

// logUDPGWDNSSuccess 以時間視窗節流(預設 30 秒一次)印出成功統計,避免洗版
var (
	lastUDPGWDNSLog atomic.Int64
)

func logUDPGWDNSSuccess(source string) {
	const windowSec = 30
	now := time.Now().Unix()
	last := lastUDPGWDNSLog.Load()
	if now-last < windowSec {
		return
	}
	if !lastUDPGWDNSLog.CompareAndSwap(last, now) {
		return // 其他 goroutine 剛印過
	}
	log.Printf("UDPGW DNS: ✅ working via %s — total success=%d failed=%d (last %ds window)",
		source, udpgwDNSSuccess.Load(), udpgwDNSFailed.Load(), windowSec)
}

// dnsForwardOriginal 試著把 DNS 查詢 forward 給 client 指定的 server
func dnsForwardOriginal(f *udpgwFrame) ([]byte, string, error) {
	if f.dstIP == nil || f.dstIP.IsUnspecified() {
		return nil, "", errors.New("invalid dst")
	}
	addr := net.JoinHostPort(f.dstIP.String(), fmt.Sprintf("%d", f.dstPort))
	return dnsRoundtrip("udp", addr, f.payload, udpgwDNSTimeout)
}

// dnsForwardConfigured 退到 globalConfig.DNSServer 解析
// 與 /etc/resolv.conf 走同一條路,但用 UDP→TCP fallback
func dnsForwardConfigured(query []byte) ([]byte, string, error) {
	servers := configuredDNSServers()
	if len(servers) == 0 {
		// 沒設定就用 8.8.8.8 兜底
		servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	var lastErr error
	for _, srv := range servers {
		// 先 UDP 後 TCP
		for _, proto := range []string{"udp", "tcp"} {
			resp, _, err := dnsRoundtrip(proto, srv, query, udpgwDNSTimeout)
			if err == nil {
				return resp, srv + "/" + proto, nil
			}
			lastErr = err
		}
	}
	return nil, "", fmt.Errorf("all DNS servers failed: %w", lastErr)
}

// dnsRoundtrip 對指定 server 送出 raw DNS query 並讀回 raw response
func dnsRoundtrip(network, server string, query []byte, timeout time.Duration) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, network, server)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if network == "tcp" {
		// DNS over TCP 多 2 byte 長度前綴
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
		if _, err := conn.Write(hdr[:]); err != nil {
			return nil, "", err
		}
		if _, err := conn.Write(query); err != nil {
			return nil, "", err
		}
		var rh [2]byte
		if _, err := io.ReadFull(conn, rh[:]); err != nil {
			return nil, "", err
		}
		rl := binary.BigEndian.Uint16(rh[:])
		buf := make([]byte, rl)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, "", err
		}
		return buf, server, nil
	}

	// UDP
	if _, err := conn.Write(query); err != nil {
		return nil, "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, "", err
	}
	return buf[:n], server, nil
}

// configuredDNSServers 取得 dns.go 解析後的 server 清單
func configuredDNSServers() []string {
	if s := dnsStatePtr.Load(); s != nil {
		return s.servers
	}
	return nil
}

// udpgwHealthCheck 啟動時檢查 udpgw 進程是否存活並 log 結果
func udpgwHealthCheck() {
	addr := fmt.Sprintf("127.0.0.1:%d", getUDPGWPort())
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		log.Printf("UDPGW HEALTH-CHECK: ❌ udpgw process at %s NOT reachable — %v", addr, err)
		log.Printf("UDPGW HEALTH-CHECK:    DNS 仍可用(走 wstunnel 內建攔截);其他 UDP App 將失效")
		log.Printf("UDPGW HEALTH-CHECK:    請檢查 entrypoint.sh 是否成功啟動 udpgw -l 0.0.0.0:%d", getUDPGWPort())
		return
	}
	conn.Close()
	log.Printf("UDPGW HEALTH-CHECK: ✅ udpgw process is alive at %s", addr)
}

// udpgwStatsSnapshot 取得目前 UDPGW 統計快照,給 admin API 使用
func udpgwStatsSnapshot() map[string]interface{} {
	return map[string]interface{}{
		"sessions":       udpgwSessions.Load(),
		"dns_intercept":  udpgwDNSIntercept.Load(),
		"dns_success":    udpgwDNSSuccess.Load(),
		"dns_failed":     udpgwDNSFailed.Load(),
		"bytes_up":       udpgwBytesUp.Load(),
		"bytes_down":     udpgwBytesDown.Load(),
		"udpgw_port":     getUDPGWPort(),
	}
}
