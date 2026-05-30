// Package udpgw 攔截 SSH direct-tcpip 通往 udpgw 的連線,在 channel 層
// 解析 UDPGW frame,將 DNS 查詢由 wstunnel 自己回應,其他 UDP 透明轉發給
// 真正的 udpgw 進程。
//
// 詳細協定格式見 BadVPN udpgw_protocol.h:
//
//	[2 bytes length, LE]
//	[1 byte flags]
//	[2 bytes conid, LE]
//	[4 or 16 bytes addr][2 bytes port, BE]
//	[N bytes payload]
package udpgw

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

	"wstunnel/internal/config"
	"wstunnel/internal/dnsx"
	"wstunnel/internal/logging"
)

const (
	flagKeepalive = 0x01
	flagRebind    = 0x02
	flagDNS       = 0x04
	flagIPv6      = 0x08

	defaultPort      = 7300
	dnsTimeout       = 5 * time.Second
	maxFrameLen      = 65535
	logSampleSec     = 30
)

// 全域 UDPGW 統計,用於觀測。
var (
	sessions      atomic.Int64
	dnsIntercept  atomic.Int64
	dnsSuccess    atomic.Int64
	dnsFailed     atomic.Int64
	bytesUp       atomic.Uint64
	bytesDown     atomic.Uint64
	lastSuccessLog atomic.Int64
)

type frame struct {
	flags   uint8
	conid   uint16
	dstIP   net.IP
	dstPort uint16
	payload []byte
}

func (f *frame) isKeepalive() bool { return f.flags&flagKeepalive != 0 }
func (f *frame) isIPv6() bool      { return f.flags&flagIPv6 != 0 }
func (f *frame) isDNS() bool {
	return f.flags&flagDNS != 0 || f.dstPort == 53
}

// IsTarget 判斷 SSH direct-tcpip 的目的地是否指向本機的 udpgw。
func IsTarget(host string, port uint32) bool {
	if int(port) != Port() {
		return false
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0":
		return true
	}
	return false
}

// Port 取得 udpgw 監聽 port,預設 7300。
func Port() int {
	c := config.Get()
	c.Lock.RLock()
	p := c.UDPGWPort
	c.Lock.RUnlock()
	if p <= 0 {
		return defaultPort
	}
	return p
}

func readFrame(r io.Reader) (*frame, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint16(lenBuf[:])
	if length < 3 {
		return nil, fmt.Errorf("udpgw: frame too short (%d)", length)
	}
	if int(length) > maxFrameLen {
		return nil, fmt.Errorf("udpgw: frame too large (%d)", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	f := &frame{
		flags: body[0],
		conid: binary.LittleEndian.Uint16(body[1:3]),
	}
	pos := 3
	if f.isKeepalive() {
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

func writeFrame(w io.Writer, f *frame) error {
	addrLen := 4
	if f.isIPv6() {
		addrLen = 16
	}
	bodyLen := 1 + 2 + addrLen + 2 + len(f.payload)
	if f.isKeepalive() {
		bodyLen = 3
	}
	if bodyLen > maxFrameLen {
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

// safeWriter 包裝 ssh.Channel 的並行寫入。
type safeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// HandleChannel 接管一條目的地為 udpgw 的 SSH direct-tcpip channel。
func HandleChannel(ch ssh.Channel, remoteAddr net.Addr, username string) {
	sessions.Add(1)
	defer sessions.Add(-1)

	log.Printf("UDPGW: session start user='%s' from %s", username, remoteAddr)
	defer log.Printf("UDPGW: session end user='%s' from %s", username, remoteAddr)

	defer ch.Close()

	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", Port()), 3*time.Second)
	if err != nil {
		log.Printf("UDPGW: ⚠️  cannot reach local udpgw process at 127.0.0.1:%d: %v "+
			"— DNS will still work via interception, but other UDP traffic will be dropped",
			Port(), err)
		upstream = nil
	}
	if upstream != nil {
		defer upstream.Close()
	}

	chWriter := &safeWriter{w: ch}
	var wg sync.WaitGroup

	if upstream != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 32*1024)
			for {
				n, err := upstream.Read(buf)
				if n > 0 {
					if _, werr := chWriter.Write(buf[:n]); werr != nil {
						return
					}
					bytesDown.Add(uint64(n))
				}
				if err != nil {
					return
				}
			}
		}()
	}

	for {
		f, err := readFrame(ch)
		if err != nil {
			break
		}
		bytesUp.Add(uint64(len(f.payload)))

		if f.isKeepalive() {
			if upstream != nil {
				if err := writeFrame(upstream, f); err != nil {
					break
				}
			}
			continue
		}

		if f.isDNS() {
			dnsIntercept.Add(1)
			go interceptDNS(f, chWriter, username)
			continue
		}

		if upstream == nil {
			continue
		}
		if err := writeFrame(upstream, f); err != nil {
			break
		}
	}

	if upstream != nil {
		upstream.Close()
	}
	wg.Wait()
}

// interceptDNS 攔截 DNS 查詢,使用 dnsx resolver chain 解析後回包。
//
// 策略:
//  1. 先試 frame 中的原始 dst (例如 client 設定的 8.8.8.8:53),5 秒逾時
//  2. 失敗則改用 globalConfig.DNSServer 解析(走 dnsx 的多 server failover + UDP→TCP)
//  3. 全部失敗則記錯誤,不回應 (client 會自己 timeout)
func interceptDNS(f *frame, chWriter *safeWriter, username string) {
	if len(f.payload) < 12 {
		return
	}

	respPayload, source, err := dnsForwardOriginal(f)
	if err != nil {
		respPayload, source, err = dnsForwardConfigured(f.payload)
	}

	if err != nil {
		dnsFailed.Add(1)
		log.Printf("UDPGW DNS: ❌ user='%s' dst=%s:%d FAILED — %v",
			username, f.dstIP, f.dstPort, err)
		return
	}

	dnsSuccess.Add(1)
	resp := &frame{
		flags:   f.flags,
		conid:   f.conid,
		dstIP:   f.dstIP,
		dstPort: f.dstPort,
		payload: respPayload,
	}
	if err := writeFrame(chWriter, resp); err != nil {
		if !logging.IsBenign(err) {
			log.Printf("UDPGW DNS: write reply failed for user='%s': %v", username, err)
		}
		return
	}

	logSuccess(source)
}

// logSuccess 以時間視窗節流(預設 30 秒一次)印出成功統計,避免洗版。
func logSuccess(source string) {
	now := time.Now().Unix()
	last := lastSuccessLog.Load()
	if now-last < logSampleSec {
		return
	}
	if !lastSuccessLog.CompareAndSwap(last, now) {
		return
	}
	log.Printf("UDPGW DNS: ✅ working via %s — total success=%d failed=%d (last %ds window)",
		source, dnsSuccess.Load(), dnsFailed.Load(), logSampleSec)
}

// dnsForwardOriginal 試著把 DNS 查詢 forward 給 client 指定的 server。
func dnsForwardOriginal(f *frame) ([]byte, string, error) {
	if f.dstIP == nil || f.dstIP.IsUnspecified() {
		return nil, "", errors.New("invalid dst")
	}
	addr := net.JoinHostPort(f.dstIP.String(), fmt.Sprintf("%d", f.dstPort))
	return roundtrip("udp", addr, f.payload, dnsTimeout)
}

// dnsForwardConfigured 退到 globalConfig.DNSServer 解析(走 dnsx 的清單)。
func dnsForwardConfigured(query []byte) ([]byte, string, error) {
	servers := dnsx.Servers()
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	var lastErr error
	for _, srv := range servers {
		for _, proto := range []string{"udp", "tcp"} {
			resp, _, err := roundtrip(proto, srv, query, dnsTimeout)
			if err == nil {
				return resp, srv + "/" + proto, nil
			}
			lastErr = err
		}
	}
	return nil, "", fmt.Errorf("all DNS servers failed: %w", lastErr)
}

// roundtrip 對指定 server 送出 raw DNS query 並讀回 raw response。
func roundtrip(network, server string, query []byte, timeout time.Duration) ([]byte, string, error) {
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

// HealthCheck 啟動時檢查 udpgw 進程是否存活並 log 結果。
func HealthCheck() {
	addr := fmt.Sprintf("127.0.0.1:%d", Port())
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		log.Printf("UDPGW HEALTH-CHECK: ❌ udpgw process at %s NOT reachable — %v", addr, err)
		log.Printf("UDPGW HEALTH-CHECK:    DNS 仍可用(走 wstunnel 內建攔截);其他 UDP App 將失效")
		log.Printf("UDPGW HEALTH-CHECK:    請檢查 entrypoint.sh 是否成功啟動 udpgw -l 0.0.0.0:%d", Port())
		return
	}
	conn.Close()
	log.Printf("UDPGW HEALTH-CHECK: ✅ udpgw process is alive at %s", addr)
}

// Stats 回傳目前統計快照,給 admin /api/udpgw/status 用。
func Stats() map[string]interface{} {
	return map[string]interface{}{
		"sessions":      sessions.Load(),
		"dns_intercept": dnsIntercept.Load(),
		"dns_success":   dnsSuccess.Load(),
		"dns_failed":    dnsFailed.Load(),
		"bytes_up":      bytesUp.Load(),
		"bytes_down":    bytesDown.Load(),
		"udpgw_port":    Port(),
	}
}
