// ssh_server.go — SSH 連線處理核心
//
// 職責：
//   * SSH host key 持久化(避免每次重啟客戶端都看到 host key changed)
//   * handshakeConn: 把已被 Peek 過的 reader 重新接回 net.Conn
//   * tolerantCopy: 雙向資料轉發,具備暫時性網路錯誤的退避重試
//   * handleDirectTCPIP: 處理 SSH client 要求的 TCP forward
//   * handleSshConnection: SSH 握手後的主迴圈,分派 channel
//   * sendKeepAlives: 背景 keepalive
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshHostKeyFile = "data/ssh_host_key"

var bufferPool sync.Pool

// loadOrGenerateSSHHostKey 從磁碟載入持久化的 SSH host key,若不存在則產生並儲存
func loadOrGenerateSSHHostKey() ssh.Signer {
	if data, err := os.ReadFile(sshHostKeyFile); err == nil {
		if signer, err := ssh.ParsePrivateKey(data); err == nil {
			log.Printf("System: Loaded SSH host key from %s", sshHostKeyFile)
			return signer
		}
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("FATAL: Failed to generate SSH host key: %v", err)
	}

	if err := os.MkdirAll("data", 0755); err == nil {
		privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		if err := os.WriteFile(sshHostKeyFile, pemBlock, 0600); err != nil {
			log.Printf("System: Warning - Failed to save SSH host key: %v", err)
		} else {
			log.Printf("System: Generated and saved new SSH host key to %s", sshHostKeyFile)
		}
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatalf("FATAL: Failed to create SSH signer from host key: %v", err)
	}
	return signer
}

// handshakeConn 把已被 Peek 過的 reader 重新黏回 net.Conn,以便 SSH library 從正確位置讀
type handshakeConn struct {
	net.Conn
	r io.Reader
}

func (hc *handshakeConn) Read(p []byte) (n int, err error) { return hc.r.Read(p) }

// tolerantCopy 雙向 byte copy,對暫時性網路錯誤做退避重試
//
// 設計理念:在不穩定的行動網路下(切基地台、4G/Wi-Fi 切換),client/target 可能短暫斷流,
// 直接 break 會導致整個 SSH session 中斷。tolerantCopy 對 net.Error.Temporary() 的錯誤
// 做有限次數退避,讓網路抖動時連線可以續命。
func tolerantCopy(dst io.Writer, src io.Reader, direction string, remoteAddr net.Addr, username string) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	globalConfig.lock.RLock()
	maxRetries := globalConfig.TolerantCopyMaxRetries
	retryDelay := time.Duration(globalConfig.TolerantCopyRetryDelayMs) * time.Millisecond
	globalConfig.lock.RUnlock()

	consecutiveTempErrors := 0
	val, _ := globalTraffic.LoadOrStore(username, &TrafficInfo{})
	traffic := val.(*TrafficInfo)

	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			if consecutiveTempErrors > 0 && debugEnabled {
				log.Printf("TCP Proxy (%s): Network recovery for %s after %d failed attempts.",
					direction, remoteAddr, consecutiveTempErrors)
			}
			consecutiveTempErrors = 0

			nw, wErr := dst.Write(buf[0:nr])
			if nw > 0 {
				if direction == "Client->Target" {
					atomic.AddUint64(&traffic.Sent, uint64(nw))
				} else {
					atomic.AddUint64(&traffic.Received, uint64(nw))
				}
			}
			if wErr != nil {
				if !isBenignNetError(wErr) {
					log.Printf("TCP Proxy (%s): Permanent write error for %s: %v", direction, remoteAddr, wErr)
				}
				break
			}
			if nr != nw {
				if debugEnabled {
					log.Printf("TCP Proxy (%s): Short write for %s, closing", direction, remoteAddr)
				}
				break
			}
		}
		if rErr != nil {
			if isBenignNetError(rErr) {
				break
			}
			if netErr, ok := rErr.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				consecutiveTempErrors++
				if consecutiveTempErrors > maxRetries {
					log.Printf("TCP Proxy (%s): Too many errors for %s, giving up. Last error: %v",
						direction, remoteAddr, rErr)
					break
				}
				if debugEnabled {
					log.Printf("TCP Proxy (%s): Temporary error for %s: %v. Retrying in %v... (%d/%d)",
						direction, remoteAddr, rErr, retryDelay, consecutiveTempErrors, maxRetries)
				}
				time.Sleep(retryDelay)
				continue
			}
			log.Printf("TCP Proxy (%s): Unrecoverable read error for %s: %v", direction, remoteAddr, rErr)
			break
		}
	}
}

// handleDirectTCPIP 處理 SSH client 要求的 TCP forward
// 解析失敗會用分類過的訊息(NXDOMAIN/TIMEOUT/...)印出,方便排障
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr, username string) {
	destAddr := net.JoinHostPort(destHost, fmt.Sprintf("%d", destPort))

	globalConfig.lock.RLock()
	connectTimeout := time.Duration(globalConfig.TargetConnectTimeoutSeconds) * time.Second
	globalConfig.lock.RUnlock()

	destConn, err := dialContextSmart(context.Background(), destAddr, connectTimeout)
	if err != nil {
		if kind, hint := classifyDNSError(err); kind != "" && kind != "OTHER" {
			log.Printf("TCP Proxy: dial %s for user '%s' FAILED [%s] — %s | err=%v",
				destAddr, username, kind, hint, err)
		} else if !isBenignNetError(err) {
			log.Printf("TCP Proxy: dial %s for user '%s' FAILED — %v", destAddr, username, err)
		}
		ch.Close()
		return
	}
	defer destConn.Close()

	if tcpConn, ok := destConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(1 * time.Minute)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if tcpConn, ok := destConn.(*net.TCPConn); ok {
			defer tcpConn.CloseWrite()
		} else {
			defer destConn.Close()
		}
		tolerantCopy(destConn, ch, "Client->Target", remoteAddr, username)
	}()
	go func() {
		defer wg.Done()
		defer ch.CloseWrite()
		tolerantCopy(ch, destConn, "Target->Client", remoteAddr, username)
	}()
	wg.Wait()
}

// sendKeepAlives 對 ssh.Conn 定期發送 keepalive,維持 NAT/防火牆 mapping
func sendKeepAlives(sshConn ssh.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_, _, err := sshConn.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

// handleSshConnection 對單一進來的 SSH 連線執行握手,並進入 channel 主迴圈
//
// channel 種類:
//   * direct-tcpip:        SSH 標準 TCP forward,若目標是 udpgw 則交給 udpgw.go 攔截
//   * tun-tcpip/ip-tunnel: 客製的 IP-over-SSH 隧道(ip_tunnel.go)
//   * 其他:                Reject(unsupported)
func handleSshConnection(c net.Conn, r io.Reader, sshCfg *ssh.ServerConfig) {
	connForSSH := &handshakeConn{Conn: c, r: r}
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(connForSSH, sshCfg)
	if err != nil {
		if !isBenignNetError(err) {
			log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	globalConfig.lock.RLock()
	idleTimeout := time.Duration(globalConfig.IdleTimeoutSeconds) * time.Second
	globalConfig.lock.RUnlock()

	if idleTimeout > 0 {
		c.SetReadDeadline(time.Time{})
		doneDeadline := make(chan struct{})
		defer close(doneDeadline)
		go func() {
			ticker := time.NewTicker(idleTimeout / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c.SetReadDeadline(time.Now().Add(idleTimeout))
				case <-doneDeadline:
					return
				}
			}
		}()
	} else {
		c.SetReadDeadline(time.Time{})
	}

	defer sshConn.Close()
	username := sshConn.User()
	defer func() {
		if val, ok := userConnectionCount.Load(username); ok {
			atomic.AddInt32(val.(*int32), -1)
		}
	}()
	log.Printf("Auth success for user '%s' from %s", username, sshConn.RemoteAddr())

	done := make(chan struct{})
	defer close(done)
	go sendKeepAlives(sshConn, done)

	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{
		ConnID:      connID,
		Username:    username,
		RemoteAddr:  sshConn.RemoteAddr().String(),
		ConnectTime: time.Now(),
		sshConn:     sshConn,
	}
	onlineUsers.Store(onlineUser.ConnID, onlineUser)
	defer onlineUsers.Delete(onlineUser.ConnID)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			// RFC 4254 Section 7.2: direct-tcpip ExtraData 包含 4 個欄位
			var payload struct {
				Host           string
				Port           uint32
				OriginatorIP   string
				OriginatorPort uint32
			}
			ssh.Unmarshal(newChan.ExtraData(), &payload)
			// 若目標是 udpgw,接管以攔截 DNS 並透明轉發其他 UDP (見 udpgw.go)
			if isUDPGWTarget(payload.Host, payload.Port) {
				go handleUDPGWChannel(ch, sshConn.RemoteAddr(), username)
			} else {
				go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr(), username)
			}
		case "tun-tcpip", "ip-tunnel":
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			go handleIPTunnel(ch, sshConn.RemoteAddr())
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}
