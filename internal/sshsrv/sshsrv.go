// Package sshsrv 處理 SSH 連線:握手、tolerantCopy、direct-tcpip 分派、
// 線上使用者註冊表、密碼認證 callback。
package sshsrv

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

	"wstunnel/internal/config"
	"wstunnel/internal/dnsx"
	"wstunnel/internal/iptun"
	"wstunnel/internal/logging"
	"wstunnel/internal/proxy"
	"wstunnel/internal/store"
	"wstunnel/internal/traffic"
	"wstunnel/internal/udpgw"
)

const sshHostKeyFile = "data/ssh_host_key"

// OnlineUser 表示一個目前活躍的 SSH 連線,用於後台顯示與管理。
type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	SSHConn     ssh.Conn  `json:"-"`
}

var (
	online              sync.Map // connID → *OnlineUser
	userConnectionCount sync.Map // username → *int32

	bufferPool sync.Pool
	bufPoolMu  sync.Mutex
)

// InitBufferPool 在啟動時依 config 初始化 bufferPool;設定變更後可重呼叫。
func InitBufferPool() {
	bufPoolMu.Lock()
	defer bufPoolMu.Unlock()
	c := config.Get()
	c.Lock.RLock()
	size := c.BufferSizeKB
	c.Lock.RUnlock()
	if size <= 0 {
		size = 32
	}
	bufferPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, size*1024)
		return &buf
	}}
}

// OnlineRange 遍歷所有線上使用者(後台 /api/connections 用)。
func OnlineRange(fn func(u *OnlineUser) bool) {
	online.Range(func(_, v interface{}) bool {
		return fn(v.(*OnlineUser))
	})
}

// Lookup 依 connID 找到對應 OnlineUser。
func Lookup(connID string) (*OnlineUser, bool) {
	v, ok := online.Load(connID)
	if !ok {
		return nil, false
	}
	return v.(*OnlineUser), true
}

// CountOnline 取得目前線上連線數(後台用)。
func CountOnline() int {
	n := 0
	online.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

// KickByUsername 關掉所有指定使用者的活躍連線(封停帳號用)。
func KickByUsername(username string) {
	var conns []ssh.Conn
	online.Range(func(_, v interface{}) bool {
		u := v.(*OnlineUser)
		if u.Username == username {
			conns = append(conns, u.SSHConn)
		}
		return true
	})
	for _, c := range conns {
		c.Close()
	}
}

// KickByConnID 關閉特定 conn_id 的連線。回傳是否找到並關閉。
func KickByConnID(connID string) bool {
	v, ok := online.Load(connID)
	if !ok {
		return false
	}
	v.(*OnlineUser).SSHConn.Close()
	return true
}

// LoadOrGenerateHostKey 從磁碟載入持久化的 SSH host key,若不存在則產生並儲存。
func LoadOrGenerateHostKey() ssh.Signer {
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

// BuildServerConfig 組出 SSH server config,包含密碼認證 callback。
func BuildServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion:    "SSH-2.0-WSTunnel_Pro",
		PasswordCallback: passwordCallback,
	}
	cfg.AddHostKey(LoadOrGenerateHostKey())
	return cfg
}

// passwordCallback SSH 密碼認證,整合帳號狀態/到期/流量上限/連線數。
//
// 順序刻意設計:先做廉價檢查(查 row、enabled、expiry、流量、連線數),
// 再做昂貴的 bcrypt 比對。bcrypt cost=12 約 300ms,可避免被當枚舉預言機。
func passwordCallback(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
	user := c.User()
	acc, err := store.GetAccount(user)
	if err != nil || !acc.Enabled {
		return nil, fmt.Errorf("auth failed")
	}
	if acc.ExpiryDate != "" {
		exp, err := time.Parse("2006-01-02", acc.ExpiryDate)
		if err != nil || time.Now().After(exp.Add(24*time.Hour)) {
			return nil, fmt.Errorf("user expired")
		}
	}
	if acc.LimitGB > 0 {
		t := traffic.Get(user)
		if traffic.LoadSent(t)+traffic.LoadReceived(t) >= uint64(acc.LimitGB*1e9) {
			return nil, fmt.Errorf("traffic limit exceeded")
		}
	}
	if acc.MaxSessions > 0 {
		v, _ := userConnectionCount.LoadOrStore(user, new(int32))
		countPtr := v.(*int32)
		if atomic.LoadInt32(countPtr) >= int32(acc.MaxSessions) {
			return nil, fmt.Errorf("max sessions exceeded")
		}
		atomic.AddInt32(countPtr, 1)
	}
	if store.VerifyPassword(acc.PasswordHash, string(p)) {
		return nil, nil
	}
	// bcrypt 失敗:把剛剛累加的 session 計數退回去
	if acc.MaxSessions > 0 {
		if v, ok := userConnectionCount.Load(user); ok {
			atomic.AddInt32(v.(*int32), -1)
		}
	}
	return nil, fmt.Errorf("invalid credentials")
}

// HandshakeConn 把已被 Peek 過的 reader 重新黏回 net.Conn。
type HandshakeConn struct {
	net.Conn
	R io.Reader
}

func (hc *HandshakeConn) Read(p []byte) (n int, err error) { return hc.R.Read(p) }

// tolerantCopy 雙向 byte copy,對暫時性網路錯誤做退避重試。
func tolerantCopy(dst io.Writer, src io.Reader, direction string, remoteAddr net.Addr, username string) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	cfg := config.Get()
	cfg.Lock.RLock()
	maxRetries := cfg.TolerantCopyMaxRetries
	retryDelay := time.Duration(cfg.TolerantCopyRetryDelayMs) * time.Millisecond
	cfg.Lock.RUnlock()

	consecutiveTempErrors := 0
	t := traffic.Get(username)

	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			if consecutiveTempErrors > 0 && logging.DebugEnabled {
				log.Printf("TCP Proxy (%s): Network recovery for %s after %d failed attempts.",
					direction, remoteAddr, consecutiveTempErrors)
			}
			consecutiveTempErrors = 0

			nw, wErr := dst.Write(buf[0:nr])
			if nw > 0 {
				if direction == "Client->Target" {
					traffic.AddSent(t, uint64(nw))
				} else {
					traffic.AddReceived(t, uint64(nw))
				}
			}
			if wErr != nil {
				if !logging.IsBenign(wErr) {
					log.Printf("TCP Proxy (%s): Permanent write error for %s: %v", direction, remoteAddr, wErr)
				}
				break
			}
			if nr != nw {
				if logging.DebugEnabled {
					log.Printf("TCP Proxy (%s): Short write for %s, closing", direction, remoteAddr)
				}
				break
			}
		}
		if rErr != nil {
			if logging.IsBenign(rErr) {
				break
			}
			if netErr, ok := rErr.(net.Error); ok && (netErr.Timeout() || netErr.Temporary()) {
				consecutiveTempErrors++
				if consecutiveTempErrors > maxRetries {
					log.Printf("TCP Proxy (%s): Too many errors for %s, giving up. Last error: %v",
						direction, remoteAddr, rErr)
					break
				}
				if logging.DebugEnabled {
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

// handleDirectTCPIP 處理 SSH client 要求的 TCP forward。
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32, remoteAddr net.Addr, username string) {
	destAddr := net.JoinHostPort(destHost, fmt.Sprintf("%d", destPort))

	cfg := config.Get()
	cfg.Lock.RLock()
	connectTimeout := time.Duration(cfg.TargetConnectTimeoutSeconds) * time.Second
	cfg.Lock.RUnlock()

	destConn, err := proxy.DialTarget(context.Background(), destAddr, connectTimeout)
	if err != nil {
		if kind, hint := dnsx.ClassifyError(err); kind != "" && kind != "OTHER" {
			log.Printf("TCP Proxy: dial %s for user '%s' FAILED [%s] — %s | err=%v",
				destAddr, username, kind, hint, err)
		} else if !logging.IsBenign(err) {
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

// sendKeepAlives 對 ssh.Conn 定期發送 keepalive,維持 NAT/防火牆 mapping。
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

// HandleConnection 對單一進來的 SSH 連線執行握手,並進入 channel 主迴圈。
func HandleConnection(c net.Conn, r io.Reader, sshCfg *ssh.ServerConfig) {
	connForSSH := &HandshakeConn{Conn: c, R: r}
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(connForSSH, sshCfg)
	if err != nil {
		if !logging.IsBenign(err) {
			log.Printf("SSH handshake failed for %s: %v", c.RemoteAddr(), err)
		}
		return
	}

	cfg := config.Get()
	cfg.Lock.RLock()
	idleTimeout := time.Duration(cfg.IdleTimeoutSeconds) * time.Second
	cfg.Lock.RUnlock()

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
	user := &OnlineUser{
		ConnID:      connID,
		Username:    username,
		RemoteAddr:  sshConn.RemoteAddr().String(),
		ConnectTime: time.Now(),
		SSHConn:     sshConn,
	}
	online.Store(connID, user)
	defer online.Delete(connID)

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			var payload struct {
				Host           string
				Port           uint32
				OriginatorIP   string
				OriginatorPort uint32
			}
			ssh.Unmarshal(newChan.ExtraData(), &payload)
			if udpgw.IsTarget(payload.Host, payload.Port) {
				go udpgw.HandleChannel(ch, sshConn.RemoteAddr(), username)
			} else {
				go handleDirectTCPIP(ch, payload.Host, payload.Port, sshConn.RemoteAddr(), username)
			}
		case "tun-tcpip", "ip-tunnel":
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			go iptun.HandleChannel(ch, sshConn.RemoteAddr())
		default:
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
}
