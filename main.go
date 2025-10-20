package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- 结构体及全局变量 (增加 Timeout 配置) ---
type AccountInfo struct { /* ...内容不变... */
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"`
}
type Config struct {
	ListenAddr     string                 `json:"listen_addr"`
	SocksAddr      string                 `json:"socks_addr"`
	AdminAddr      string                 `json:"admin_addr"`
	AdminAccounts  map[string]string      `json:"admin_accounts"`
	Accounts       map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout int                  `json:"handshake_timeout"` // [新增] 握手超时时间（秒）
	ProbeUA        string                 `json:"probe_ua"`         // [新增] 探测用的User-Agent关键字
	ConnectUA      string                 `json:"connect_ua"`       // [新增] 最终连接用的User-Agent关键字
	lock           sync.RWMutex
}
var globalConfig *Config
var activeConn int64
type OnlineUser struct { /* ...内容不变... */
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshConn     ssh.Conn
}
var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct { Username string; Expiry time.Time }
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex

// --- 辅助函数 (无改动) ---
func addOnlineUser(user *OnlineUser) { onlineUsers.Store(user.ConnID, user) }
func removeOnlineUser(connID string) { onlineUsers.Delete(connID) }
func createSession(username string) *http.Cookie { /* ... */ 
	sessionTokenBytes := make([]byte, 32); rand.Read(sessionTokenBytes); sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour); sessionsLock.Lock(); sessions[sessionToken] = Session{Username: username, Expiry: expiry}; sessionsLock.Unlock()
	return &http.Cookie{Name: sessionCookieName, Value: sessionToken, Expires: expiry, Path: "/", HttpOnly: true}
}
func validateSession(r *http.Request) bool { /* ... */ 
	cookie, err := r.Cookie(sessionCookieName); if err != nil { return false }
	sessionsLock.RLock(); session, ok := sessions[cookie.Value]; sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok { sessionsLock.Lock(); delete(sessions, cookie.Value); sessionsLock.Unlock() }
		return false
	}
	return true
}
func sendJSON(w http.ResponseWriter, code int, payload interface{}) { /* ... */
	response, _ := json.Marshal(payload); w.Header().Set("Content-Type", "application/json"); w.WriteHeader(code); w.Write(response)
}


// --- 网络核心逻辑 (无改動) ---
func socks5Connect(socksAddr string, destHost string, destPort uint16) (net.Conn, error) { /* ...内容不变... */
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
	if tcpConn, ok := c.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
	_, err = c.Write([]byte{0x05, 0x01, 0x00}); if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2); if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}; req = append(req, []byte(destHost)...); req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err = c.Write(req); err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4); if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed") }
	switch rep[3] {
	case 0x01: io.CopyN(io.Discard, c, 4+2); case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2); case 0x04: io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}
func handleDirectTCPIP(ch ssh.Channel, destHost string, destPort uint32) { /* ...内容不变... */
	atomic.AddInt64(&activeConn, 1); defer atomic.AddInt64(&activeConn, -1)
	globalConfig.lock.RLock(); socksServerAddr := globalConfig.SocksAddr; globalConfig.lock.RUnlock()
	socksConn, err := socks5Connect(socksServerAddr, destHost, uint16(destPort)); if err != nil { log.Printf("connect to SOCKS5 fail: %v", err); ch.Close(); return }
	defer socksConn.Close()
	done := make(chan struct{}, 2); go func() { io.Copy(socksConn, ch); socksConn.Close(); done <- struct{}{} }(); go func() { io.Copy(ch, socksConn); ch.Close(); done <- struct{}{} }(); <-done
}
type combinedConn struct { net.Conn; reader io.Reader }
func (c *combinedConn) Read(p []byte) (n int, err error) { return c.reader.Read(p) }


// ==============================================================================
// === 核心修改点 1: 全面升级 httpHandshake 函数，支持多Payload和超时 ===
// ==============================================================================
func httpHandshake(conn net.Conn) (net.Conn, error) {
	// 1. 设置整体握手超时
	if globalConfig.HandshakeTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(time.Duration(globalConfig.HandshakeTimeout) * time.Second))
	}

	reader := bufio.NewReader(conn)
	
	// 2. 使用 for 循环来处理多个payload
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return nil, fmt.Errorf("read http request fail: %v", err)
		}
		// 总是丢弃请求体
		io.Copy(ioutil.Discard, req.Body)
		req.Body.Close()

		ua := req.UserAgent()
		
		// 3. 检查是否是最终的连接请求
		if globalConfig.ConnectUA != "" && strings.Contains(ua, globalConfig.ConnectUA) {
			// 收到连接信号，发送101响应并结束握手
			_, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			if err != nil {
				return nil, fmt.Errorf("write http 101 response fail: %v", err)
			}

			// [关键] 握手成功，清除超时设置
			conn.SetReadDeadline(time.Time{})
			
			// 组合连接并返回
			finalConn := &combinedConn{
				Conn:   conn,
				reader: io.MultiReader(reader, conn),
			}
			return finalConn, nil
		}

		// 4. 检查是否是探测请求
		if globalConfig.ProbeUA != "" && strings.Contains(ua, globalConfig.ProbeUA) {
			// 收到探测信号，返回200 OK，然后继续循环等待下一个请求
			log.Printf("Received probe request from %s (UA: %s)", conn.RemoteAddr(), ua)
			_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			if err != nil {
				return nil, fmt.Errorf("write http 200 response fail: %v", err)
			}
			// 继续 for 循环
			continue
		}

		// 5. 如果两种UA都不是，则认证失败
		return nil, fmt.Errorf("invalid user-agent: %s", ua)
	}
}


// --- 主连接处理器 (无改动) ---
func handleSshConnection(c net.Conn, sshCfg *ssh.ServerConfig) { /* ...内容不变... */
	handshakedConn, err := httpHandshake(c)
	if err != nil { log.Printf("http handshake failed: %v", err); return } // defer c.Close() in parent will handle it
	log.Printf("Phase 1 OK: HTTP handshake passed, waiting SSH payload")
	sshConn, chans, reqs, err := ssh.NewServerConn(handshakedConn, sshCfg); if err != nil { log.Printf("ssh handshake failed for %s: %v", c.RemoteAddr(), err); return }
	defer sshConn.Close()
	connID := sshConn.RemoteAddr().String() + "-" + hex.EncodeToString(sshConn.SessionID())
	onlineUser := &OnlineUser{ ConnID: connID, Username: sshConn.User(), RemoteAddr: sshConn.RemoteAddr().String(), ConnectTime: time.Now(), sshConn: sshConn, }; addOnlineUser(onlineUser)
	log.Printf("Phase 2: SSH handshake success from %s for user '%s'", sshConn.RemoteAddr(), sshConn.User()); defer removeOnlineUser(connID)
	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" { newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed"); continue }
		ch, _, err := newChan.Accept(); if err != nil { log.Printf("accept channel fail: %v", err); continue }
		var payload struct { Host string; Port uint32; OriginAddr string; OriginPort uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil { log.Printf("bad payload: %v", err); ch.Close(); continue }
		go handleDirectTCPIP(ch, payload.Host, payload.Port)
	}
}

// --- Web服务器逻辑 (无改动) ---
func safeSaveConfig() error { /* ... */ /* ...内容不变... */ }
func authMiddleware(next http.HandlerFunc) http.HandlerFunc { /* ... */ /* ...内容不变... */ }
func loginHandler(w http.ResponseWriter, r *http.Request) { /* ... */ /* ...内容不变... */ }
func logoutHandler(w http.ResponseWriter, r *http.Request) { /* ... */ /* ...内容不变... */ }
func apiHandler(w http.ResponseWriter, r *http.Request) { /* ... */ /* ...内容不变... */ }

// main 函数
func main() {
	configFile, err := os.ReadFile("config.json"); if err != nil { log.Fatalf("FATAL: 无法读取 config.json 文件: %v", err) }
	
	// ==============================================================================
	// === 核心修改点 2: 加载配置时设置默认值 ===
	// ==============================================================================
	globalConfig = &Config{}
	err = json.Unmarshal(configFile, globalConfig)
	if err != nil { log.Fatalf("FATAL: 解析 config.json 文件失败: %v", err) }
	
	// 为新配置项设置默认值
	if globalConfig.HandshakeTimeout == 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	// ProbeUA 默认为空，表示不启用探测功能

	if globalConfig.ListenAddr == "" || globalConfig.SocksAddr == "" || len(globalConfig.AdminAccounts) == 0 {
		log.Fatalf("FATAL: config.json 缺少必要配置项")
	}
	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	
	go func() { /* ...Web服务器逻辑不变... */
		mux := http.NewServeMux(); mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "login.html") }); mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", authMiddleware(logoutHandler)); mux.HandleFunc("/api/", authMiddleware(apiHandler))
		adminHandler := func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "admin.html") }; mux.HandleFunc("/admin.html", authMiddleware(adminHandler))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" { http.NotFound(w, r); return }
			if validateSession(r) { http.Redirect(w, r, "/admin.html", http.StatusFound) } else { http.Redirect(w, r, "/login.html", http.StatusFound) }
		})
		log.Printf("Admin panel listening on http://%s", globalConfig.AdminAddr); if err := http.ListenAndServe(globalConfig.AdminAddr, mux); err != nil { log.Fatalf("FATAL: 无法启动Admin panel: %v", err) }
	}()
	
	sshCfg := &ssh.ServerConfig{ /* ...SSH配置不变... */
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) { 
			globalConfig.lock.RLock(); accountInfo, userExists := globalConfig.Accounts[c.User()]; globalConfig.lock.RUnlock()
			if !userExists { log.Printf("Auth failed: user '%s' not found.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			if !accountInfo.Enabled { log.Printf("Auth failed: user '%s' is disabled.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			if accountInfo.ExpiryDate != "" {
				expiry, err := time.Parse("2006-01-02", accountInfo.ExpiryDate); if err != nil { log.Printf("Auth failed: parse expiry date for user '%s'.", c.User()); return nil, fmt.Errorf("invalid credentials") }
				if time.Now().After(expiry.Add(24 * time.Hour)) { log.Printf("Auth failed: user '%s' has expired.", c.User()); return nil, fmt.Errorf("invalid credentials") }
			}
			if string(p) == accountInfo.Password { log.Printf("Auth successful for user: '%s'", c.User()); return nil, nil }
			log.Printf("Auth failed: incorrect password for user '%s'", c.User()); return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader); if err != nil { log.Fatalf("generate host key fail: %v", err) }
	privateKey, err := ssh.NewSignerFromKey(priv); if err != nil { log.Fatalf("create signer fail: %v", err) }
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr); if err != nil { log.Fatalf("listen fail: %v", err) }
	log.Printf("SSH server listening on %s, forwarding to SOCKS5 %s", globalConfig.ListenAddr, globalConfig.SocksAddr)

	for {
		conn, err := l.Accept(); if err != nil { log.Printf("accept fail: %v", err); continue }
		if tcpConn, ok := conn.(*net.TCPConn); ok { tcpConn.SetNoDelay(true) }
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil { log.Printf("FATAL: Panic recovered in connection handler for %s: %v", c.RemoteAddr(), r) }
				c.Close()
			}()
			handleSshConnection(c, sshCfg)
		}(conn)
	}
}
