package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- 配置结构 (不变) ---
type Settings struct {
	HTTPPort           int      `json:"http_port"`
	Socks5Addr         string   `json:"socks5_addr"`
	SshUser            string   `json:"ssh_user"`
	SshPass            string   `json:"ssh_pass"`
	Timeout            int      `json:"timeout"`
	UAKeywordWS        string   `json:"ua_keyword_ws"`
	EnableDeviceIDAuth bool     `json:"enable_device_id_auth"`
}
type DeviceInfo struct {
	FriendlyName string `json:"friendly_name"`
	Expiry       string `json:"expiry"`
	LimitGB      int    `json:"limit_gb"`
	UsedBytes    int64  `json:"used_bytes"`
	Enabled      bool   `json:"enabled"`
}
type Config struct {
	Settings  Settings                `json:"settings"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	lock      sync.RWMutex
}

func loadConfig(file string) (*Config, error) {
	cfg := &Config{DeviceIDs: make(map[string]DeviceInfo)}
	data, err := ioutil.ReadFile(file); if err != nil { return nil, fmt.Errorf("无法读取配置文件 %s: %w", file, err) }
	if err := json.Unmarshal(data, &cfg); err != nil { return nil, fmt.Errorf("解析配置文件 %s 失败: %w", file, err) }
	if cfg.Settings.Socks5Addr == "" { cfg.Settings.Socks5Addr = "127.0.0.1:1080" }
	if cfg.Settings.SshUser == "" { cfg.Settings.SshUser = "a555" }
	if cfg.Settings.SshPass == "" { cfg.Settings.SshPass = "a444" }
	if cfg.Settings.HTTPPort == 0 { cfg.Settings.HTTPPort = 8080 }
	return cfg, nil
}

// --- 连接包装器 (用于解决bufio预读问题，逻辑正确) ---
type prefixedConn struct {
	net.Conn
	prefix *bytes.Reader
}
func (c *prefixedConn) Read(p []byte) (n int, err error) {
	if c.prefix.Len() > 0 { return c.prefix.Read(p) }
	return c.Conn.Read(p)
}


// --- SOCKS5 和 SSH 转发逻辑 (逻辑正确) ---
func socks5Connect(socksAddr, destHost string, destPort uint16) (net.Conn, error) {
	c, err := net.Dial("tcp", socksAddr); if err != nil { return nil, err }
	_, err = c.Write([]byte{0x05, 0x01, 0x00}); if err != nil { c.Close(); return nil, err }
	buf := make([]byte, 2); if _, err := io.ReadFull(c, buf); err != nil { c.Close(); return nil, err }
	if buf[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 auth failed") }
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destHost))}; req = append(req, []byte(destHost)...); req = append(req, byte(destPort>>8), byte(destPort&0xff))
	if _, err = c.Write(req); err != nil { c.Close(); return nil, err }
	rep := make([]byte, 4); if _, err := io.ReadFull(c, rep); err != nil { c.Close(); return nil, err }
	if rep[1] != 0x00 { c.Close(); return nil, fmt.Errorf("socks5 connect failed, status: %x", rep[1]) }
	switch rep[3] {
	case 0x01: io.CopyN(io.Discard, c, 4+2); case 0x03: alen := make([]byte, 1); io.ReadFull(c, alen); io.CopyN(io.Discard, c, int64(alen[0])+2); case 0x04: io.CopyN(io.Discard, c, 16+2)
	}
	return c, nil
}

func handleDirectTCPIP(cfg *Config, ch ssh.Channel, destHost string, destPort uint32) {
	socksServerAddr := cfg.Settings.Socks5Addr // 从传入的cfg获取，更安全
	socksConn, err := socks5Connect(socksServerAddr, destHost, uint16(destPort))
	if err != nil { log.Printf("[SOCKS5] Connect failed: %v", err); ch.Close(); return }
	defer socksConn.Close()
	var wg sync.WaitGroup; wg.Add(2)
	go func() { defer wg.Done(); io.Copy(socksConn, ch) }()
	go func() { defer wg.Done(); io.Copy(ch, socksConn) }()
	wg.Wait()
}


// ==============================================================================
// === 核心修复: handleConnection 函数不再依赖全局变量，而是接收cfg作为参数 ===
// ==============================================================================
func handleConnection(conn net.Conn, sshConfig *ssh.ServerConfig, cfg *Config) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	log.Printf("[+] Connection opened from %s", remoteIP)
	defer func() {
		log.Printf("[-] Connection closed for %s", remoteIP)
		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	
	// 使用传入的cfg，而不是globalConfig
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(cfg.Settings.Timeout) * time.Second))
	req, err := http.ReadRequest(reader)
	if err != nil {
		if err != io.EOF { log.Printf("[-] Handshake read error from %s: %v", remoteIP, err) }
		return
	}
	
	passAuth := false
	if cfg.Settings.EnableDeviceIDAuth {
		credential := req.Header.Get("Sec-WebSocket-Key")
		ua := req.UserAgent()
		cfg.lock.RLock()
		deviceInfo, found := cfg.DeviceIDs[credential]
		cfg.lock.RUnlock()
		if found && deviceInfo.Enabled && strings.Contains(ua, cfg.Settings.UAKeywordWS) {
			// [!!] 修复一个隐藏的bug，time.Parse的格式化字符串是 "2006-01-02"
			expiry, err := time.Parse("2006-01-02", deviceInfo.Expiry)
			if err == nil && time.Now().Before(expiry.Add(24*time.Hour)) {
				passAuth = true
			}
		}
	} else {
		if strings.Contains(req.UserAgent(), cfg.Settings.UAKeywordWS) {
			passAuth = true
		}
	}

	if !passAuth {
		log.Printf("[!] Auth failed for %s.", remoteIP)
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	log.Printf("[*] Handshake auth successful for %s.", remoteIP)
	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil { return }
	
	var prefixBytes []byte
	if reader.Buffered() > 0 {
		prefixBytes = make([]byte, reader.Buffered())
		n, _ := reader.Read(prefixBytes)
		prefixBytes = prefixBytes[:n]
	}

	pConn := &prefixedConn{
		Conn:   conn,
		prefix: bytes.NewReader(prefixBytes),
	}

	_ = conn.SetReadDeadline(time.Time{})
	sshConn, chans, reqs, err := ssh.NewServerConn(pConn, sshConfig)
	if err != nil {
		log.Printf("[SSH] Handshake failed for %s: %v", remoteIP, err)
		return
	}
	defer sshConn.Close()
	log.Printf("[SSH] Session started for %s (%s)", sshConn.User(), sshConn.RemoteAddr())

	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip allowed")
			continue
		}
		ch, _, err := newChan.Accept()
		if err != nil { log.Printf("[SSH] Accept channel failed: %v", err); continue }
		var payload struct{ Host string; Port uint32 }
		if err := ssh.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			log.Printf("[SSH] Invalid payload: %v. Raw data (hex): %x", err, newChan.ExtraData())
			ch.Close()
			continue
		}
		// 将cfg也传递给下一层，保持依赖注入
		go handleDirectTCPIP(cfg, ch, payload.Host, payload.Port)
	}
}

// --- 主函数 ---
func main() {
	var configFile = "ws_config.json"
	// 仍然需要一个全局变量，但在main函数中初始化后，通过参数传递给goroutine
	cfg, err := loadConfig(configFile); if err != nil { log.Fatalf("FATAL: %v", err) }
	
	settings := cfg.Settings
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == settings.SshUser && string(p) == settings.SshPass { return nil, nil }
			return nil, fmt.Errorf("invalid credentials")
		},
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	privateKey, _ := ssh.NewSignerFromKey(priv)
	sshConfig.AddHostKey(privateKey)

	addr := fmt.Sprintf("0.0.0.0:%d", settings.HTTPPort)
	ln, err := net.Listen("tcp", addr); if err != nil { log.Fatalf("FATAL: Failed to listen on %s: %v", addr, err) }
	log.Printf("[*] Server listening on %s. Forwarding to SOCKS5 at %s", addr, settings.Socks5Addr)

	for {
		conn, err := ln.Accept(); if err != nil { log.Printf("[!] Accept error: %v", err); continue }
		// ==============================================================================
		// === 核心修复: 将cfg作为参数，明确地传递给新的goroutine ===
		// ==============================================================================
		go handleConnection(conn, sshConfig, cfg)
	}
}
