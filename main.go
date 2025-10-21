// main.go
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

// --- 结构体及全局变量 (保持不变) ---
type AccountInfo struct {
	Password   string `json:"password"`
	Enabled    bool   `json:"enabled"`
	ExpiryDate string `json:"expiry_date"`
}

type Config struct {
	ListenAddr         string                 `json:"listen_addr"`
	AdminAddr          string                 `json:"admin_addr"`
	AdminAccounts      map[string]string      `json:"admin_accounts"`
	Accounts           map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout   int                    `json:"handshake_timeout,omitempty"`
	ConnectUA          string                 `json:"connect_ua,omitempty"`
	BufferSizeKB       int                    `json:"buffer_size_kb,omitempty"`
	IdleTimeoutSeconds int                    `json:"idle_timeout_seconds,omitempty"`
	lock               sync.RWMutex
}

var globalConfig *Config
var activeConn int64

type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	sshConn     ssh.Conn
}

var onlineUsers sync.Map
const sessionCookieName = "wstunnel_admin_session"
type Session struct {
	Username string
	Expiry   time.Time
}
var sessions = make(map[string]Session)
var sessionsLock sync.RWMutex

// --- 其它函数 (保持不变) ---
// addOnlineUser, removeOnlineUser, createSession, validateSession, sendJSON, bufferPool,
// timedCopy, handleDirectTCPIP, combinedConn, httpHandshake, sendKeepAlives,
// handleSshConnection, safeSaveConfig, authMiddleware, loginHandler, logoutHandler,
// apiHandler 都保持不变，此处省略以保持简洁...
// (请从您原来的main.go文件中保留这些函数的完整代码)
// ...

// --- main ---
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("FATAL: 无法读取 config.json: %v", err)
	}
	globalConfig = &Config{}
	err = json.Unmarshal(configFile, globalConfig)
	if err != nil {
		log.Fatalf("FATAL: 解析 config.json 失败: %v", err)
	}
	if globalConfig.ListenAddr == "" || len(globalConfig.AdminAccounts) == 0 {
		log.Fatalf("FATAL: config.json 缺少 listen_addr 或 admin_accounts")
	}

	if globalConfig.AdminAddr == "" { globalConfig.AdminAddr = "127.0.0.1:9090" }
	if globalConfig.HandshakeTimeout <= 0 { globalConfig.HandshakeTimeout = 5 }
	if globalConfig.ConnectUA == "" { globalConfig.ConnectUA = "26.4.0" }
	if globalConfig.BufferSizeKB <= 0 { globalConfig.BufferSizeKB = 128 }
	if globalConfig.IdleTimeoutSeconds <= 0 { globalConfig.IdleTimeoutSeconds = 90 }

	bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, globalConfig.BufferSizeKB*1024); return &b }}

	if err := createTunDevice(); err != nil {
		log.Fatalf("FATAL: Could not create TUN device: %v. Please ensure you are running as root and have TUN module loaded.", err)
	}

	// ***************************************************************
	// ***********************  核心修改点  ************************
	// ***************************************************************
	// 在启动所有网络服务之前，启动中央数据包分发器
	go readFromTunAndDistribute()
	// ***************************************************************
	// ***************************************************************

	log.Println("====== WSTUNNEL (TCP + IP Tunnel Mode) Starting ======")
	log.Printf("Config: HandshakeTimeout=%ds, ConnectUA='%s', BufferSize=%dKB, IdleTimeout=%ds",
		globalConfig.HandshakeTimeout, globalConfig.ConnectUA, globalConfig.BufferSizeKB, globalConfig.IdleTimeoutSeconds)

	// 启动Web管理面板 (goroutine)
	go func() {
		// ... 您的Web服务器代码保持不变 ...
	}()

	// 配置SSH服务器
	sshCfg := &ssh.ServerConfig{
		// ... 您的PasswordCallback等配置保持不变 ...
	}
	// ... 您的主机密钥生成代码保持不变 ...
	sshCfg.AddHostKey(privateKey)

	l, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil {
		log.Fatalf("listen fail: %v", err)
	}
	log.Printf("SSH server listening on %s. IP Tunnel traffic will be handled on port 7300.", globalConfig.ListenAddr)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}
		// ... 您的连接处理逻辑保持不变 ...
		go func(c net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("FATAL: Panic recovered for %s: %v", c.RemoteAddr(), r)
				}
				c.Close()
			}()
			handleSshConnection(c, sshCfg)
		}(conn)
	}
}

// 请确保您将main.go中省略的函数（例如 handleDirectTCPIP, apiHandler 等）从您原来的文件中复制过来。
// 这里为了清晰地展示核心修改，省略了未改动的函数体。
