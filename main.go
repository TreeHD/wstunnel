// main.go — 程式進入點
//
// 本檔的職責很單純:
//   1. log 初始化
//   2. 載入設定 / 流量資料 / DNS / TUN
//   3. 啟動所有 listener (admin / proxy / 80 / 443)
//   4. 等待 SIGINT/SIGTERM 後優雅關閉
//
// 各子系統的細節請見:
//   * config.go      — Config 結構、env、save/load
//   * traffic.go     — 流量統計與持久化
//   * session.go     — 後台登入 cookie
//   * tls.go         — TLS 憑證與 SNI 白名單
//   * logging.go     — log 收集器與降噪
//   * ssh_server.go  — SSH 握手、direct-tcpip、tolerantCopy
//   * dispatcher.go  — 80/443 入口分流
//   * dns.go         — DNS 解析子系統
//   * upstream.go    — 上游 Proxy 鏈接(SOCKS5/HTTP with Auth)
//   * ip_tunnel.go   — IP-over-SSH 隧道
//   * nat_setup.go   — IP 轉發 / iptables NAT
//   * session_manager.go — 隧道 client session 註冊表
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	log.SetOutput(globalLog)
	log.SetFlags(0)

	loadOrInitConfig()
	printStartupBanner()
	loadTrafficData()

	// 初始化 DNS 子系統並啟動健檢(dns.go / udpgw.go)
	initDNS()
	go func() {
		// 延遲讓 listener / udpgw 先就緒,健檢結果才有意義
		time.Sleep(2 * time.Second)
		dnsHealthCheck()
		time.Sleep(1 * time.Second)
		udpgwHealthCheck()
		upstreamHealthCheck()
	}()

	// IP 隧道功能(若 TUN 不可用則安靜降級,不影響其他功能)
	if err := createTunDevice(); err != nil {
		log.Printf("System: Warning - IP Tunnel feature disabled (%v)", err)
	} else {
		go readFromTunAndDistribute()
	}

	startPeriodicTrafficSaver()

	bufferPool = sync.Pool{New: func() interface{} {
		buf := make([]byte, globalConfig.BufferSizeKB*1024)
		return &buf
	}}

	var wg sync.WaitGroup

	adminServer := startAdminServer(&wg)

	sshCfg := buildSSHServerConfig()
	tlsListener, sshListener := startTunnelListeners(&wg, sshCfg)

	// 等中斷訊號
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	gracefulShutdown(adminServer, tlsListener, sshListener, &wg)
}

// buildSSHServerConfig 組出 SSH server config,包含密碼認證 callback
func buildSSHServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion:    "SSH-2.0-WSTunnel_Pro",
		PasswordCallback: passwordCallback,
	}
	cfg.AddHostKey(loadOrGenerateSSHHostKey())
	return cfg
}

// passwordCallback SSH 密碼認證,整合帳號狀態/到期/流量上限/連線數
func passwordCallback(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
	user := c.User()
	globalConfig.lock.RLock()
	acc, ok := globalConfig.Accounts[user]
	globalConfig.lock.RUnlock()
	if !ok || !acc.Enabled {
		return nil, fmt.Errorf("auth failed")
	}
	if acc.ExpiryDate != "" {
		exp, err := time.Parse("2006-01-02", acc.ExpiryDate)
		if err != nil || time.Now().After(exp.Add(24*time.Hour)) {
			return nil, fmt.Errorf("user expired")
		}
	}
	if acc.LimitGB > 0 {
		v, _ := globalTraffic.LoadOrStore(user, &TrafficInfo{})
		t := v.(*TrafficInfo)
		if atomic.LoadUint64(&t.Sent)+atomic.LoadUint64(&t.Received) >= uint64(acc.LimitGB*1e9) {
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
	if string(p) == acc.Password {
		return nil, nil
	}
	if acc.MaxSessions > 0 {
		if v, ok := userConnectionCount.Load(user); ok {
			atomic.AddInt32(v.(*int32), -1)
		}
	}
	return nil, fmt.Errorf("invalid credentials")
}

// startTunnelListeners 啟動 80 (HTTP Upgrade) 與 443 (TLS multiplexer) 兩個入口
func startTunnelListeners(wg *sync.WaitGroup, sshCfg *ssh.ServerConfig) (net.Listener, net.Listener) {
	// 80: HTTP Upgrade
	sshListener, err := net.Listen("tcp", globalConfig.ListenAddr)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on %s: %v", globalConfig.ListenAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: HTTP Upgrade server listening on %s", globalConfig.ListenAddr)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				log.Printf("System: SSH listener (HTTP Upgrade) stopped. %v", err)
				return
			}
			go handleHttpUpgrade(conn, sshCfg)
		}
	}()

	// 443: TLS multiplexer
	tlsConfig, err := generateOrLoadTLSConfig()
	if err != nil {
		log.Fatalf("FATAL: Could not configure TLS: %v", err)
	}
	tlsListener, err := tls.Listen("tcp", globalConfig.ListenTLSAddr, tlsConfig)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on TLS %s: %v", globalConfig.ListenTLSAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: Super TLS multiplexing server listening on %s", globalConfig.ListenTLSAddr)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				log.Printf("System: Super TLS listener stopped. %v", err)
				return
			}
			go dispatchConnection(conn, sshCfg)
		}
	}()

	return tlsListener, sshListener
}

// gracefulShutdown 對所有 server 做有序關閉,並做最後一次流量存盤
func gracefulShutdown(adminServer *http.Server, tlsL, sshL net.Listener, wg *sync.WaitGroup) {
	log.Println("==================================================")
	log.Println("         WSTunnel Service Shutting Down...")
	log.Println("==================================================")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := adminServer.Shutdown(ctx); err != nil {
		log.Printf("System: Error closing admin panel: %v", err)
	} else {
		log.Println("System: Admin panel gracefully shut down.")
	}
	closeListener(sshL, "SSH listener (HTTP Upgrade)")
	closeListener(tlsL, "SSH listener (TLS)")

	log.Println("System: Performing final traffic data save...")
	if err := saveTrafficData(); err != nil {
		log.Printf("System: Error during final traffic data save: %v", err)
	}

	wg.Wait()
	log.Println("Shutdown complete.")
}

func closeListener(l net.Listener, label string) {
	if err := l.Close(); err != nil {
		log.Printf("System: Error closing %s: %v", label, err)
	} else {
		log.Printf("System: %s gracefully shut down.", label)
	}
}
