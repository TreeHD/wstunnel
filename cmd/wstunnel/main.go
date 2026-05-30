// Package main — wstunnel 程式進入點(薄殼)。
//
// 本檔只負責:
//   1. log 初始化
//   2. 載入設定 / 流量資料
//   3. 啟動所有 listener (admin / 80 / 443)
//   4. 等待 SIGINT/SIGTERM 後優雅關閉
//
// 各子系統實作位於 internal/<pkg>/。
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"wstunnel/internal/adminapi"
	"wstunnel/internal/config"
	"wstunnel/internal/dispatcher"
	"wstunnel/internal/dnsx"
	"wstunnel/internal/iptun"
	"wstunnel/internal/logging"
	"wstunnel/internal/proxy"
	"wstunnel/internal/sshsrv"
	"wstunnel/internal/tlsutil"
	"wstunnel/internal/traffic"
	"wstunnel/internal/udpgw"
)

func main() {
	log.SetOutput(logging.Default)
	log.SetFlags(0)

	config.LoadOrInit()
	printStartupBanner()
	traffic.Load()

	adminapi.ServerStartTime = time.Now()

	// DNS 子系統初始化 + 啟動健檢(背景)
	dnsx.Init()
	go func() {
		time.Sleep(2 * time.Second)
		dnsx.HealthCheck()
		time.Sleep(1 * time.Second)
		udpgw.HealthCheck()
		proxy.HealthCheck()
	}()

	// IP 隧道功能(若 TUN 不可用則安靜降級)
	if err := iptun.CreateTunDevice(); err != nil {
		log.Printf("System: Warning - IP Tunnel feature disabled (%v)", err)
	} else {
		go iptun.ReadAndDistribute()
	}

	var wg sync.WaitGroup
	traffic.StartPeriodicSaver(config.Get().TrafficSaveIntervalSeconds, &wg)

	sshsrv.InitBufferPool()

	adminServer := adminapi.Start(&wg)
	sshCfg := sshsrv.BuildServerConfig()
	tlsListener, sshListener := startTunnelListeners(&wg, sshCfg)

	// 等中斷訊號
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	gracefulShutdown(adminServer, tlsListener, sshListener, &wg)
}

// startTunnelListeners 啟動 80 (HTTP Upgrade) 與 443 (TLS multiplexer) 兩個入口。
func startTunnelListeners(wg *sync.WaitGroup, sshCfg *ssh.ServerConfig) (net.Listener, net.Listener) {
	cfg := config.Get()

	sshListener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on %s: %v", cfg.ListenAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: HTTP Upgrade server listening on %s", cfg.ListenAddr)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				log.Printf("System: SSH listener (HTTP Upgrade) stopped. %v", err)
				return
			}
			go dispatcher.HandleHTTPUpgrade(conn, sshCfg)
		}
	}()

	tlsConfig, err := tlsutil.LoadOrGenerate()
	if err != nil {
		log.Fatalf("FATAL: Could not configure TLS: %v", err)
	}
	tlsListener, err := tls.Listen("tcp", cfg.ListenTLSAddr, tlsConfig)
	if err != nil {
		log.Fatalf("FATAL: Cannot listen on TLS %s: %v", cfg.ListenTLSAddr, err)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("System: Super TLS multiplexing server listening on %s", cfg.ListenTLSAddr)
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				log.Printf("System: Super TLS listener stopped. %v", err)
				return
			}
			go dispatcher.DispatchTLS(conn, sshCfg)
		}
	}()

	return tlsListener, sshListener
}

// gracefulShutdown 對所有 server 做有序關閉,並做最後一次流量存盤。
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
	if err := traffic.Save(); err != nil {
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

// printStartupBanner 啟動時把當前生效設定 dump 出來。
func printStartupBanner() {
	c := config.Get()
	log.Println("==================================================")
	log.Println("          WSTunnel Service Starting Up")
	log.Println("==================================================")
	log.Printf("  Listen Addr (HTTP Upgrade): %s", c.ListenAddr)
	log.Printf("  Listen Addr (TLS Multiplexer): %s  <-- SUPER PORT", c.ListenTLSAddr)
	log.Printf("  Allowed SNI Hosts: %v", c.AllowedSNI)
	log.Printf("  Admin Panel Addr: %s", c.AdminAddr)
	if c.DNSServer != "" {
		log.Printf("  DNS Server (custom): %s", c.DNSServer)
	} else {
		log.Printf("  DNS Server: (using container default, /etc/resolv.conf)")
	}
	if c.UpstreamProxyEnabled && c.UpstreamProxyURL != "" {
		log.Printf("  Upstream Proxy: ENABLED (%s)", proxy.RedactURL(c.UpstreamProxyURL))
	} else {
		log.Printf("  Upstream Proxy: disabled (direct dial)")
	}
	log.Println("------------------ Behaviors ---------------------")
	log.Printf("  Handshake Timeout: %d seconds", c.HandshakeTimeout)
	log.Printf("  Required User-Agent: %s", c.ConnectUA)
	log.Printf("  Connection Idle Timeout: %d seconds", c.IdleTimeoutSeconds)
	log.Printf("  Target Connect Timeout: %d seconds", c.TargetConnectTimeoutSeconds)
	log.Println("------------------- Performance ------------------")
	log.Printf("  Buffer Size: %d KB", c.BufferSizeKB)
	log.Printf("  Network Error Retries: %d times", c.TolerantCopyMaxRetries)
	log.Printf("  Retry Delay: %d ms", c.TolerantCopyRetryDelayMs)
	log.Println("--------------------- Defaults -------------------")
	log.Printf("  New User Default Expiry: %d days", c.DefaultExpiryDays)
	log.Printf("  New User Default Traffic: %.2f GB", c.DefaultLimitGB)
	log.Println("------------------ Persistence -------------------")
	log.Printf("  Traffic Save Interval: %d seconds", c.TrafficSaveIntervalSeconds)
	log.Println("==================================================")
}
