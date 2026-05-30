// config.go — 設定結構與帳號資料定義
//
// 職責：
//   * 定義 Config / AccountInfo / OnlineUser 結構
//   * env 解析輔助函式
//   * 設定檔的 load / save / 預設值套用
//
// 流量、SSH、TLS 等子系統的細節皆不在此處。
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

type AccountInfo struct {
	Password     string  `json:"password"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

type Config struct {
	ListenAddr                  string                 `json:"listen_addr"`
	ListenTLSAddr               string                 `json:"listen_tls_addr"`
	AllowedSNI                  []string               `json:"allowed_sni"`
	AdminAddr                   string                 `json:"admin_addr"`
	AdminAccounts               map[string]string      `json:"admin_accounts"`
	Accounts                    map[string]AccountInfo `json:"accounts"`
	HandshakeTimeout            int                    `json:"handshake_timeout,omitempty"`
	ConnectUA                   string                 `json:"connect_ua,omitempty"`
	BufferSizeKB                int                    `json:"buffer_size_kb,omitempty"`
	IdleTimeoutSeconds          int                    `json:"idle_timeout_seconds,omitempty"`
	TolerantCopyMaxRetries      int                    `json:"tolerant_copy_max_retries,omitempty"`
	TolerantCopyRetryDelayMs    int                    `json:"tolerant_copy_retry_delay_ms,omitempty"`
	TargetConnectTimeoutSeconds int                    `json:"target_connect_timeout_seconds,omitempty"`
	DefaultExpiryDays           int                    `json:"default_expiry_days,omitempty"`
	DefaultLimitGB              float64                `json:"default_limit_gb,omitempty"`
	TrafficSaveIntervalSeconds  int                    `json:"traffic_save_interval_seconds,omitempty"`
	ProxyAddr                   string                 `json:"proxy_addr,omitempty"`
	// DNSServer 指定代理出站時使用的 DNS 伺服器,格式為 "ip:port"。
	// 留空則使用容器預設 DNS(/etc/resolv.conf)。
	// 支援多伺服器逗號分隔,例如 "8.8.8.8, 1.1.1.1:53"。
	DNSServer string `json:"dns_server,omitempty"`
	// UDPGWPort 指定本機 udpgw 進程監聽的 port,留空則用預設 7300
	UDPGWPort int `json:"udpgw_port,omitempty"`
	lock      sync.RWMutex
}

type OnlineUser struct {
	ConnID      string    `json:"conn_id"`
	Username    string    `json:"username"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectTime time.Time `json:"connect_time"`
	// sshConn 在 ssh_server.go 中設定,型別為 ssh.Conn
	sshConn interface{ Close() error }
}

var (
	globalConfig    *Config
	serverStartTime = time.Now()

	onlineUsers         sync.Map
	userConnectionCount sync.Map
)

const (
	configFilePath = "data/config.json"
)

// envToInt 從 env 讀整數,失敗或未設定回 default
func envToInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

// envToFloat64 從 env 讀浮點數,失敗或未設定回 default
func envToFloat64(key string, defaultVal float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}

// safeSaveConfig 取寫鎖序列化整個 config 並寫盤
func safeSaveConfig() error {
	globalConfig.lock.Lock()
	defer globalConfig.lock.Unlock()

	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	data, err := json.MarshalIndent(globalConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(configFilePath, data, 0644)
}

// loadOrInitConfig 讀取 data/config.json,不存在時依 env 建立預設並存盤
func loadOrInitConfig() {
	globalConfig = &Config{}

	if data, err := ioutil.ReadFile(configFilePath); err == nil {
		if err := json.Unmarshal(data, globalConfig); err != nil {
			log.Fatalf("FATAL: Cannot parse %s: %v", configFilePath, err)
		}
		log.Printf("System: Loaded configuration from %s", configFilePath)
		applyConfigDefaults()
		return
	}

	log.Printf("System: %s not found, constructing default configuration and saving...", configFilePath)
	buildDefaultConfigFromEnv()
	applyConfigDefaults()
	if err := safeSaveConfig(); err != nil {
		log.Printf("System: Warning - Failed to save initial config: %v", err)
	}
}

// buildDefaultConfigFromEnv 從 env 變數建構初始 config
func buildDefaultConfigFromEnv() {
	globalConfig = &Config{
		ListenAddr:                  os.Getenv("LISTEN_ADDR"),
		ListenTLSAddr:               os.Getenv("LISTEN_TLS_ADDR"),
		AdminAddr:                   os.Getenv("ADMIN_ADDR"),
		ProxyAddr:                   os.Getenv("PROXY_ADDR"),
		ConnectUA:                   os.Getenv("CONNECT_UA"),
		DNSServer:                   os.Getenv("DNS_SERVER"),
		HandshakeTimeout:            envToInt("HANDSHAKE_TIMEOUT", 5),
		BufferSizeKB:                envToInt("BUFFER_SIZE_KB", 32),
		IdleTimeoutSeconds:          envToInt("IDLE_TIMEOUT_SECONDS", 120),
		TolerantCopyMaxRetries:      envToInt("TOLERANT_COPY_MAX_RETRIES", 100),
		TolerantCopyRetryDelayMs:    envToInt("TOLERANT_COPY_RETRY_DELAY_MS", 500),
		TargetConnectTimeoutSeconds: envToInt("TARGET_CONNECT_TIMEOUT_SECONDS", 10),
		DefaultExpiryDays:           envToInt("DEFAULT_EXPIRY_DAYS", 30),
		DefaultLimitGB:              envToFloat64("DEFAULT_LIMIT_GB", 0.0),
		TrafficSaveIntervalSeconds:  envToInt("TRAFFIC_SAVE_INTERVAL_SECONDS", 300),
		UDPGWPort:                   envToInt("UDPGW_PORT", 0),
	}

	globalConfig.Accounts = make(map[string]AccountInfo)
	if accountsJson := os.Getenv("ACCOUNTS"); accountsJson != "" {
		if err := json.Unmarshal([]byte(accountsJson), &globalConfig.Accounts); err != nil {
			log.Printf("System: Warning - Failed to parse ACCOUNTS environment variable: %v", err)
		}
	}

	globalConfig.AdminAccounts = make(map[string]string)
	if adminJson := os.Getenv("ADMIN_ACCOUNTS"); adminJson != "" {
		if err := json.Unmarshal([]byte(adminJson), &globalConfig.AdminAccounts); err != nil {
			log.Printf("System: Warning - Failed to parse ADMIN_ACCOUNTS environment variable: %v", err)
		}
	} else {
		// 隨機產生預設管理員密碼
		randomPass := generateRandomPassword(16)
		globalConfig.AdminAccounts["admin"] = randomPass
		log.Println("==================================================")
		log.Println("  [重要] 首次啟動,已自動產生管理員帳號")
		log.Printf("  帳號: admin")
		log.Printf("  密碼: %s", randomPass)
		log.Println("  請儘速登入後台修改密碼!")
		log.Println("==================================================")
	}

	if sniJson := os.Getenv("ALLOWED_SNI"); sniJson != "" {
		if err := json.Unmarshal([]byte(sniJson), &globalConfig.AllowedSNI); err != nil {
			log.Printf("System: Warning - Failed to parse ALLOWED_SNI environment variable: %v", err)
		}
	}
}

// applyConfigDefaults 對未設定或非法的欄位套用合理預設值
func applyConfigDefaults() {
	if globalConfig.ListenAddr == "" {
		globalConfig.ListenAddr = "0.0.0.0:80"
	}
	if globalConfig.ListenTLSAddr == "" {
		globalConfig.ListenTLSAddr = "0.0.0.0:443"
	}
	if globalConfig.AdminAddr == "" {
		globalConfig.AdminAddr = "0.0.0.0:9090"
	}
	if globalConfig.HandshakeTimeout <= 0 {
		globalConfig.HandshakeTimeout = 5
	}
	if globalConfig.BufferSizeKB <= 0 {
		globalConfig.BufferSizeKB = 32
	}
	if globalConfig.DefaultExpiryDays <= 0 {
		globalConfig.DefaultExpiryDays = 30
	}
	if globalConfig.IdleTimeoutSeconds <= 0 {
		globalConfig.IdleTimeoutSeconds = 120
	}
	if globalConfig.TolerantCopyMaxRetries <= 0 {
		globalConfig.TolerantCopyMaxRetries = 100
	}
	if globalConfig.TolerantCopyRetryDelayMs <= 0 {
		globalConfig.TolerantCopyRetryDelayMs = 500
	}
	if globalConfig.TargetConnectTimeoutSeconds <= 0 {
		globalConfig.TargetConnectTimeoutSeconds = 10
	}
	if globalConfig.TrafficSaveIntervalSeconds <= 0 {
		globalConfig.TrafficSaveIntervalSeconds = 300
	}
	if globalConfig.ProxyAddr == "" {
		globalConfig.ProxyAddr = ":1080"
	}
}

// printStartupBanner 啟動時把當前生效設定 dump 出來
func printStartupBanner() {
	log.Println("==================================================")
	log.Println("          WSTunnel Service Starting Up")
	log.Println("==================================================")
	log.Printf("  Listen Addr (HTTP Upgrade): %s", globalConfig.ListenAddr)
	log.Printf("  Listen Addr (TLS Multiplexer): %s  <-- SUPER PORT", globalConfig.ListenTLSAddr)
	log.Printf("  Proxy Server Addr (SOCKS5/HTTP): %s", globalConfig.ProxyAddr)
	log.Printf("  Allowed SNI Hosts: %v", globalConfig.AllowedSNI)
	log.Printf("  Admin Panel Addr: %s", globalConfig.AdminAddr)
	if globalConfig.DNSServer != "" {
		log.Printf("  DNS Server (custom): %s", globalConfig.DNSServer)
	} else {
		log.Printf("  DNS Server: (using container default, /etc/resolv.conf)")
	}
	log.Println("------------------ Behaviors ---------------------")
	log.Printf("  Handshake Timeout: %d seconds", globalConfig.HandshakeTimeout)
	log.Printf("  Required User-Agent: %s", globalConfig.ConnectUA)
	log.Printf("  Connection Idle Timeout: %d seconds", globalConfig.IdleTimeoutSeconds)
	log.Printf("  Target Connect Timeout: %d seconds", globalConfig.TargetConnectTimeoutSeconds)
	log.Println("------------------- Performance ------------------")
	log.Printf("  Buffer Size: %d KB", globalConfig.BufferSizeKB)
	log.Printf("  Network Error Retries: %d times", globalConfig.TolerantCopyMaxRetries)
	log.Printf("  Retry Delay: %d ms", globalConfig.TolerantCopyRetryDelayMs)
	log.Println("--------------------- Defaults -------------------")
	log.Printf("  New User Default Expiry: %d days", globalConfig.DefaultExpiryDays)
	log.Printf("  New User Default Traffic: %.2f GB", globalConfig.DefaultLimitGB)
	log.Println("------------------ Persistence -------------------")
	log.Printf("  Traffic Save Interval: %d seconds", globalConfig.TrafficSaveIntervalSeconds)
	log.Println("==================================================")
}
