// Package config 集中管理 wstunnel 的設定結構與帳號資料。
//
// 設計上保留 singleton 模式:整個程式共用一個 *Config 實例,以
// Get()/Set helpers 對外暴露,內部用 sync.RWMutex 保護並發存取。
package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"

	"wstunnel/internal/logging"
)

// AccountInfo 描述單一使用者帳號的資料(密碼、限額、到期日等)。
type AccountInfo struct {
	Password     string  `json:"password"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

// Config 是 data/config.json 的 schema,同時對應後台 /api/settings。
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
	// DNSServer 指定代理出站時使用的 DNS 伺服器,格式為 "ip:port"。
	// 留空則使用容器預設 DNS(/etc/resolv.conf)。支援多伺服器逗號分隔。
	DNSServer string `json:"dns_server,omitempty"`
	// UDPGWPort 指定本機 udpgw 進程監聽的 port,留空則用預設 7300
	UDPGWPort int `json:"udpgw_port,omitempty"`
	// UpstreamProxyEnabled 啟用後,所有從 SSH Tunnel 內走出來的 TCP 流量
	// 都會再經過下方設定的上游 SOCKS5/HTTP Proxy(支援 Auth)
	UpstreamProxyEnabled bool `json:"upstream_proxy_enabled,omitempty"`
	// UpstreamProxyURL 形如 socks5://user:pass@host:1080 或 http://user:pass@host:8080
	UpstreamProxyURL string `json:"upstream_proxy_url,omitempty"`

	Lock sync.RWMutex `json:"-"`
}

const filePath = "data/config.json"

var current *Config

// Get 取得目前生效的 Config。
//
// 注意:呼叫者使用 Config 的欄位前須自行透過 Lock 保護(讀走 RLock,寫走 Lock)。
// 我們不在 getter 層自動加鎖,因為大多數讀取要連帶讀多個欄位,
// 在外部統一加鎖比較有效率。
func Get() *Config {
	return current
}

// Replace 直接替換內部 singleton(僅供 tests / 啟動時用)
func Replace(c *Config) {
	current = c
}

// Save 序列化目前 Config 並寫盤(取寫鎖)。
func Save() error {
	if current == nil {
		return fmt.Errorf("config not initialized")
	}
	current.Lock.Lock()
	defer current.Lock.Unlock()

	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(filePath, data, 0644)
}

// LoadOrInit 讀取 data/config.json,不存在時依 env 建立預設並存盤。
func LoadOrInit() {
	current = &Config{}

	if data, err := ioutil.ReadFile(filePath); err == nil {
		if err := json.Unmarshal(data, current); err != nil {
			log.Fatalf("FATAL: Cannot parse %s: %v", filePath, err)
		}
		log.Printf("System: Loaded configuration from %s", filePath)
		applyDefaults()
		return
	}

	log.Printf("System: %s not found, constructing default configuration and saving...", filePath)
	buildFromEnv()
	applyDefaults()
	if err := Save(); err != nil {
		log.Printf("System: Warning - Failed to save initial config: %v", err)
	}
}

// EnvInt 從 env 讀整數,失敗或未設定回 default
func EnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

// EnvFloat64 從 env 讀浮點數,失敗或未設定回 default
func EnvFloat64(key string, defaultVal float64) float64 {
	if val := os.Getenv(key); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return f
		}
	}
	return defaultVal
}

// buildFromEnv 從 env 變數建構初始 config
func buildFromEnv() {
	current = &Config{
		ListenAddr:                  os.Getenv("LISTEN_ADDR"),
		ListenTLSAddr:               os.Getenv("LISTEN_TLS_ADDR"),
		AdminAddr:                   os.Getenv("ADMIN_ADDR"),
		ConnectUA:                   os.Getenv("CONNECT_UA"),
		DNSServer:                   os.Getenv("DNS_SERVER"),
		HandshakeTimeout:            EnvInt("HANDSHAKE_TIMEOUT", 5),
		BufferSizeKB:                EnvInt("BUFFER_SIZE_KB", 32),
		IdleTimeoutSeconds:          EnvInt("IDLE_TIMEOUT_SECONDS", 120),
		TolerantCopyMaxRetries:      EnvInt("TOLERANT_COPY_MAX_RETRIES", 100),
		TolerantCopyRetryDelayMs:    EnvInt("TOLERANT_COPY_RETRY_DELAY_MS", 500),
		TargetConnectTimeoutSeconds: EnvInt("TARGET_CONNECT_TIMEOUT_SECONDS", 10),
		DefaultExpiryDays:           EnvInt("DEFAULT_EXPIRY_DAYS", 30),
		DefaultLimitGB:              EnvFloat64("DEFAULT_LIMIT_GB", 0.0),
		TrafficSaveIntervalSeconds:  EnvInt("TRAFFIC_SAVE_INTERVAL_SECONDS", 300),
		UDPGWPort:                   EnvInt("UDPGW_PORT", 0),
		UpstreamProxyURL:            os.Getenv("UPSTREAM_PROXY_URL"),
		UpstreamProxyEnabled:        os.Getenv("UPSTREAM_PROXY_ENABLED") == "1" || os.Getenv("UPSTREAM_PROXY_ENABLED") == "true",
	}

	current.Accounts = make(map[string]AccountInfo)
	if accountsJson := os.Getenv("ACCOUNTS"); accountsJson != "" {
		if err := json.Unmarshal([]byte(accountsJson), &current.Accounts); err != nil {
			log.Printf("System: Warning - Failed to parse ACCOUNTS environment variable: %v", err)
		}
	}

	current.AdminAccounts = make(map[string]string)
	if adminJson := os.Getenv("ADMIN_ACCOUNTS"); adminJson != "" {
		if err := json.Unmarshal([]byte(adminJson), &current.AdminAccounts); err != nil {
			log.Printf("System: Warning - Failed to parse ADMIN_ACCOUNTS environment variable: %v", err)
		}
	} else {
		// 隨機產生預設管理員密碼
		randomPass := logging.RandomPassword(16)
		current.AdminAccounts["admin"] = randomPass
		log.Println("==================================================")
		log.Println("  [重要] 首次啟動,已自動產生管理員帳號")
		log.Printf("  帳號: admin")
		log.Printf("  密碼: %s", randomPass)
		log.Println("  請儘速登入後台修改密碼!")
		log.Println("==================================================")
	}

	if sniJson := os.Getenv("ALLOWED_SNI"); sniJson != "" {
		if err := json.Unmarshal([]byte(sniJson), &current.AllowedSNI); err != nil {
			log.Printf("System: Warning - Failed to parse ALLOWED_SNI environment variable: %v", err)
		}
	}
}

// applyDefaults 對未設定或非法的欄位套用合理預設值
func applyDefaults() {
	if current.ListenAddr == "" {
		current.ListenAddr = "0.0.0.0:80"
	}
	if current.ListenTLSAddr == "" {
		current.ListenTLSAddr = "0.0.0.0:443"
	}
	if current.AdminAddr == "" {
		current.AdminAddr = "0.0.0.0:9090"
	}
	if current.HandshakeTimeout <= 0 {
		current.HandshakeTimeout = 5
	}
	if current.BufferSizeKB <= 0 {
		current.BufferSizeKB = 32
	}
	if current.DefaultExpiryDays <= 0 {
		current.DefaultExpiryDays = 30
	}
	if current.IdleTimeoutSeconds <= 0 {
		current.IdleTimeoutSeconds = 120
	}
	if current.TolerantCopyMaxRetries <= 0 {
		current.TolerantCopyMaxRetries = 100
	}
	if current.TolerantCopyRetryDelayMs <= 0 {
		current.TolerantCopyRetryDelayMs = 500
	}
	if current.TargetConnectTimeoutSeconds <= 0 {
		current.TargetConnectTimeoutSeconds = 10
	}
	if current.TrafficSaveIntervalSeconds <= 0 {
		current.TrafficSaveIntervalSeconds = 300
	}
}
