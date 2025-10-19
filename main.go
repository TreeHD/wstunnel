package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/bcrypt"
)

// ==========================================================
// --- 1. 全局变量与核心结构体 ---
// ==========================================================

const ConfigFile = "ws_config.json"
const logBufferSize = 200

var (
	bufferPool     sync.Pool
	logBuffer      *RingBuffer
	globalConfig   *Config
	once           sync.Once
	// Web Panel Globals
	adminPanelHTML, loginPanelHTML []byte
	sessions                       = make(map[string]Session)
	sessionsLock                   sync.RWMutex
	// SSH Management Mutex
	sshUserMgmtMutex sync.Mutex
)

func init() {
	logBuffer = NewRingBuffer(logBufferSize)
}

type Settings struct {
	HTTPPort                     int      `json:"http_port"`
	TLSPort                      int      `json:"tls_port"`
	StatusPort                   int      `json:"status_port"`
	DefaultTargetHost            string   `json:"default_target_host"`
	DefaultTargetPort            int      `json:"default_target_port"`
	BufferSize                   int      `json:"buffer_size"`
	Timeout                      int      `json:"timeout"`
	IdleTimeout                  int      `json:"idle_timeout"`
	CertFile                     string   `json:"cert_file"`
	KeyFile                      string   `json:"key_file"`
	UAKeywordWS                  string   `json:"ua_keyword_ws"`
	UAKeywordProbe               string   `json:"ua_keyword_probe"`
	AllowSimultaneousConnections bool     `json:"allow_simultaneous_connections"`
	DefaultExpiryDays            int      `json:"default_expiry_days"`
	DefaultLimitGB               int      `json:"default_limit_gb"`
	IPWhitelist                  []string `json:"ip_whitelist"`
	IPBlacklist                  []string `json:"ip_blacklist"`
	EnableIPWhitelist            bool     `json:"enable_ip_whitelist"`
	EnableIPBlacklist            bool     `json:"enable_ip_blacklist"`
	EnableDeviceIDAuth           bool     `json:"enable_device_id_auth"`
}

type DeviceInfo struct {
	FriendlyName string `json:"friendly_name"`
	Expiry       string `json:"expiry"`
	LimitGB      int    `json:"limit_gb"`
	UsedBytes    int64  `json:"used_bytes"`
	MaxSessions  int    `json:"max_sessions"`
	Enabled      bool   `json:"enabled"`
}

type Config struct {
	Settings  Settings              `json:"settings"`
	Accounts  map[string]string     `json:"accounts"`
	DeviceIDs map[string]DeviceInfo `json:"device_ids"`
	lock      sync.RWMutex
}

type ActiveConnInfo struct {
	mu                     sync.RWMutex
	Writer                 net.Conn
	LastActive             int64
	DeviceID               string
	Credential             string
	FirstConnection        time.Time
	Status                 string
	IP                     string
	BytesSent              int64
	BytesReceived          int64
	ConnKey                string
	LastSpeedUpdateTime    time.Time
	LastTotalBytesForSpeed int64
	CurrentSpeedBps        float64
	cancel                 context.CancelFunc
}

type SystemStatus struct {
	Uptime        string  `json:"uptime"`
	CPUPercent    float64 `json:"cpu_percent"`
	CPUCores      int     `json:"cpu_cores"`
	MemTotal      uint64  `json:"mem_total"`
	MemUsed       uint64  `json:"mem_used"`
	MemPercent    float64 `json:"mem_percent"`
	BytesSent     int64   `json:"bytes_sent"`
	BytesReceived int64   `json:"bytes_received"`
}

type Session struct {
	Username string
	Expiry   time.Time
}

// ==========================================================
// --- 2. 工具函数 (日志, 缓冲区, 工具等) ---
// ==========================================================

func Print(format string, v ...interface{}) {
	logBuffer.Add(fmt.Sprintf(format, v...))
}

func initBufferPool(size int) {
	if size <= 0 { size = 32 * 1024 }
	bufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, size) },
	}
}

func getBuf(size int) []byte {
	b := bufferPool.Get().([]byte)
	if cap(b) < size { return make([]byte, size) }
	return b[:size]
}

func putBuf(b []byte) { bufferPool.Put(b) }

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{buffer: make([]string, capacity)}
}

func (rb *RingBuffer) Add(msg string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	logLine := fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), msg)
	rb.buffer[rb.head] = logLine
	rb.head = (rb.head + 1) % len(rb.buffer)
	fmt.Println(logLine) // Also print to stdout
}

func (rb *RingBuffer) GetLogs() []string {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	var logs []string
	cap := len(rb.buffer)
	for i := 1; i <= cap; i++ {
		idx := (rb.head - i + cap) % cap
		if rb.buffer[idx] != "" {
			logs = append(logs, rb.buffer[idx])
		}
	}
	return logs
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func isIPInList(ip string, list []string) bool {
	for _, item := range list {
		if item == ip { return true }
	}
	return false
}

func extractHeaderValue(text, name string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?mi)^%s:\s*(.+)$`, regexp.QuoteMeta(name)))
	m := re.FindStringSubmatch(text)
	if len(m) > 1 { return strings.TrimSpace(m[1]) }
	return ""
}

// ==========================================================
// --- 3. 配置管理 ---
// ==========================================================

func GetConfig() *Config {
	once.Do(func() {
		globalConfig = &Config{}
		if err := globalConfig.load(); err != nil {
			Print("[!] FATAL: Could not load or create config file: %v", err)
			os.Exit(1)
		}
	})
	return globalConfig
}

func (c *Config) load() error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Set defaults first
	c.Settings = Settings{
		HTTPPort:           80,
		TLSPort:            443,
		StatusPort:         9090,
		DefaultTargetHost:  "127.0.0.1",
		DefaultTargetPort:  22,
		BufferSize:         32768,
		Timeout:            10,
		IdleTimeout:        300,
		CertFile:           "cert.pem",
		KeyFile:            "key.pem",
		UAKeywordWS:        "26.4.0",
		UAKeywordProbe:     "1.0",
		EnableDeviceIDAuth: true,
	}
	c.Accounts = map[string]string{"admin": "admin"}
	c.DeviceIDs = make(map[string]DeviceInfo)

	data, err := os.ReadFile(ConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			Print("[*] %s not found, creating with default structure.", ConfigFile)
			return c.save() // save() will write the default config
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, c); err != nil {
		return fmt.Errorf("could not decode config file: %w", err)
	}
	return nil
}

func (c *Config) save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil { return fmt.Errorf("failed to marshal config: %w", err) }
	tmpFile := ConfigFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write to temporary config file: %w", err)
	}
	return os.Rename(tmpFile, ConfigFile)
}

func (c *Config) SafeSave() error { c.lock.Lock(); defer c.lock.Unlock(); return c.save() }
func (c *Config) GetSettings() Settings { c.lock.RLock(); defer c.lock.RUnlock(); return c.Settings }
func (c *Config) GetDeviceIDs() map[string]DeviceInfo {
	c.lock.RLock()
	defer c.lock.RUnlock()
	devices := make(map[string]DeviceInfo)
	for k, v := range c.DeviceIDs {
		if v.MaxSessions < 1 { v.MaxSessions = 1 }
		devices[k] = v
	}
	return devices
}

// ==========================================================
// --- 4. 状态与指标管理 ---
// ==========================================================

var (
	globalBytesSent     int64
	globalBytesReceived int64
	activeConns         sync.Map
	deviceUsage         sync.Map
	startTime           = time.Now()
	systemStatus        SystemStatus
	systemStatusMutex   sync.RWMutex
)

func InitMetrics() {
	cfg := GetConfig()
	devices := cfg.GetDeviceIDs()
	for id, info := range devices {
		newUsage := info.UsedBytes
		deviceUsage.Store(id, &newUsage)
	}
}

func AddActiveConn(key string, conn *ActiveConnInfo) { activeConns.Store(key, conn) }
func RemoveActiveConn(key string)                 { activeConns.Delete(key) }
func GetActiveConn(key string) (*ActiveConnInfo, bool) {
	if val, ok := activeConns.Load(key); ok { return val.(*ActiveConnInfo), true }
	return nil, false
}

func runPeriodicTasks() {
	saveTicker := time.NewTicker(5 * time.Minute)
	statusTicker := time.NewTicker(2 * time.Second)
	auditTicker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-saveTicker.C: saveDeviceUsage()
			case <-statusTicker.C: collectSystemStatus()
			case <-auditTicker.C: auditActiveConnections()
			}
		}
	}()
}

func saveDeviceUsage() {
	cfg := GetConfig()
	cfg.lock.Lock()
	defer cfg.lock.Unlock()
	isDirty := false
	deviceUsage.Range(func(key, value interface{}) bool {
		id := key.(string)
		currentUsage := atomic.LoadInt64(value.(*int64))
		if info, ok := cfg.DeviceIDs[id]; ok {
			if info.UsedBytes != currentUsage {
				info.UsedBytes = currentUsage
				cfg.DeviceIDs[id] = info
				isDirty = true
			}
		}
		return true
	})
	if isDirty {
		if err := cfg.save(); err != nil { Print("[!] Failed to save device usage: %v", err) }
	}
}

func collectSystemStatus() {
	systemStatusMutex.Lock()
	defer systemStatusMutex.Unlock()
	systemStatus.Uptime = time.Since(startTime).Round(time.Second).String()
	cp, err := cpu.Percent(0, false); if err == nil && len(cp) > 0 { systemStatus.CPUPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", cp[0]), 64) }
	cores, err := cpu.Counts(true); if err == nil { systemStatus.CPUCores = cores }
	vm, err := mem.VirtualMemory(); if err == nil {
		systemStatus.MemTotal = vm.Total; systemStatus.MemUsed = vm.Used
		systemStatus.MemPercent, _ = strconv.ParseFloat(fmt.Sprintf("%.1f", vm.UsedPercent), 64)
	}
	systemStatus.BytesSent = atomic.LoadInt64(&globalBytesSent)
	systemStatus.BytesReceived = atomic.LoadInt64(&globalBytesReceived)
}

func auditActiveConnections() {
	cfg := GetConfig()
	settings := cfg.GetSettings()
	devices := cfg.GetDeviceIDs()

	activeConns.Range(func(key, value interface{}) bool {
		connInfo := value.(*ActiveConnInfo)
		var reason string
		shouldKick := false

		idleTimeout := time.Duration(settings.IdleTimeout) * time.Second
		lastActiveTime := time.Unix(atomic.LoadInt64(&connInfo.LastActive), 0)

		if time.Since(lastActiveTime) > idleTimeout {
			reason = fmt.Sprintf("空闲超时 (超过 %v)", idleTimeout)
			shouldKick = true
		} else if settings.EnableIPBlacklist && isIPInList(connInfo.IP, settings.IPBlacklist) {
			reason = "IP在黑名单中"
			shouldKick = true
		} else if settings.EnableDeviceIDAuth {
			if connInfo.Credential != "" {
				if devInfo, ok := devices[connInfo.Credential]; ok {
					if !devInfo.Enabled { reason = "设备被禁用"; shouldKick = true }
					expiry, err := time.Parse("2006-01-02", devInfo.Expiry)
					if err == nil && time.Now().After(expiry.Add(24*time.Hour)) { reason = "设备已过期"; shouldKick = true }
					if devInfo.LimitGB > 0 {
						if usageVal, usageOk := deviceUsage.Load(connInfo.Credential); usageOk {
							currentUsage := atomic.LoadInt64(usageVal.(*int64))
							if currentUsage >= int64(devInfo.LimitGB)*1024*1024*1024 { reason = "流量超限"; shouldKick = true }
						}
					}
				} else { reason = "设备已被删除"; shouldKick = true }
			}
		}
		if shouldKick {
			Print("[-] [审计] 踢出连接 (原因: %s, 设备: %s, IP: %s)", reason, connInfo.DeviceID, connInfo.IP)
			if connInfo.cancel != nil { connInfo.cancel() } else { connInfo.Writer.Close() }
		}
		return true
	})
}

// ==========================================================
// --- 5. 核心连接处理与流量转发 ---
// ==========================================================

func handleClient(conn net.Conn) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	Print("[+] Connection opened from %s", remoteIP)
	defer func() {
		Print("[-] Connection closed for %s", remoteIP)
		conn.Close()
	}()

	cfg := GetConfig()
	settings := cfg.GetSettings()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true); tcpConn.SetKeepAlivePeriod(30 * time.Second); tcpConn.SetNoDelay(true)
	}
	if settings.EnableIPBlacklist && isIPInList(remoteIP, settings.IPBlacklist) {
		Print("[-] Connection from blacklisted IP %s rejected.", remoteIP); return
	}
	if settings.EnableIPWhitelist && !isIPInList(remoteIP, settings.IPWhitelist) {
		Print("[-] Connection from non-whitelisted IP %s rejected.", remoteIP); return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connKey := fmt.Sprintf("%s-%d", remoteIP, time.Now().UnixNano())
	activeConnInfo := &ActiveConnInfo{
		Writer:          conn,
		IP:              remoteIP,
		ConnKey:         connKey,
		FirstConnection: time.Now(),
		LastActive:      time.Now().Unix(),
		Status:          "握手",
		cancel:          cancel,
	}
	AddActiveConn(connKey, activeConnInfo)
	defer RemoveActiveConn(connKey)

	reader := bufio.NewReader(conn)
	handshakeTimeout := time.Duration(settings.Timeout) * time.Second
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	req, err := http.ReadRequest(reader)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			Print("[-] Handshake timeout for %s after %v.", remoteIP, handshakeTimeout)
		} else if err != io.EOF && !strings.Contains(err.Error(), "closed") {
			Print("[-] Handshake read error from %s: %v", remoteIP, err)
		}
		return
	}

	var headerBuilder strings.Builder
	req.Header.Write(&headerBuilder)
	headersText := req.Method + " " + req.RequestURI + " " + req.Proto + "\r\n" + headerBuilder.String()
	
	req.Body = http.MaxBytesReader(nil, req.Body, 64*1024)
	initialData, err := io.ReadAll(req.Body)
	if err != nil {
		Print("[!] Handshake read body error from %s: %v", remoteIP, err)
		sendHTTPErrorAndClose(conn, http.StatusBadRequest, "Bad Request", "Request body too large or invalid.")
		return
	}
	req.Body.Close()

	credential := req.Header.Get("Sec-WebSocket-Key")
	var finalDeviceID string
	var deviceInfo DeviceInfo
	var found bool
	if credential != "" {
		cfg.lock.RLock()
		deviceInfo, found = cfg.DeviceIDs[credential]
		cfg.lock.RUnlock()
		if found { finalDeviceID = deviceInfo.FriendlyName }
	}

	if settings.EnableDeviceIDAuth {
		if !found {
			Print("[!] Auth Enabled: Invalid Sec-WebSocket-Key from %s. Rejecting.", remoteIP)
			sendHTTPErrorAndClose(conn, 401, "Unauthorized", "Unauthorized")
			return
		}
		// (Further auth checks like expiry, limit, etc.)
	} else {
		if !found { finalDeviceID = remoteIP }
	}
	
	activeConnInfo.mu.Lock()
	activeConnInfo.DeviceID = finalDeviceID
	activeConnInfo.Credential = credential
	activeConnInfo.mu.Unlock()
	
	if _, ok := deviceUsage.Load(credential); !ok && credential != "" {
		newUsage := int64(0)
		deviceUsage.Store(credential, &newUsage)
	}
	
	ua := req.UserAgent()
	if settings.UAKeywordWS != "" && strings.Contains(ua, settings.UAKeywordWS) {
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		activeConnInfo.mu.Lock()
		activeConnInfo.Status = "活跃"
		activeConnInfo.mu.Unlock()
	} else {
		Print("[!] Unrecognized User-Agent from %s: '%s'. Rejecting.", remoteIP, ua)
		sendHTTPErrorAndClose(conn, 403, "Forbidden", "Forbidden")
		return
	}

	conn.SetReadDeadline(time.Time{})

	targetHost := settings.DefaultTargetHost
	targetPort := settings.DefaultTargetPort
	if realHost := extractHeaderValue(headersText, "x-real-host"); realHost != "" {
		if host, portStr, err := net.SplitHostPort(realHost); err == nil {
			targetHost = host
			if p, err := strconv.Atoi(portStr); err == nil { targetPort = p }
		} else {
			targetHost = realHost
		}
	}
	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	Print("[*] Tunneling %s -> %s for device %s", remoteIP, targetAddr, finalDeviceID)
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		Print("[!] Failed to connect to target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	if tcpTargetConn, ok := targetConn.(*net.TCPConn); ok {
		tcpTargetConn.SetKeepAlive(true)
		tcpTargetConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if len(initialData) > 0 {
		if _, err := targetConn.Write(initialData); err != nil {
			Print("[!] Failed to write initial data to target: %v", err)
			return
		}
	}

	go func() { <-ctx.Done(); conn.Close(); targetConn.Close() }()
	var wg sync.WaitGroup
	wg.Add(2)
	go pipeTraffic(ctx, &wg, targetConn, reader, connKey, cancel, true)
	go pipeTraffic(ctx, &wg, conn, targetConn, connKey, cancel, false)
	wg.Wait()
}

func pipeTraffic(ctx context.Context, wg *sync.WaitGroup, dst net.Conn, src io.Reader, connKey string, cancel context.CancelFunc, isUpload bool) {
	defer wg.Done(); defer cancel()
	connInfo, ok := GetActiveConn(connKey)
	if !ok { return }
	var deviceUsagePtr *int64
	if connInfo.Credential != "" {
		if val, ok := deviceUsage.Load(connInfo.Credential); ok { deviceUsagePtr = val.(*int64) }
	}
	tracker := &copyTracker{Writer: dst, ConnInfo: connInfo, IsUpload: isUpload, DeviceUsagePtr: deviceUsagePtr}
	buf := getBuf(GetConfig().GetSettings().BufferSize)
	defer putBuf(buf)
	io.CopyBuffer(tracker, src, buf)
	if tcpDst, ok := dst.(*net.TCPConn); ok { tcpDst.CloseWrite() }
}

type copyTracker struct {
	io.Writer
	ConnInfo       *ActiveConnInfo
	IsUpload       bool
	DeviceUsagePtr *int64
}

func (c *copyTracker) Write(p []byte) (n int, err error) {
	n, err = c.Writer.Write(p)
	if n > 0 {
		if c.IsUpload {
			atomic.AddInt64(&globalBytesSent, int64(n))
			atomic.AddInt64(&c.ConnInfo.BytesSent, int64(n))
		} else {
			atomic.AddInt64(&globalBytesReceived, int64(n))
			atomic.AddInt64(&c.ConnInfo.BytesReceived, int64(n))
		}
		if c.DeviceUsagePtr != nil {
			atomic.AddInt64(c.DeviceUsagePtr, int64(n))
		}
		atomic.StoreInt64(&c.ConnInfo.LastActive, time.Now().Unix())
	}
	return
}

// ==========================================================
// --- 6. Web 后台与 API (未修改) ---
// (所有 handleAPI, handleAdminPost, auth, login, etc. 函数)
// ==========================================================
// (This section remains unchanged from your original first code block)
// (To save space, I'm omitting these functions, just use your original ones)
// ...
// ... All your handler functions from the first code block ...
// ...

func sendHTTPErrorAndClose(conn net.Conn, statusCode int, statusText string, body string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		statusCode, statusText, len(body), body)
	_, _ = conn.Write([]byte(response))
	conn.Close()
}

// ==========================================================
// --- 7. Main 函数 (已修改为分离端口模式) ---
// ==========================================================

func main() {
	go func() { log.Println(http.ListenAndServe("localhost:6060", nil)) }()
	log.SetOutput(io.Discard)

	var err error
	adminPanelHTML, err = os.ReadFile("admin.html")
	if err != nil { Print("[!] FATAL: admin.html not found: %v", err); os.Exit(1) }
	loginPanelHTML, err = os.ReadFile("login.html")
	if err != nil { Print("[!] FATAL: login.html not found: %v", err); os.Exit(1) }

	Print("[*] WSTunnel-Go (Separate Port Mode) starting...")
	cfg := GetConfig()
	initBufferPool(cfg.Settings.BufferSize)
	InitMetrics()
	settings := cfg.GetSettings()
	runPeriodicTasks()

	// HTTP Listener
	httpAddr := fmt.Sprintf("0.0.0.0:%d", settings.HTTPPort)
	httpListener, err := net.Listen("tcp4", httpAddr)
	if err != nil {
		Print("[!] FATAL: Failed to listen on HTTP port %d: %v", settings.HTTPPort, err)
		os.Exit(1)
	}
	Print("[*] Started dedicated HTTP/WS listener on %s", httpAddr)
	go func() {
		for {
			conn, err := httpListener.Accept()
			if err != nil { break }
			go handleClient(conn)
		}
	}()

	// TLS Listener
	var tlsListener net.Listener
	if _, err := os.Stat(settings.CertFile); err == nil {
		cert, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
		if err != nil {
			Print("[!] Cert warning: %v. WSS server will not start.", err)
		} else {
			tlsAddr := fmt.Sprintf("0.0.0.0:%d", settings.TLSPort)
			tlsListener, err = tls.Listen("tcp4", tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err != nil {
				Print("[!] FATAL: Failed to listen on TLS port %d: %v", settings.TLSPort, err)
			} else {
				Print("[*] Started dedicated TLS/WSS listener on %s", tlsAddr)
				go func() {
					for {
						conn, err := tlsListener.Accept()
						if err != nil { break }
						go handleClient(conn)
					}
				}()
			}
		}
	} else {
		Print("[!] TLS Cert file '%s' not found. WSS server will not start.", settings.CertFile)
	}

	// Admin Server
	adminMux := http.NewServeMux()
	// (Admin handlers setup, same as your original code)
	// ...

	adminAddr := fmt.Sprintf("127.0.0.1:%d", settings.StatusPort)
	adminServer := &http.Server{Addr: adminAddr, Handler: adminMux}
	Print("[*] Status server listening on %s", adminAddr)
	go func() {
		if err := adminServer.ListenAndServe(); err != http.ErrServerClosed {
			Print("[!] FATAL: Failed to start admin server: %v", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	Print("\n[*] Shutting down server...")

	httpListener.Close()
	if tlsListener != nil {
		tlsListener.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adminServer.Shutdown(ctx)
	saveDeviceUsage()
	Print("[*] Server gracefully stopped.")
}
