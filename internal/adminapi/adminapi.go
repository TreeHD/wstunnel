// Package adminapi 實作 9090 後台所有 HTTP handler。
//
// 路由集中在 Handler 入口,內部依路徑/方法分派到各個 sub-handler。
// 這裡刻意不拆 sub-package,因為 admin API 變動頻繁,集中管理較好維護。
package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"wstunnel/internal/cluster"
	"wstunnel/internal/config"
	"wstunnel/internal/dnsx"
	"wstunnel/internal/logging"
	"wstunnel/internal/proxy"
	"wstunnel/internal/session"
	"wstunnel/internal/sshsrv"
	"wstunnel/internal/store"
	"wstunnel/internal/traffic"
	"wstunnel/internal/udpgw"
)

// ServerStartTime 由 main 設置,用於 uptime 顯示。
var ServerStartTime time.Time

// AuthMiddleware 對未授權請求做適當回應(API 回 401,網頁 302 到登入頁)。
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := session.Validate(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			session.SendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		} else {
			http.Redirect(w, r, "/login.html", http.StatusFound)
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		session.SendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	if !store.VerifyAdminPassword(creds.Username, creds.Password) {
		session.SendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	http.SetCookie(w, session.Create(creds.Username))
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(session.CookieName)
	if err == nil {
		session.Revoke(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: session.CookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login.html", http.StatusFound)
}

// apiHandler 是 /api/* 的總路由。
func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/server_status":
		apiServerStatus(w, r)
	case r.URL.Path == "/api/connections":
		apiConnections(w, r)
	case r.URL.Path == "/api/accounts":
		apiAccountsList(w, r)
	case r.URL.Path == "/api/accounts/set_status" && r.Method == "POST":
		apiSetAccountStatus(w, r)
	case r.URL.Path == "/api/accounts/reset-traffic" && r.Method == "POST":
		apiResetAccountTraffic(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "POST":
		apiUpsertAccount(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/accounts/") && r.Method == "DELETE":
		apiDeleteAccount(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/connections/") && r.Method == "DELETE":
		apiKickConnection(w, r)
	case r.URL.Path == "/api/admin/update_password" && r.Method == "POST":
		apiUpdateAdminPassword(w, r)
	case r.URL.Path == "/api/settings":
		apiSettings(w, r)
	case r.URL.Path == "/api/logs":
		session.SendJSON(w, http.StatusOK, logging.Default.GetLogs())
	case r.URL.Path == "/api/traffic":
		session.SendJSON(w, http.StatusOK, traffic.Snapshot())
	case r.URL.Path == "/api/whoami":
		if user, ok := session.Validate(r); ok {
			session.SendJSON(w, http.StatusOK, map[string]string{"username": user})
		}
	case r.URL.Path == "/api/udpgw/status":
		session.SendJSON(w, http.StatusOK, udpgw.Stats())
	case r.URL.Path == "/api/upstream/test" && r.Method == "POST":
		apiUpstreamTest(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/cluster/"):
		clusterAPIHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func apiServerStatus(w http.ResponseWriter, r *http.Request) {
	var globalSent, globalRcvd uint64
	traffic.Range(func(_ string, t *traffic.Info) bool {
		globalSent += traffic.LoadSent(t)
		globalRcvd += traffic.LoadReceived(t)
		return true
	})
	cpuPercent, _ := cpu.Percent(0, false)
	memInfo, _ := mem.VirtualMemory()
	session.SendJSON(w, http.StatusOK, map[string]interface{}{
		"uptime":          time.Since(ServerStartTime).Round(time.Second).String(),
		"active_conns":    sshsrv.CountOnline(),
		"global_sent":     globalSent,
		"global_rcvd":     globalRcvd,
		"cpu_percent":     cpuPercent[0],
		"mem_percent":     memInfo.UsedPercent,
		"mem_used_bytes":  memInfo.Used,
		"mem_total_bytes": memInfo.Total,
	})
}

func apiConnections(w http.ResponseWriter, r *http.Request) {
	var conns []map[string]interface{}
	sshsrv.OnlineRange(func(u *sshsrv.OnlineUser) bool {
		acc, err := store.GetAccount(u.Username)
		if err != nil {
			return true
		}
		t := traffic.Get(u.Username)
		sentBytes := traffic.LoadSent(t)
		receivedBytes := traffic.LoadReceived(t)
		usedBytes := sentBytes + receivedBytes
		var remainingBytes int64 = -1
		if acc.LimitGB > 0 {
			remainingBytes = int64(acc.LimitGB*1e9) - int64(usedBytes)
			if remainingBytes < 0 {
				remainingBytes = 0
			}
		}
		conns = append(conns, map[string]interface{}{
			"conn_id":         u.ConnID,
			"username":        u.Username,
			"ip":              u.RemoteAddr,
			"connect_time":    u.ConnectTime,
			"sent_bytes":      sentBytes,
			"received_bytes":  receivedBytes,
			"expiry_date":     acc.ExpiryDate,
			"used_bytes":      usedBytes,
			"remaining_bytes": remainingBytes,
		})
		return true
	})
	session.SendJSON(w, http.StatusOK, conns)
}

// apiAccountsList 回傳所有帳號(密碼 hash 不會被序列化,Account.PasswordHash 是 json:"-")。
func apiAccountsList(w http.ResponseWriter, r *http.Request) {
	accounts, err := store.ListAccounts()
	if err != nil {
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	// 為了和舊 UI 的 map<username, AccountInfo> 結構相容,把 list 轉成 map
	out := make(map[string]store.Account, len(accounts))
	for _, a := range accounts {
		out[a.Username] = a
	}
	session.SendJSON(w, http.StatusOK, out)
}

func apiSetAccountStatus(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	if payload.Username == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	if err := store.SetAccountEnabled(payload.Username, payload.Enabled); err != nil {
		if err == store.ErrAccountNotFound {
			session.SendJSON(w, http.StatusNotFound, map[string]string{"message": "错误：用户不存在"})
			return
		}
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}

	if !payload.Enabled {
		sshsrv.KickByUsername(payload.Username)
	}
	actionStr := "封禁"
	if payload.Enabled {
		actionStr = "解封"
	}
	session.SendJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("账号 %s 已成功%s", payload.Username, actionStr),
	})
}

func apiResetAccountTraffic(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	if p.Username == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	if traffic.Reset(p.Username) {
		session.SendJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf("账号 %s 的流量已重置", p.Username),
		})
	} else {
		session.SendJSON(w, http.StatusNotFound, map[string]string{"message": "未找到该用户的流量记录，无法重置"})
	}
}

func apiUpsertAccount(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	if username == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	// 用 *string 區分「沒帶 password」與「帶了空字串」(後者視同想清空,但這裡不允許)
	var payload struct {
		Password     *string `json:"password"`
		Enabled      bool    `json:"enabled"`
		ExpiryDate   string  `json:"expiry_date"`
		LimitGB      float64 `json:"limit_gb"`
		MaxSessions  int     `json:"max_sessions"`
		FriendlyName string  `json:"friendly_name"`
	}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}

	newPlain := ""
	if payload.Password != nil {
		newPlain = *payload.Password
	}
	acc := store.Account{
		Username:     username,
		Enabled:      payload.Enabled,
		ExpiryDate:   payload.ExpiryDate,
		LimitGB:      payload.LimitGB,
		MaxSessions:  payload.MaxSessions,
		FriendlyName: payload.FriendlyName,
	}
	if err := store.UpsertAccount(acc, newPlain); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 更新成功"})
}

func apiDeleteAccount(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	if username == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：不能删除空用户名的账户"})
		return
	}
	if err := store.DeleteAccount(username); err != nil {
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 删除成功"})
}

func apiKickConnection(w http.ResponseWriter, r *http.Request) {
	connID := strings.TrimPrefix(r.URL.Path, "/api/connections/")
	if u, ok := sshsrv.Lookup(connID); ok {
		u.SSHConn.Close()
		session.SendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"})
	}
}

func apiUpdateAdminPassword(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	user, _ := session.Validate(r)
	if err := store.VerifyAndUpdateAdminPassword(user, payload.OldPassword, payload.NewPassword); err != nil {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "旧密码错误"})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "密码更新成功"})
}

func apiSettings(w http.ResponseWriter, r *http.Request) {
	cfg := config.Get()
	if r.Method == "GET" {
		cfg.Lock.RLock()
		defer cfg.Lock.RUnlock()
		session.SendJSON(w, http.StatusOK, cfg)
		return
	}
	if r.Method == "POST" {
		var newSettings config.Config
		if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
			session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的设置格式"})
			return
		}
		cfg.Lock.Lock()
		cfg.HandshakeTimeout = newSettings.HandshakeTimeout
		cfg.ConnectUA = newSettings.ConnectUA
		cfg.BufferSizeKB = newSettings.BufferSizeKB
		cfg.IdleTimeoutSeconds = newSettings.IdleTimeoutSeconds
		cfg.TolerantCopyMaxRetries = newSettings.TolerantCopyMaxRetries
		cfg.TolerantCopyRetryDelayMs = newSettings.TolerantCopyRetryDelayMs
		cfg.TargetConnectTimeoutSeconds = newSettings.TargetConnectTimeoutSeconds
		cfg.DefaultExpiryDays = newSettings.DefaultExpiryDays
		cfg.DefaultLimitGB = newSettings.DefaultLimitGB
		cfg.AllowedSNI = newSettings.AllowedSNI
		cfg.DNSServer = newSettings.DNSServer
		cfg.UDPGWPort = newSettings.UDPGWPort
		cfg.UpstreamProxyEnabled = newSettings.UpstreamProxyEnabled
		cfg.UpstreamProxyURL = strings.TrimSpace(newSettings.UpstreamProxyURL)
		cfg.Lock.Unlock()

		// DNS / buffer pool 可能需要 rebuild
		dnsx.Rebuild()
		sshsrv.InitBufferPool()

		if err := config.Save(); err != nil {
			session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": "保存配置失败: " + err.Error()})
			return
		}
		session.SendJSON(w, http.StatusOK, map[string]string{"message": "设置已保存"})
	}
}

// apiUpstreamTest 對當前(或 body 提供的)上游 proxy 做一次端到端測試。
func apiUpstreamTest(w http.ResponseWriter, r *http.Request) {
	var override struct {
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&override)

	s := proxy.CurrentSettings()
	if override.URL != "" {
		u, err := url.Parse(strings.TrimSpace(override.URL))
		if err != nil || u.Host == "" {
			session.SendJSON(w, http.StatusBadRequest, map[string]interface{}{
				"ok": false, "error": "invalid url",
			})
			return
		}
		s = proxy.Settings{Enabled: true, RawURL: override.URL, Parsed: u}
		if u.User != nil {
			s.Username = u.User.Username()
			s.Password, _ = u.User.Password()
		}
	}

	if !s.Enabled {
		session.SendJSON(w, http.StatusOK, map[string]interface{}{
			"ok": true, "mode": "direct", "message": "上游未啟用,目前走直連",
		})
		return
	}

	const probe = "example.com:80"
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := proxy.DialVia(ctx, s, probe, 8*time.Second)
	elapsed := time.Since(start)

	resp := map[string]interface{}{
		"mode":      strings.ToLower(s.Parsed.Scheme),
		"proxy":     proxy.RedactURL(s.RawURL),
		"target":    probe,
		"elapsed":   elapsed.String(),
		"timestamp": time.Now().Unix(),
	}
	if err != nil {
		resp["ok"] = false
		resp["error"] = err.Error()
		session.SendJSON(w, http.StatusOK, resp)
		return
	}
	conn.Close()
	resp["ok"] = true
	resp["message"] = "成功透過上游 proxy 連到 " + probe
	session.SendJSON(w, http.StatusOK, resp)
}

// Start 啟動後台 HTTP server,回傳 *http.Server 供主流程做 graceful shutdown。
func Start(wg *sync.WaitGroup) *http.Server {
	cfg := config.Get()
	srv := &http.Server{Addr: cfg.AdminAddr}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "web/login.html")
		})
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", logoutHandler)
		// Slave 心跳:用 token + HMAC 自證,故意不走 AuthMiddleware
		mux.HandleFunc("/api/cluster/heartbeat", cluster.HandleHeartbeat)
		mux.HandleFunc("/api/", AuthMiddleware(apiHandler))
		mux.HandleFunc("/", AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.ServeFile(w, r, "web/admin.html")
				return
			}
			http.NotFound(w, r)
		}))
		srv.Handler = mux
		log.Printf("System: Admin panel listening on http://%s", cfg.AdminAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("FATAL: Cannot start admin panel: %v", err)
		}
	}()
	return srv
}
