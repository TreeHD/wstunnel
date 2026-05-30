// api.go — Admin 後台 HTTP 介面
//
// 職責：
//   * authMiddleware: 對非 /login 路徑強制帶有效 session
//   * loginHandler / logoutHandler: 登入登出
//   * apiHandler: /api/* 的單一進入點(內部 switch)
//   * startAdminServer: 啟動後台 listener
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/crypto/ssh"
)

// authMiddleware 對未授權請求做適當回應(API 回 401,網頁 302 到登入頁)
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := validateSession(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "Unauthorized"})
		} else {
			http.Redirect(w, r, "/login.html", http.StatusFound)
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	globalConfig.lock.RLock()
	p, ok := globalConfig.AdminAccounts[creds.Username]
	globalConfig.lock.RUnlock()
	if !ok || p != creds.Password {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"message": "用户名或密码错误"})
		return
	}
	http.SetCookie(w, createSession(creds.Username))
	sendJSON(w, http.StatusOK, map[string]string{"message": "Login successful"})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionsLock.Lock()
		delete(sessions, cookie.Value)
		sessionsLock.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login.html", http.StatusFound)
}

// apiHandler 是 /api/* 的總路由,使用 switch 做 path 比對
// 之所以不拆細分 sub-handler 是因為原本就這樣寫,搬遷時保留 API 行為一致
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
		sendJSON(w, http.StatusOK, globalLog.GetLogs())
	case r.URL.Path == "/api/traffic":
		trafficData := make(map[string]*TrafficInfo)
		globalTraffic.Range(func(k, v interface{}) bool { trafficData[k.(string)] = v.(*TrafficInfo); return true })
		sendJSON(w, http.StatusOK, trafficData)
	case r.URL.Path == "/api/whoami":
		if user, ok := validateSession(r); ok {
			sendJSON(w, http.StatusOK, map[string]string{"username": user})
		}
	case r.URL.Path == "/api/udpgw/status":
		sendJSON(w, http.StatusOK, udpgwStatsSnapshot())
	default:
		http.NotFound(w, r)
	}
}

func apiServerStatus(w http.ResponseWriter, r *http.Request) {
	var globalSent, globalRcvd uint64
	globalTraffic.Range(func(_, v interface{}) bool {
		t := v.(*TrafficInfo)
		globalSent += atomic.LoadUint64(&t.Sent)
		globalRcvd += atomic.LoadUint64(&t.Received)
		return true
	})
	var activeConns int
	onlineUsers.Range(func(_, _ interface{}) bool {
		activeConns++
		return true
	})
	cpuPercent, _ := cpu.Percent(0, false)
	memInfo, _ := mem.VirtualMemory()
	sendJSON(w, http.StatusOK, map[string]interface{}{
		"uptime":          time.Since(serverStartTime).Round(time.Second).String(),
		"active_conns":    activeConns,
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
	onlineUsers.Range(func(_, v interface{}) bool {
		u := v.(*OnlineUser)
		globalConfig.lock.RLock()
		acc, ok := globalConfig.Accounts[u.Username]
		globalConfig.lock.RUnlock()
		if !ok {
			return true
		}
		t_val, _ := globalTraffic.LoadOrStore(u.Username, &TrafficInfo{})
		t := t_val.(*TrafficInfo)
		sentBytes := atomic.LoadUint64(&t.Sent)
		receivedBytes := atomic.LoadUint64(&t.Received)
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
	sendJSON(w, http.StatusOK, conns)
}

func apiAccountsList(w http.ResponseWriter, r *http.Request) {
	globalConfig.lock.RLock()
	defer globalConfig.lock.RUnlock()
	sendJSON(w, http.StatusOK, globalConfig.Accounts)
}

func apiSetAccountStatus(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Username string `json:"username"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	if payload.Username == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	globalConfig.lock.Lock()
	acc, ok := globalConfig.Accounts[payload.Username]
	if !ok {
		globalConfig.lock.Unlock()
		sendJSON(w, http.StatusNotFound, map[string]string{"message": "错误：用户不存在"})
		return
	}
	acc.Enabled = payload.Enabled
	globalConfig.Accounts[payload.Username] = acc
	if !payload.Enabled {
		var connsToClose []ssh.Conn
		onlineUsers.Range(func(_, v interface{}) bool {
			u := v.(*OnlineUser)
			if u.Username == payload.Username {
				if c, ok := u.sshConn.(ssh.Conn); ok {
					connsToClose = append(connsToClose, c)
				}
			}
			return true
		})
		for _, conn := range connsToClose {
			conn.Close()
		}
	}
	globalConfig.lock.Unlock()
	actionStr := "封禁"
	if payload.Enabled {
		actionStr = "解封"
	}
	sendJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("账号 %s 已成功%s", payload.Username, actionStr),
	})
}

func apiResetAccountTraffic(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	if p.Username == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	if v, ok := globalTraffic.Load(p.Username); ok {
		t := v.(*TrafficInfo)
		atomic.StoreUint64(&t.Sent, 0)
		atomic.StoreUint64(&t.Received, 0)
		sendJSON(w, http.StatusOK, map[string]string{
			"message": fmt.Sprintf("账号 %s 的流量已重置", p.Username),
		})
	} else {
		sendJSON(w, http.StatusNotFound, map[string]string{"message": "未找到该用户的流量记录，无法重置"})
	}
}

func apiUpsertAccount(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	if username == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：用户名不能为空"})
		return
	}
	var newInfo AccountInfo
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	tempInfo := struct {
		Password *string `json:"password"`
	}{}
	json.Unmarshal(bodyBytes, &tempInfo)
	json.Unmarshal(bodyBytes, &newInfo)

	globalConfig.lock.Lock()
	existingInfo, isUpdate := globalConfig.Accounts[username]
	if isUpdate {
		if tempInfo.Password == nil {
			newInfo.Password = existingInfo.Password
		}
	} else if newInfo.Password == "" {
		globalConfig.lock.Unlock()
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "新用户必须提供密码"})
		return
	}
	globalConfig.Accounts[username] = newInfo
	globalConfig.lock.Unlock()

	if err := safeSaveConfig(); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"message": "保存配置失败: " + err.Error()})
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 更新成功"})
}

func apiDeleteAccount(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	if username == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "错误：不能删除空用户名的账户"})
		return
	}
	globalConfig.lock.Lock()
	delete(globalConfig.Accounts, username)
	globalConfig.lock.Unlock()
	safeSaveConfig()
	sendJSON(w, http.StatusOK, map[string]string{"message": "账户 " + username + " 删除成功"})
}

func apiKickConnection(w http.ResponseWriter, r *http.Request) {
	connID := strings.TrimPrefix(r.URL.Path, "/api/connections/")
	if user, ok := onlineUsers.Load(connID); ok {
		if c, ok := user.(*OnlineUser).sshConn.(ssh.Conn); ok {
			c.Close()
		}
		sendJSON(w, http.StatusOK, map[string]string{"message": "连接已断开"})
	}
}

func apiUpdateAdminPassword(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效请求"})
		return
	}
	user, _ := validateSession(r)
	globalConfig.lock.Lock()
	if globalConfig.AdminAccounts[user] == payload.OldPassword {
		globalConfig.AdminAccounts[user] = payload.NewPassword
		globalConfig.lock.Unlock()
		safeSaveConfig()
		sendJSON(w, http.StatusOK, map[string]string{"message": "密码更新成功"})
	} else {
		globalConfig.lock.Unlock()
		sendJSON(w, http.StatusForbidden, map[string]string{"message": "旧密码错误"})
	}
}

func apiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		globalConfig.lock.RLock()
		defer globalConfig.lock.RUnlock()
		sendJSON(w, http.StatusOK, globalConfig)
		return
	}
	if r.Method == "POST" {
		var newSettings Config
		if err := json.NewDecoder(r.Body).Decode(&newSettings); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"message": "无效的设置格式"})
			return
		}
		globalConfig.lock.Lock()
		globalConfig.HandshakeTimeout = newSettings.HandshakeTimeout
		globalConfig.ConnectUA = newSettings.ConnectUA
		globalConfig.BufferSizeKB = newSettings.BufferSizeKB
		globalConfig.IdleTimeoutSeconds = newSettings.IdleTimeoutSeconds
		globalConfig.TolerantCopyMaxRetries = newSettings.TolerantCopyMaxRetries
		globalConfig.TolerantCopyRetryDelayMs = newSettings.TolerantCopyRetryDelayMs
		globalConfig.TargetConnectTimeoutSeconds = newSettings.TargetConnectTimeoutSeconds
		globalConfig.DefaultExpiryDays = newSettings.DefaultExpiryDays
		globalConfig.DefaultLimitGB = newSettings.DefaultLimitGB
		globalConfig.AllowedSNI = newSettings.AllowedSNI
		globalConfig.DNSServer = newSettings.DNSServer
		globalConfig.UDPGWPort = newSettings.UDPGWPort
		globalConfig.lock.Unlock()
		// DNS server 可能已變更,重建 resolver(dns.go)
		rebuildResolver()
		if err := safeSaveConfig(); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"message": "保存配置失败: " + err.Error()})
			return
		}
		bufferPool = sync.Pool{New: func() interface{} {
			buf := make([]byte, globalConfig.BufferSizeKB*1024)
			return &buf
		}}
		sendJSON(w, http.StatusOK, map[string]string{"message": "设置已保存"})
	}
}

// startAdminServer 啟動後台 HTTP server,回傳 *http.Server 供主流程做 graceful shutdown
func startAdminServer(wg *sync.WaitGroup) *http.Server {
	srv := &http.Server{Addr: globalConfig.AdminAddr}
	wg.Add(1)
	go func() {
		defer wg.Done()
		mux := http.NewServeMux()
		mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "frontend/login.html")
		})
		mux.HandleFunc("/login", loginHandler)
		mux.HandleFunc("/logout", logoutHandler)
		mux.HandleFunc("/api/", authMiddleware(apiHandler))
		mux.HandleFunc("/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.ServeFile(w, r, "frontend/admin.html")
				return
			}
			http.NotFound(w, r)
		}))
		srv.Handler = mux
		log.Printf("System: Admin panel listening on http://%s", globalConfig.AdminAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("FATAL: Cannot start admin panel: %v", err)
		}
	}()
	return srv
}
