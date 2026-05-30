// session.go — 後台 admin session 管理
//
// 職責：
//   * 簽發/驗證 admin 登入 cookie
//   * 過期清理
//
// 注意：這裡的 session 與 SSH session / TUN session 完全無關,僅用於 9090 後台
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const sessionCookieName = "wstunnel_admin_session"

type Session struct {
	Username string
	Expiry   time.Time
}

var (
	sessions     = make(map[string]Session)
	sessionsLock sync.RWMutex
)

// createSession 簽發一個新的後台登入 cookie
func createSession(username string) *http.Cookie {
	sessionTokenBytes := make([]byte, 32)
	rand.Read(sessionTokenBytes)
	sessionToken := hex.EncodeToString(sessionTokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	sessionsLock.Lock()
	sessions[sessionToken] = Session{Username: username, Expiry: expiry}
	sessionsLock.Unlock()
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		Expires:  expiry,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// validateSession 驗 cookie,過期會順便清掉
func validateSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	sessionsLock.RLock()
	session, ok := sessions[cookie.Value]
	sessionsLock.RUnlock()
	if !ok || time.Now().After(session.Expiry) {
		if ok {
			sessionsLock.Lock()
			delete(sessions, cookie.Value)
			sessionsLock.Unlock()
		}
		return "", false
	}
	return session.Username, true
}

// sendJSON 統一的 JSON 回應輔助
func sendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
