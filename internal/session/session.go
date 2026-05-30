// Package session 提供 admin 後台 cookie-based 登入 session 管理。
//
// 注意:這裡的 session 與 SSH session / TUN session 完全無關,
// 僅用於 9090 後台。
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// CookieName 是 admin 登入 cookie 的名字。
const CookieName = "wstunnel_admin_session"

type entry struct {
	Username string
	Expiry   time.Time
}

var (
	sessions = make(map[string]entry)
	mu       sync.RWMutex
)

// Create 簽發一個新的後台登入 cookie。
func Create(username string) *http.Cookie {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)
	expiry := time.Now().Add(12 * time.Hour)
	mu.Lock()
	sessions[token] = entry{Username: username, Expiry: expiry}
	mu.Unlock()
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Expires:  expiry,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// Validate 驗 cookie,過期會順便清掉,回 (username, ok)。
func Validate(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return "", false
	}
	mu.RLock()
	s, ok := sessions[cookie.Value]
	mu.RUnlock()
	if !ok || time.Now().After(s.Expiry) {
		if ok {
			mu.Lock()
			delete(sessions, cookie.Value)
			mu.Unlock()
		}
		return "", false
	}
	return s.Username, true
}

// Revoke 主動撤銷指定 token(登出用)。
func Revoke(token string) {
	mu.Lock()
	delete(sessions, token)
	mu.Unlock()
}

// SendJSON 是後台 handler 共用的 JSON 回應輔助。
func SendJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
