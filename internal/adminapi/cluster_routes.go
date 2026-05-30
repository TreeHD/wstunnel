// cluster_routes.go — 把叢集相關路由接進 adminapi。
//
// 路由分兩類:
//   1. /api/cluster/heartbeat       — Slave 心跳端點(只在 Master 模式有效;不需 admin 認證)
//   2. /api/cluster/...              — 後台管理 (列節點、加節點、踢節點、看 Slave log/連線)
//
// heartbeat 自帶 token + HMAC 驗證,所以不該被包進 AuthMiddleware(否則會被 redirect 到 /login)。
package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"wstunnel/internal/cluster"
	"wstunnel/internal/config"
	"wstunnel/internal/session"
)

// clusterAPIHandler 處理 /api/cluster/<sub>(heartbeat 除外,heartbeat 在 mux 層直接掛)。
//
// 這些路徑都需要 admin 登入(由 AuthMiddleware 包起來)。
func clusterAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/cluster/role":
		// 給 UI 判斷顯示哪些頁面
		c := config.Get()
		c.Lock.RLock()
		role := c.ClusterRole
		c.Lock.RUnlock()
		if role == "" {
			role = "standalone"
		}
		session.SendJSON(w, http.StatusOK, map[string]string{"role": role})
	case r.URL.Path == "/api/cluster/slaves" && r.Method == "GET":
		if !cluster.IsMaster() {
			session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
			return
		}
		session.SendJSON(w, http.StatusOK, cluster.ListSlaves())
	case r.URL.Path == "/api/cluster/slaves" && r.Method == "POST":
		clusterAddSlave(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/cluster/slaves/") && r.Method == "DELETE":
		clusterRemoveSlave(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/cluster/slaves/") && r.Method == "PATCH":
		clusterRenameSlave(w, r)
	case r.URL.Path == "/api/cluster/online" && r.Method == "GET":
		if !cluster.IsMaster() {
			session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
			return
		}
		session.SendJSON(w, http.StatusOK, cluster.AllOnline())
	case strings.HasPrefix(r.URL.Path, "/api/cluster/slaves/") && strings.HasSuffix(r.URL.Path, "/logs") && r.Method == "GET":
		clusterSlaveLogs(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/cluster/slaves/") && strings.HasSuffix(r.URL.Path, "/kick") && r.Method == "POST":
		clusterKickFromSlave(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/cluster/slaves/") && strings.HasSuffix(r.URL.Path, "/compose") && r.Method == "POST":
		clusterCompose(w, r)
	default:
		http.NotFound(w, r)
	}
}

func clusterAddSlave(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	var p struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid request"})
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node name required"})
		return
	}
	rec, err := cluster.AddSlave(p.Name, p.Notes)
	if err != nil {
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, rec)
}

func clusterRemoveSlave(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/cluster/slaves/")
	if id == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node id required"})
		return
	}
	if err := cluster.RemoveSlave(id); err != nil {
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "節點已移除"})
}

func clusterRenameSlave(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/cluster/slaves/")
	if id == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node id required"})
		return
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid request"})
		return
	}
	if err := cluster.RenameSlave(id, p.Name); err != nil {
		session.SendJSON(w, http.StatusInternalServerError, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "已更新"})
}

func clusterSlaveLogs(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	// /api/cluster/slaves/<id>/logs
	rest := strings.TrimPrefix(r.URL.Path, "/api/cluster/slaves/")
	id := strings.TrimSuffix(rest, "/logs")
	if id == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node id required"})
		return
	}
	session.SendJSON(w, http.StatusOK, cluster.SlaveLogTail(id, 200))
}

func clusterKickFromSlave(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/cluster/slaves/")
	id := strings.TrimSuffix(rest, "/kick")
	if id == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node id required"})
		return
	}
	var p struct {
		ConnID string `json:"conn_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.ConnID == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "conn_id required"})
		return
	}
	if err := cluster.RequestKick(id, p.ConnID); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"message": "已排入待踢佇列"})
}

func clusterCompose(w http.ResponseWriter, r *http.Request) {
	if !cluster.IsMaster() {
		session.SendJSON(w, http.StatusForbidden, map[string]string{"message": "not in master mode"})
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/cluster/slaves/")
	id := strings.TrimSuffix(rest, "/compose")
	if id == "" {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "node id required"})
		return
	}
	var p struct {
		MasterURL     string `json:"master_url"`
		PublicAddr    string `json:"public_addr"`
		SkipTLSVerify bool   `json:"skip_tls_verify"`
		IncludeDNSTT  bool   `json:"include_dnstt"`
		HeartbeatSec  int    `json:"heartbeat_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": "invalid request"})
		return
	}
	yaml, err := cluster.GenerateSlaveCompose(cluster.ComposeOptions{
		NodeID:        id,
		MasterURL:     strings.TrimSpace(p.MasterURL),
		PublicAddr:    strings.TrimSpace(p.PublicAddr),
		SkipTLSVerify: p.SkipTLSVerify,
		IncludeDNSTT:  p.IncludeDNSTT,
		HeartbeatSec:  p.HeartbeatSec,
	})
	if err != nil {
		session.SendJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	session.SendJSON(w, http.StatusOK, map[string]string{"yaml": yaml})
}
