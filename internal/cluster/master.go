// master.go — Master 端叢集執行緒。
//
// 主要責任:
//   1. 維護 NodeID → *SlaveRuntime 的「即時狀態」記憶體表
//   2. 提供 HTTP handler 供 Slave 心跳呼叫
//   3. 將 Slave 回報的 traffic delta 累加進本機 traffic store
//   4. 維護 per-slave 的踢除待辦佇列(由後台呼叫 RequestKick 加入)
//
// 持久化資料(node_id/token/name)放在 store(SQLite);runtime 狀態僅在記憶體。
package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"wstunnel/internal/config"
	"wstunnel/internal/store"
	"wstunnel/internal/traffic"
)

// SlaveRuntime 是 Master 端為一個 Slave 維護的即時狀態。
type SlaveRuntime struct {
	NodeID   string
	NodeName string

	LastSeen    time.Time
	PublicAddr  string
	Version     string
	CPUPercent  float64
	MemPercent  float64
	UptimeSec   int64
	ActiveConns int

	// Online 是 Slave 上次心跳所回報的活躍連線快照
	Online []OnlineSnapshot

	// LogTail 是來自此 Slave 的最近 log
	LogTail []LogEntry

	// PendingKicks 是 Master 待 Slave 處理的踢除指令(map 為了去重)
	PendingKicks map[string]struct{}
}

// 單一 Master 進程的全域狀態。
var (
	masterMu       sync.RWMutex
	masterRuntimes = map[string]*SlaveRuntime{}
)

// 每個 Slave 保留多少行 log tail
const maxLogTailPerSlave = 500

// IsMaster 回傳目前是否處於 Master 模式。
func IsMaster() bool {
	c := config.Get()
	if c == nil {
		return false
	}
	c.Lock.RLock()
	defer c.Lock.RUnlock()
	return c.ClusterRole == string(RoleMaster)
}

// IsSlave 回傳目前是否處於 Slave 模式。
func IsSlave() bool {
	c := config.Get()
	if c == nil {
		return false
	}
	c.Lock.RLock()
	defer c.Lock.RUnlock()
	return c.ClusterRole == string(RoleSlave)
}

// GenerateToken 生成 Slave token / NodeID 用的隨機字串。
func GenerateToken() string {
	var buf [24]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// AddSlave 在 store 中註冊一個新節點,回傳產生的 SlaveRecord(包含新 token)。
func AddSlave(name, notes string) (store.SlaveRecord, error) {
	id := "node-" + GenerateToken()[:12]
	rec := store.SlaveRecord{
		NodeID:    id,
		NodeName:  name,
		Token:     GenerateToken(),
		CreatedAt: time.Now().Unix(),
		Notes:     notes,
	}
	if err := store.UpsertSlave(rec); err != nil {
		return store.SlaveRecord{}, err
	}
	return rec, nil
}

// RemoveSlave 從 store 中移除一個節點,並丟棄其 runtime。
func RemoveSlave(nodeID string) error {
	if err := store.DeleteSlave(nodeID); err != nil {
		return err
	}
	masterMu.Lock()
	delete(masterRuntimes, nodeID)
	masterMu.Unlock()
	return nil
}

// RenameSlave 更新 Slave 的友善名稱。
func RenameSlave(nodeID, newName string) error {
	return store.RenameSlave(nodeID, newName)
}

// RequestKick 把 conn_id 排入指定 Slave 的踢除佇列,等下次心跳下發。
func RequestKick(nodeID, connID string) error {
	masterMu.Lock()
	defer masterMu.Unlock()
	rt, ok := masterRuntimes[nodeID]
	if !ok {
		return fmt.Errorf("slave %s is not online", nodeID)
	}
	if rt.PendingKicks == nil {
		rt.PendingKicks = make(map[string]struct{})
	}
	rt.PendingKicks[connID] = struct{}{}
	return nil
}

// SlaveSummary 是後台 UI 用的 Slave 列表單筆。
type SlaveSummary struct {
	NodeID      string  `json:"node_id"`
	NodeName    string  `json:"node_name"`
	Notes       string  `json:"notes,omitempty"`
	CreatedAt   int64   `json:"created_at"`
	Online      bool    `json:"online"`
	LastSeenAgo int64   `json:"last_seen_ago_sec"` // 0 表示從未連線
	PublicAddr  string  `json:"public_addr,omitempty"`
	Version     string  `json:"version,omitempty"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	UptimeSec   int64   `json:"uptime_sec"`
	ActiveConns int     `json:"active_conns"`
}

// 超過此秒數沒收到心跳即視為離線(以兩倍預設 30s 心跳為基準)。
const offlineThresholdSec = 90

// ListSlaves 回傳所有已註冊節點 + runtime 狀態,給 UI 使用。
func ListSlaves() []SlaveSummary {
	records, _ := store.ListSlaves()

	masterMu.RLock()
	defer masterMu.RUnlock()

	now := time.Now()
	out := make([]SlaveSummary, 0, len(records))
	for _, r := range records {
		s := SlaveSummary{
			NodeID:    r.NodeID,
			NodeName:  r.NodeName,
			Notes:     r.Notes,
			CreatedAt: r.CreatedAt,
		}
		if rt, ok := masterRuntimes[r.NodeID]; ok && !rt.LastSeen.IsZero() {
			ago := int64(now.Sub(rt.LastSeen).Seconds())
			s.LastSeenAgo = ago
			s.Online = ago <= offlineThresholdSec
			s.PublicAddr = rt.PublicAddr
			s.Version = rt.Version
			s.CPUPercent = rt.CPUPercent
			s.MemPercent = rt.MemPercent
			s.UptimeSec = rt.UptimeSec
			s.ActiveConns = rt.ActiveConns
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// SlaveOnlineEntry 同時帶上「在哪台 Slave」的線上連線快照。
type SlaveOnlineEntry struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	OnlineSnapshot
}

// AllOnline 給 Master UI 拉取「跨節點線上連線」清單。
func AllOnline() []SlaveOnlineEntry {
	records, _ := store.ListSlaves()
	nameMap := map[string]string{}
	for _, r := range records {
		nameMap[r.NodeID] = r.NodeName
	}

	masterMu.RLock()
	defer masterMu.RUnlock()
	var out []SlaveOnlineEntry
	now := time.Now().Unix()
	for id, rt := range masterRuntimes {
		if rt.LastSeen.IsZero() || now-rt.LastSeen.Unix() > offlineThresholdSec {
			continue
		}
		for _, o := range rt.Online {
			out = append(out, SlaveOnlineEntry{
				NodeID:         id,
				NodeName:       nameMap[id],
				OnlineSnapshot: o,
			})
		}
	}
	return out
}

// SlaveLogTail 取出指定 Slave 已收到的最近 log。
func SlaveLogTail(nodeID string, limit int) []LogEntry {
	masterMu.RLock()
	defer masterMu.RUnlock()
	rt, ok := masterRuntimes[nodeID]
	if !ok {
		return nil
	}
	if limit <= 0 || limit > len(rt.LogTail) {
		limit = len(rt.LogTail)
	}
	out := make([]LogEntry, limit)
	copy(out, rt.LogTail[len(rt.LogTail)-limit:])
	return out
}

// HandleHeartbeat 是 Master 對 /api/cluster/heartbeat 的 HTTP handler。
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body failed"})
		return
	}

	nodeID := r.Header.Get(HeaderNodeID)
	auth := r.Header.Get(HeaderAuthorization)
	sig := r.Header.Get(HeaderSignature)
	if nodeID == "" || auth == "" || sig == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing auth headers"})
		return
	}
	const bearer = "Bearer "
	if len(auth) <= len(bearer) || auth[:len(bearer)] != bearer {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid auth scheme"})
		return
	}
	token := auth[len(bearer):]

	rec, err := store.GetSlave(nodeID)
	if err != nil || rec.Token != token {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unknown node or token"})
		return
	}
	if !Verify(token, body, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
		return
	}

	var req HeartbeatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}

	// === 更新 runtime ===
	masterMu.Lock()
	rt := masterRuntimes[nodeID]
	if rt == nil {
		rt = &SlaveRuntime{NodeID: nodeID, PendingKicks: map[string]struct{}{}}
		masterRuntimes[nodeID] = rt
	}
	rt.NodeName = req.NodeName
	if rt.NodeName == "" {
		rt.NodeName = rec.NodeName
	}
	rt.LastSeen = time.Now()
	rt.PublicAddr = req.PublicAddr
	rt.Version = req.Version
	rt.CPUPercent = req.CPUPercent
	rt.MemPercent = req.MemPercent
	rt.UptimeSec = req.UptimeSec
	rt.ActiveConns = req.ActiveConns
	rt.Online = req.Online

	if len(req.LogTail) > 0 {
		rt.LogTail = append(rt.LogTail, req.LogTail...)
		if len(rt.LogTail) > maxLogTailPerSlave {
			rt.LogTail = rt.LogTail[len(rt.LogTail)-maxLogTailPerSlave:]
		}
	}

	for _, cid := range req.AckKick {
		delete(rt.PendingKicks, cid)
	}

	kicks := make([]string, 0, len(rt.PendingKicks))
	for cid := range rt.PendingKicks {
		kicks = append(kicks, cid)
	}
	masterMu.Unlock()

	// === 流量聚合 ===
	for user, d := range req.TrafficDelta {
		t := traffic.Get(user)
		traffic.AddSent(t, d.Sent)
		traffic.AddReceived(t, d.Received)
	}

	// === 組裝 response ===
	// Accounts:從 store 拉所有帳號,連 hash 一起送(Slave 端要拿 hash 寫回 SQLite)
	accountList, _ := store.ListAccounts()
	accounts := make(map[string]AccountSync, len(accountList))
	for _, a := range accountList {
		accounts[a.Username] = AccountSync{
			Username:     a.Username,
			PasswordHash: a.PasswordHash,
			Enabled:      a.Enabled,
			ExpiryDate:   a.ExpiryDate,
			LimitGB:      a.LimitGB,
			MaxSessions:  a.MaxSessions,
			FriendlyName: a.FriendlyName,
		}
	}

	cfg := config.Get()
	cfg.Lock.RLock()
	shared := &SharedSettings{
		HandshakeTimeout:            cfg.HandshakeTimeout,
		ConnectUA:                   cfg.ConnectUA,
		BufferSizeKB:                cfg.BufferSizeKB,
		IdleTimeoutSeconds:          cfg.IdleTimeoutSeconds,
		TolerantCopyMaxRetries:      cfg.TolerantCopyMaxRetries,
		TolerantCopyRetryDelayMs:    cfg.TolerantCopyRetryDelayMs,
		TargetConnectTimeoutSeconds: cfg.TargetConnectTimeoutSeconds,
		DefaultExpiryDays:           cfg.DefaultExpiryDays,
		DefaultLimitGB:              cfg.DefaultLimitGB,
		AllowedSNI:                  append([]string(nil), cfg.AllowedSNI...),
	}
	interval := cfg.HeartbeatIntervalSec
	cfg.Lock.RUnlock()
	if interval <= 0 {
		interval = 30
	}

	resp := HeartbeatResponse{
		ProtocolVersion: ProtocolVersion,
		ServerTime:      time.Now().Unix(),
		NextIntervalSec: interval,
		Accounts:        accounts,
		SharedSettings:  shared,
		KickConnIDs:     kicks,
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
