// master.go — Master 端叢集執行緒。
//
// 主要責任:
//   1. 維護 NodeID → *SlaveRuntime 的「即時狀態」記憶體表
//   2. 提供 HTTP handler 供 Slave 心跳呼叫
//   3. 將 Slave 回報的 traffic delta 累加進本機 traffic store
//      (使 Master 能看到全叢集聚合的使用者總流量)
//   4. 維護 per-slave 的踢除待辦佇列(由後台呼叫 RequestKick 加入)
//
// 持久化資料(node_id/token/name)放在 config.Slaves;runtime 狀態僅在記憶體。
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

	// LogTail 是來自此 Slave 的最近 log(由心跳累積,有上限以免吃記憶體)
	LogTail []LogEntry

	// PendingKicks 是 Master 待 Slave 處理的踢除指令(map 為了去重)
	PendingKicks map[string]struct{}

	// totalRcvSent / totalRcvRcvd 用來偵測 Slave 重啟回報異常增量(目前只記錄,未強制處理)
	totalRcvSent uint64
	totalRcvRcvd uint64
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

// AddSlave 在 config.Slaves 中註冊一個新的 Slave 節點,回傳產生的 SlaveRecord(包含新 token)。
func AddSlave(name, notes string) (config.SlaveRecord, error) {
	cfg := config.Get()
	cfg.Lock.Lock()
	if cfg.Slaves == nil {
		cfg.Slaves = make(map[string]config.SlaveRecord)
	}
	id := "node-" + GenerateToken()[:12]
	rec := config.SlaveRecord{
		NodeID:    id,
		NodeName:  name,
		Token:     GenerateToken(),
		CreatedAt: time.Now().Unix(),
		Notes:     notes,
	}
	cfg.Slaves[id] = rec
	cfg.Lock.Unlock()
	if err := config.Save(); err != nil {
		return config.SlaveRecord{}, err
	}
	return rec, nil
}

// RemoveSlave 從 config.Slaves 中移除一個節點,並丟棄其 runtime。
func RemoveSlave(nodeID string) error {
	cfg := config.Get()
	cfg.Lock.Lock()
	delete(cfg.Slaves, nodeID)
	cfg.Lock.Unlock()
	masterMu.Lock()
	delete(masterRuntimes, nodeID)
	masterMu.Unlock()
	return config.Save()
}

// RenameSlave 更新 Slave 的友善名稱。
func RenameSlave(nodeID, newName string) error {
	cfg := config.Get()
	cfg.Lock.Lock()
	rec, ok := cfg.Slaves[nodeID]
	if !ok {
		cfg.Lock.Unlock()
		return fmt.Errorf("node not found")
	}
	rec.NodeName = newName
	cfg.Slaves[nodeID] = rec
	cfg.Lock.Unlock()
	return config.Save()
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
	cfg := config.Get()
	cfg.Lock.RLock()
	records := make([]config.SlaveRecord, 0, len(cfg.Slaves))
	for _, v := range cfg.Slaves {
		records = append(records, v)
	}
	cfg.Lock.RUnlock()

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

// SlaveOnlineSnapshot 同時回傳所有 Slave 上的線上連線(展開為單一 list,each tagged with node)。
type SlaveOnlineEntry struct {
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name"`
	OnlineSnapshot
}

// AllOnline 給 Master UI 拉取「跨節點線上連線」清單。
func AllOnline() []SlaveOnlineEntry {
	cfg := config.Get()
	nameMap := map[string]string{}
	cfg.Lock.RLock()
	for id, r := range cfg.Slaves {
		nameMap[id] = r.NodeName
	}
	cfg.Lock.RUnlock()

	masterMu.RLock()
	defer masterMu.RUnlock()
	var out []SlaveOnlineEntry
	now := time.Now().Unix()
	for id, rt := range masterRuntimes {
		// 已離線太久就不展示
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
//
// 流程:
//   1. 讀 body(限制大小防 DoS)
//   2. 用 X-Cluster-Node-ID 找對應 token
//   3. 驗 Bearer + HMAC
//   4. 反序列化 → 更新 runtime → 累計 traffic
//   5. 組裝 response 回送
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// 1MB 上限,單一心跳不可能更大
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

	cfg := config.Get()
	cfg.Lock.RLock()
	rec, ok := cfg.Slaves[nodeID]
	cfg.Lock.RUnlock()
	if !ok || rec.Token != token {
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

	// 處理 ack 的踢除指令
	for _, cid := range req.AckKick {
		delete(rt.PendingKicks, cid)
	}

	// 收集要下發的 kick(複製出來,避免持鎖跨包邊界)
	kicks := make([]string, 0, len(rt.PendingKicks))
	for cid := range rt.PendingKicks {
		kicks = append(kicks, cid)
	}
	masterMu.Unlock()

	// === 流量聚合:把 Slave 增量累加到 Master 的 traffic store ===
	for user, d := range req.TrafficDelta {
		t := traffic.Get(user)
		traffic.AddSent(t, d.Sent)
		traffic.AddReceived(t, d.Received)
	}

	// === 組裝 response ===
	cfg.Lock.RLock()
	accounts := make(map[string]config.AccountInfo, len(cfg.Accounts))
	for u, a := range cfg.Accounts {
		accounts[u] = a
	}
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
