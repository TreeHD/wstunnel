// slave.go — Slave 端心跳客戶端。
//
// 啟動後背景執行 heartbeat loop:每 N 秒做一次 HTTP POST 到 Master,
// 並把 response 中的帳號 / 共用設定 / 踢除指令套用到本機。
package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"wstunnel/internal/config"
	"wstunnel/internal/logging"
	"wstunnel/internal/store"
	"wstunnel/internal/traffic"
)

// SlaveHooks 是 Slave runtime 需要從外部注入的 callback,
// 主要為了避免 cluster package 反向依賴 sshsrv / adminapi 造成 import 循環。
type SlaveHooks struct {
	// KickConnID 強制斷開指定 conn_id 的 SSH 連線。找不到該回 false(會記錄但不影響運作)。
	KickConnID func(connID string) bool

	// KickUsername 踢光指定 user 的所有活躍連線(帳號被刪除/停用時用)。
	KickUsername func(username string)

	// ListOnline 回傳目前活躍連線的快照,給 heartbeat 上報用。
	ListOnline func() []OnlineSnapshot

	// ApplySettings 把 Master 下發的 SharedSettings 套用到本機 config。
	ApplySettings func(s SharedSettings)
}

var hooks atomic.Value // SlaveHooks

// RegisterSlaveHooks 在啟動時注入 callback。可重入(後寫覆蓋前寫)。
func RegisterSlaveHooks(h SlaveHooks) { hooks.Store(h) }

func getHooks() SlaveHooks {
	if v := hooks.Load(); v != nil {
		return v.(SlaveHooks)
	}
	return SlaveHooks{}
}

// slaveState 維護心跳 loop 跨 iteration 需要記住的東西。
type slaveState struct {
	startTime    time.Time
	lastReported map[string]uint64 // key: "<user>:s" / "<user>:r" → 上次回報的累計值
	lastLogSeq   int64
}

// runOnce 計算自上次心跳到現在的流量增量(per-user)並更新 lastReported 為新基準。
func (s *slaveState) flushTrafficDelta() map[string]TrafficDelta {
	out := map[string]TrafficDelta{}
	traffic.Range(func(user string, t *traffic.Info) bool {
		curSent := traffic.LoadSent(t)
		curRcvd := traffic.LoadReceived(t)
		prevSent := s.lastReported[user+":s"]
		prevRcvd := s.lastReported[user+":r"]
		var d TrafficDelta
		if curSent > prevSent {
			d.Sent = curSent - prevSent
		}
		if curRcvd > prevRcvd {
			d.Received = curRcvd - prevRcvd
		}
		// 流量「倒退」(例如 traffic.Reset 被呼叫)就重設基準,不上報負量
		s.lastReported[user+":s"] = curSent
		s.lastReported[user+":r"] = curRcvd
		if d.Sent > 0 || d.Received > 0 {
			out[user] = d
		}
		return true
	})
	return out
}

// StartSlave 啟動 Slave 的心跳 goroutine,呼叫一次即可。
//
// 沒有設好 MasterURL / NodeID / MasterToken 會立刻記錄錯誤後退出,不阻塞主流程。
func StartSlave(wg *sync.WaitGroup) {
	cfg := config.Get()
	cfg.Lock.RLock()
	masterURL := cfg.MasterURL
	token := cfg.MasterToken
	nodeID := cfg.NodeID
	skipVerify := cfg.SkipMasterTLSVerify
	cfg.Lock.RUnlock()

	if masterURL == "" || token == "" || nodeID == "" {
		log.Printf("Cluster: Slave mode enabled but master_url/master_token/node_id incomplete; staying offline")
		return
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, //#nosec G402 — 自簽憑證情境的 escape hatch
		},
	}

	state := &slaveState{
		startTime:    time.Now(),
		lastReported: map[string]uint64{},
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Cluster: Slave loop started, will heartbeat to %s as %s", masterURL, nodeID)
		// 第一次心跳延遲 3s 等其他子系統就緒
		time.Sleep(3 * time.Second)

		for {
			interval := slaveHeartbeatOnce(httpClient, masterURL, token, nodeID, state)
			if interval < 10 {
				interval = 10
			} else if interval > 300 {
				interval = 300
			}
			time.Sleep(time.Duration(interval) * time.Second)
		}
	}()
}

// slaveHeartbeatOnce 執行一次心跳,回傳下次 sleep 的秒數(由 Master 建議或預設值)。
func slaveHeartbeatOnce(client *http.Client, masterURL, token, nodeID string, state *slaveState) int {
	cfg := config.Get()
	cfg.Lock.RLock()
	nodeName := cfg.NodeName
	publicAddr := cfg.PublicAddr
	defaultInterval := cfg.HeartbeatIntervalSec
	cfg.Lock.RUnlock()
	if defaultInterval <= 0 {
		defaultInterval = 30
	}

	// 收集 stats(失敗就送 0,不阻塞)
	var cpuPct, memPct float64
	if vs, err := cpu.Percent(0, false); err == nil && len(vs) > 0 {
		cpuPct = vs[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		memPct = vm.UsedPercent
	}

	h := getHooks()
	var online []OnlineSnapshot
	if h.ListOnline != nil {
		online = h.ListOnline()
	}

	// log tail(自上次以來新增)
	var logTail []LogEntry
	rawLines, nextSeq := logging.Default.GetLogsSince(state.lastLogSeq)
	state.lastLogSeq = nextSeq
	if len(rawLines) > 0 {
		// 心跳 log 上限,避免單包過大
		if len(rawLines) > 200 {
			rawLines = rawLines[len(rawLines)-200:]
		}
		logTail = make([]LogEntry, 0, len(rawLines))
		for _, line := range rawLines {
			line = strings.TrimRight(line, "\n")
			ts, msg := splitLogLine(line)
			logTail = append(logTail, LogEntry{Timestamp: ts, Message: msg})
		}
	}

	req := HeartbeatRequest{
		ProtocolVersion: ProtocolVersion,
		NodeID:          nodeID,
		NodeName:        nodeName,
		PublicAddr:      publicAddr,
		CPUPercent:      cpuPct,
		MemPercent:      memPct,
		UptimeSec:       int64(time.Since(state.startTime).Seconds()),
		ActiveConns:     len(online),
		TrafficDelta:    state.flushTrafficDelta(),
		Online:          online,
		LogTail:         logTail,
		AckKick:         drainAckKicks(),
		SentAt:          time.Now().Unix(),
	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Printf("Cluster: heartbeat marshal failed: %v", err)
		return defaultInterval
	}

	endpoint := strings.TrimRight(masterURL, "/") + "/api/cluster/heartbeat"
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		log.Printf("Cluster: heartbeat new request failed: %v", err)
		return defaultInterval
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(HeaderAuthorization, "Bearer "+token)
	httpReq.Header.Set(HeaderSignature, Sign(token, body))
	httpReq.Header.Set(HeaderNodeID, nodeID)

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Cluster: heartbeat to master failed: %v", err)
		// 發送失敗 → 把 traffic 增量還原回去,避免下一次心跳漏報
		rollbackTraffic(state, req.TrafficDelta)
		return defaultInterval
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		log.Printf("Cluster: heartbeat got status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		rollbackTraffic(state, req.TrafficDelta)
		return defaultInterval
	}

	var hresp HeartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hresp); err != nil {
		log.Printf("Cluster: heartbeat decode response failed: %v", err)
		return defaultInterval
	}

	applyHeartbeatResponse(&hresp)

	if hresp.NextIntervalSec > 0 {
		return hresp.NextIntervalSec
	}
	return defaultInterval
}

// rollbackTraffic 在心跳失敗時把 lastReported 退回上一輪,以便下次能重新累積。
func rollbackTraffic(state *slaveState, delta map[string]TrafficDelta) {
	for user, d := range delta {
		state.lastReported[user+":s"] -= d.Sent
		state.lastReported[user+":r"] -= d.Received
	}
}

// applyHeartbeatResponse 套用 Master 下發的內容。
func applyHeartbeatResponse(resp *HeartbeatResponse) {
	cfg := config.Get()
	dirty := false

	// 帳號:nil = 不變;非 nil 即整批覆蓋(逐筆 upsert,並把 hash 直接寫進去)
	if resp.Accounts != nil {
		// 找出本地有但 Master 沒下發的帳號 → delete
		existing, _ := store.ListAccounts()
		killUsers := map[string]struct{}{}
		for _, old := range existing {
			newAcc, stillExists := resp.Accounts[old.Username]
			if !stillExists {
				killUsers[old.Username] = struct{}{}
				_ = store.DeleteAccount(old.Username)
				continue
			}
			if old.Enabled && !newAcc.Enabled {
				killUsers[old.Username] = struct{}{}
			}
		}
		// 寫入 / 更新 Master 下發的帳號(密碼 hash 直接帶進去,不重新 hash)
		for _, a := range resp.Accounts {
			acc := store.Account{
				Username:     a.Username,
				PasswordHash: a.PasswordHash,
				Enabled:      a.Enabled,
				ExpiryDate:   a.ExpiryDate,
				LimitGB:      a.LimitGB,
				MaxSessions:  a.MaxSessions,
				FriendlyName: a.FriendlyName,
			}
			// 傳空 newPlain → UpsertAccount 會用 acc.PasswordHash 寫進去
			if err := store.UpsertAccount(acc, ""); err != nil {
				log.Printf("Cluster: apply account %s failed: %v", a.Username, err)
			}
		}
		// 踢除被刪/被停用的帳號
		if h := getHooks(); h.KickUsername != nil {
			for u := range killUsers {
				h.KickUsername(u)
			}
		}
	}

	// 共用設定
	if resp.SharedSettings != nil {
		cfg.Lock.Lock()
		cfg.HandshakeTimeout = resp.SharedSettings.HandshakeTimeout
		cfg.ConnectUA = resp.SharedSettings.ConnectUA
		cfg.BufferSizeKB = resp.SharedSettings.BufferSizeKB
		cfg.IdleTimeoutSeconds = resp.SharedSettings.IdleTimeoutSeconds
		cfg.TolerantCopyMaxRetries = resp.SharedSettings.TolerantCopyMaxRetries
		cfg.TolerantCopyRetryDelayMs = resp.SharedSettings.TolerantCopyRetryDelayMs
		cfg.TargetConnectTimeoutSeconds = resp.SharedSettings.TargetConnectTimeoutSeconds
		cfg.DefaultExpiryDays = resp.SharedSettings.DefaultExpiryDays
		cfg.DefaultLimitGB = resp.SharedSettings.DefaultLimitGB
		cfg.AllowedSNI = append([]string(nil), resp.SharedSettings.AllowedSNI...)
		cfg.Lock.Unlock()
		dirty = true

		if h := getHooks(); h.ApplySettings != nil {
			h.ApplySettings(*resp.SharedSettings)
		}
	}

	if dirty {
		if err := config.Save(); err != nil {
			log.Printf("Cluster: save config after heartbeat failed: %v", err)
		}
	}

	// 處理踢除指令
	if len(resp.KickConnIDs) > 0 {
		h := getHooks()
		if h.KickConnID == nil {
			log.Printf("Cluster: received %d kick(s) but no hook installed", len(resp.KickConnIDs))
			return
		}
		for _, cid := range resp.KickConnIDs {
			h.KickConnID(cid)
			recordAckKick(cid)
		}
	}
}

// === Ack-Kick 累積佇列 ===
//
// Slave 處理完踢除指令後不能立即回傳,因為 response 已經寫出。
// 改放進佇列,下一次心跳的 AckKick 一起送過去。
var (
	ackKickMu    sync.Mutex
	ackKickQueue []string
)

func recordAckKick(connID string) {
	ackKickMu.Lock()
	ackKickQueue = append(ackKickQueue, connID)
	ackKickMu.Unlock()
}

func drainAckKicks() []string {
	ackKickMu.Lock()
	defer ackKickMu.Unlock()
	if len(ackKickQueue) == 0 {
		return nil
	}
	out := ackKickQueue
	ackKickQueue = nil
	return out
}

// splitLogLine 從 Collector 寫入的格式 "YYYY/MM/DD HH:MM:SS message" 拆出 ts / msg。
// 拆失敗就把整行當 message。
func splitLogLine(line string) (ts, msg string) {
	const tsLen = len("2006/01/02 15:04:05 ")
	if len(line) > tsLen && line[4] == '/' && line[7] == '/' && line[13] == ':' {
		return line[:tsLen-1], line[tsLen:]
	}
	return "", line
}

// HasValidConfig 給 main 啟動前快速檢查 Slave config 是否完整。
func HasValidConfig() error {
	cfg := config.Get()
	cfg.Lock.RLock()
	defer cfg.Lock.RUnlock()
	switch {
	case cfg.MasterURL == "":
		return fmt.Errorf("master_url not set")
	case cfg.MasterToken == "":
		return fmt.Errorf("master_token not set")
	case cfg.NodeID == "":
		return fmt.Errorf("node_id not set")
	}
	return nil
}
