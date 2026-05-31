// Package cluster 定義 Master/Slaves 多機部署的共用型別與輔助函式。
//
// 通訊模型:Pull-mode — Slave 主動以 HTTPS POST 推送心跳到 Master,
// Master 在 response 中回送需要 Slave 套用的最新狀態(帳號、共享設定、踢除指令)。
//
// 認證:每個 Slave 在 Master 註冊時取得一組 token,後續 heartbeat 同時帶
//   - Authorization: Bearer <token>          (基本身份識別)
//   - X-Cluster-Signature: hex(HMAC-SHA256)  (防止 token 在傳輸中被竊聽後仿造)
//
// 此 package 不引用其他 internal package(僅依賴 stdlib + traffic 型別),
// 以避免任何 import 循環。
package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// 通訊協定版本,日後欄位變動時可用來做相容判斷。
const ProtocolVersion = 1

// HTTP header 名稱(避免重複硬編字串)。
const (
	HeaderAuthorization = "Authorization"
	HeaderSignature     = "X-Cluster-Signature"
	HeaderNodeID        = "X-Cluster-Node-ID"
)

// Role 表示本進程在叢集中的角色。
type Role string

const (
	RoleStandalone Role = "standalone" // 預設;單機模式,不啟用任何叢集邏輯
	RoleMaster     Role = "master"     // 集中管理者
	RoleSlave      Role = "slave"      // 工作節點,定期向 Master 心跳
)

// AccountSync 是叢集同步用的帳號封裝。
//
// 為何不直接用 store.Account?store.Account 的 PasswordHash 標 json:"-",
// 對外永不暴露(避免 admin API 不小心吐出來)。叢集同步需要把 hash 跨機傳遞,
// 所以這裡用一份「明確序列化 hash」的副本。傳輸通道靠 HTTPS + HMAC 保護。
type AccountSync struct {
	Username     string  `json:"username"`
	PasswordHash string  `json:"password_hash"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

// TrafficDelta 是一次心跳要回報的單一使用者流量增量。
//
// 採「增量」而非「累計值」是為了讓 Master 可以正確聚合多個 Slave 的同名帳號
// 而不會因為 Slave 重啟流量歸零造成 Master 端負成長。
type TrafficDelta struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

// OnlineSnapshot 是心跳中描述某條 Slave 上活躍連線的精簡資料。
type OnlineSnapshot struct {
	ConnID      string `json:"conn_id"`
	Username    string `json:"username"`
	RemoteAddr  string `json:"remote_addr"`
	ConnectTime int64  `json:"connect_time"` // unix sec
}

// LogEntry 對應 logging.Default.GetLogs() 的單筆記錄。
//
// 不直接 import logging 是為了避免循環依賴;對欄位的相容性由 logging side 保證。
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

// HeartbeatRequest 是 Slave → Master 的請求 body。
type HeartbeatRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	NodeID          string `json:"node_id"`
	NodeName        string `json:"node_name"`
	Version         string `json:"version,omitempty"` // wstunnel build version,可選

	// PublicAddr 是 Slave 自我聲明的「給使用者連的對外位址」,
	// 例如 "tunnel.example.com:443"。Master 會在 UI 顯示。
	PublicAddr string `json:"public_addr,omitempty"`

	// Stats:輕量資源指標,給 Master UI 用。
	CPUPercent  float64 `json:"cpu_percent,omitempty"`
	MemPercent  float64 `json:"mem_percent,omitempty"`
	UptimeSec   int64   `json:"uptime_sec,omitempty"`
	ActiveConns int     `json:"active_conns,omitempty"`

	// TrafficDelta:本次心跳週期內,各使用者的流量增量。
	TrafficDelta map[string]TrafficDelta `json:"traffic_delta,omitempty"`

	// Online:目前線上連線快照(完整覆寫 Master 端對此 NodeID 的快取)。
	Online []OnlineSnapshot `json:"online,omitempty"`

	// LogTail:自上次心跳以來新增的 log 行(可選,Master 可能限制大小)。
	LogTail []LogEntry `json:"log_tail,omitempty"`

	// AckKick:Slave 已成功踢除的 conn_id 列表,讓 Master 從待辦中移除。
	AckKick []string `json:"ack_kick,omitempty"`

	// SentAt:Slave 送出此 heartbeat 的 unix 時間,僅供 debug。
	SentAt int64 `json:"sent_at"`
}

// HeartbeatResponse 是 Master → Slave 回送的指令包。
//
// 採「整體覆蓋」(Accounts / SharedSettings)+「指令累加」(KickConnIDs)的混合策略:
//   - 帳號 / 共享設定:Slave 套用後完全等同於 Master 端
//   - 踢除指令:單向佇列,Slave ack 後從 Master 中移除
type HeartbeatResponse struct {
	ProtocolVersion int    `json:"protocol_version"`
	ServerTime      int64  `json:"server_time"`
	Message         string `json:"message,omitempty"`

	// NextIntervalSec:Master 建議下一次心跳間隔(秒)。Slave 應遵守,
	// 但 client 端會 clamp 到 [10, 300] 以防誤設造成失聯。
	NextIntervalSec int `json:"next_interval_sec,omitempty"`

	// Accounts:Master 上所有要下發到 Slave 的帳號 (nil 表示「不變動」)。
	// 注意是 nil 才是不變;空 map {} 表示「清空所有帳號」。
	Accounts map[string]AccountSync `json:"accounts,omitempty"`

	// SharedSettings:要下發的共用設定。同樣 nil = 不變。
	SharedSettings *SharedSettings `json:"shared_settings,omitempty"`

	// KickConnIDs:Master 要求 Slave 踢除的連線 id。Slave 處理後應在
	// 下一次心跳的 AckKick 中回報。
	KickConnIDs []string `json:"kick_conn_ids,omitempty"`
}

// SharedSettings 是 Master 會強制同步給 Slave 的設定子集。
//
// 為何只挑選子集而不直接同步整個 Config?
//   - ListenAddr / AdminAddr 等是「節點本機資源」,不應遠端覆寫
//   - AdminAccounts 是後台帳號,Slave 端應由維運人員獨立管理
//   - DNSServer / UDPGWPort 牽涉到節點所在網路環境,讓本機自管即可
//
// 這裡選的是「會直接影響使用者連線體驗」的那些,讓集中管理有意義。
type SharedSettings struct {
	HandshakeTimeout            int      `json:"handshake_timeout"`
	ConnectUA                   string   `json:"connect_ua"`
	BufferSizeKB                int      `json:"buffer_size_kb"`
	IdleTimeoutSeconds          int      `json:"idle_timeout_seconds"`
	TolerantCopyMaxRetries      int      `json:"tolerant_copy_max_retries"`
	TolerantCopyRetryDelayMs    int      `json:"tolerant_copy_retry_delay_ms"`
	TargetConnectTimeoutSeconds int      `json:"target_connect_timeout_seconds"`
	DefaultExpiryDays           int      `json:"default_expiry_days"`
	DefaultLimitGB              float64  `json:"default_limit_gb"`
	AllowedSNI                  []string `json:"allowed_sni"`
}

// Sign 用 token 對 body 計算 HMAC-SHA256,回傳 lower-case hex。
func Sign(token string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify 在 constant-time 下比對 signature 是否符合。
// 任一參數為空一律視為驗證失敗,避免「空 token + 空簽章」誤判通過。
func Verify(token string, body []byte, signature string) bool {
	if token == "" || signature == "" {
		return false
	}
	expected, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), expected)
}
