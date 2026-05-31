// migrate.go — 從舊版 data/config.json(包含 accounts / admin_accounts / slaves 欄位)
// 匯入到 SQLite。冪等:已遷移過會 no-op。
//
// 觸發時機:main 啟動時,在 store.Init() 之後、其他子系統開始之前。
//
// 行為:
//   1. 讀 data/config.json 的 raw bytes,反序列化進臨時 struct(legacy schema)
//   2. 若有 accounts → bcrypt-hash 密碼後 UpsertAccount
//   3. 若有 admin_accounts → bcrypt-hash 後 SetAdminPassword
//   4. 若有 slaves → UpsertSlave
//   5. 把 config.json 改寫成新 schema(僅系統設定),原檔備份成 .pre-sqlite.bak
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"wstunnel/internal/logging"
	"wstunnel/internal/store"
)

// legacyAccountInfo 完整對應舊版 AccountInfo,僅作 unmarshal 用。
type legacyAccountInfo struct {
	Password     string  `json:"password"`
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

type legacySlave struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
	Notes     string `json:"notes"`
}

type legacyShape struct {
	Accounts      map[string]legacyAccountInfo `json:"accounts"`
	AdminAccounts map[string]string            `json:"admin_accounts"`
	Slaves        map[string]legacySlave       `json:"slaves"`
}

// MigrateFromLegacy 在 store 已 Init 後呼叫。回傳 nil 表示成功(可能是 no-op)。
func MigrateFromLegacy() error {
	raw, err := ioutil.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // 沒有舊檔可遷移
		}
		return fmt.Errorf("read legacy config: %w", err)
	}
	var legacy legacyShape
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return fmt.Errorf("parse legacy config: %w", err)
	}

	hasLegacyData := len(legacy.Accounts) > 0 || len(legacy.AdminAccounts) > 0 || len(legacy.Slaves) > 0
	if !hasLegacyData {
		return nil
	}

	log.Println("==================================================")
	log.Printf("System: Migrating legacy config.json → SQLite (%d accounts, %d admins, %d slaves)",
		len(legacy.Accounts), len(legacy.AdminAccounts), len(legacy.Slaves))

	for username, a := range legacy.Accounts {
		acc := store.Account{
			Username:     username,
			Enabled:      a.Enabled,
			ExpiryDate:   a.ExpiryDate,
			LimitGB:      a.LimitGB,
			MaxSessions:  a.MaxSessions,
			FriendlyName: a.FriendlyName,
		}
		// 舊版的 password 是明文,UpsertAccount 會 bcrypt-hash
		if err := store.UpsertAccount(acc, a.Password); err != nil {
			return fmt.Errorf("migrate account %s: %w", username, err)
		}
	}
	for adminUser, plain := range legacy.AdminAccounts {
		// 已經存在(同 schema 內)時也覆寫一次,確保密碼被 bcrypt 化
		if err := store.SetAdminPassword(adminUser, plain); err != nil {
			return fmt.Errorf("migrate admin %s: %w", adminUser, err)
		}
	}
	for _, s := range legacy.Slaves {
		rec := store.SlaveRecord{
			NodeID:    s.NodeID,
			NodeName:  s.NodeName,
			Token:     s.Token,
			Notes:     s.Notes,
			CreatedAt: s.CreatedAt,
		}
		if err := store.UpsertSlave(rec); err != nil {
			return fmt.Errorf("migrate slave %s: %w", s.NodeID, err)
		}
	}

	// 備份原檔再改寫
	backup := filePath + ".pre-sqlite.bak"
	if err := ioutil.WriteFile(backup, raw, 0o600); err != nil {
		log.Printf("System: Warning - failed to write %s: %v", backup, err)
	} else {
		log.Printf("System: Backed up legacy config to %s (mode 0600)", backup)
	}

	// 重新 marshal 一次目前 in-memory config(已不含 legacy 欄位),覆蓋掉舊檔
	if err := Save(); err != nil {
		return fmt.Errorf("rewrite config.json: %w", err)
	}
	log.Printf("System: Migration complete. config.json rewritten without account fields.")
	log.Println("==================================================")
	return nil
}

// EnsureDefaultAdmin 若 SQLite 內完全沒有 admin 帳號,自動產生一組隨機密碼的 admin。
//
// 取代舊版在 buildFromEnv 裡偷塞 admin_accounts 的邏輯。
func EnsureDefaultAdmin() {
	if store.HasAnyAdmin() {
		return
	}
	pass := logging.RandomPassword(16)
	if err := store.SetAdminPassword("admin", pass); err != nil {
		log.Printf("System: Warning - failed to create default admin: %v", err)
		return
	}
	log.Println("==================================================")
	log.Println("  [重要] 首次啟動,已自動產生管理員帳號")
	log.Printf("  帳號: admin")
	log.Printf("  密碼: %s", pass)
	log.Println("  請儘速登入後台修改密碼!")
	log.Println("==================================================")
}
