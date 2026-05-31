// accounts.go — 帳號 CRUD。
//
// SSH 使用者密碼一律走 bcrypt。Account.PasswordHash 不會在 list/get 中暴露給呼叫者
// (回傳 struct 仍然包含,但 admin API 必須過濾)。
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Account 是 store 對外暴露的帳號資料結構。
// PasswordHash 永遠是 bcrypt 字串,不會是明文。
type Account struct {
	Username     string  `json:"username"`
	PasswordHash string  `json:"-"` // 永不序列化
	Enabled      bool    `json:"enabled"`
	ExpiryDate   string  `json:"expiry_date"`
	LimitGB      float64 `json:"limit_gb"`
	MaxSessions  int     `json:"max_sessions"`
	FriendlyName string  `json:"friendly_name"`
}

// ErrAccountNotFound 指定使用者不存在。
var ErrAccountNotFound = errors.New("account not found")

// GetAccount 依 username 查單筆帳號。找不到回 ErrAccountNotFound。
func GetAccount(username string) (Account, error) {
	var a Account
	var enabled int
	err := db.QueryRow(`SELECT username, password_hash, enabled, expiry_date, limit_gb, max_sessions, friendly_name
		FROM accounts WHERE username=?`, username).
		Scan(&a.Username, &a.PasswordHash, &enabled, &a.ExpiryDate, &a.LimitGB, &a.MaxSessions, &a.FriendlyName)
	if err == sql.ErrNoRows {
		return Account{}, ErrAccountNotFound
	}
	if err != nil {
		return Account{}, err
	}
	a.Enabled = enabled != 0
	return a, nil
}

// ListAccounts 回傳所有帳號。
func ListAccounts() ([]Account, error) {
	rows, err := db.Query(`SELECT username, password_hash, enabled, expiry_date, limit_gb, max_sessions, friendly_name
		FROM accounts ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		var a Account
		var enabled int
		if err := rows.Scan(&a.Username, &a.PasswordHash, &enabled, &a.ExpiryDate, &a.LimitGB, &a.MaxSessions, &a.FriendlyName); err != nil {
			return nil, err
		}
		a.Enabled = enabled != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpsertAccount 寫入或更新帳號。
//
// 若 newPlain != "" 會 hash 後覆蓋密碼;若為空字串則保留原密碼(編輯帳號時很常用)。
// 新建帳號(原本不存在)且 newPlain 為空時回錯誤,因為沒密碼無法登入。
func UpsertAccount(a Account, newPlain string) error {
	now := time.Now().Unix()
	existing, err := GetAccount(a.Username)
	isUpdate := err == nil
	if err != nil && !errors.Is(err, ErrAccountNotFound) {
		return err
	}

	hash := a.PasswordHash
	switch {
	case newPlain != "":
		h, err := HashPassword(newPlain)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}
		hash = h
	case isUpdate && hash == "":
		hash = existing.PasswordHash
	case !isUpdate && hash == "":
		return fmt.Errorf("new account requires password")
	}

	enabled := 0
	if a.Enabled {
		enabled = 1
	}
	createdAt := now
	if isUpdate {
		// 保留原 created_at
		var ct int64
		if e := db.QueryRow(`SELECT created_at FROM accounts WHERE username=?`, a.Username).Scan(&ct); e == nil {
			createdAt = ct
		}
	}
	_, err = db.Exec(`INSERT INTO accounts(username, password_hash, enabled, expiry_date, limit_gb, max_sessions, friendly_name, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET
			password_hash=excluded.password_hash,
			enabled=excluded.enabled,
			expiry_date=excluded.expiry_date,
			limit_gb=excluded.limit_gb,
			max_sessions=excluded.max_sessions,
			friendly_name=excluded.friendly_name,
			updated_at=excluded.updated_at`,
		a.Username, hash, enabled, a.ExpiryDate, a.LimitGB, a.MaxSessions, a.FriendlyName, createdAt, now)
	return err
}

// SetAccountEnabled 開關啟用狀態(後台封禁/解封用)。
func SetAccountEnabled(username string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	res, err := db.Exec(`UPDATE accounts SET enabled=?, updated_at=? WHERE username=?`, v, time.Now().Unix(), username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAccountNotFound
	}
	return nil
}

// DeleteAccount 移除帳號(traffic 記錄保留以利稽核)。
func DeleteAccount(username string) error {
	_, err := db.Exec(`DELETE FROM accounts WHERE username=?`, username)
	return err
}

// VerifyAccountPassword 用於 SSH passwordCallback。
// 回傳 (account, ok)。失敗一律 ok=false,不細分原因。
func VerifyAccountPassword(username, plain string) (Account, bool) {
	a, err := GetAccount(username)
	if err != nil {
		return Account{}, false
	}
	if !a.Enabled {
		return Account{}, false
	}
	if !VerifyPassword(a.PasswordHash, plain) {
		return Account{}, false
	}
	return a, true
}
