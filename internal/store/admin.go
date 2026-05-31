// admin.go — 後台 admin 帳號 CRUD。
package store

import (
	"database/sql"
	"errors"
	"time"
)

// ErrAdminNotFound 指定 admin 不存在。
var ErrAdminNotFound = errors.New("admin not found")

// VerifyAdminPassword 後台登入 callback。回傳 (username, ok)。
func VerifyAdminPassword(username, plain string) bool {
	var hash string
	err := db.QueryRow(`SELECT password_hash FROM admin_accounts WHERE username=?`, username).Scan(&hash)
	if err != nil {
		return false
	}
	return VerifyPassword(hash, plain)
}

// SetAdminPassword 建立或更新 admin 帳號密碼(plain 會被 hash)。
func SetAdminPassword(username, plain string) error {
	hash, err := HashPassword(plain)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO admin_accounts(username,password_hash,created_at,updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, updated_at=excluded.updated_at`,
		username, hash, now, now)
	return err
}

// SetAdminPasswordHash 直接寫已 hash 過的字串(遷移時用)。
// hash 必須已是 bcrypt 格式。
func SetAdminPasswordHash(username, hash string) error {
	if !IsBcryptHash(hash) {
		return errors.New("not a bcrypt hash")
	}
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT INTO admin_accounts(username,password_hash,created_at,updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, updated_at=excluded.updated_at`,
		username, hash, now, now)
	return err
}

// HasAnyAdmin 是否存在任何 admin 帳號。首次啟動會回 false。
func HasAnyAdmin() bool {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM admin_accounts`).Scan(&n); err == nil {
		return n > 0
	}
	return false
}

// VerifyAndUpdateAdminPassword 後台「修改密碼」流程:驗舊密碼 → 寫新 hash。
func VerifyAndUpdateAdminPassword(username, oldPlain, newPlain string) error {
	if !VerifyAdminPassword(username, oldPlain) {
		return errors.New("old password mismatch")
	}
	return SetAdminPassword(username, newPlain)
}

// AdminExists 帳號是否存在。
func AdminExists(username string) bool {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM admin_accounts WHERE username=?`, username).Scan(&n)
	return err == nil && n > 0
}

// _ 抑制未使用 import 警告(預留 sql 套件給其他 helper)
var _ = sql.ErrNoRows
