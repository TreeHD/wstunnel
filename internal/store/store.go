// Package store 是 wstunnel 的 SQLite 儲存層。
//
// 設計原則:
//   - 走 modernc.org/sqlite,純 Go 實作,維持 CGO_ENABLED=0
//   - 全域 singleton:Init() 在 main 啟動時呼叫一次,後續用 DB() 拿 *sql.DB
//   - 寫入採 WAL + busy_timeout,並發友善
//   - 帳號 / 管理員 / Slaves 走「直讀」(規模小且呼叫頻率低)
//   - traffic 走「記憶體 cache + 定期 batch upsert」(高頻寫入)
//
// schema migration:meta 表記錄 schema_version,Init() 會自動套用所有未執行的 migration。
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

const (
	defaultDBPath = "data/wstunnel.db"
)

var (
	db     *sql.DB
	dbOnce sync.Once
	dbErr  error
)

// Init 開啟(必要時建立)SQLite 檔並套用 migration。多次呼叫只執行一次。
func Init() error {
	dbOnce.Do(func() {
		path := defaultDBPath
		if v := os.Getenv("WSTUNNEL_DB_PATH"); v != "" {
			path = v
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			dbErr = fmt.Errorf("mkdir for db: %w", err)
			return
		}
		// _pragma 在 modernc.org/sqlite 是用 query string 語法傳入
		dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
		conn, err := sql.Open("sqlite", dsn)
		if err != nil {
			dbErr = fmt.Errorf("open sqlite: %w", err)
			return
		}
		// modernc 內部不用 connection pool 也能跑得很好,但保守限制一下並發寫入
		conn.SetMaxOpenConns(8)
		if err := conn.Ping(); err != nil {
			dbErr = fmt.Errorf("ping sqlite: %w", err)
			return
		}
		db = conn
		if err := migrate(); err != nil {
			dbErr = fmt.Errorf("migrate: %w", err)
			return
		}
		log.Printf("Store: SQLite ready at %s", path)
	})
	return dbErr
}

// DB 取得已初始化的 *sql.DB,主要供 traffic / cluster 等高耦合寫入用。
// 一般 CRUD 請走本 package 提供的 helper。
func DB() *sql.DB { return db }

// Close 關閉 DB 連線(主要給 graceful shutdown 用)。
func Close() error {
	if db == nil {
		return nil
	}
	return db.Close()
}

// migrate 套用所有未執行的 schema 變更。
//
// 新增 schema 時請 append 到 migrations,不要修改既有 entry。
func migrate() error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create meta: %w", err)
	}

	var current int
	err := db.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'`).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read schema_version: %w", err)
	}

	for i, sqlStmt := range migrations {
		ver := i + 1
		if ver <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", ver, err)
		}
		if _, err := tx.Exec(sqlStmt); err != nil {
			tx.Rollback()
			return fmt.Errorf("apply migration %d: %w", ver, err)
		}
		if _, err := tx.Exec(
			`INSERT INTO meta(key,value) VALUES('schema_version',?)
			 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			fmt.Sprintf("%d", ver),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("bump schema_version to %d: %w", ver, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", ver, err)
		}
		log.Printf("Store: applied migration %d", ver)
	}
	return nil
}

// migrations 是有順序的 schema 變更清單。永遠 append,絕不修改舊條目。
var migrations = []string{
	// v1 — 初始 schema
	`
	CREATE TABLE accounts (
		username      TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		enabled       INTEGER NOT NULL DEFAULT 1,
		expiry_date   TEXT NOT NULL DEFAULT '',
		limit_gb      REAL NOT NULL DEFAULT 0,
		max_sessions  INTEGER NOT NULL DEFAULT 1,
		friendly_name TEXT NOT NULL DEFAULT '',
		created_at    INTEGER NOT NULL,
		updated_at    INTEGER NOT NULL
	);
	CREATE TABLE admin_accounts (
		username      TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at    INTEGER NOT NULL,
		updated_at    INTEGER NOT NULL
	);
	CREATE TABLE traffic (
		username    TEXT PRIMARY KEY,
		sent        INTEGER NOT NULL DEFAULT 0,
		received    INTEGER NOT NULL DEFAULT 0,
		updated_at  INTEGER NOT NULL
	);
	CREATE TABLE slaves (
		node_id    TEXT PRIMARY KEY,
		node_name  TEXT NOT NULL,
		token      TEXT NOT NULL,
		notes      TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL
	);
	`,
}
