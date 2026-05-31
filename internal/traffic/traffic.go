// Package traffic 集中管理使用者流量統計與持久化。
//
// 對外只暴露 Get(user) / Snapshot() / Save() / Load() 等簡單 API,
// 內部用 sync.Map 存放每個使用者的 *Info,並用 atomic 操作對單一使用者的
// Sent/Received 做無鎖累加。
//
// 持久化:走 internal/store 的 SQLite。Save() 是 batch upsert,
// 啟動時 Load() 會把所有 row 拉進記憶體 cache。
package traffic

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"wstunnel/internal/store"
)

// Info 描述單一使用者的累積流量。
type Info struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

var store_ sync.Map // username → *Info

// Get 取得(或建立)指定使用者的 Info pointer。
// 回傳的 pointer 內部欄位請務必用 atomic 操作。
func Get(username string) *Info {
	v, _ := store_.LoadOrStore(username, &Info{})
	return v.(*Info)
}

// Lookup 嘗試取得指定使用者的 Info,若不存在回 nil。
func Lookup(username string) *Info {
	if v, ok := store_.Load(username); ok {
		return v.(*Info)
	}
	return nil
}

// Range 遍歷所有 (username, *Info)。
func Range(fn func(username string, t *Info) bool) {
	store_.Range(func(k, v interface{}) bool {
		return fn(k.(string), v.(*Info))
	})
}

// Reset 清空指定使用者的流量計數(後台用)。
func Reset(username string) bool {
	v, ok := store_.Load(username)
	if !ok {
		return false
	}
	t := v.(*Info)
	atomic.StoreUint64(&t.Sent, 0)
	atomic.StoreUint64(&t.Received, 0)
	return true
}

// AddSent / AddReceived 給轉發層 atomic 累加用。
func AddSent(t *Info, n uint64)     { atomic.AddUint64(&t.Sent, n) }
func AddReceived(t *Info, n uint64) { atomic.AddUint64(&t.Received, n) }

// LoadSent / LoadReceived 給統計用。
func LoadSent(t *Info) uint64     { return atomic.LoadUint64(&t.Sent) }
func LoadReceived(t *Info) uint64 { return atomic.LoadUint64(&t.Received) }

// Snapshot 回傳目前所有使用者流量的拷貝(用於後台 /api/traffic)。
func Snapshot() map[string]*Info {
	out := make(map[string]*Info)
	store_.Range(func(k, v interface{}) bool {
		t := v.(*Info)
		out[k.(string)] = &Info{
			Sent:     atomic.LoadUint64(&t.Sent),
			Received: atomic.LoadUint64(&t.Received),
		}
		return true
	})
	return out
}

// Save 把當前記憶體快照 batch upsert 到 SQLite。
// 用單一 transaction,避免 N row 各觸發一次 fsync。
func Save() error {
	db := store.DB()
	if db == nil {
		return fmt.Errorf("store not initialized")
	}
	snap := Snapshot()
	if len(snap) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO traffic(username,sent,received,updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET
			sent=excluded.sent,
			received=excluded.received,
			updated_at=excluded.updated_at`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for u, t := range snap {
		if _, err := stmt.Exec(u, t.Sent, t.Received, now); err != nil {
			tx.Rollback()
			return fmt.Errorf("upsert %s: %w", u, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	log.Printf("System: Traffic data saved (%d users)", len(snap))
	return nil
}

// Load 從 SQLite 讀回所有 user traffic 進記憶體 cache。
func Load() {
	db := store.DB()
	if db == nil {
		log.Printf("System: Traffic load skipped (store not initialized)")
		return
	}
	rows, err := db.Query(`SELECT username,sent,received FROM traffic`)
	if err != nil {
		log.Printf("System: Failed to load traffic: %v", err)
		return
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var u string
		var s, r uint64
		if err := rows.Scan(&u, &s, &r); err != nil {
			log.Printf("System: Traffic row scan error: %v", err)
			continue
		}
		store_.Store(u, &Info{Sent: s, Received: r})
		n++
	}
	log.Printf("System: Loaded %d user traffic records from SQLite", n)
}

// StartPeriodicSaver 啟動背景常式定期存盤。
// intervalSec=0 視為 default 300。
func StartPeriodicSaver(intervalSec int, wg *sync.WaitGroup) {
	if intervalSec <= 0 {
		intervalSec = 300
	}
	d := time.Duration(intervalSec) * time.Second
	log.Printf("System: Traffic data will be saved every %v.", d)
	go func() {
		ticker := time.NewTicker(d)
		defer ticker.Stop()
		for range ticker.C {
			if err := Save(); err != nil {
				log.Printf("System: Error during periodic traffic data save: %v", err)
			}
		}
	}()
}
