// Package traffic 集中管理使用者流量統計與持久化。
//
// 對外只暴露 Get(user) / Snapshot() / Save() / Load() 等簡單 API,
// 內部用 sync.Map 存放每個使用者的 *Info,並用 atomic 操作對單一使用者的
// Sent/Received 做無鎖累加。
package traffic

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Info 描述單一使用者的累積流量。
type Info struct {
	Sent     uint64 `json:"sent"`
	Received uint64 `json:"received"`
}

const filePath = "data/traffic.json"

var store sync.Map // username → *Info

// Get 取得(或建立)指定使用者的 Info pointer。
// 回傳的 pointer 內部欄位請務必用 atomic 操作。
func Get(username string) *Info {
	v, _ := store.LoadOrStore(username, &Info{})
	return v.(*Info)
}

// Lookup 嘗試取得指定使用者的 Info,若不存在回 nil。
func Lookup(username string) *Info {
	if v, ok := store.Load(username); ok {
		return v.(*Info)
	}
	return nil
}

// Range 遍歷所有 (username, *Info)。
func Range(fn func(username string, t *Info) bool) {
	store.Range(func(k, v interface{}) bool {
		return fn(k.(string), v.(*Info))
	})
}

// Reset 清空指定使用者的流量計數(後台用)。
func Reset(username string) bool {
	v, ok := store.Load(username)
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
	store.Range(func(k, v interface{}) bool {
		t := v.(*Info)
		out[k.(string)] = &Info{
			Sent:     atomic.LoadUint64(&t.Sent),
			Received: atomic.LoadUint64(&t.Received),
		}
		return true
	})
	return out
}

// Save 把 store 內容序列化寫盤。
func Save() error {
	data, err := json.MarshalIndent(Snapshot(), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal traffic data: %w", err)
	}
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write traffic data to file: %w", err)
	}
	log.Printf("System: Traffic data successfully saved to %s", filePath)
	return nil
}

// Load 啟動時讀回流量資料。
func Load() {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("System: Traffic data file (%s) not found, starting with empty records.", filePath)
			return
		}
		log.Printf("System: Error reading traffic data file: %v", err)
		return
	}
	var fromFile map[string]*Info
	if err := json.Unmarshal(data, &fromFile); err != nil {
		log.Printf("System: Error parsing traffic data file: %v", err)
		return
	}
	for u, info := range fromFile {
		store.Store(u, &Info{
			Sent:     atomic.LoadUint64(&info.Sent),
			Received: atomic.LoadUint64(&info.Received),
		})
	}
	log.Printf("System: Successfully loaded %d user traffic records from %s", len(fromFile), filePath)
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
