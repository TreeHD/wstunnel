// Package logging 提供集中化的 log 收集與降噪輔助。
//
// Collector 把最近 N 行 log 留在記憶體供後台 /api/logs 查看,
// 同時 mirror 到 stderr 給 docker logs 用。
//
// IsBenign 判斷錯誤是否為「客戶端正常斷線」的雜訊,讓上層邏輯可以
// 靜默處理避免洗版。
package logging

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Collector 是一個 io.Writer,把每行 log 同時寫到記憶體環狀緩衝與 stderr。
type Collector struct {
	mu     sync.RWMutex
	logs   []string
	maxCap int
	// nextSeq 是下一行寫入時要分配的序號(從 1 開始)。
	// 配合 baseSeq 可推算「目前緩衝中第 i 個 log 的全域序號」。
	nextSeq  int64
	baseSeq  int64 // 緩衝中第 0 個 log 對應的全域序號
}

// NewCollector 建立一個容量為 maxCap 的 Collector。
func NewCollector(maxCap int) *Collector {
	return &Collector{maxCap: maxCap, nextSeq: 1, baseSeq: 1}
}

func (lc *Collector) Write(p []byte) (n int, err error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	logLine := time.Now().Format("2006/01/02 15:04:05 ") + string(p)
	lc.logs = append(lc.logs, logLine)
	lc.nextSeq++
	if len(lc.logs) > lc.maxCap {
		drop := len(lc.logs) - lc.maxCap
		lc.logs = lc.logs[drop:]
		lc.baseSeq += int64(drop)
	}
	fmt.Fprint(os.Stderr, logLine)
	return len(p), nil
}

// GetLogs 回傳目前緩衝中所有 log 的副本。
func (lc *Collector) GetLogs() []string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	out := make([]string, len(lc.logs))
	copy(out, lc.logs)
	return out
}

// GetLogsSince 取得序號 >= sinceSeq 的 log,並回傳下次該用的 sinceSeq。
//
// 用法(Slave heartbeat):
//	lines, next := logging.Default.GetLogsSince(state.lastLogSeq)
//	state.lastLogSeq = next
//
// 注意:若 sinceSeq 早於目前緩衝最舊那筆,會自動 catch-up 到緩衝起點(漏掉的 log
// 視為丟失,不影響 cursor 推進),避免 Slave 重啟後第一次 sync 把 200 行老 log 全送過去。
// 傳 0 視為「從目前最新開始」(初次心跳)。
func (lc *Collector) GetLogsSince(sinceSeq int64) (lines []string, nextSeq int64) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	if sinceSeq <= 0 {
		return nil, lc.nextSeq
	}
	if sinceSeq < lc.baseSeq {
		sinceSeq = lc.baseSeq
	}
	startIdx := int(sinceSeq - lc.baseSeq)
	if startIdx >= len(lc.logs) {
		return nil, lc.nextSeq
	}
	out := make([]string, len(lc.logs)-startIdx)
	copy(out, lc.logs[startIdx:])
	return out, lc.nextSeq
}

// Default 是程式全域共用的 Collector,容量 200 行。
var Default = NewCollector(200)

// DebugEnabled 由 WSTUNNEL_DEBUG=1 開啟詳細 log。
var DebugEnabled = os.Getenv("WSTUNNEL_DEBUG") == "1"

// IsBenign 判斷錯誤是否為「客戶端正常斷線」這類無動作意義的雜訊。
// 例如:io.EOF、connection reset by peer、broken pipe、use of closed network connection、i/o timeout。
// 這類錯誤在 mobile VPN 場景頻率極高,印出來只會洗版。
func IsBenign(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection reset by peer"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "use of closed network connection"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "EOF"):
		return true
	}
	return false
}

// RandomPassword 產生 base64 編碼後截斷至指定長度的隨機字串,用於 admin 預設密碼。
func RandomPassword(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	pw := base64.URLEncoding.EncodeToString(bytes)
	if len(pw) > length {
		pw = pw[:length]
	}
	return pw
}
