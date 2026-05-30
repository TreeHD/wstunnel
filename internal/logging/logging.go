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
}

// NewCollector 建立一個容量為 maxCap 的 Collector。
func NewCollector(maxCap int) *Collector {
	return &Collector{maxCap: maxCap}
}

func (lc *Collector) Write(p []byte) (n int, err error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	logLine := time.Now().Format("2006/01/02 15:04:05 ") + string(p)
	lc.logs = append(lc.logs, logLine)
	if len(lc.logs) > lc.maxCap {
		lc.logs = lc.logs[len(lc.logs)-lc.maxCap:]
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
