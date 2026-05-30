// logging.go — 系統 log 收集器與降噪輔助
//
// 職責：
//   * LogCollector 把最近 N 行 log 留在記憶體供後台查看
//   * isBenignNetError 過濾正常斷線的雜訊(RST/EOF/broken pipe ...)
//   * debugLog 環境變數控制的詳細 log
package main

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

type LogCollector struct {
	mu     sync.RWMutex
	logs   []string
	maxCap int
}

func (lc *LogCollector) Write(p []byte) (n int, err error) {
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

func (lc *LogCollector) GetLogs() []string {
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	logsCopy := make([]string, len(lc.logs))
	copy(logsCopy, lc.logs)
	return logsCopy
}

var globalLog = &LogCollector{maxCap: 200}

// debugEnabled 由 WSTUNNEL_DEBUG=1 開啟詳細 log
var debugEnabled = os.Getenv("WSTUNNEL_DEBUG") == "1"

// isBenignNetError 判斷錯誤是否為「客戶端正常斷線」這類無動作意義的雜訊
//
// 例如:
//   * io.EOF
//   * connection reset by peer (App 切後台、網路切換、遠端主動關)
//   * broken pipe
//   * use of closed network connection (本地關閉)
//   * i/o timeout (idle 逾時)
//
// 這類錯誤在 mobile VPN 場景頻率極高,印出來只會洗版淹沒真正有意義的錯誤
func isBenignNetError(err error) bool {
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

// generateRandomPassword 給 admin 預設密碼用,長度為 base64 編碼後截斷
func generateRandomPassword(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	pw := base64.URLEncoding.EncodeToString(bytes)
	if len(pw) > length {
		pw = pw[:length]
	}
	return pw
}
