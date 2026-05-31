// password.go — bcrypt hash 與驗證 helper。
//
// 我們對「使用者(SSH)密碼」與「後台 admin 密碼」一律走 bcrypt(單向 hash),
// 沒辦法在 UI 顯示明文密碼,管理員只能「重設」。這是刻意選擇:
//   - 不需要設計 master.key / 解密邏輯
//   - cluster 同步只傳 hash,Master/Slave 不需共享 key
//   - 即使 SQLite 檔外洩也不會直接洩漏密碼
package store

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost 是 bcrypt 的 work factor。預設 12:
//   - 10(預設)→ 約 100ms,有點太快
//   - 12        → 約 300ms,使用者可接受、暴力破解難度高
//   - 14+       → 過慢,登入會明顯卡頓
const bcryptCost = 12

// bcryptPrefixes 是 bcrypt hash 的合法版本前綴。
// 任何以這幾個開頭的字串都當成已經 hash 過。
var bcryptPrefixes = []string{"$2a$", "$2b$", "$2y$"}

// HashPassword 把明文密碼 bcrypt-hash 成 60-byte 字串。
// 若輸入本身已經是 bcrypt hash 直接回傳(讓遷移階段冪等)。
func HashPassword(plain string) (string, error) {
	if IsBcryptHash(plain) {
		return plain, nil
	}
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword 比對明文密碼與 bcrypt hash。
// 不符合 / hash 格式錯誤一律回 false(不洩漏失敗原因)。
func VerifyPassword(hash, plain string) bool {
	if hash == "" || plain == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// IsBcryptHash 判斷字串是否已是 bcrypt hash(用於遷移時偵測「需 hash」vs「已 hash」)。
func IsBcryptHash(s string) bool {
	if len(s) < 60 {
		return false
	}
	for _, p := range bcryptPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
