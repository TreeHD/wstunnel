package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wstunnel/internal/store"
)

// TestMigrateFromLegacy 驗證舊版 config.json 內的 accounts/admin/slaves
// 都能被正確匯入到 SQLite,且明文密碼會被 bcrypt-hash。
func TestMigrateFromLegacy(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	os.Setenv("WSTUNNEL_DB_PATH", filepath.Join(tmp, "wstunnel.db"))
	t.Cleanup(func() { os.Unsetenv("WSTUNNEL_DB_PATH") })

	// 寫一份 legacy 格式的 config.json
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]interface{}{
		"listen_addr": "0.0.0.0:80",
		"accounts": map[string]interface{}{
			"alice": map[string]interface{}{
				"password":     "alice-pass",
				"enabled":      true,
				"expiry_date":  "2099-01-01",
				"limit_gb":     1.5,
				"max_sessions": 2,
			},
		},
		"admin_accounts": map[string]string{
			"admin": "admin-secret",
		},
		"slaves": map[string]interface{}{
			"node-abc": map[string]interface{}{
				"node_id":    "node-abc",
				"node_name":  "Tokyo-A",
				"token":      "tok-xyz",
				"created_at": int64(1700000000),
			},
		},
	}
	data, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile("data/config.json", data, 0o600); err != nil {
		t.Fatal(err)
	}

	LoadOrInit()
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	if err := MigrateFromLegacy(); err != nil {
		t.Fatalf("MigrateFromLegacy: %v", err)
	}

	// 1. account 應該被 hash 後存進去
	a, err := store.GetAccount("alice")
	if err != nil {
		t.Fatalf("alice not migrated: %v", err)
	}
	if !store.IsBcryptHash(a.PasswordHash) {
		t.Fatalf("alice password not hashed: %q", a.PasswordHash)
	}
	if !store.VerifyPassword(a.PasswordHash, "alice-pass") {
		t.Fatal("alice password verify failed")
	}
	if a.LimitGB != 1.5 || a.MaxSessions != 2 || a.ExpiryDate != "2099-01-01" {
		t.Fatalf("alice fields wrong: %+v", a)
	}

	// 2. admin 也該能用原密碼登入
	if !store.VerifyAdminPassword("admin", "admin-secret") {
		t.Fatal("admin login failed after migrate")
	}

	// 3. slave 應該被搬進去
	s, err := store.GetSlave("node-abc")
	if err != nil {
		t.Fatalf("slave not migrated: %v", err)
	}
	if s.NodeName != "Tokyo-A" || s.Token != "tok-xyz" {
		t.Fatalf("slave fields wrong: %+v", s)
	}

	// 4. 備份應該存在
	if _, err := os.Stat("data/config.json.pre-sqlite.bak"); err != nil {
		t.Fatalf("backup not created: %v", err)
	}

	// 5. 改寫後的 config.json 不應該再含 accounts/admin/slaves
	post, _ := os.ReadFile("data/config.json")
	var raw map[string]json.RawMessage
	json.Unmarshal(post, &raw)
	for _, banned := range []string{"accounts", "admin_accounts", "slaves"} {
		if _, ok := raw[banned]; ok {
			t.Errorf("config.json still contains %q after migration", banned)
		}
	}

	// 6. 再跑一次應該是 no-op(冪等)
	if err := MigrateFromLegacy(); err != nil {
		t.Fatalf("second MigrateFromLegacy failed: %v", err)
	}
}
