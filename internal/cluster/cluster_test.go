package cluster

import (
	"os"
	"path/filepath"
	"testing"

	"wstunnel/internal/store"
)

func TestSignVerify(t *testing.T) {
	const token = "secret-token-123"
	body := []byte(`{"node_id":"abc","sent_at":1700000000}`)

	sig := Sign(token, body)
	if sig == "" {
		t.Fatal("Sign returned empty")
	}

	if !Verify(token, body, sig) {
		t.Fatal("Verify failed for valid signature")
	}
	if Verify("wrong-token", body, sig) {
		t.Fatal("Verify accepted wrong token")
	}
	if Verify(token, append(body, '!'), sig) {
		t.Fatal("Verify accepted tampered body")
	}
	if Verify("", body, sig) {
		t.Fatal("Verify accepted empty token")
	}
	if Verify(token, body, "") {
		t.Fatal("Verify accepted empty signature")
	}
	if Verify(token, body, "not-hex") {
		t.Fatal("Verify accepted non-hex signature")
	}
}

func TestComposeContainsRequiredFields(t *testing.T) {
	// store 需要 init,用 tmp dir 跑
	tmp := t.TempDir()
	os.Setenv("WSTUNNEL_DB_PATH", filepath.Join(tmp, "test.db"))
	t.Cleanup(func() { os.Unsetenv("WSTUNNEL_DB_PATH") })
	if err := store.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	if _, err := GenerateSlaveCompose(ComposeOptions{NodeID: "non-existent"}); err == nil {
		t.Fatal("expected error for non-existent node")
	}

	// 加一個再產出來看看內容
	rec, err := AddSlave("test-node", "")
	if err != nil {
		t.Fatalf("AddSlave: %v", err)
	}
	yaml, err := GenerateSlaveCompose(ComposeOptions{
		NodeID:       rec.NodeID,
		MasterURL:    "http://example.com:9090",
		HeartbeatSec: 30,
	})
	if err != nil {
		t.Fatalf("GenerateSlaveCompose: %v", err)
	}
	for _, want := range []string{"CLUSTER_ROLE", "MASTER_URL", "MASTER_TOKEN", rec.Token, rec.NodeID} {
		if !contains(yaml, want) {
			t.Errorf("yaml missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
