package cluster

import (
	"testing"
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
	// 直接打到 config 套用最小設定;cluster 用 config singleton。
	// 這裡不真的 init config,而是測單純呼叫不會 panic 的 path。
	// (完整 e2e 留給整合測試。)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	_, err := GenerateSlaveCompose(ComposeOptions{NodeID: "non-existent"})
	if err == nil {
		t.Fatal("expected error for non-existent node")
	}
}
