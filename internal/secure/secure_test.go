package secure

import (
	"testing"
	"time"
)

func TestSecretScopesAndTamper(t *testing.T) {
	k := make([]byte, 32)
	b, e := Seal(k, "node:one", []byte("fixture"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Open(k, "node:two", b); e == nil {
		t.Fatal("cross-scope accepted")
	}
	b[len(b)-1] ^= 1
	if _, e = Open(k, "node:one", b); e == nil {
		t.Fatal("tamper accepted")
	}
}
func TestTOTPReplayAndRFC(t *testing.T) {
	s := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if Code(s, 1) != "287082" {
		t.Fatal("RFC vector")
	}
	now := time.Unix(59, 0)
	step, ok := TOTP(s, "287082", -1, now)
	if !ok {
		t.Fatal("valid rejected")
	}
	if _, ok = TOTP(s, "287082", step, now); ok {
		t.Fatal("replay accepted")
	}
}
func TestPassword(t *testing.T) {
	h := Password("synthetic-long-password")
	if !VerifyPassword("synthetic-long-password", h) || VerifyPassword("wrong", h) {
		t.Fatal("password verification")
	}
}
