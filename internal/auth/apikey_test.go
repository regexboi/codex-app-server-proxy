package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/mishca/codex-app-server-proxy/internal/config"
)

func sha(v string) string {
	s := sha256.Sum256([]byte(v))
	return hex.EncodeToString(s[:])
}

func TestAuthenticateHeader(t *testing.T) {
	a, err := NewAuthenticator([]config.APIKey{
		{ID: "u1", Hash: sha("user-secret"), Role: "user"},
		{ID: "a1", Hash: sha("admin-secret"), Role: "admin"},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	principal, ok := a.AuthenticateHeader("Bearer user-secret")
	if !ok {
		t.Fatalf("expected user key to authenticate")
	}
	if principal.Role != "user" || principal.KeyID != "u1" {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	principal, ok = a.AuthenticateHeader("Bearer admin-secret")
	if !ok {
		t.Fatalf("expected admin key to authenticate")
	}
	if principal.Role != "admin" || principal.KeyID != "a1" {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	if _, ok := a.AuthenticateHeader("Bearer wrong"); ok {
		t.Fatalf("unexpected auth success for wrong key")
	}
	if _, ok := a.AuthenticateHeader("Basic abc"); ok {
		t.Fatalf("unexpected auth success for malformed header")
	}
}
