package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mishca/codex-app-server-proxy/internal/auth"
)

func TestMethodAllowBlockMatrix(t *testing.T) {
	root := t.TempDir()
	engine, err := NewEngine(root)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	allowed := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "skills/list", "params": map[string]any{}}
	if _, err := engine.RewriteInbound(allowed, auth.Principal{Role: "user"}, false); err != nil {
		t.Fatalf("skills/list should be allowed: %v", err)
	}

	blocked := map[string]any{"jsonrpc": "2.0", "id": 2, "method": "account/read", "params": map[string]any{}}
	if _, err := engine.RewriteInbound(blocked, auth.Principal{Role: "user"}, false); err == nil {
		t.Fatalf("account/read should be blocked")
	}
}

func TestSandboxRewriteDefault(t *testing.T) {
	root := t.TempDir()
	engine, err := NewEngine(root)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "thread/start",
		"params": map[string]any{
			"cwd": filepath.Join(root, "project"),
		},
	}
	out, err := engine.RewriteInbound(msg, auth.Principal{Role: "user"}, false)
	if err != nil {
		t.Fatalf("RewriteInbound: %v", err)
	}
	params := out["params"].(map[string]any)
	if params["cwd"] != engine.WorkspaceRoot() {
		t.Fatalf("cwd was not forced to workspace root: %v", params["cwd"])
	}
	if params["sandboxMode"] != "workspaceWrite" {
		t.Fatalf("expected workspaceWrite sandboxMode, got %v", params["sandboxMode"])
	}
	if params["approvalPolicy"] != "never" {
		t.Fatalf("expected approvalPolicy never, got %v", params["approvalPolicy"])
	}
	if params["networkAccess"] != true {
		t.Fatalf("expected networkAccess true")
	}
}

func TestDangerOverrideAdminOnly(t *testing.T) {
	root := t.TempDir()
	engine, err := NewEngine(root)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	msg := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "turn/start", "params": map[string]any{}}

	if _, err := engine.RewriteInbound(msg, auth.Principal{Role: "user"}, true); err == nil {
		t.Fatalf("expected non-admin danger override to fail")
	}

	out, err := engine.RewriteInbound(msg, auth.Principal{Role: "admin"}, true)
	if err != nil {
		t.Fatalf("admin danger override should pass: %v", err)
	}
	params := out["params"].(map[string]any)
	if params["sandboxMode"] != "dangerFullAccess" {
		t.Fatalf("expected dangerFullAccess sandboxMode, got %v", params["sandboxMode"])
	}
}

func TestCanonicalizeRejectsEscapeAndSymlinkBreakout(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	outside := t.TempDir()
	link := filepath.Join(root, "escape-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	engine, err := NewEngine(root)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	if _, err := engine.CanonicalizeWithinRoot("../etc"); err == nil {
		t.Fatalf("expected ../ escape to be rejected")
	}

	if _, err := engine.CanonicalizeWithinRoot(filepath.Join("escape-link", "foo")); err == nil {
		t.Fatalf("expected symlink breakout to be rejected")
	}

	if _, err := engine.CanonicalizeWithinRoot("inside"); err != nil {
		t.Fatalf("expected inside path to pass: %v", err)
	}
}
