package probe

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupProbeEnv(t *testing.T) (fakeCodex string, serviceHome string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	fakeCodex = filepath.Join(repoRoot, "testdata", "fake-codex.sh")

	serviceHome = t.TempDir()
	if err := os.WriteFile(filepath.Join(serviceHome, "auth.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write auth.json: %v", err)
	}
	return fakeCodex, serviceHome
}

func TestCheckNowReadyProPlan(t *testing.T) {
	fakeCodex, serviceHome := setupProbeEnv(t)
	t.Setenv("FAKE_PLAN_TYPE", "pro")
	t.Setenv("FAKE_MISSING_AUTH", "0")

	checker := NewChecker(fakeCodex, serviceHome, "pro", 3*time.Second, time.Second)
	status := checker.CheckNow(context.Background())
	if !status.Ready {
		t.Fatalf("expected ready, got status=%+v", status)
	}
}

func TestCheckNowFailsWhenAuthMissing(t *testing.T) {
	fakeCodex, serviceHome := setupProbeEnv(t)
	t.Setenv("FAKE_MISSING_AUTH", "1")
	t.Setenv("FAKE_PLAN_TYPE", "pro")

	checker := NewChecker(fakeCodex, serviceHome, "pro", 3*time.Second, time.Second)
	status := checker.CheckNow(context.Background())
	if status.Ready {
		t.Fatalf("expected not ready for missing auth")
	}
}

func TestCheckNowFailsForNonProPlan(t *testing.T) {
	fakeCodex, serviceHome := setupProbeEnv(t)
	t.Setenv("FAKE_MISSING_AUTH", "0")
	t.Setenv("FAKE_PLAN_TYPE", "free")

	checker := NewChecker(fakeCodex, serviceHome, "pro", 3*time.Second, time.Second)
	status := checker.CheckNow(context.Background())
	if status.Ready {
		t.Fatalf("expected not ready for non-pro plan")
	}
}
