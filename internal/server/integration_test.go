package server_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mishca/codex-app-server-proxy/internal/auth"
	"github.com/mishca/codex-app-server-proxy/internal/config"
	"github.com/mishca/codex-app-server-proxy/internal/policy"
	"github.com/mishca/codex-app-server-proxy/internal/probe"
	"github.com/mishca/codex-app-server-proxy/internal/server"
	"github.com/mishca/codex-app-server-proxy/internal/session"
)

type testEnv struct {
	server     *httptest.Server
	manager    *session.Manager
	workspace  string
	dataDir    string
	serviceDir string
	fakeCodex  string
	userToken  string
	adminToken string
}

func TestSessionFlowAndSSE(t *testing.T) {
	env := setupEnv(t)
	defer env.Close(t)

	sessionID := env.createSession(t, env.userToken)
	sse := env.openSSE(t, sessionID, env.userToken)
	defer sse.close()

	env.sendRPCExpectAccepted(t, sessionID, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "init-1",
		"method":  "initialize",
		"params":  map[string]any{},
	}, false)
	env.sendRPCExpectAccepted(t, sessionID, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "thread-1",
		"method":  "thread/start",
		"params":  map[string]any{},
	}, false)
	env.sendRPCExpectAccepted(t, sessionID, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "turn-1",
		"method":  "turn/start",
		"params":  map[string]any{},
	}, false)
	env.sendRPCExpectAccepted(t, sessionID, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "skills-1",
		"method":  "skills/list",
		"params":  map[string]any{},
	}, false)

	mustSeeDataWithSubstring(t, sse.data, `"method":"thread/event"`)
	mustSeeDataWithSubstring(t, sse.data, `"method":"turn/event"`)
}

func TestBlockedMethodGetsDeterministicPolicyError(t *testing.T) {
	env := setupEnv(t)
	defer env.Close(t)

	sessionID := env.createSession(t, env.userToken)

	resp := env.sendRPC(t, sessionID, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "blocked-1",
		"method":  "account/read",
		"params":  map[string]any{},
	}, false)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	errObj, _ := body["error"].(map[string]any)
	if code, _ := errObj["code"].(string); code != "policy_denied" {
		t.Fatalf("expected policy_denied, got %v", code)
	}
}

func TestSessionHomesAreIsolated(t *testing.T) {
	env := setupEnv(t)
	defer env.Close(t)

	sessionA := env.createSession(t, env.userToken)
	sessionB := env.createSession(t, env.userToken)

	sseA := env.openSSE(t, sessionA, env.userToken)
	defer sseA.close()
	sseB := env.openSSE(t, sessionB, env.userToken)
	defer sseB.close()

	env.sendRPCExpectAccepted(t, sessionA, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "init-a",
		"method":  "initialize",
		"params":  map[string]any{},
	}, false)
	env.sendRPCExpectAccepted(t, sessionB, env.userToken, map[string]any{
		"jsonrpc": "2.0",
		"id":      "init-b",
		"method":  "initialize",
		"params":  map[string]any{},
	}, false)

	homeA := mustExtractCodexHome(t, sseA.data)
	homeB := mustExtractCodexHome(t, sseB.data)

	if homeA == homeB {
		t.Fatalf("expected isolated CODEX_HOME values, got both=%s", homeA)
	}
	if !strings.HasPrefix(homeA, filepath.Join(env.dataDir, "sessions")+string(os.PathSeparator)) {
		t.Fatalf("unexpected session home A: %s", homeA)
	}
	if !strings.HasPrefix(homeB, filepath.Join(env.dataDir, "sessions")+string(os.PathSeparator)) {
		t.Fatalf("unexpected session home B: %s", homeB)
	}
	if strings.Contains(homeA, filepath.Join(os.Getenv("HOME"), ".codex")) || strings.Contains(homeB, filepath.Join(os.Getenv("HOME"), ".codex")) {
		t.Fatalf("session homes should not point at personal ~/.codex")
	}
}

func setupEnv(t *testing.T) *testEnv {
	t.Helper()
	t.Setenv("FAKE_PLAN_TYPE", "pro")
	t.Setenv("FAKE_MISSING_AUTH", "0")

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	fakeCodex := filepath.Join(repoRoot, "testdata", "fake-codex.sh")

	workspace := t.TempDir()
	dataDir := t.TempDir()
	serviceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serviceDir, "auth.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write service auth: %v", err)
	}

	userToken := "user-token"
	adminToken := "admin-token"
	authn, err := auth.NewAuthenticator([]config.APIKey{
		{ID: "u", Hash: hash(userToken), Role: "user"},
		{ID: "a", Hash: hash(adminToken), Role: "admin"},
	})
	if err != nil {
		t.Fatalf("auth init: %v", err)
	}

	policyEngine, err := policy.NewEngine(workspace)
	if err != nil {
		t.Fatalf("policy init: %v", err)
	}

	checker := probe.NewChecker(fakeCodex, serviceDir, "pro", 3*time.Second, time.Second)
	initial := checker.CheckNow(context.Background())
	if !initial.Ready {
		t.Fatalf("probe should be ready, got %+v", initial)
	}

	logger := log.New(io.Discard, "", 0)
	manager := session.NewManager(fakeCodex, workspace, dataDir, serviceDir, 8, 5*time.Minute, logger)
	api := server.New(authn, policyEngine, manager, checker, logger)
	httpServer := httptest.NewServer(api.Handler())

	return &testEnv{
		server:     httpServer,
		manager:    manager,
		workspace:  workspace,
		dataDir:    dataDir,
		serviceDir: serviceDir,
		fakeCodex:  fakeCodex,
		userToken:  userToken,
		adminToken: adminToken,
	}
}

func (e *testEnv) Close(t *testing.T) {
	t.Helper()
	e.server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	e.manager.Shutdown(ctx)
}

func (e *testEnv) createSession(t *testing.T, token string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/v1/sessions", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create session request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create session status=%d body=%s", resp.StatusCode, string(body))
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode create session: %v", err)
	}
	sessionID, _ := payload["sessionId"].(string)
	if sessionID == "" {
		t.Fatalf("missing sessionId in response: %#v", payload)
	}
	return sessionID
}

type sseReader struct {
	data chan string
	resp *http.Response
}

func (s *sseReader) close() {
	if s.resp != nil {
		_ = s.resp.Body.Close()
	}
}

func (e *testEnv) openSSE(t *testing.T, sessionID, token string) *sseReader {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.server.URL+"/v1/sessions/"+sessionID+"/events", nil)
	if err != nil {
		t.Fatalf("new sse request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open sse: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("sse status=%d body=%s", resp.StatusCode, string(body))
	}

	out := &sseReader{data: make(chan string, 256), resp: resp}
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 5*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				out.data <- strings.TrimPrefix(line, "data: ")
			}
		}
		close(out.data)
	}()
	return out
}

func (e *testEnv) sendRPCExpectAccepted(t *testing.T, sessionID, token string, msg map[string]any, danger bool) {
	t.Helper()
	resp := e.sendRPC(t, sessionID, token, msg, danger)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("rpc status=%d body=%s", resp.StatusCode, string(body))
	}
}

func (e *testEnv) sendRPC(t *testing.T, sessionID, token string, msg map[string]any, danger bool) *http.Response {
	t.Helper()
	payload, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal rpc: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, e.server.URL+"/v1/sessions/"+sessionID+"/rpc", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("new rpc request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if danger {
		req.Header.Set("X-Codex-Danger", "true")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rpc request: %v", err)
	}
	return resp
}

func mustSeeDataWithSubstring(t *testing.T, ch <-chan string, needle string) {
	t.Helper()
	timeout := time.After(4 * time.Second)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout waiting for sse data containing %q", needle)
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("sse stream closed before receiving %q", needle)
			}
			if strings.Contains(line, needle) {
				return
			}
		}
	}
}

func mustExtractCodexHome(t *testing.T, ch <-chan string) string {
	t.Helper()
	timeout := time.After(4 * time.Second)
	for {
		select {
		case <-timeout:
			t.Fatalf("timeout waiting for initialize codexHome")
		case line, ok := <-ch:
			if !ok {
				t.Fatalf("sse stream closed before initialize result")
			}
			var msg map[string]any
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				continue
			}
			result, _ := msg["result"].(map[string]any)
			if result == nil {
				continue
			}
			home, _ := result["codexHome"].(string)
			if home != "" {
				return home
			}
		}
	}
}

func hash(v string) string {
	s := sha256.Sum256([]byte(v))
	return hex.EncodeToString(s[:])
}

func (e *testEnv) String() string {
	return fmt.Sprintf("url=%s workspace=%s", e.server.URL, e.workspace)
}
