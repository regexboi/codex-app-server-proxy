package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Checker struct {
	codexBinaryPath string
	serviceHome     string
	requirePlanType string
	timeout         time.Duration
	cacheTTL        time.Duration

	mu     sync.Mutex
	cached Status
}

type Status struct {
	Ready     bool      `json:"ready"`
	PlanType  string    `json:"planType,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

func NewChecker(codexBinaryPath, serviceHome, requirePlanType string, timeout, cacheTTL time.Duration) *Checker {
	return &Checker{
		codexBinaryPath: codexBinaryPath,
		serviceHome:     serviceHome,
		requirePlanType: strings.ToLower(strings.TrimSpace(requirePlanType)),
		timeout:         timeout,
		cacheTTL:        cacheTTL,
	}
}

func (c *Checker) CheckNow(ctx context.Context) Status {
	status := Status{CheckedAt: time.Now().UTC()}

	checkCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, c.codexBinaryPath, "app-server", "--listen", "stdio://")
	cmd.Env = append(os.Environ(), "CODEX_HOME="+c.serviceHome)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		status.Error = fmt.Sprintf("open stdin: %v", err)
		return status
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		status.Error = fmt.Sprintf("open stdout: %v", err)
		return status
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		status.Error = fmt.Sprintf("open stderr: %v", err)
		return status
	}

	if err := cmd.Start(); err != nil {
		status.Error = fmt.Sprintf("start codex app-server: %v", err)
		return status
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	_ = stderr // consumed by process kill; not required for probe result.

	writer := bufio.NewWriter(stdin)
	requests := []string{
		`{"jsonrpc":"2.0","id":"probe-init","method":"initialize","params":{"clientInfo":{"name":"codex-proxy","version":"0.1.0"}}}`,
		`{"jsonrpc":"2.0","id":"probe-account","method":"account/read","params":{}}`,
	}
	for _, req := range requests {
		if _, err := writer.WriteString(req + "\n"); err != nil {
			status.Error = fmt.Sprintf("write probe request: %v", err)
			return status
		}
	}
	if err := writer.Flush(); err != nil {
		status.Error = fmt.Sprintf("flush probe request: %v", err)
		return status
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		var msg map[string]any
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}
		id, _ := msg["id"].(string)
		if id != "probe-account" {
			continue
		}
		if _, hasErr := msg["error"]; hasErr {
			status.Error = extractJSONRPCErrorMessage(msg["error"])
			return status
		}
		result, _ := msg["result"].(map[string]any)
		if requiresAuth(result) {
			status.Error = "service CODEX_HOME is not logged in (run codex login --device-auth)"
			return status
		}
		planType, err := extractPlanType(result)
		if err != nil {
			status.Error = err.Error()
			return status
		}
		status.PlanType = strings.ToLower(planType)
		if normalizePlanType(status.PlanType) != normalizePlanType(c.requirePlanType) {
			status.Error = fmt.Sprintf("required planType=%s, got %s", c.requirePlanType, status.PlanType)
			return status
		}
		status.Ready = true
		return status
	}

	if err := scanner.Err(); err != nil {
		status.Error = fmt.Sprintf("read probe response: %v", err)
		return status
	}
	if checkCtx.Err() != nil {
		status.Error = checkCtx.Err().Error()
		return status
	}
	status.Error = "did not receive probe-account response"
	return status
}

func (c *Checker) Ready(ctx context.Context) Status {
	c.mu.Lock()
	cached := c.cached
	if !cached.CheckedAt.IsZero() && time.Since(cached.CheckedAt) < c.cacheTTL {
		c.mu.Unlock()
		return cached
	}
	c.mu.Unlock()

	fresh := c.CheckNow(ctx)
	c.mu.Lock()
	c.cached = fresh
	c.mu.Unlock()
	return fresh
}

func extractPlanType(v any) (string, error) {
	if v == nil {
		return "", errors.New("planType missing in account/read result")
	}
	switch t := v.(type) {
	case map[string]any:
		if planRaw, ok := t["planType"]; ok {
			if plan, ok := planRaw.(string); ok && strings.TrimSpace(plan) != "" {
				return plan, nil
			}
		}
		if planRaw, ok := t["plan_type"]; ok {
			if plan, ok := planRaw.(string); ok && strings.TrimSpace(plan) != "" {
				return plan, nil
			}
		}
		for _, child := range t {
			if plan, err := extractPlanType(child); err == nil {
				return plan, nil
			}
		}
	case []any:
		for _, child := range t {
			if plan, err := extractPlanType(child); err == nil {
				return plan, nil
			}
		}
	}
	return "", errors.New("planType missing in account/read result")
}

func requiresAuth(result map[string]any) bool {
	if result == nil {
		return false
	}
	if req, ok := result["requiresOpenaiAuth"].(bool); ok && req {
		if acct, exists := result["account"]; !exists || acct == nil {
			return true
		}
	}
	return false
}

func extractJSONRPCErrorMessage(v any) string {
	if errObj, ok := v.(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok && strings.TrimSpace(msg) != "" {
			return "account/read returned error: " + msg
		}
	}
	return "account/read returned error"
}

var nonAlnumPlanRe = regexp.MustCompile(`[^a-z0-9]+`)

func normalizePlanType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	return nonAlnumPlanRe.ReplaceAllString(v, "")
}
