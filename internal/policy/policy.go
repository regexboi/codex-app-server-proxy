package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mishca/codex-app-server-proxy/internal/auth"
)

type Engine struct {
	workspaceRoot string
}

type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string {
	return e.Reason
}

func NewEngine(workspaceRoot string) (*Engine, error) {
	if workspaceRoot == "" {
		return nil, errors.New("workspace root is required")
	}
	abs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("workspace root abs: %w", err)
	}
	eval, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace root eval symlinks: %w", err)
	}
	return &Engine{workspaceRoot: filepath.Clean(eval)}, nil
}

func (e *Engine) WorkspaceRoot() string {
	return e.workspaceRoot
}

func (e *Engine) RewriteInbound(msg map[string]any, principal auth.Principal, dangerRequested bool) (map[string]any, error) {
	method, _ := msg["method"].(string)
	if method == "" {
		return nil, &PolicyError{Reason: "missing method"}
	}

	if isBlockedMethod(method) {
		return nil, &PolicyError{Reason: "method blocked by policy"}
	}
	if !isAllowedMethod(method) {
		return nil, &PolicyError{Reason: "method not allowed by policy"}
	}

	cloned, err := cloneMap(msg)
	if err != nil {
		return nil, &PolicyError{Reason: "invalid JSON-RPC payload"}
	}
	params := getParamsMap(cloned)

	if err := e.validatePathInputs(params); err != nil {
		return nil, &PolicyError{Reason: err.Error()}
	}

	if dangerRequested {
		if principal.Role != "admin" {
			return nil, &PolicyError{Reason: "danger override requires admin key"}
		}
		if !dangerEligibleMethod(method) {
			return nil, &PolicyError{Reason: "danger override is not allowed for this method"}
		}
	}

	// Always force cwd to the configured workspace root.
	params["cwd"] = e.workspaceRoot

	if strings.HasPrefix(method, "thread/") || strings.HasPrefix(method, "turn/") {
		if dangerRequested {
			applyDangerMode(params)
		} else {
			applySafeSandbox(params, e.workspaceRoot)
		}
	}

	if strings.HasPrefix(method, "skills/") {
		if err := e.clampSkillsPaths(params); err != nil {
			return nil, &PolicyError{Reason: err.Error()}
		}
	}

	cloned["params"] = params
	return cloned, nil
}

func isAllowedMethod(method string) bool {
	if strings.HasPrefix(method, "thread/") {
		return true
	}
	if strings.HasPrefix(method, "turn/") {
		return true
	}
	if strings.HasPrefix(method, "skills/") {
		return true
	}

	switch method {
	case "initialize", "review/start", "model/list", "feedback/upload":
		return true
	default:
		return false
	}
}

func isBlockedMethod(method string) bool {
	blockedPrefixes := []string{
		"config/",
		"account/",
		"mcpServer/",
		"externalAgentConfig/",
		"windowsSandbox/",
	}
	for _, p := range blockedPrefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return method == "command/exec" || method == "app/list"
}

func dangerEligibleMethod(method string) bool {
	switch method {
	case "thread/start", "thread/resume", "thread/fork", "turn/start":
		return true
	default:
		return false
	}
}

func applySafeSandbox(params map[string]any, workspaceRoot string) {
	params["sandboxMode"] = "workspaceWrite"
	params["writableRoots"] = []any{workspaceRoot}
	params["networkAccess"] = true
	params["approvalPolicy"] = "never"
	params["sandbox"] = map[string]any{
		"mode":           "workspaceWrite",
		"writableRoots":  []any{workspaceRoot},
		"networkAccess":  true,
		"approvalPolicy": "never",
	}
}

func applyDangerMode(params map[string]any) {
	params["sandboxMode"] = "dangerFullAccess"
	params["networkAccess"] = true
	params["approvalPolicy"] = "never"
	params["sandbox"] = map[string]any{
		"mode":           "dangerFullAccess",
		"networkAccess":  true,
		"approvalPolicy": "never",
	}
}

func getParamsMap(msg map[string]any) map[string]any {
	params, ok := msg["params"].(map[string]any)
	if ok {
		return params
	}
	params = map[string]any{}
	msg["params"] = params
	return params
}

func (e *Engine) validatePathInputs(params map[string]any) error {
	if raw, ok := params["cwd"]; ok {
		cwd, ok := raw.(string)
		if !ok {
			return errors.New("cwd must be a string")
		}
		if _, err := e.CanonicalizeWithinRoot(cwd); err != nil {
			return fmt.Errorf("cwd rejected: %w", err)
		}
	}

	for _, key := range []string{"cwds", "writableRoots"} {
		raw, ok := params[key]
		if !ok {
			continue
		}
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("%s must be an array", key)
		}
		for _, item := range items {
			path, ok := item.(string)
			if !ok {
				return fmt.Errorf("%s must contain only strings", key)
			}
			if _, err := e.CanonicalizeWithinRoot(path); err != nil {
				return fmt.Errorf("%s rejected: %w", key, err)
			}
		}
	}
	return nil
}

func (e *Engine) clampSkillsPaths(params map[string]any) error {
	if raw, ok := params["cwds"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return errors.New("cwds must be an array")
		}
		clamped := make([]any, 0, len(items))
		for _, item := range items {
			v, ok := item.(string)
			if !ok {
				return errors.New("cwds entries must be strings")
			}
			canon, err := e.CanonicalizeWithinRoot(v)
			if err != nil {
				return fmt.Errorf("cwds entry rejected: %w", err)
			}
			clamped = append(clamped, canon)
		}
		params["cwds"] = clamped
	}

	if raw, ok := params["writableRoots"]; ok {
		items, ok := raw.([]any)
		if !ok {
			return errors.New("writableRoots must be an array")
		}
		clamped := make([]any, 0, len(items))
		for _, item := range items {
			v, ok := item.(string)
			if !ok {
				return errors.New("writableRoots entries must be strings")
			}
			canon, err := e.CanonicalizeWithinRoot(v)
			if err != nil {
				return fmt.Errorf("writableRoots entry rejected: %w", err)
			}
			clamped = append(clamped, canon)
		}
		params["writableRoots"] = clamped
	}
	return nil
}

func (e *Engine) CanonicalizeWithinRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("empty path")
	}

	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(e.workspaceRoot, candidate)
	}
	candidate = filepath.Clean(candidate)

	resolved, err := resolveWithExistingSymlinks(candidate)
	if err != nil {
		return "", err
	}
	if !isWithinRoot(e.workspaceRoot, resolved) {
		return "", errors.New("path escapes workspace root")
	}
	return resolved, nil
}

func resolveWithExistingSymlinks(path string) (string, error) {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	parts := []string{}
	cur := path
	for {
		if _, err := os.Lstat(cur); err == nil {
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			for i := len(parts) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, parts[i])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}

		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		parts = append(parts, filepath.Base(cur))
		cur = parent
	}
	return filepath.Clean(path), nil
}

func isWithinRoot(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if candidate == root {
		return true
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func cloneMap(in map[string]any) (map[string]any, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
