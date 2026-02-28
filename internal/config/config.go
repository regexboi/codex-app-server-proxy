package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type APIKey struct {
	ID   string `json:"id"`
	Hash string `json:"hash"`
	Role string `json:"role"`
}

type Config struct {
	ListenAddr       string   `json:"listen_addr"`
	WorkspaceRoot    string   `json:"workspace_root"`
	DataDir          string   `json:"data_dir"`
	ServiceCodexHome string   `json:"service_codex_home"`
	CodexBinaryPath  string   `json:"codex_binary_path"`
	SessionIdleTTL   string   `json:"session_idle_ttl"`
	MaxSessions      int      `json:"max_sessions"`
	APIKeys          []APIKey `json:"api_keys"`
	RequirePlanType  string   `json:"require_plan_type"`
	ReadyProbeTTL    string   `json:"ready_probe_ttl"`
	ReadyProbeTimeo  string   `json:"ready_probe_timeout"`

	ParsedSessionIdleTTL  time.Duration `json:"-"`
	ParsedReadyProbeTTL   time.Duration `json:"-"`
	ParsedReadyProbeTimeo time.Duration `json:"-"`
}

func Load(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}

	if err := cfg.normalizeAndValidate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) normalizeAndValidate() error {
	var err error

	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.WorkspaceRoot == "" {
		return errors.New("workspace_root is required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.ServiceCodexHome == "" {
		return errors.New("service_codex_home is required")
	}
	if c.CodexBinaryPath == "" {
		c.CodexBinaryPath = "codex"
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 20
	}
	if c.RequirePlanType == "" {
		c.RequirePlanType = "pro"
	}
	if c.SessionIdleTTL == "" {
		c.SessionIdleTTL = "30m"
	}
	if c.ReadyProbeTTL == "" {
		c.ReadyProbeTTL = "20s"
	}
	if c.ReadyProbeTimeo == "" {
		c.ReadyProbeTimeo = "6s"
	}
	c.ParsedSessionIdleTTL, err = time.ParseDuration(c.SessionIdleTTL)
	if err != nil {
		return fmt.Errorf("invalid session_idle_ttl: %w", err)
	}
	c.ParsedReadyProbeTTL, err = time.ParseDuration(c.ReadyProbeTTL)
	if err != nil {
		return fmt.Errorf("invalid ready_probe_ttl: %w", err)
	}
	c.ParsedReadyProbeTimeo, err = time.ParseDuration(c.ReadyProbeTimeo)
	if err != nil {
		return fmt.Errorf("invalid ready_probe_timeout: %w", err)
	}

	if len(c.APIKeys) == 0 {
		return errors.New("api_keys must contain at least one key")
	}
	for i, key := range c.APIKeys {
		if key.ID == "" {
			return fmt.Errorf("api_keys[%d].id is required", i)
		}
		if key.Hash == "" {
			return fmt.Errorf("api_keys[%d].hash is required", i)
		}
		role := strings.ToLower(strings.TrimSpace(key.Role))
		if role != "user" && role != "admin" {
			return fmt.Errorf("api_keys[%d].role must be user or admin", i)
		}
		c.APIKeys[i].Role = role
	}

	c.WorkspaceRoot = expandTilde(c.WorkspaceRoot)
	c.DataDir = expandTilde(c.DataDir)
	c.ServiceCodexHome = expandTilde(c.ServiceCodexHome)
	if strings.Contains(c.CodexBinaryPath, string(filepath.Separator)) {
		c.CodexBinaryPath = expandTilde(c.CodexBinaryPath)
	}

	c.WorkspaceRoot, err = filepath.Abs(c.WorkspaceRoot)
	if err != nil {
		return fmt.Errorf("workspace_root abs: %w", err)
	}
	c.DataDir, err = filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("data_dir abs: %w", err)
	}
	c.ServiceCodexHome, err = filepath.Abs(c.ServiceCodexHome)
	if err != nil {
		return fmt.Errorf("service_codex_home abs: %w", err)
	}
	return nil
}

func expandTilde(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, strings.TrimPrefix(path, "~"+string(filepath.Separator)))
		}
	}
	return path
}
