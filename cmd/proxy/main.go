package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mishca/codex-app-server-proxy/internal/auth"
	"github.com/mishca/codex-app-server-proxy/internal/config"
	"github.com/mishca/codex-app-server-proxy/internal/policy"
	"github.com/mishca/codex-app-server-proxy/internal/probe"
	"github.com/mishca/codex-app-server-proxy/internal/server"
	"github.com/mishca/codex-app-server-proxy/internal/session"
)

func main() {
	configPath := flag.String("config", "./config.json", "path to JSON config")
	flag.Parse()

	logger := log.New(os.Stdout, "codex-proxy ", log.LstdFlags|log.Lmsgprefix)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatalf("load config: %v", err)
	}

	if err := os.MkdirAll(cfg.WorkspaceRoot, 0o700); err != nil {
		logger.Fatalf("create workspace root: %v", err)
	}
	if err := os.MkdirAll(cfg.ServiceCodexHome, 0o700); err != nil {
		logger.Fatalf("create service_codex_home: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "sessions"), 0o700); err != nil {
		logger.Fatalf("create data dir: %v", err)
	}

	authn, err := auth.NewAuthenticator(cfg.APIKeys)
	if err != nil {
		logger.Fatalf("init auth: %v", err)
	}

	policyEngine, err := policy.NewEngine(cfg.WorkspaceRoot)
	if err != nil {
		logger.Fatalf("init policy: %v", err)
	}

	checker := probe.NewChecker(
		cfg.CodexBinaryPath,
		cfg.ServiceCodexHome,
		cfg.RequirePlanType,
		cfg.ParsedReadyProbeTimeo,
		cfg.ParsedReadyProbeTTL,
	)
	initial := checker.CheckNow(context.Background())
	if !initial.Ready {
		logger.Fatalf("bootstrap auth check failed: %s", initial.Error)
	}

	sessions := session.NewManager(
		cfg.CodexBinaryPath,
		cfg.WorkspaceRoot,
		cfg.DataDir,
		cfg.ServiceCodexHome,
		cfg.MaxSessions,
		cfg.ParsedSessionIdleTTL,
		logger,
	)
	defer sessions.Shutdown(context.Background())

	api := server.New(authn, policyEngine, sessions, checker, logger)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s", cfg.ListenAddr)
		errCh <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Printf("received signal: %s", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server error: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	sessions.Shutdown(shutdownCtx)
}
