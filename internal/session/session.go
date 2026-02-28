package session

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Manager struct {
	codexBinaryPath string
	workspaceRoot   string
	dataDir         string
	serviceHome     string
	maxSessions     int
	idleTTL         time.Duration
	logger          *log.Logger

	mu       sync.RWMutex
	sessions map[string]*Session

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type Event struct {
	ID   int64
	Data string
}

type Session struct {
	id   string
	home string

	cmd    *exec.Cmd
	cancel context.CancelFunc
	stdin  io.WriteCloser

	writeMu sync.Mutex

	subMu         sync.Mutex
	subscribers   map[int]chan Event
	nextSubID     int
	events        []Event
	nextEventID   int64
	eventBacklogN int

	finalizeOnce sync.Once
	closed       atomic.Bool
	lastActivity atomic.Int64

	logger *log.Logger
}

func NewManager(codexBinaryPath, workspaceRoot, dataDir, serviceHome string, maxSessions int, idleTTL time.Duration, logger *log.Logger) *Manager {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		codexBinaryPath: codexBinaryPath,
		workspaceRoot:   workspaceRoot,
		dataDir:         dataDir,
		serviceHome:     serviceHome,
		maxSessions:     maxSessions,
		idleTTL:         idleTTL,
		logger:          logger,
		sessions:        map[string]*Session{},
		ctx:             ctx,
		cancel:          cancel,
	}
	m.wg.Add(1)
	go m.reaperLoop()
	return m
}

func (m *Manager) Create() (*Session, error) {
	m.mu.Lock()
	if len(m.sessions) >= m.maxSessions {
		m.mu.Unlock()
		return nil, errors.New("max sessions reached")
	}
	m.mu.Unlock()

	id, err := randomID(12)
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}

	sessionDir := filepath.Join(m.dataDir, "sessions", id)
	home := filepath.Join(sessionDir, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, fmt.Errorf("create session home: %w", err)
	}
	if err := seedSessionHome(m.serviceHome, home); err != nil {
		return nil, err
	}

	procCtx, cancel := context.WithCancel(m.ctx)
	cmd := exec.CommandContext(procCtx, m.codexBinaryPath, "app-server", "--listen", "stdio://")
	cmd.Env = append(os.Environ(), "CODEX_HOME="+home)
	cmd.Dir = m.workspaceRoot

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("session stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("session stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("session stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start codex app-server: %w", err)
	}

	now := time.Now().UnixNano()
	s := &Session{
		id:            id,
		home:          home,
		cmd:           cmd,
		cancel:        cancel,
		stdin:         stdin,
		subscribers:   map[int]chan Event{},
		eventBacklogN: 1000,
		logger:        m.logger,
	}
	s.lastActivity.Store(now)

	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()

	m.wg.Add(3)
	go func() {
		defer m.wg.Done()
		s.readStdout(stdout)
	}()
	go func() {
		defer m.wg.Done()
		s.readStderr(stderr)
	}()
	go func() {
		defer m.wg.Done()
		err := cmd.Wait()
		if err != nil {
			s.publishLocal("proxy/session_error", map[string]any{"message": err.Error()})
		}
		s.finalize("process_exit")
		m.remove(id)
	}()

	return s, nil
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *Manager) Delete(id string) bool {
	s, ok := m.Get(id)
	if !ok {
		return false
	}
	s.Close("session_deleted")
	m.remove(id)
	return true
}

func (m *Manager) remove(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

func (m *Manager) Shutdown(ctx context.Context) {
	m.cancel()

	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()

	for _, s := range sessions {
		s.Close("server_shutdown")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.wg.Wait()
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func (m *Manager) reaperLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var expired []*Session

			m.mu.RLock()
			for _, s := range m.sessions {
				if now.Sub(s.LastActivity()) > m.idleTTL {
					expired = append(expired, s)
				}
			}
			m.mu.RUnlock()

			for _, s := range expired {
				s.Close("idle_timeout")
				m.remove(s.ID())
			}
		}
	}
}

func (s *Session) ID() string {
	return s.id
}

func (s *Session) Home() string {
	return s.home
}

func (s *Session) LastActivity() time.Time {
	ns := s.lastActivity.Load()
	if ns == 0 {
		return time.Unix(0, 0)
	}
	return time.Unix(0, ns)
}

func (s *Session) Touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

func (s *Session) Send(line []byte) error {
	if s.closed.Load() {
		return errors.New("session is closed")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return errors.New("session is closed")
	}
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		return err
	}
	s.Touch()
	return nil
}

func (s *Session) Subscribe(lastEventID int64) (<-chan Event, func()) {
	ch := make(chan Event, 128)

	s.subMu.Lock()
	if s.closed.Load() {
		s.subMu.Unlock()
		close(ch)
		return ch, func() {}
	}
	s.nextSubID++
	subID := s.nextSubID
	s.subscribers[subID] = ch
	backlog := make([]Event, 0, len(s.events))
	for _, ev := range s.events {
		if ev.ID > lastEventID {
			backlog = append(backlog, ev)
		}
	}
	s.subMu.Unlock()

replayLoop:
	for _, ev := range backlog {
		select {
		case ch <- ev:
		default:
			break replayLoop
		}
	}

	cancel := func() {
		s.subMu.Lock()
		if existing, ok := s.subscribers[subID]; ok {
			delete(s.subscribers, subID)
			close(existing)
		}
		s.subMu.Unlock()
	}
	return ch, cancel
}

func (s *Session) Close(reason string) {
	s.finalize(reason)
}

func (s *Session) finalize(reason string) {
	s.finalizeOnce.Do(func() {
		s.publishLocal("proxy/session_closed", map[string]any{"reason": reason})
		s.closed.Store(true)

		s.cancel()
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Signal(syscall.SIGTERM)
			time.AfterFunc(2*time.Second, func() {
				if s.cmd.Process != nil {
					_ = s.cmd.Process.Kill()
				}
			})
		}
		_ = s.stdin.Close()

		s.subMu.Lock()
		for id, ch := range s.subscribers {
			delete(s.subscribers, id)
			close(ch)
		}
		s.subMu.Unlock()
	})
}

func (s *Session) readStdout(reader io.ReadCloser) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		s.Touch()
		s.publish(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		s.publishLocal("proxy/stdout_error", map[string]any{"error": err.Error()})
	}
}

func (s *Session) readStderr(reader io.ReadCloser) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		s.logger.Printf("session=%s codex_stderr=%s", s.id, redact(scanner.Text()))
	}
}

func (s *Session) publish(raw string) {
	s.subMu.Lock()
	if s.closed.Load() {
		s.subMu.Unlock()
		return
	}
	s.nextEventID++
	ev := Event{ID: s.nextEventID, Data: raw}
	s.events = append(s.events, ev)
	if len(s.events) > s.eventBacklogN {
		s.events = s.events[len(s.events)-s.eventBacklogN:]
	}
	for id, ch := range s.subscribers {
		select {
		case ch <- ev:
		default:
			delete(s.subscribers, id)
			close(ch)
		}
	}
	s.subMu.Unlock()
}

func (s *Session) publishLocal(method string, params map[string]any) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	})
	s.publish(string(payload))
}

func seedSessionHome(serviceHome, sessionHome string) error {
	if err := copyFile(filepath.Join(serviceHome, "auth.json"), filepath.Join(sessionHome, "auth.json")); err != nil {
		return fmt.Errorf("seed auth.json: %w", err)
	}
	_ = copyFile(filepath.Join(serviceHome, "config.toml"), filepath.Join(sessionHome, "config.toml"))
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func randomID(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

var redactBearerRe = regexp.MustCompile(`(?i)(bearer\s+)[a-z0-9._\-]+`)

func redact(s string) string {
	return redactBearerRe.ReplaceAllString(s, "$1<redacted>")
}
