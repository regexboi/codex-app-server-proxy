package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mishca/codex-app-server-proxy/internal/auth"
	"github.com/mishca/codex-app-server-proxy/internal/policy"
	"github.com/mishca/codex-app-server-proxy/internal/probe"
	"github.com/mishca/codex-app-server-proxy/internal/session"
)

type Server struct {
	auth    *auth.Authenticator
	policy  *policy.Engine
	sess    *session.Manager
	probe   *probe.Checker
	logger  *log.Logger
	handler http.Handler
}

func New(authn *auth.Authenticator, policyEngine *policy.Engine, sessMgr *session.Manager, readyProbe *probe.Checker, logger *log.Logger) *Server {
	s := &Server{
		auth:   authn,
		policy: policyEngine,
		sess:   sessMgr,
		probe:  readyProbe,
		logger: logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/v1/sessions", s.handleSessionsRoot)
	mux.HandleFunc("/v1/sessions/", s.handleSessionSubroutes)
	s.handler = withLogging(mux, logger)
	return s
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	status := s.probe.Ready(r.Context())
	if status.Ready {
		writeJSON(w, http.StatusOK, status)
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, status)
}

func (s *Server) handleSessionsRoot(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	_ = principal

	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}

	session, err := s.sess.Create()
	if err != nil {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": map[string]any{"code": "session_create_failed", "message": err.Error()},
		})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"sessionId": session.ID()})
}

func (s *Server) handleSessionSubroutes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "missing session id"}})
		return
	}
	sessionID := parts[0]

	sess, exists := s.sess.Get(sessionID)
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "session_not_found", "message": "unknown session"}})
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, http.MethodDelete)
			return
		}
		s.sess.Delete(sessionID)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		return
	}

	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "invalid session route"}})
		return
	}

	switch parts[1] {
	case "events":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		s.handleEvents(w, r, sess)
	case "rpc":
		if r.Method != http.MethodPost {
			writeMethodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleRPC(w, r, principal, sess)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "not_found", "message": "invalid session route"}})
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": map[string]any{"code": "sse_unavailable", "message": "streaming unsupported"}})
		return
	}

	lastEventID := parseLastEventID(r)
	events, unsubscribe := sess.Subscribe(lastEventID)
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepAlive.C:
			_, _ = io.WriteString(w, ": ping\n\n")
			flusher.Flush()
		case ev, ok := <-events:
			if !ok {
				return
			}
			_, _ = io.WriteString(w, fmt.Sprintf("id: %d\n", ev.ID))
			_, _ = io.WriteString(w, "event: message\n")
			for _, line := range splitSSEDataLines(ev.Data) {
				_, _ = io.WriteString(w, "data: "+line+"\n")
			}
			_, _ = io.WriteString(w, "\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request, principal auth.Principal, sess *session.Session) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "bad_request", "message": "failed to read body"}})
		return
	}

	var msg map[string]any
	if err := json.Unmarshal(body, &msg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_json", "message": "body must be a JSON object"}})
		return
	}

	dangerRequested := strings.EqualFold(r.Header.Get("X-Codex-Danger"), "true")
	rewritten, err := s.policy.RewriteInbound(msg, principal, dangerRequested)
	if err != nil {
		var policyErr *policy.PolicyError
		if errors.As(err, &policyErr) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": map[string]any{
					"code":    "policy_denied",
					"message": policyErr.Error(),
				},
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": err.Error()}})
		return
	}

	payload, err := json.Marshal(rewritten)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "invalid_request", "message": "unable to encode rewritten message"}})
		return
	}
	if err := sess.Send(payload); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": map[string]any{"code": "upstream_write_failed", "message": err.Error()}})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": true})
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (auth.Principal, bool) {
	principal, ok := s.auth.AuthenticateHeader(r.Header.Get("Authorization"))
	if ok {
		return principal, true
	}
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error": map[string]any{"code": "unauthorized", "message": "invalid API key"},
	})
	return auth.Principal{}, false
}

func parseLastEventID(r *http.Request) int64 {
	if q := r.URL.Query().Get("lastEventId"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil {
			return v
		}
	}
	if h := r.Header.Get("Last-Event-ID"); h != "" {
		if v, err := strconv.ParseInt(h, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

func splitSSEDataLines(v string) []string {
	scanner := bufio.NewScanner(strings.NewReader(v))
	lines := make([]string, 0, 1)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
		"error": map[string]any{"code": "method_not_allowed", "message": "method not allowed"},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func withLogging(next http.Handler, logger *log.Logger) http.Handler {
	if logger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		logger.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(started).Round(time.Millisecond))
	})
}
