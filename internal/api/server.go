// Package api serves the agent-facing REST API and discovery documents.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/api/docs"
	"github.com/tut1vog/email-me/internal/audit"
	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/idempotency"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/ratelimit"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/upstream"
)

type Deps struct {
	// Config returns the current configuration. Saved changes replace it,
	// so a request reads it once (caller.cfg) and uses that snapshot
	// throughout.
	Config  func() *config.Config
	Store   *store.Store
	Keys    *keys.Manager
	Sender  upstream.Sender
	Limiter *ratelimit.Limiter
	Audit   *audit.Writer
	Log     *slog.Logger
}

type Server struct {
	Deps
	idem *idempotency.Cache
	now  func() time.Time

	busyMu sync.Mutex
	busy   map[string]int // in-flight send requests per agent
}

// maxConcurrentSends bounds per-agent memory: each send may buffer a
// max_message_bytes request several times over (JSON, decoded attachments,
// MIME encodings), so concurrency is capped before the body is read.
const maxConcurrentSends = 4

// acquireSend claims one of the agent's concurrent send slots.
func (s *Server) acquireSend(agent string) (release func(), ok bool) {
	s.busyMu.Lock()
	defer s.busyMu.Unlock()
	if s.busy[agent] >= maxConcurrentSends {
		return nil, false
	}
	s.busy[agent]++
	return func() {
		s.busyMu.Lock()
		defer s.busyMu.Unlock()
		if s.busy[agent]--; s.busy[agent] <= 0 {
			delete(s.busy, agent)
		}
	}, true
}

func New(d Deps) *Server {
	return &Server{
		Deps: d,
		idem: idempotency.New(24 * time.Hour),
		now:  time.Now,
		busy: map[string]int{},
	}
}

// Handler returns the API's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("GET /{$}", s.docsAuth(http.HandlerFunc(s.handleGuide)))
	mux.Handle("GET /llms.txt", s.docsAuth(http.HandlerFunc(s.handleGuide)))
	mux.Handle("GET /openapi.json", s.docsAuth(http.HandlerFunc(s.handleOpenAPI)))
	mux.Handle("GET /v1/capabilities", s.requireAgent(http.HandlerFunc(s.handleCapabilities)))
	mux.Handle("GET /v1/recipients/{alias}/pgp-key", s.requireAgent(http.HandlerFunc(s.handleRecipientKey)))
	mux.Handle("POST /v1/messages", s.requireAgent(http.HandlerFunc(s.handleSend)))
	for _, p := range []string{"/{$}", "/healthz", "/llms.txt", "/openapi.json", "/v1/capabilities", "/v1/recipients/{alias}/pgp-key", "/v1/messages"} {
		mux.HandleFunc(p, methodNotAllowed)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, newErr(http.StatusNotFound, CodeNotFound, "No such endpoint: %s %s. See GET / for usage.", r.Method, r.URL.Path))
	})
	return s.middleware(mux)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	writeError(w, newErr(http.StatusMethodNotAllowed, CodeMethodNotAllowed, "Method %s is not allowed on %s. See GET / for usage.", r.Method, r.URL.Path))
}

type ctxKey int

const callerKey ctxKey = 0

// caller is an authenticated agent request.
type caller struct {
	cfg       *config.Config // the configuration this request runs with
	token     *store.Token
	agent     *config.Agent
	policy    policy.Effective
	ip        netip.Addr
	transport string
}

func callerFrom(r *http.Request) *caller {
	c, _ := r.Context().Value(callerKey).(*caller)
	return c
}

// authenticate validates the bearer token and loads the agent and policy.
func (s *Server) authenticate(r *http.Request) (*caller, *apiError) {
	unauthorized := newErr(http.StatusUnauthorized, CodeUnauthorized,
		"Invalid, expired or revoked token. Send 'Authorization: Bearer <token>' with the token your operator gave you; if it still fails, ask your operator for a new token.")
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if h == "" || !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, newErr(http.StatusUnauthorized, CodeUnauthorized,
			"Missing bearer token. Send 'Authorization: Bearer <token>' with the token your operator gave you. See GET / for usage.")
	}
	id, secret, err := auth.ParseToken(tok)
	if err != nil {
		return nil, unauthorized
	}
	t, err := s.Store.GetToken(r.Context(), id)
	if err != nil || !auth.SecretMatches(secret, t.SecretHash) || !t.Active(s.now()) {
		return nil, unauthorized
	}
	// A token whose agent is no longer in config.yaml is inert.
	cfg := s.Config()
	a, ok := cfg.Agent(t.Agent)
	if !ok {
		return nil, unauthorized
	}
	n := newNetInfo(cfg)
	c := &caller{cfg: cfg, token: t, agent: a, ip: n.ClientIP(r), transport: n.Transport(r)}
	if !a.Enabled() {
		return c, newErr(http.StatusForbidden, CodeAgentDisabled, "Agent %q is disabled by the operator. Stop sending and tell your operator.", a.Name)
	}
	if len(t.AllowedCIDRs) > 0 && !ipAllowed(c.ip, t.AllowedCIDRs) {
		return c, newErr(http.StatusForbidden, CodeSourceIPNotAllowed,
			"Requests with this token are not allowed from %s. Ask your operator to allow this address.", c.ip)
	}
	c.policy = cfg.Effective(a.Policy)
	if err := s.Store.TouchToken(r.Context(), t.ID, c.ip.String(), s.now()); err != nil {
		s.Log.Warn("recording token use", "err", err, "token_id", t.ID)
	}
	return c, nil
}

func ipAllowed(ip netip.Addr, cidrs []string) bool {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
		if a, err := netip.ParseAddr(c); err == nil && a == ip {
			return true
		}
	}
	return false
}

func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := s.authenticate(r)
		if e != nil {
			if c != nil && r.Method == http.MethodPost {
				s.Audit.Record(r.Context(), &store.AuditEntry{
					Agent: c.agent.Name, TokenID: c.token.ID, SourceIP: c.ip.String(), Transport: c.transport,
					Status: store.StatusRejected, ErrorCode: e.Code,
				})
			}
			writeError(w, e)
			return
		}
		if lw, ok := w.(*logWriter); ok {
			lw.agent = c.agent.Name
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey, c)))
	})
}

// docsAuth enforces api.docs: authenticated. It is checked per request,
// so a saved change applies to the next one.
func (s *Server) docsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Config().API.Docs == "authenticated" {
			if _, e := s.authenticate(r); e != nil {
				writeError(w, newErr(http.StatusUnauthorized, CodeUnauthorized,
					"This gateway requires 'Authorization: Bearer <token>' to read its documentation. Use the token your operator gave you."))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Write([]byte(docs.Guide(baseURL(r, s.Config()))))
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(docs.OpenAPIJSON(baseURL(r, s.Config())))
}

// baseURL is the API's base URL for a request, under cfg.
func baseURL(r *http.Request, cfg *config.Config) string {
	n := newNetInfo(cfg)
	return n.BaseURL(r, cfg.API.PublicURL)
}

type recipientCap struct {
	Alias               string `json:"alias"`
	Description         string `json:"description"`
	EncryptionAvailable bool   `json:"encryption_available"`
	EncryptionRequired  bool   `json:"encryption_required"`
}

type limitsCap struct {
	MaxMessageBytes        int64    `json:"max_message_bytes"`
	MaxAttachments         int      `json:"max_attachments"`
	AllowedAttachmentTypes []string `json:"allowed_attachment_types"`
	RemainingThisHour      int      `json:"remaining_this_hour"`
	RemainingToday         int      `json:"remaining_today"`
}

type signingCap struct {
	Available   bool   `json:"available"`
	Required    bool   `json:"required"`
	Default     bool   `json:"default"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type capabilities struct {
	Agent         string         `json:"agent"`
	Recipients    []recipientCap `json:"recipients"`
	Services      []string       `json:"services"`
	Limits        limitsCap      `json:"limits"`
	SubjectPrefix string         `json:"subject_prefix"`
	Signing       signingCap     `json:"signing"`
	E2EAvailable  bool           `json:"e2e_available"`
	Transport     string         `json:"transport"`
}

// signingStatus reports whether the agent's active key can sign right now.
func (s *Server) signingStatus(ctx context.Context, agent string) (available bool, fpr string) {
	if !s.Keys.Enabled() {
		return false, ""
	}
	k, err := s.Keys.ActiveKey(ctx, agent)
	if err != nil {
		return false, ""
	}
	return s.now().Before(k.ExpiresAt), k.Fingerprint
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	p := c.policy
	var rcpts []recipientCap
	for _, alias := range p.Recipients {
		rc, ok := c.cfg.Recipient(alias)
		if !ok {
			continue // not reached: the policy was resolved against c.cfg
		}
		rcpts = append(rcpts, recipientCap{
			Alias:               alias,
			Description:         rc.Description,
			EncryptionAvailable: rc.KeyUsable(s.now()),
			EncryptionRequired:  rc.RequireEncryption || p.RequireEncryption,
		})
	}
	if rcpts == nil {
		rcpts = []recipientCap{}
	}
	hour, day, err := s.Limiter.Remaining(r.Context(), c.agent.Name, p.RateLimit)
	if err != nil {
		s.internal(w, "computing rate limits", err)
		return
	}
	avail, fpr := s.signingStatus(r.Context(), c.agent.Name)
	hasSign := p.HasService(policy.SvcSign)
	services := make([]string, 0, len(p.Services))
	for _, svc := range policy.AllServices {
		if p.HasService(svc) {
			services = append(services, svc)
		}
	}
	writeJSON(w, http.StatusOK, capabilities{
		Agent:         c.agent.Name,
		Recipients:    rcpts,
		Services:      services,
		SubjectPrefix: p.Prefix(c.agent.Name),
		Limits: limitsCap{
			MaxMessageBytes:        p.MaxMessageBytes,
			MaxAttachments:         p.MaxAttachments,
			AllowedAttachmentTypes: nonNil(p.AllowedAttachmentTypes),
			RemainingThisHour:      hour,
			RemainingToday:         day,
		},
		Signing: signingCap{
			Available:   avail && hasSign,
			Required:    p.RequireSigning,
			Default:     avail && hasSign,
			Fingerprint: fpr,
		},
		E2EAvailable: p.HasService(policy.SvcE2E) && !p.RequireSigning,
		Transport:    c.transport,
	})
}

func (s *Server) handleRecipientKey(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	alias := r.PathValue("alias")
	if !c.policy.HasService(policy.SvcE2E) {
		writeError(w, newErr(http.StatusForbidden, CodeServiceNotAllowed,
			"Fetching recipient keys requires the e2e service, which this agent does not have.").with("service", policy.SvcE2E))
		return
	}
	rc, ok := c.cfg.Recipient(alias)
	if !ok || !c.policy.AllowsRecipient(alias) {
		writeError(w, newErr(http.StatusForbidden, CodeRecipientNotAllow,
			"Recipient alias %q is not permitted for this agent. Allowed: %s.", alias, strings.Join(c.policy.Recipients, ", ")).
			with("allowed", nonNil(c.policy.Recipients)))
		return
	}
	if rc.Key == nil {
		writeError(w, newErr(http.StatusNotFound, CodeNotFound, "Recipient %q has no PGP public key configured, so it cannot receive encrypted mail.", alias))
		return
	}
	if !rc.KeyUsable(s.now()) {
		writeError(w, newErr(http.StatusServiceUnavailable, CodeEncryptionUnavail,
			"Recipient %q's PGP key has expired or been revoked. Tell your operator to update it; do not retry.", alias))
		return
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("X-Email-Me-Key-Fingerprint", rc.Fingerprint())
	w.Write([]byte(rc.PGPPublicKey))
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.Log.Error(what, "err", err)
	writeError(w, newErr(http.StatusInternalServerError, CodeInternal, "Internal error. Retry later; if it persists, tell your operator."))
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// middleware adds security headers, panic recovery and request logging
// (method, path, status, duration, agent — never bodies or tokens).
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &logWriter{ResponseWriter: w, status: http.StatusOK}
		h := lw.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.Log.Error("panic in API handler", "panic", fmt.Sprint(rec), "path", r.URL.Path)
				if !lw.wrote {
					writeError(lw, newErr(http.StatusInternalServerError, CodeInternal, "Internal error. Retry later; if it persists, tell your operator."))
				}
			}
			s.Log.Info("api request", "method", r.Method, "path", r.URL.Path, "status", lw.status,
				"duration_ms", time.Since(start).Milliseconds(), "agent", lw.agent)
		}()
		next.ServeHTTP(lw, r)
	})
}

type logWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	agent  string
}

func (l *logWriter) WriteHeader(code int) {
	if !l.wrote {
		l.status, l.wrote = code, true
	}
	l.ResponseWriter.WriteHeader(code)
}

func (l *logWriter) Write(b []byte) (int, error) {
	l.wrote = true
	return l.ResponseWriter.Write(b)
}

func (l *logWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }
