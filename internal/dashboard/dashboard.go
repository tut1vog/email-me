// Package dashboard serves the operator's management UI: agents, tokens,
// policies, signing keys, recipients, audit log and settings. It is the only management
// interface; there is no management API or CLI.
package dashboard

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/units"
	"github.com/tut1vog/email-me/internal/upstream"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	sessionCookie = "email_me_session"
	maxFormBytes  = 64 << 10
)

type Deps struct {
	Config     *config.Config
	Store      *store.Store
	Recipients *recipients.Registry
	Keys       *keys.Manager
	Sender     upstream.Sender
	Log        *slog.Logger
}

type Server struct {
	Deps
	sessions *auth.Sessions
	throttle *auth.LoginThrottle
	pages    map[string]*template.Template
	now      func() time.Time

	smtpMu    sync.Mutex
	smtpCheck *smtpStatus

	argonSlots chan struct{}
}

type smtpStatus struct {
	At  time.Time
	OK  bool
	Err string
}

func New(d Deps) (*Server, error) {
	s := &Server{
		Deps:     d,
		sessions: auth.NewSessions(d.Config.Dashboard.SessionTTL.D()),
		// Backoff is capped at a minute: brute force against a ≥12-character
		// password is hopeless at that rate, and every local client shares
		// one address behind Docker's NAT, so long lockouts would let any
		// local process lock the operator out.
		throttle:   auth.NewLoginThrottle(5, time.Minute),
		argonSlots: make(chan struct{}, 2),
		pages:      map[string]*template.Template{},
		now:        time.Now,
	}
	all, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	// Files named _*.html are partials (icon sprite, shared fragments):
	// parsed into every page, never rendered as pages themselves.
	partials := []string{"templates/layout.html"}
	var pages []string
	for _, p := range all {
		switch base := strings.TrimPrefix(p, "templates/"); {
		case base == "layout.html":
		case strings.HasPrefix(base, "_"):
			partials = append(partials, p)
		default:
			pages = append(pages, p)
		}
	}
	fm := s.funcs()
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		t, err := template.New("layout.html").Funcs(fm).ParseFS(templateFS, append(partials[:len(partials):len(partials)], p)...)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", p, err)
		}
		s.pages[name] = t
	}
	return s, nil
}

// Handler returns the dashboard's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)

	authed := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireSession(h)) }
	authed("POST /logout", s.logout)
	authed("GET /{$}", s.overview)
	authed("GET /agents", s.agents)
	authed("GET /agents/new", s.newAgentPage)
	authed("POST /agents", s.createAgent)
	authed("GET /agents/{id}", s.agentOverview)
	authed("GET /agents/{id}/tokens", s.agentTokens)
	authed("GET /agents/{id}/policy", s.agentPolicy)
	authed("GET /agents/{id}/signing", s.agentSigning)
	authed("POST /agents/{id}", s.updateAgent)
	authed("POST /agents/{id}/policy", s.updatePolicy)
	authed("GET /agents/{id}/delete", s.deleteAgentPage)
	authed("POST /agents/{id}/delete", s.deleteAgent)
	authed("POST /agents/{id}/tokens", s.issueToken)
	authed("POST /agents/{id}/tokens/{tid}/revoke", s.revokeToken)
	authed("POST /agents/{id}/keys", s.createKey)
	authed("POST /agents/{id}/keys/rotate", s.rotateKey)
	authed("GET /agents/{id}/keys/{fpr}/public.asc", s.downloadPublicKey)
	authed("GET /agents/{id}/keys/{fpr}/revocation.asc", s.downloadRevocation)
	authed("GET /agents/{id}/keys/{fpr}/revocation-compromised.asc", s.downloadRevocationCompromised)
	authed("GET /recipients", s.recipients)
	authed("GET /recipients/new", s.newRecipientPage)
	authed("POST /recipients", s.createRecipient)
	authed("GET /recipients/{alias}", s.recipientPage)
	authed("POST /recipients/{alias}", s.updateRecipient)
	authed("GET /recipients/{alias}/delete", s.deleteRecipientPage)
	authed("POST /recipients/{alias}/delete", s.deleteRecipient)
	authed("GET /audit", s.auditPage)
	authed("GET /audit.csv", s.auditCSV)
	authed("GET /settings", s.settings)
	authed("POST /settings/test-smtp", s.testSMTP)
	authed("POST /settings/test-send", s.testSend)
	authed("GET /settings/guide", s.guidePreview)
	authed("GET /keys.asc", s.keyBundle)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin, not no-referrer: under no-referrer browsers send
		// "Origin: null" on the dashboard's own form POSTs, which sameOrigin
		// must reject. Nothing is sent to other origins either way.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.Method == http.MethodPost {
			if !s.sameOrigin(r) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
			// Dashboard forms are small; never buffer large or multipart bodies.
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin rejects cross-site POSTs using Origin (or Referer as fallback).
func (s *Server) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return true // non-browser client; CSRF token still required
		}
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		origin = u.Scheme + "://" + u.Host
	}
	if origin == "null" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

type ctxKey int

const sessionKey ctxKey = 0

func sessionFrom(r *http.Request) *auth.Session {
	sess, _ := r.Context().Value(sessionKey).(*auth.Session)
	return sess
}

func (s *Server) requireSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		var sess *auth.Session
		if err == nil {
			sess, _ = s.sessions.Get(c.Value)
		}
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "session expired; log in again", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if !sess.ValidCSRF(r.PostForm.Get("csrf")) {
				http.Error(w, "invalid CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", "Log in", map[string]any{"Next": safeNext(r.URL.Query().Get("next")), "Error": "", "SharedHost": sharedHostHint(r.Host)})
}

// sharedHostHint returns a dedicated-host URL suggestion when the dashboard
// is opened as plain localhost/127.0.0.1. Browsers send cookies for a host to
// every port on it, so a web server some local process runs on another port
// of the same host would receive the session cookie. A dedicated name such as
// email-me.localhost keeps the cookie away from other ports' hosts.
func sharedHostHint(host string) string {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h, port = host, ""
	}
	if !config.IsLoopbackHost(h) {
		return ""
	}
	u := "http://email-me.localhost"
	if port != "" {
		u += ":" + port
	}
	return u
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	// ParseForm (not FormValue) so multipart bodies are never parsed or spilled to disk.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostForm.Get("next"))
	// Begin counts the attempt before the expensive password check, so
	// parallel guesses cannot all slip past the throttle.
	if ok, wait := s.throttle.Begin(ip); !ok {
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "login", "Log in", map[string]any{"Next": next, "SharedHost": sharedHostHint(r.Host),
			"Error": fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", int(wait.Seconds())+1)})
		return
	}
	if !s.verifyPassword(r.Context(), r.PostForm.Get("password")) {
		s.Log.Warn("dashboard login failed", "ip", ip)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, "login", "Log in", map[string]any{"Next": next, "Error": "Wrong password.", "SharedHost": sharedHostHint(r.Host)})
		return
	}
	s.throttle.Success(ip)
	sess := s.sessions.Create()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.ID, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.Config.Dashboard.SessionTTL.D().Seconds()),
	})
	s.Log.Info("dashboard login", "ip", ip)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Delete(sessionFrom(r).ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// verifyPassword runs argon2id (64 MiB per check) under a small semaphore so
// concurrent login attempts cannot exhaust memory.
func (s *Server) verifyPassword(ctx context.Context, password string) bool {
	select {
	case s.argonSlots <- struct{}{}:
		defer func() { <-s.argonSlots }()
	case <-ctx.Done():
		return false
	}
	return auth.VerifyPassword(s.Config.Dashboard.AdminPasswordHash, password)
}

// safeNext only allows local paths as post-login redirects: no scheme, no
// host, no "//" or backslash tricks, and no control characters (browsers
// strip tabs and newlines, turning "/\t/evil.com" into "//evil.com").
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	for _, c := range next {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return next
}

type page struct {
	Title    string
	Nav      string // page (template) name; agent tabs highlight by it
	Section  string // sidebar section the page belongs to
	CSRF     string
	Flash    []auth.Flash
	LoggedIn bool
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	p := page{Title: title, Nav: name, Section: sectionOf(name), Data: data}
	if sess := sessionFrom(r); sess != nil {
		p.CSRF, p.Flash, p.LoggedIn = sess.CSRF, sess.PopFlash(), true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, p); err != nil {
		s.Log.Error("rendering dashboard page", "page", name, "err", err)
	}
}

// sectionOf maps a page template to the sidebar section it highlights.
func sectionOf(name string) string {
	switch name {
	case "overview":
		return "overview"
	case "agents", "agent", "agent_tokens", "agent_policy", "agent_signing", "agent_new", "agent_delete", "token":
		return "agents"
	case "recipients", "recipient_new", "recipient", "recipient_delete":
		return "recipients"
	case "audit":
		return "audit"
	case "settings", "guide":
		return "settings"
	}
	return ""
}

func (s *Server) flash(r *http.Request, kind, format string, args ...any) {
	if sess := sessionFrom(r); sess != nil {
		sess.AddFlash(kind, fmt.Sprintf(format, args...))
	}
}

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, path string) {
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	s.Log.Error(what, "err", err)
	http.Error(w, "internal error: "+what, http.StatusInternalServerError)
}

// funcs returns the template functions. until reads s.now at render time,
// so tests that pin the clock get deterministic relative times.
func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"ts":       ts,
		"until":    func(t any) string { return relTime(t, s.now()) },
		"bytesize": bytesize,
		"short": func(s string) string {
			if len(s) > 16 {
				return s[len(s)-16:]
			}
			return s
		},
		"join": strings.Join,
		"add":  func(a, b int) int { return a + b },
		"sub":  func(a, b int) int { return a - b },
		"has": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
	}
}

func ts(t any) string {
	switch v := t.(type) {
	case time.Time:
		if v.IsZero() {
			return "—"
		}
		return v.UTC().Format("2006-01-02 15:04 UTC")
	case *time.Time:
		if v == nil {
			return "—"
		}
		return v.UTC().Format("2006-01-02 15:04 UTC")
	}
	return "—"
}

// bytesize formats a byte count the way config.yaml writes it ("10MiB").
func bytesize(v any) string {
	switch n := v.(type) {
	case int64:
		return units.ByteSize(n).String()
	case int:
		return units.ByteSize(n).String()
	case units.ByteSize:
		return n.String()
	case *units.ByteSize:
		if n == nil {
			return ""
		}
		return n.String()
	}
	return fmt.Sprint(v)
}

// relTime describes t relative to now: "in 12 days", "3 hours ago",
// "just now". It returns "" for a zero time or nil pointer.
func relTime(t any, now time.Time) string {
	var at time.Time
	switch v := t.(type) {
	case time.Time:
		at = v
	case *time.Time:
		if v == nil {
			return ""
		}
		at = *v
	default:
		return ""
	}
	if at.IsZero() {
		return ""
	}
	d := at.Sub(now)
	future := d > 0
	if !future {
		d = -d
	}
	var n int
	var unit string
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		n, unit = int(d/time.Minute), "minute"
	case d < 48*time.Hour:
		n, unit = int(d/time.Hour), "hour"
	case d < 60*24*time.Hour:
		n, unit = int(d/(24*time.Hour)), "day"
	case d < 730*24*time.Hour:
		n, unit = int(d/(30*24*time.Hour)), "month"
	default:
		n, unit = int(d/(365*24*time.Hour)), "year"
	}
	if n != 1 {
		unit += "s"
	}
	if future {
		return fmt.Sprintf("in %d %s", n, unit)
	}
	return fmt.Sprintf("%d %s ago", n, unit)
}
