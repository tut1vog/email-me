package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/tut1vog/email-me/internal/api"
	"github.com/tut1vog/email-me/internal/api/docs"
	"github.com/tut1vog/email-me/internal/audit"
	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/ratelimit"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/upstream"
)

func init() {
	raw := func(r io.Reader, _ http.Header, _ *openapi3.SchemaRef, _ openapi3filter.EncodingFn) (any, error) {
		b, err := io.ReadAll(r)
		return string(b), err
	}
	openapi3filter.RegisterBodyDecoder("text/markdown", raw)
	openapi3filter.RegisterBodyDecoder("application/pgp-keys", raw)
}

type harness struct {
	t        *testing.T
	env      *testutil.Env
	st       *store.Store
	settings *settings.Manager
	keys     *keys.Manager
	ts       *httptest.Server
	router   routers.Router
	logs     *syncBuffer
	srv      *api.Server
	// unchecked are agents the API sees although validation would refuse
	// them, to test the API's own guards.
	unchecked map[string]*config.Agent
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func loadSpec(t testing.TB) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(docs.OpenAPIYAML())
	if err != nil {
		t.Fatalf("loading openapi.yaml: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("openapi.yaml is not a valid OpenAPI document: %v", err)
	}
	return doc
}

func newHarness(t *testing.T, o testutil.Options) *harness {
	t.Helper()
	env := testutil.NewEnv(t, o)
	st, sm := testutil.Bootstrap(t, env)
	h := &harness{t: t, env: env, st: st, settings: sm, unchecked: map[string]*config.Agent{}}
	current := func() *config.Config {
		c := sm.Current()
		if len(h.unchecked) == 0 {
			return c
		}
		cp := *c
		cp.Agents = maps.Clone(c.Agents)
		maps.Copy(cp.Agents, h.unchecked)
		return &cp
	}
	km := testutil.Keys(t, env, st, sm)
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := api.New(api.Deps{
		Config: current, Store: st, Keys: km,
		Sender:  upstream.NewDynamic(func() config.SMTP { return sm.Current().Upstream.SMTP }),
		Limiter: ratelimit.New(st), Audit: audit.NewWriter(st, func() bool { return sm.Current().Audit.LogSubject }, log), Log: log,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	doc := loadSpec(t)
	doc.Servers = openapi3.Servers{{URL: ts.URL}}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatal(err)
	}
	h.keys, h.ts, h.router, h.logs, h.srv = km, ts, router, logs, srv
	return h
}

func ptr[T any](v T) *T { return &v }

// agent creates an agent (with a signing key when signing is configured) and a token.
func (h *harness) agent(name string, p policy.Policy) (*config.Agent, string) {
	h.t.Helper()
	a := testutil.AddAgent(h.t, h.settings, name, p)
	if h.keys.Enabled() {
		if _, err := h.keys.Create(context.Background(), a.Name); err != nil {
			h.t.Fatal(err)
		}
	}
	return a, h.token(a, nil, nil)
}

// uncheckedAgent adds an agent that validation would refuse, with a token.
func (h *harness) uncheckedAgent(name string, p policy.Policy) string {
	h.t.Helper()
	a := &config.Agent{Name: name, Policy: p}
	h.unchecked[name] = a
	if h.keys.Enabled() {
		if _, err := h.keys.Create(context.Background(), name); err != nil {
			h.t.Fatal(err)
		}
	}
	return h.token(a, nil, nil)
}

// putAgent replaces an agent in the configuration, as the dashboard does.
func (h *harness) putAgent(a *config.Agent) {
	h.t.Helper()
	if _, err := h.settings.PutAgent(context.Background(), a, false); err != nil {
		h.t.Fatal(err)
	}
}

// putRecipient adds or replaces a recipient, as the dashboard does.
func (h *harness) putRecipient(in recipients.Input, create bool) {
	h.t.Helper()
	cur, _ := h.settings.Current().Recipient(in.Alias)
	r, err := recipients.Validate(in, cur, time.Now())
	if err == nil {
		_, err = h.settings.PutRecipient(context.Background(), r, create)
	}
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) token(a *config.Agent, cidrs []string, expires *time.Time) string {
	h.t.Helper()
	tok, id, hash := auth.NewToken()
	if err := h.st.CreateToken(context.Background(), &store.Token{ID: id, Agent: a.Name, SecretHash: hash, AllowedCIDRs: cidrs, CreatedAt: time.Now(), ExpiresAt: expires}); err != nil {
		h.t.Fatal(err)
	}
	return tok
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("response is not JSON (%d): %s", r.status, r.body)
	}
	return m
}

func (r resp) code(t *testing.T) string {
	t.Helper()
	c, _ := r.json(t)["error"].(string)
	return c
}

// do sends a request and validates the response against openapi.yaml.
func (h *harness) do(method, path, token string, body any, mods ...func(*http.Request)) resp {
	h.t.Helper()
	var rb []byte
	switch b := body.(type) {
	case nil:
	case string:
		rb = []byte(b)
	case []byte:
		rb = b
	default:
		rb, _ = json.Marshal(b)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(rb))
	if err != nil {
		h.t.Fatal(err)
	}
	if rb != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mods {
		m(req)
	}
	res, err := h.ts.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	r := resp{status: res.StatusCode, header: res.Header, body: out}
	h.validate(method, path, rb, r)
	return r
}

func (h *harness) validate(method, path string, reqBody []byte, r resp) {
	h.t.Helper()
	vreq, _ := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(reqBody))
	vreq.Header.Set("Content-Type", "application/json")
	route, params, err := h.router.FindRoute(vreq)
	if err != nil {
		if r.status == http.StatusNotFound || r.status == http.StatusMethodNotAllowed {
			return // undocumented paths/methods
		}
		h.t.Errorf("%s %s returned %d but is not in openapi.yaml: %v", method, path, r.status, err)
		return
	}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request: vreq, PathParams: params, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		},
		Status:  r.status,
		Header:  r.header,
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	in.SetBodyBytes(r.body)
	if err := openapi3filter.ValidateResponse(context.Background(), in); err != nil {
		h.t.Errorf("%s %s → %d does not match openapi.yaml: %v\nbody: %s", method, path, r.status, err, r.body)
	}
}

func (h *harness) auditRows(agent string) []*store.AuditEntry {
	h.t.Helper()
	rows, err := h.st.ListAudit(context.Background(), store.AuditFilter{Agent: agent})
	if err != nil {
		h.t.Fatal(err)
	}
	return rows
}

func withHost(host string) func(*http.Request) {
	return func(r *http.Request) { r.Host = host }
}

func msg(to string, subject string, md string) map[string]any {
	return map[string]any{"to": []string{to}, "subject": subject, "body": map[string]any{"markdown": md}}
}

func hasString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func mustContain(t *testing.T, s string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			t.Errorf("expected %q in:\n%s", sub, s)
		}
	}
}
