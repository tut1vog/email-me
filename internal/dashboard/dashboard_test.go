package dashboard_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/dashboard"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/upstream"
)

type dash struct {
	t        *testing.T
	env      *testutil.Env
	st       *store.Store
	reg      *recipients.Registry
	settings *settings.Manager
	keys     *keys.Manager
	ts       *httptest.Server
	c        *http.Client
}

func newDash(t *testing.T, o testutil.Options) *dash {
	t.Helper()
	env := testutil.NewEnv(t, o)
	cfg := env.Config
	st := testutil.OpenStore(t, env)
	sm := testutil.BootstrapSettings(t, env, st)
	reg, _, err := recipients.Bootstrap(context.Background(), st, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ko := keys.Options{Email: cfg.Upstream.From}
	if cfg.Signing != nil {
		ko.KEK, ko.Validity = cfg.Signing.KEK, cfg.Signing.KeyValidity.D()
	}
	km := keys.NewManager(st, ko)
	srv, err := dashboard.New(dashboard.Deps{Config: cfg, Store: st, Recipients: reg, Keys: km, Sender: upstream.NewSMTP(cfg.Upstream.SMTP), Log: testutil.DiscardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &dash{t: t, env: env, st: st, reg: reg, settings: sm, keys: km, ts: ts, c: c}
}

type page struct {
	status int
	header http.Header
	body   string
}

func (d *dash) get(path string) page {
	d.t.Helper()
	res, err := d.c.Get(d.ts.URL + path)
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return page{res.StatusCode, res.Header, string(b)}
}

func (d *dash) post(path string, form url.Values, mods ...func(*http.Request)) page {
	d.t.Helper()
	req, _ := http.NewRequest("POST", d.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", d.ts.URL)
	for _, m := range mods {
		m(req)
	}
	res, err := d.c.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return page{res.StatusCode, res.Header, string(b)}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (d *dash) csrf() string {
	d.t.Helper()
	m := csrfRe.FindStringSubmatch(d.get("/settings").body)
	if m == nil {
		d.t.Fatal("no CSRF token on page")
	}
	return m[1]
}

func (d *dash) login() {
	d.t.Helper()
	p := d.post("/login", url.Values{"password": {d.env.AdminPW}, "next": {"/"}})
	if p.status != http.StatusSeeOther {
		d.t.Fatalf("login: %d %s", p.status, p.body)
	}
}

func (d *dash) form(kv ...string) url.Values {
	v := url.Values{"csrf": {d.csrf()}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v
}

var agentLocRe = regexp.MustCompile(`^/agents/(ag_[^/]+)`)

func (d *dash) createAgent(name string, recipients ...string) *store.Agent {
	d.t.Helper()
	f := d.form("name", name, "description", "test agent")
	for _, r := range recipients {
		f.Add("recipients", r)
	}
	p := d.post("/agents", f)
	m := agentLocRe.FindStringSubmatch(p.header.Get("Location"))
	if p.status != http.StatusSeeOther || m == nil {
		d.t.Fatalf("create agent: %d %s", p.status, p.header.Get("Location"))
	}
	a, err := d.st.GetAgent(context.Background(), m[1])
	if err != nil {
		d.t.Fatal(err)
	}
	return a
}

func TestLoginRequiredAndHeaders(t *testing.T) {
	d := newDash(t, testutil.Options{})
	p := d.get("/agents")
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/login?next=%2Fagents" {
		t.Fatalf("unauthenticated: %d %s", p.status, p.header.Get("Location"))
	}
	lp := d.get("/login")
	for h, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"} {
		if lp.header.Get(h) != want {
			t.Errorf("%s = %q", h, lp.header.Get(h))
		}
	}
	if csp := lp.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	if s := d.get("/static/style.css"); s.status != 200 {
		t.Fatal("static assets must be served without login")
	}
	if strings.Contains(lp.body, "<script>") || strings.Contains(lp.body, "onclick") {
		t.Fatal("no inline scripts (CSP)")
	}
}

func TestLoginFlowAndThrottle(t *testing.T) {
	d := newDash(t, testutil.Options{})
	for i := 0; i < 5; i++ {
		if p := d.post("/login", url.Values{"password": {"wrong"}}); p.status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, p.status)
		}
	}
	if p := d.post("/login", url.Values{"password": {d.env.AdminPW}}); p.status != http.StatusTooManyRequests {
		t.Fatalf("throttled login must be refused even with the right password: %d", p.status)
	}

	d2 := newDash(t, testutil.Options{})
	p := d2.post("/login", url.Values{"password": {d2.env.AdminPW}, "next": {"//evil.example/"}})
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/" {
		t.Fatalf("open redirect: %s", p.header.Get("Location"))
	}
	cookie := p.header.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie lacks %s: %s", want, cookie)
		}
	}
	home := d2.get("/")
	if home.status != 200 || !strings.Contains(home.body, "Create your first agent") {
		t.Fatalf("first-run overview: %d", home.status)
	}
	d2.post("/logout", d2.form())
	if p := d2.get("/"); p.status != http.StatusSeeOther {
		t.Fatal("logout must end the session")
	}
}

func TestCSRFAndOrigin(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	if p := d.post("/agents", url.Values{"name": {"x"}}); p.status != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", p.status)
	}
	if p := d.post("/agents", url.Values{"name": {"x"}, "csrf": {"forged"}}); p.status != http.StatusForbidden {
		t.Fatalf("wrong CSRF: %d", p.status)
	}
	evil := func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }
	if p := d.post("/agents", d.form("name", "x"), evil); p.status != http.StatusForbidden {
		t.Fatalf("cross-origin: %d", p.status)
	}
	agents, _ := d.st.ListAgents(context.Background())
	if len(agents) != 0 {
		t.Fatal("no agent may be created by rejected requests")
	}
}

var tokenRe = regexp.MustCompile(`em_[a-z2-7]{12}_[a-z2-7]{52}`)

func TestAgentTokenAndKeyLifecycle(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	ctx := context.Background()

	if p := d.post("/agents", d.form("name", "Bad Name")); p.header.Get("Location") != "/agents/new" {
		t.Fatal("invalid name must be rejected")
	}
	a := d.createAgent("bench", "me")
	if a.Policy.Recipients == nil || (*a.Policy.Recipients)[0] != "me" {
		t.Fatalf("recipients not saved: %+v", a.Policy)
	}
	k1, err := d.st.ActiveKey(ctx, a.ID)
	if err != nil {
		t.Fatal("agent must get a signing key on creation")
	}
	ap := d.get("/agents/" + a.ID)
	if ap.status != 200 || !strings.Contains(ap.body, k1.Fingerprint) || !strings.Contains(ap.body, "Agent bench created") {
		t.Fatalf("agent page: %d", ap.status)
	}
	if p := d.post("/agents", d.form("name", "bench")); !strings.Contains(d.get("/agents/new").body, "already exists") || p.status != http.StatusSeeOther {
		t.Fatal("duplicate names must be rejected")
	}

	// Issue a token: shown once, and it authenticates.
	tp := d.post("/agents/"+a.ID+"/tokens", d.form("label", "build-02", "expires_days", "30", "cidrs", "10.0.0.0/8, 192.168.1.5"))
	tok := tokenRe.FindString(tp.body)
	if tp.status != 200 || tok == "" || !strings.Contains(tp.body, "EMAIL_ME_TOKEN") || !strings.Contains(tp.body, "GET the base URL") {
		t.Fatalf("token page: %d", tp.status)
	}
	id, secret, _ := auth.ParseToken(tok)
	st, err := d.st.GetToken(ctx, id)
	if err != nil || !auth.SecretMatches(secret, st.SecretHash) || st.Label != "build-02" || st.ExpiresAt == nil ||
		strings.Join(st.AllowedCIDRs, ",") != "10.0.0.0/8,192.168.1.5/32" {
		t.Fatalf("stored token: %+v %v", st, err)
	}
	if strings.Contains(d.get("/agents/"+a.ID).body, secret) {
		t.Fatal("token secret must never be shown again")
	}
	if p := d.post("/agents/"+a.ID+"/tokens", d.form("cidrs", "not-an-ip")); p.status != http.StatusSeeOther {
		t.Fatal("bad CIDR must be rejected with a flash")
	}
	d.post("/agents/"+a.ID+"/tokens/"+id+"/revoke", d.form())
	st, _ = d.st.GetToken(ctx, id)
	if st.RevokedAt == nil {
		t.Fatal("token must be revoked")
	}

	// Keys: download, rotate, revocation certificates.
	pub := d.get("/agents/" + a.ID + "/keys/" + k1.Fingerprint + "/public.asc")
	if pub.status != 200 || !strings.Contains(pub.body, "BEGIN PGP PUBLIC KEY BLOCK") || strings.Contains(pub.body, "PRIVATE") ||
		!strings.Contains(pub.header.Get("Content-Disposition"), "bench-") {
		t.Fatalf("public key download: %d", pub.status)
	}
	d.post("/agents/"+a.ID+"/keys/rotate", d.form())
	k2, _ := d.st.ActiveKey(ctx, a.ID)
	if k2.Fingerprint == k1.Fingerprint {
		t.Fatal("rotation must change the key")
	}
	for _, kind := range []string{"revocation.asc", "revocation-compromised.asc"} {
		if rev := d.get("/agents/" + a.ID + "/keys/" + k1.Fingerprint + "/" + kind); rev.status != 200 || !strings.Contains(rev.body, "Revocation certificate") {
			t.Fatalf("retired key %s: %d", kind, rev.status)
		}
	}
	other := d.createAgent("other")
	if p := d.get("/agents/" + other.ID + "/keys/" + k2.Fingerprint + "/public.asc"); p.status != 404 {
		t.Fatal("keys must only be served under their own agent")
	}
	if b := d.get("/keys.asc"); strings.Count(b.body, "BEGIN PGP PUBLIC KEY BLOCK") != 3 {
		t.Fatalf("bundle should hold 3 keys (2 for bench, 1 for other), got %d", strings.Count(b.body, "BEGIN PGP PUBLIC KEY BLOCK"))
	}

	// Disable, then delete with confirmation.
	d.post("/agents/"+a.ID, d.form("description", "renamed"))
	a2, _ := d.st.GetAgent(ctx, a.ID)
	if a2.Enabled || a2.Description != "renamed" {
		t.Fatalf("update: %+v", a2)
	}
	if !strings.Contains(d.get("/agents/"+a.ID+"/delete").body, "revocation certificate") {
		t.Fatal("delete page must offer revocation certificates")
	}
	d.post("/agents/"+a.ID+"/delete", d.form("confirm", "wrong"))
	if _, err := d.st.GetAgent(ctx, a.ID); err != nil {
		t.Fatal("wrong confirmation must not delete")
	}
	d.post("/agents/"+a.ID+"/delete", d.form("confirm", "bench"))
	if _, err := d.st.GetAgent(ctx, a.ID); err == nil {
		t.Fatal("agent must be deleted")
	}
}

func TestPolicyEditorEnforcesSigningRules(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	a := d.createAgent("vault", "me")
	save := func(kv ...string) {
		d.post("/agents/"+a.ID+"/policy", d.form(kv...))
	}
	save("ov_services", "on", "services", "markdown", "services", "e2e", "require_signing", "inherit")
	page := d.get("/agents/" + a.ID).body
	if !strings.Contains(page, "mutually exclusive") {
		t.Fatal("require_signing (inherited true) + e2e must be refused with an explanation")
	}
	got, _ := d.st.GetAgent(context.Background(), a.ID)
	if got.Policy.Services != nil {
		t.Fatal("refused policy must not be saved")
	}
	save("ov_recipients", "on", "recipients", "me", "ov_services", "on", "services", "e2e", "require_signing", "false",
		"ov_rate", "on", "per_hour", "5", "per_day", "50", "ov_max_bytes", "on", "max_bytes", "2MiB")
	got, _ = d.st.GetAgent(context.Background(), a.ID)
	if got.Policy.Services == nil || (*got.Policy.Services)[0] != "e2e" || got.Policy.RequireSigning == nil || *got.Policy.RequireSigning ||
		got.Policy.RateLimit.PerHour != 5 || int64(*got.Policy.MaxMessageBytes) != 2<<20 {
		t.Fatalf("policy not saved: %+v", got.Policy)
	}
	save("ov_recipients", "on", "recipients", "ghost", "require_signing", "false")
	if !strings.Contains(d.get("/agents/"+a.ID).body, "Unknown recipient aliases: ghost") {
		t.Fatal("unknown alias must be refused")
	}
	save("ov_rate", "on", "per_hour", "zero", "per_day", "1", "require_signing", "false")
	if !strings.Contains(d.get("/agents/"+a.ID).body, "Rate limits must be numbers") {
		t.Fatal("bad numbers must be refused")
	}
}

func TestOverviewWarnings(t *testing.T) {
	d := newDash(t, testutil.Options{PublicURL: "http://gw.example.com:8025"})
	d.login()
	a := d.createAgent("bench", "me")
	d.st.InsertAudit(context.Background(), &store.AuditEntry{AgentID: a.ID, Status: store.StatusSent, Transport: "insecure"})
	body := d.get("/").body
	for _, want := range []string{"Plain HTTP from a non-local network", "bench", "Signing is not configured", "plain HTTP on a non-localhost host"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
}

func TestAuditPageAndCSV(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	a := d.createAgent("bench", "me")
	ctx := context.Background()
	d.st.InsertAudit(ctx, &store.AuditEntry{AgentID: a.ID, TokenID: "tok", Status: store.StatusSent, Recipients: []string{"me"}, Transport: "local", Subject: "=cmd|' /C calc'!A0", TS: time.Now()})
	d.st.InsertAudit(ctx, &store.AuditEntry{AgentID: a.ID, Status: store.StatusRejected, ErrorCode: "recipient_not_allowed", TS: time.Now()})
	p := d.get("/audit?status=rejected")
	if !strings.Contains(p.body, "recipient_not_allowed") || strings.Contains(p.body, "<span class=\"tag ok\">sent</span>") {
		t.Fatal("status filter")
	}
	csv := d.get("/audit.csv")
	if !strings.Contains(csv.header.Get("Content-Type"), "text/csv") || !strings.Contains(csv.body, "bench") || !strings.Contains(csv.body, "'=cmd") {
		t.Fatalf("CSV must include rows and neutralize formulas:\n%s", csv.body)
	}
}

func TestSettingsHideSecretsAndTestSMTP(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	s := d.get("/settings").body
	for _, secret := range []string{d.env.SMTP.Pass, d.env.AdminPW, "$argon2id$"} {
		if strings.Contains(s, secret) {
			t.Fatalf("settings page leaks a secret: %q", secret)
		}
	}
	if !strings.Contains(s, "password_file") {
		t.Fatal("settings should show the effective config")
	}
	p := d.post("/settings/test-smtp", d.form("back", "/settings"))
	if p.status != http.StatusSeeOther || !strings.Contains(d.get("/settings").body, "Connected and authenticated") {
		t.Fatal("SMTP test should succeed against the fake server")
	}
	d.post("/settings/test-send", d.form("alias", "me"))
	c := d.env.SMTP.Last(t)
	if c.To[0] != "me@example.com" || !strings.Contains(string(c.Data), "Test message") {
		t.Fatal("test send")
	}
	if g := d.get("/settings/guide"); !strings.Contains(g.body, "/v1/capabilities") {
		t.Fatal("guide preview")
	}
	if r := d.get("/recipients"); !strings.Contains(r.body, "me@example.com") || !strings.Contains(r.body, "Ops pager") {
		t.Fatal("recipients page")
	}
}

func TestLoginRedirectTargets(t *testing.T) {
	d := newDash(t, testutil.Options{})
	for next, want := range map[string]string{
		"/agents?x=1":           "/agents?x=1",
		"/\t/evil.example":      "/",
		"/\\evil.example":       "/",
		"//evil.example":        "/",
		"https://evil.example/": "/",
		"/%0a/evil.example":     "/%0a/evil.example", // percent-encoded stays a local path
		"":                      "/",
	} {
		p := d.post("/login", url.Values{"password": {d.env.AdminPW}, "next": {next}})
		if got := p.header.Get("Location"); got != want {
			t.Errorf("next=%q redirected to %q, want %q", next, got, want)
		}
	}
}

func TestParallelGuessesAreThrottled(t *testing.T) {
	d := newDash(t, testutil.Options{})
	const n = 20
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			req, _ := http.NewRequest("POST", d.ts.URL+"/login", strings.NewReader(url.Values{"password": {"wrong guess"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			res.Body.Close()
			codes <- res.StatusCode
		}()
	}
	verified := 0
	for i := 0; i < n; i++ {
		if <-codes == http.StatusUnauthorized {
			verified++
		}
	}
	if verified > 5 {
		t.Fatalf("%d parallel guesses reached the password check; the throttle allows 5", verified)
	}
}

func TestLoginRejectsMultipartAndHugeBodies(t *testing.T) {
	d := newDash(t, testutil.Options{})
	big := strings.NewReader("password=" + strings.Repeat("a", 200<<10))
	req, _ := http.NewRequest("POST", d.ts.URL+"/login", big)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized login body: %d", res.StatusCode)
	}
	mp := "--X\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + d.env.AdminPW + "\r\n--X--\r\n"
	req, _ = http.NewRequest("POST", d.ts.URL+"/login", strings.NewReader(mp))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	res, _ = d.c.Do(req)
	res.Body.Close()
	if res.StatusCode == http.StatusSeeOther {
		t.Fatal("multipart login bodies must not be parsed")
	}
}

func TestSharedHostHint(t *testing.T) {
	d := newDash(t, testutil.Options{})
	req, _ := http.NewRequest("GET", d.ts.URL+"/login", nil)
	req.Host = "localhost:8026"
	res, _ := http.DefaultClient.Do(req)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "http://email-me.localhost:8026") {
		t.Fatal("plain localhost should suggest a dedicated host name")
	}
	req.Host = "email-me.localhost:8026"
	res, _ = http.DefaultClient.Do(req)
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(b), "Tip: open the dashboard") {
		t.Fatal("no hint on a dedicated host name")
	}
}
