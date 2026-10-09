package dashboard_test

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/dashboard"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/upstream"
)

type dash struct {
	t        *testing.T
	env      *testutil.Env
	st       *store.Store
	settings *settings.Manager
	keys     *keys.Manager
	ts       *httptest.Server
	c        *http.Client
	srv      *dashboard.Server
}

func newDash(t *testing.T, o testutil.Options) *dash {
	t.Helper()
	return newDashWith(t, o, nil)
}

// newDashWith is newDash with a hook that can change the state database
// before the settings manager opens it.
func newDashWith(t *testing.T, o testutil.Options, prepare func(*testutil.Env, *store.Store)) *dash {
	t.Helper()
	env := testutil.NewEnv(t, o)
	st := testutil.OpenStore(t, env)
	if prepare != nil {
		prepare(env, st)
	}
	sm := testutil.Settings(t, env, st)
	km := testutil.Keys(t, env, st, sm)
	srv, err := dashboard.New(dashboard.Deps{Store: st, Settings: sm, Keys: km,
		Sender: upstream.NewDynamic(func() config.SMTP { return sm.Current().Upstream.SMTP }),
		Log:    testutil.DiscardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	d := &dash{t: t, env: env, st: st, settings: sm, keys: km, ts: ts, srv: srv}
	d.c = newClient()
	return d
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// session returns d with a client of its own: another browser.
func (d *dash) session() *dash {
	cp := *d
	cp.c = newClient()
	return &cp
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

// login signs in with a fresh console link, as the operator does.
func (d *dash) login() {
	d.t.Helper()
	if p := d.get("/login?token=" + d.srv.NewLink()); p.status != http.StatusSeeOther || p.header.Get("Location") != "/" {
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

var agentLocRe = regexp.MustCompile(`^/agents/([^/]+)/tokens$`)

func (d *dash) createAgent(name string, recipients ...string) *config.Agent {
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
	return d.agent(m[1])
}

// agent returns the current configuration's agent, failing if there is none.
func (d *dash) agent(name string) *config.Agent {
	d.t.Helper()
	a, ok := d.settings.Current().Agent(name)
	if !ok {
		d.t.Fatalf("no agent %s", name)
	}
	return a
}

func TestLoginRequiredAndHeaders(t *testing.T) {
	d := newDash(t, testutil.Options{})
	p := d.get("/agents")
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated: %d %s", p.status, p.header.Get("Location"))
	}
	lp := d.get("/login")
	if lp.status != http.StatusUnauthorized || !strings.Contains(lp.body, "email-me console") {
		t.Fatalf("login page must say how to get a link: %d", lp.status)
	}
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
	if p := d.post("/agents", url.Values{"name": {"x"}}); p.status != http.StatusUnauthorized {
		t.Fatalf("POST without a session: %d", p.status)
	}
}

func TestConsoleLogin(t *testing.T) {
	d := newDash(t, testutil.Options{})
	link := d.srv.NewLink()
	if p := d.get("/login?token=wrong"); p.status != http.StatusUnauthorized || !strings.Contains(p.body, "already used") {
		t.Fatalf("a wrong link: %d", p.status)
	}
	p := d.get("/login?token=" + link)
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/" {
		t.Fatalf("a fresh link: %d %s", p.status, p.header.Get("Location"))
	}
	cookie := p.header.Get("Set-Cookie")
	for _, want := range []string{"HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("cookie lacks %s: %s", want, cookie)
		}
	}
	home := d.get("/")
	if home.status != 200 || !strings.Contains(home.body, "Create your first agent") {
		t.Fatalf("first-run overview: %d", home.status)
	}
	// The link works once: another browser cannot reuse it.
	other := d.session()
	if p := other.get("/login?token=" + link); p.status != http.StatusUnauthorized {
		t.Fatalf("a spent link: %d", p.status)
	}
	other.login()
	d.post("/logout", d.form())
	if p := d.get("/"); p.status != http.StatusSeeOther {
		t.Fatal("logout must end the session")
	}
	if p := other.get("/"); p.status != 200 {
		t.Fatal("logout ends only its own session")
	}
	// Closing the console ends every session and voids unspent links.
	unspent := d.srv.NewLink()
	d.srv.EndSessions()
	if p := other.get("/"); p.status != http.StatusSeeOther {
		t.Fatal("EndSessions must end every session")
	}
	if p := d.get("/login?token=" + unspent); p.status != http.StatusUnauthorized {
		t.Fatal("EndSessions must void unspent links")
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
	if len(d.settings.Current().Agents) != 0 {
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
	k1, err := d.st.ActiveKey(ctx, a.Name)
	if err != nil {
		t.Fatal("agent must get a signing key on creation")
	}
	ap := d.get("/agents/" + a.Name)
	if ap.status != 200 || !strings.Contains(ap.body, k1.Fingerprint) || !strings.Contains(ap.body, "Agent bench created") {
		t.Fatalf("agent page: %d", ap.status)
	}
	if p := d.post("/agents", d.form("name", "bench")); !strings.Contains(d.get("/agents/new").body, "already exists") || p.status != http.StatusSeeOther {
		t.Fatal("duplicate names must be rejected")
	}

	// Issue a token: shown once, and it authenticates.
	tp := d.post("/agents/"+a.Name+"/tokens", d.form("label", "build-02", "expires_days", "30", "cidrs", "10.0.0.0/8, 192.168.1.5"))
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
	if strings.Contains(d.get("/agents/"+a.Name).body, secret) {
		t.Fatal("token secret must never be shown again")
	}
	if p := d.post("/agents/"+a.Name+"/tokens", d.form("cidrs", "not-an-ip")); p.status != http.StatusSeeOther {
		t.Fatal("bad CIDR must be rejected with a flash")
	}
	d.post("/agents/"+a.Name+"/tokens/"+id+"/revoke", d.form())
	st, _ = d.st.GetToken(ctx, id)
	if st.RevokedAt == nil {
		t.Fatal("token must be revoked")
	}

	// Keys: download, rotate, revocation certificates.
	pub := d.get("/agents/" + a.Name + "/keys/" + k1.Fingerprint + "/public.asc")
	if pub.status != 200 || !strings.Contains(pub.body, "BEGIN PGP PUBLIC KEY BLOCK") || strings.Contains(pub.body, "PRIVATE") ||
		!strings.Contains(pub.header.Get("Content-Disposition"), "bench-") {
		t.Fatalf("public key download: %d", pub.status)
	}
	d.post("/agents/"+a.Name+"/keys/rotate", d.form())
	k2, _ := d.st.ActiveKey(ctx, a.Name)
	if k2.Fingerprint == k1.Fingerprint {
		t.Fatal("rotation must change the key")
	}
	for _, kind := range []string{"revocation.asc", "revocation-compromised.asc"} {
		if rev := d.get("/agents/" + a.Name + "/keys/" + k1.Fingerprint + "/" + kind); rev.status != 200 || !strings.Contains(rev.body, "Revocation certificate") {
			t.Fatalf("retired key %s: %d", kind, rev.status)
		}
	}
	other := d.createAgent("other")
	if p := d.get("/agents/" + other.Name + "/keys/" + k2.Fingerprint + "/public.asc"); p.status != 404 {
		t.Fatal("keys must only be served under their own agent")
	}
	if b := d.get("/keys.asc"); strings.Count(b.body, "BEGIN PGP PUBLIC KEY BLOCK") != 3 {
		t.Fatalf("bundle should hold 3 keys (2 for bench, 1 for other), got %d", strings.Count(b.body, "BEGIN PGP PUBLIC KEY BLOCK"))
	}

	// Disable, then delete with confirmation.
	d.post("/agents/"+a.Name, d.form("description", "renamed"))
	if a2 := d.agent("bench"); a2.Enabled() || a2.Description != "renamed" {
		t.Fatalf("update: %+v", a2)
	}
	if !strings.Contains(d.get("/agents/"+a.Name+"/delete").body, "revocation certificate") {
		t.Fatal("delete page must offer revocation certificates")
	}
	d.post("/agents/"+a.Name+"/delete", d.form("confirm", "wrong"))
	d.agent("bench") // wrong confirmation must not delete
	d.post("/agents/"+a.Name+"/delete", d.form("confirm", "bench"))
	if _, ok := d.settings.Current().Agent("bench"); ok {
		t.Fatal("agent must be deleted")
	}
	if ks, _ := d.st.ListKeys(ctx, "bench"); len(ks) != 0 {
		t.Fatal("its keys must be deleted")
	}
	if _, err := d.st.GetToken(ctx, id); err == nil {
		t.Fatal("its tokens must be deleted")
	}
	if !strings.Contains(read(t, d.env.Path), "other:") || strings.Contains(read(t, d.env.Path), "bench:") {
		t.Fatal("config.yaml must follow")
	}
}

func TestPolicyEditorEnforcesSigningRules(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	a := d.createAgent("vault", "me")
	save := func(kv ...string) {
		d.post("/agents/"+a.Name+"/policy", d.form(kv...))
	}
	save("ov_services", "on", "services", "markdown", "services", "e2e", "require_signing", "inherit")
	page := d.get("/agents/" + a.Name).body
	if !strings.Contains(page, "mutually exclusive") {
		t.Fatal("require_signing (inherited true) + e2e must be refused with an explanation")
	}
	if got := d.agent("vault"); got.Policy.Services != nil {
		t.Fatal("refused policy must not be saved")
	}
	save("ov_recipients", "on", "recipients", "me", "ov_services", "on", "services", "e2e", "require_signing", "false",
		"ov_rate", "on", "per_hour", "5", "per_day", "50", "ov_max_bytes", "on", "max_bytes", "2MiB")
	got := d.agent("vault")
	if got.Policy.Services == nil || (*got.Policy.Services)[0] != "e2e" || got.Policy.RequireSigning == nil || *got.Policy.RequireSigning ||
		got.Policy.RateLimit.PerHour != 5 || int64(*got.Policy.MaxMessageBytes) != 2<<20 {
		t.Fatalf("policy not saved: %+v", got.Policy)
	}
	save("ov_recipients", "on", "recipients", "ghost", "require_signing", "false")
	if !strings.Contains(d.get("/agents/"+a.Name).body, "Unknown recipient aliases: ghost") {
		t.Fatal("unknown alias must be refused")
	}
	save("ov_rate", "on", "per_hour", "zero", "per_day", "1", "require_signing", "false")
	if !strings.Contains(d.get("/agents/"+a.Name).body, "Rate limits must be numbers") {
		t.Fatal("bad numbers must be refused")
	}
}

func TestOverviewWarnings(t *testing.T) {
	d := newDash(t, testutil.Options{PublicURL: "http://gw.example.com:8025"})
	d.login()
	a := d.createAgent("bench", "me")
	d.st.InsertAudit(context.Background(), &store.AuditEntry{Agent: a.Name, Status: store.StatusSent, Transport: "insecure"})
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
	d.st.InsertAudit(ctx, &store.AuditEntry{Agent: a.Name, TokenID: "tok", Status: store.StatusSent, Recipients: []string{"me"}, Transport: "local", Subject: "=cmd|' /C calc'!A0", TS: time.Now()})
	d.st.InsertAudit(ctx, &store.AuditEntry{Agent: a.Name, Status: store.StatusRejected, ErrorCode: "recipient_not_allowed", TS: time.Now()})
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
	for _, secret := range []string{d.env.SMTP.Pass} {
		if strings.Contains(s, secret) {
			t.Fatalf("settings page leaks a secret: %q", secret)
		}
	}
	for _, want := range []string{`id="bootstrap"`, d.env.Config.KEK.File,
		`name="password" type="password" autocomplete="new-password"`, "A password is stored, encrypted.", `value="gateway@example.com"`,
		`action="/settings/certify-key"`, `name="private_key"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("settings page lacks %q", want)
		}
	}
	// A rejected save shows what was typed, except the password.
	p := d.post("/settings/upstream", d.form("host", "smtp.example.net", "port", "abc", "security", "starttls", "password", "typed-secret", "from", "gateway@example.com"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "Port must be a number") ||
		!strings.Contains(p.body, `value="smtp.example.net"`) || strings.Contains(p.body, "typed-secret") {
		t.Fatalf("rejected upstream save: %d", p.status)
	}
	p = d.post("/settings/test-smtp", d.form("back", "/settings"))
	if p.status != http.StatusSeeOther || !strings.Contains(d.get("/settings").body, "Connected and authenticated") {
		t.Fatal("SMTP test should succeed against the fake server")
	}
	if b := d.get("/recipients/me").body; !strings.Contains(b, `action="/recipients/me/test"`) {
		t.Fatal("the recipient page must offer a test message")
	}
	if strings.Contains(d.get("/settings").body, "/settings/test-send") {
		t.Fatal("test messages are sent from the recipient page, not Settings")
	}
	if p := d.post("/recipients/me/test", d.form()); p.status != http.StatusSeeOther || p.header.Get("Location") != "/recipients/me" {
		t.Fatalf("test send: %d to %q", p.status, p.header.Get("Location"))
	}
	if b := d.get("/recipients/me").body; !strings.Contains(b, "Test message sent to me.") {
		t.Fatal("test send must flash on the recipient page")
	}
	if p := d.post("/recipients/nope/test", d.form()); p.status != http.StatusNotFound {
		t.Fatalf("test send to an unknown alias: %d", p.status)
	}
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

func TestRedirectTargets(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	for back, want := range map[string]string{
		"/agents?x=1":           "/agents?x=1",
		"/\t/evil.example":      "/",
		"/\\evil.example":       "/",
		"//evil.example":        "/",
		"https://evil.example/": "/",
		"/%0a/evil.example":     "/%0a/evil.example", // percent-encoded stays a local path
		"":                      "/",
	} {
		p := d.post("/settings/test-smtp", d.form("back", back))
		if got := p.header.Get("Location"); got != want {
			t.Errorf("back=%q redirected to %q, want %q", back, got, want)
		}
	}
}

func TestSessionCookieSecureBehindTLS(t *testing.T) {
	d := newDash(t, testutil.Options{})
	secure := func(proto string) bool {
		t.Helper()
		req, _ := http.NewRequest("GET", d.ts.URL+"/login?token="+d.srv.NewLink(), nil)
		req.Header.Set("X-Forwarded-Proto", proto)
		res, err := d.c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		for _, c := range res.Cookies() {
			if c.Name == "email_me_session" {
				return c.Secure
			}
		}
		t.Fatalf("no session cookie: %d", res.StatusCode)
		return false
	}
	if secure("http") {
		t.Fatal("plain HTTP must not get a Secure cookie")
	}
	if !secure("https") {
		t.Fatal("behind a TLS proxy the session cookie must be Secure")
	}
}

func TestRejectsMultipartAndHugeBodies(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	csrf := d.csrf()
	big := strings.NewReader("csrf=" + csrf + "&name=" + strings.Repeat("a", 200<<10))
	req, _ := http.NewRequest("POST", d.ts.URL+"/agents", big)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := d.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", res.StatusCode)
	}
	mp := "--X\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n" + csrf + "\r\n--X\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nmp\r\n--X--\r\n"
	req, _ = http.NewRequest("POST", d.ts.URL+"/agents", strings.NewReader(mp))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=X")
	res, _ = d.c.Do(req)
	res.Body.Close()
	if _, ok := d.settings.Current().Agent("mp"); ok || res.StatusCode == http.StatusSeeOther {
		t.Fatal("multipart bodies must not be parsed")
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
