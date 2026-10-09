package dashboard_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// saved checks a card save's redirect and returns the page it lands on.
func (d *dash) saved(p page, card string) string {
	d.t.Helper()
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/settings#"+card {
		d.t.Fatalf("save %s: %d %s\n%s", card, p.status, p.header.Get("Location"), p.body)
	}
	return d.get("/settings").body
}

func TestSettingsUpstreamCardAppliesAtOnce(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	env := d.env

	// A second server with other credentials: the saved settings point there.
	other := testutil.StartSMTP(t)
	other.Pass = "other-secret"
	port := strconv.Itoa(other.Port)
	body := d.saved(d.post("/settings/upstream", d.form("host", "127.0.0.1", "port", port, "security", "none",
		"username", other.User, "password", "other-secret", "timeout", "5s", "from", "gateway@example.com",
		"from_name_template", "{agent} via email-me")), "upstream")
	if !strings.Contains(body, "Upstream SMTP settings saved and applied.") || strings.Contains(body, "other-secret") ||
		!strings.Contains(body, `value="`+port+`"`) {
		t.Fatal("saved upstream settings must be shown, the password never")
	}
	if got := d.settings.Current().Upstream.SMTP; got.Port != other.Port || got.Password != "other-secret" {
		t.Fatalf("current upstream = %+v", got)
	}
	for _, path := range []string{"/agents", "/"} {
		if b := d.get(path).body; strings.Contains(b, `id="restart-banner"`) || strings.Contains(b, "Restart to apply") {
			t.Errorf("%s: saved settings need no restart", path)
		}
	}
	if strings.Contains(body, "test-smtp-saved") || !strings.Contains(body, "Not checked yet.") {
		t.Fatal("the tests run against the settings in effect; there is no separate test of saved ones")
	}

	// The tests and agents' sends use the new server at once.
	d.post("/settings/test-smtp", d.form("back", "/settings#upstream"))
	if b := d.get("/settings").body; !strings.Contains(b, "Connected and authenticated to 127.0.0.1:"+port) {
		t.Fatal("the connection test must reach the new server")
	}
	d.post("/settings/test-send", d.form("alias", "me"))
	if env.SMTP.Count() != 0 || other.Count() != 1 {
		t.Fatalf("test send: old server %d, new server %d", env.SMTP.Count(), other.Count())
	}
	d.saved(d.post("/settings/upstream", d.form("host", "127.0.0.1", "port", port, "security", "none",
		"username", other.User, "password", "wrong", "timeout", "5s", "from", "gateway@example.com")), "upstream")
	d.post("/settings/test-smtp", d.form("back", "/settings#upstream"))
	if b := d.get("/settings").body; !strings.Contains(b, "SMTP connection test failed") {
		t.Fatal("a wrong password must fail the connection test")
	}

	// Removing and replacing the password at once is refused.
	p := d.post("/settings/upstream", d.form("host", "127.0.0.1", "security", "none", "password", "x", "remove_password", "on", "from", "gateway@example.com"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "not both") {
		t.Fatalf("password and remove: %d", p.status)
	}
	// A username without a password saves, with a warning.
	body = d.saved(d.post("/settings/upstream", d.form("host", "127.0.0.1", "security", "none", "username", "u", "remove_password", "on", "from", "gateway@example.com")), "upstream")
	if !strings.Contains(body, "Note: "+config.SMTPPasswordMissing) {
		t.Fatal("username without password must warn")
	}

	// Back to the first server; saving the same values again changes nothing.
	revert := []string{"host", env.SMTP.Host, "port", strconv.Itoa(env.SMTP.Port), "security", "none",
		"username", env.SMTP.User, "timeout", "5s", "from", "gateway@example.com", "from_name_template", "{agent} via email-me"}
	body = d.saved(d.post("/settings/upstream", d.form(append(revert, "password", env.SMTP.Pass)...)), "upstream")
	if !strings.Contains(body, "Upstream SMTP settings saved and applied.") {
		t.Fatal("reverting is a change")
	}
	body = d.saved(d.post("/settings/upstream", d.form(revert...)), "upstream")
	if !strings.Contains(body, "Upstream SMTP settings saved; nothing changed.") {
		t.Fatal("an unchanged save must say so")
	}
	d.post("/settings/test-send", d.form("alias", "me"))
	if env.SMTP.Count() != 1 || other.Count() != 1 {
		t.Fatalf("after reverting: old server %d, new server %d", env.SMTP.Count(), other.Count())
	}
}

func TestSettingsCardsValidate(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	before, cur := d.settings.Saved(), d.settings.Current()
	for _, c := range []struct {
		card string
		kv   []string
		want string
	}{
		{"api", []string{"docs", "secret"}, "api.docs must be public or authenticated"},
		{"api", []string{"docs", "public", "trusted_proxies", "10.0.0.0/8 nonsense"}, `api.trusted_proxies: &#34;nonsense&#34; is not an IP or CIDR`},
		{"api", []string{"docs", "public", "public_url", "ftp://x"}, "api.public_url must be an absolute http(s) URL"},
		{"dashboard", []string{"session_ttl", "30s"}, "dashboard.session_ttl must be at least 1m"},
		{"dashboard", []string{"session_ttl", "soon"}, "Session lifetime: invalid duration"},
		{"audit", []string{"retention_days", "-1"}, "audit.retention_days must be at least 1"},
		{"audit", []string{"retention_days", "many"}, "Retention must be a number"},
		{"signing", []string{"key_validity", "12h"}, "signing.key_validity must be between 1d and 50y"},
		{"upstream", []string{"host", "smtp.example.net:25", "security", "starttls"}, "upstream.smtp.host must be a hostname"},
	} {
		p := d.post("/settings/"+c.card, d.form(c.kv...))
		if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, c.want) {
			t.Errorf("%s %v: %d, want %q", c.card, c.kv, p.status, c.want)
		}
		if p.status == http.StatusUnprocessableEntity && !strings.Contains(p.body, `value="`+c.kv[1]+`"`) && c.kv[0] != "docs" {
			t.Errorf("%s: the submitted value must be shown again", c.card)
		}
	}
	if len(config.DiffSettings(d.settings.Saved(), before)) != 0 || d.settings.Current() != cur {
		t.Fatal("rejected saves must not store or apply anything")
	}

	d.saved(d.post("/settings/api", d.form("docs", "authenticated", "trusted_proxies", "10.0.0.0/8, 192.168.1.1 172.16.0.0/12",
		"public_url", "https://gw.example.com/", "external_transport_encryption", "on")), "api")
	d.saved(d.post("/settings/dashboard", d.form("session_ttl", "2h")), "dashboard")
	d.saved(d.post("/settings/audit", d.form("retention_days", "90", "log_subject", "on")), "audit")
	body := d.saved(d.post("/settings/signing", d.form("key_validity", "3y")), "signing")
	s := d.settings.Saved()
	if s.API.Docs != "authenticated" || strings.Join(s.API.TrustedProxies, ",") != "10.0.0.0/8,192.168.1.1,172.16.0.0/12" ||
		s.API.PublicURL != "https://gw.example.com" || !s.API.ExternalTransportEncryption ||
		s.Dashboard.SessionTTL.String() != "2h0m0s" || s.Audit.RetentionDays != 90 || !s.Audit.LogSubject || s.Signing.KeyValidity.String() != "3y" {
		t.Fatalf("saved: %+v", s)
	}
	for _, want := range []string{`value="2h"`, `value="90"`, `value="3y"`, `value="10.0.0.0/8, 192.168.1.1, 172.16.0.0/12"`, `<option value="authenticated" selected>`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks saved value %q", want)
		}
	}
	want := []string{"api.docs", "api.external_transport_encryption", "api.public_url", "api.trusted_proxies",
		"audit.log_subject", "audit.retention_days", "dashboard.session_ttl", "signing.key_validity"}
	if got := config.DiffSettings(before, d.settings.Current().Managed()); !slices.Equal(got, want) {
		t.Fatalf("applied = %v", got)
	}
	if !strings.Contains(body, "Signing settings saved and applied.") || d.env.Config.API.Docs != "public" {
		t.Fatal("a save applies a new configuration; the boot one is never modified")
	}

	// The session lifetime applies to the next login.
	d.post("/logout", d.form())
	p := d.post("/login", url.Values{"password": {d.env.AdminPW}, "next": {"/"}})
	if c := p.header.Get("Set-Cookie"); p.status != http.StatusSeeOther || !strings.Contains(c, "Max-Age=7200") {
		t.Fatalf("login after session_ttl 2h: %d %q", p.status, c)
	}

	nd := newDash(t, testutil.Options{})
	nd.login()
	if p := nd.post("/settings/signing", nd.form("key_validity", "1y")); p.status != http.StatusSeeOther || !strings.Contains(nd.get("/settings").body, "Signing is not configured") {
		t.Fatal("signing settings need a KEK")
	}
}

func TestSettingsDefaultPolicyCard(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	body := d.get("/settings").body
	if !strings.Contains(body, `action="/settings/policy"`) || !strings.Contains(body, "Default: markdown, attachments, thread, sign") {
		t.Fatal("the default policy card shows the built-in defaults")
	}

	// e2e with signing required (the built-in default with a KEK) is refused.
	p := d.post("/settings/policy", d.form("ov_services", "on", "services", "markdown", "services", "e2e", "require_signing", "inherit"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "mutually exclusive") ||
		!strings.Contains(p.body, `name="services" value="e2e" checked`) {
		t.Fatalf("e2e + signing: %d", p.status)
	}
	p = d.post("/settings/policy", d.form("ov_rate", "on", "per_hour", "zero", "per_day", "1"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "Rate limits must be numbers") || !strings.Contains(p.body, `value="zero"`) {
		t.Fatalf("bad numbers: %d", p.status)
	}

	// Unknown aliases are saved with a note.
	body = d.saved(d.post("/settings/policy", d.form("ov_recipients", "on", "recipients", "me", "recipients", "ghost",
		"ov_services", "on", "services", "markdown", "services", "e2e", "require_signing", "false",
		"ov_rate", "on", "per_hour", "5", "per_day", "50")), "policy")
	if !strings.Contains(body, "Default policy saved and applied.") || !strings.Contains(body, "do not exist and are ignored: ghost") {
		t.Fatal("unknown aliases must be noted")
	}
	pol := d.settings.Saved().Defaults.Policy
	if pol.Recipients == nil || strings.Join(*pol.Recipients, ",") != "me,ghost" || pol.RateLimit.PerHour != 5 ||
		pol.RequireSigning == nil || *pol.RequireSigning || pol.MaxAttachments != nil {
		t.Fatalf("saved policy: %+v", pol)
	}
	if !strings.Contains(body, `name="ov_rate" checked`) || !strings.Contains(body, `name="per_hour" value="5"`) ||
		!strings.Contains(body, `name="ov_max_att" >`) {
		t.Fatal("the saved policy must round-trip into the form")
	}
	// Agents that inherit the default policy get it at once.
	if eff := d.reg.Effective(policy.Policy{}); eff.RateLimit.PerHour != 5 || eff.RequireSigning || strings.Join(eff.Recipients, ",") != "me" {
		t.Fatalf("effective default policy: %+v", eff)
	}

	// Without a KEK, require_signing is refused.
	nd := newDash(t, testutil.Options{})
	nd.login()
	if p := nd.post("/settings/policy", nd.form("require_signing", "true")); p.status != http.StatusUnprocessableEntity ||
		!strings.Contains(p.body, "signing is not configured") {
		t.Fatalf("require_signing without a KEK: %d", p.status)
	}
}

func TestSettingsLoadProblemsNotice(t *testing.T) {
	d := newDashWith(t, testutil.Options{}, func(env *testutil.Env, st *store.Store) {
		testutil.BootstrapSettings(t, env, st)
		row, err := st.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		row.Doc = []byte(`{"api":{"docs":"maybe"}`)
		if err := st.SaveSettings(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	})
	d.login()
	if len(d.settings.LoadProblems()) != 1 {
		t.Fatalf("load problems: %v", d.settings.LoadProblems())
	}
	for _, path := range []string{"/", "/agents", "/settings"} {
		b := d.get(path).body
		if !strings.Contains(b, "The saved settings have problems.") || !strings.Contains(b, "cannot be decoded") {
			t.Errorf("%s lacks the load-problems banner", path)
		}
		if strings.Contains(b, "saved settings: ") {
			t.Errorf("%s repeats the problems as config warnings", path)
		}
	}
	if o := d.get("/").body; !strings.Contains(o, "Saved settings") {
		t.Error("load problems must be on the attention list")
	}

	// A valid save replaces the broken settings: the problems are gone at once.
	d.saved(d.post("/settings/api", d.form("docs", "public")), "api")
	if len(d.settings.LoadProblems()) != 0 {
		t.Fatalf("after a valid save: %v", d.settings.LoadProblems())
	}
	for _, path := range []string{"/", "/settings"} {
		if b := d.get(path).body; strings.Contains(b, "The saved settings have problems.") || strings.Contains(b, "cannot be decoded") {
			t.Errorf("%s still shows the load problems", path)
		}
	}
}

func TestSettingsUpstreamNotConfigured(t *testing.T) {
	d := newDashWith(t, testutil.Options{Signing: true}, func(env *testutil.Env, st *store.Store) {
		if _, err := st.SeedSettings(context.Background(), &store.Settings{Doc: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
	})
	d.login()
	o := d.get("/").body
	for _, want := range []string{"Configure SMTP", `href="/settings#upstream"`, "not configured"} {
		if !strings.Contains(o, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Contains(o, "upstream SMTP is not configured: set it") {
		t.Error("the raw config warning must not be listed as well")
	}
	s := d.get("/settings").body
	if !strings.Contains(s, `<span class="tag danger">not configured</span>`) || strings.Contains(s, `action="/settings/test-smtp"`) {
		t.Error("the upstream card must say it is not configured and offer no tests of the running sender")
	}

	// No From address: no signing key with an empty user ID.
	a := d.createAgent("bench", "me")
	if _, err := d.st.ActiveKey(context.Background(), a.ID); err == nil {
		t.Fatal("no key may be generated without a From address")
	}
	sg := d.get("/agents/" + a.ID + "/signing").body
	if !strings.Contains(sg, "none is set") || strings.Contains(sg, `action="/agents/`+a.ID+`/keys"`) {
		t.Fatal("the signing tab must explain why no key can be generated")
	}
	if p := d.post("/agents/"+a.ID+"/keys", d.form()); p.status != http.StatusSeeOther || !strings.Contains(d.get("/agents/"+a.ID+"/signing").body, "no From address is configured") {
		t.Fatal("generating a key without a From address must be refused")
	}
	if o := d.get("/").body; !strings.Contains(o, "One can be generated once a From address is set") {
		t.Error("the missing key notice must point at the From address")
	}

	// Saving a From address applies it and gives the agent its key.
	body := d.saved(d.post("/settings/upstream", d.form("host", d.env.SMTP.Host, "port", strconv.Itoa(d.env.SMTP.Port), "security", "none",
		"from", "gateway@example.com")), "upstream")
	if !strings.Contains(body, "Upstream SMTP settings saved and applied. Generated a signing key for 1 agent.") {
		t.Fatal("saving a From address must generate the missing keys")
	}
	if _, err := d.st.ActiveKey(context.Background(), a.ID); err != nil {
		t.Fatalf("no key after saving a From address: %v", err)
	}
	if o := d.get("/").body; strings.Contains(o, "Configure SMTP") || strings.Contains(o, "No signing key") {
		t.Error("the upstream and key notices must be gone")
	}
}

func TestSettingsPasswordNotices(t *testing.T) {
	raw := newDash(t, testutil.Options{})
	raw.login()
	if b := raw.get("/").body; !strings.Contains(b, "SMTP password") || !strings.Contains(b, "Stored unencrypted") {
		t.Error("a password stored without a KEK must be flagged")
	}
	if b := raw.get("/settings").body; !strings.Contains(b, "stored <strong>unencrypted</strong>") {
		t.Error("the upstream card must say the password is unencrypted")
	}

	lost := newDashWith(t, testutil.Options{Signing: true}, func(env *testutil.Env, st *store.Store) {
		testutil.BootstrapSettings(t, env, st)
		row, err := st.GetSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		row.SMTPPassword, row.PasswordSealed = []byte(strings.Repeat("x", 40)), true
		if err := st.SaveSettings(context.Background(), row); err != nil {
			t.Fatal(err)
		}
	})
	lost.login()
	if b := lost.get("/").body; !strings.Contains(b, "cannot be decrypted") || !strings.Contains(b, `href="/settings#upstream"`) {
		t.Error("an undecryptable password must be flagged")
	}
	if b := lost.get("/settings").body; !strings.Contains(b, "<strong>cannot be decrypted</strong>") {
		t.Error("the upstream card must say the password cannot be decrypted")
	}
}

func TestRestartFromDashboard(t *testing.T) {
	d := newDash(t, testutil.Options{})
	up := d.get("/up")
	boot := up.body
	if up.status != 200 || !strings.HasPrefix(up.header.Get("Content-Type"), "text/plain") || len(boot) < 16 || strings.ContainsAny(boot, "<\n") {
		t.Fatalf("GET /up without login: %d %q", up.status, boot)
	}
	if d.get("/up").body != boot {
		t.Fatal("the boot id is fixed for a start")
	}
	if p := d.post("/settings/restart", url.Values{}); p.status == http.StatusOK || d.restart.count() != 0 {
		t.Fatal("restarting needs a session")
	}
	d.login()
	d.saved(d.post("/settings/audit", d.form("retention_days", "60")), "audit")
	if b := d.get("/agents").body; strings.Contains(b, `id="restart-banner"`) {
		t.Fatal("no banner while config.yaml is unchanged")
	}
	if s := d.get("/settings").body; !strings.Contains(s, "config.yaml is unchanged since email-me started.") {
		t.Fatal("the restart card says config.yaml is unchanged")
	}

	// config.yaml changes on disk: every page offers the restart.
	d.configChanged.Store(true)
	banner := d.get("/agents").body
	if !strings.Contains(banner, `id="restart-banner"`) || !strings.Contains(banner, "changed on disk") ||
		!strings.Contains(banner, `action="/settings/restart"`) || !strings.Contains(banner, "data-confirm=") {
		t.Fatal("the restart banner offers Restart now, with a confirmation")
	}
	if o := d.get("/").body; !strings.Contains(o, "Restart to apply") {
		t.Error("a changed config.yaml must be on the attention list")
	}
	if s := d.get("/settings").body; !strings.Contains(s, `<span class="tag warn">changed</span>`) || !strings.Contains(s, "config.yaml changed on disk since email-me started.") {
		t.Fatal("the restart card says config.yaml changed")
	}

	// config.yaml no longer loads: nothing restarts and the session stays.
	d.restart.fail(errors.New("config.yaml no longer loads: parsing config: yaml: line 3: did not find expected key"))
	p := d.post("/settings/restart", d.form())
	if p.status != http.StatusSeeOther || p.header.Get("Location") != "/settings#restart" || d.restart.count() != 0 {
		t.Fatalf("refused restart: %d %s", p.status, p.header.Get("Location"))
	}
	if s := d.get("/settings"); s.status != 200 || !strings.Contains(s.body, "Not restarted: config.yaml no longer loads: parsing config") {
		t.Fatal("a refused restart is reported and keeps the session")
	}

	d.restart.fail(nil)
	csrf := d.csrf()
	p = d.post("/settings/restart", url.Values{"csrf": {csrf}})
	if p.status != 200 || d.restart.count() != 1 {
		t.Fatalf("restart: %d, %d calls", p.status, d.restart.count())
	}
	for _, want := range []string{`data-restart-poll="/up"`, `data-boot="` + boot + `"`, `data-next="/login?next=/settings"`,
		`<meta http-equiv="refresh" content="8;url=/login?next=/settings">`, `href="/login?next=/settings"`, "log in again", "in flight finish first", `class="auth"`} {
		if !strings.Contains(p.body, want) {
			t.Errorf("restarting page lacks %q", want)
		}
	}
	if strings.Contains(p.body, csrf) || strings.Contains(p.body, `action="/logout"`) {
		t.Error("the restarting page is rendered logged out")
	}
	if c := p.header.Get("Set-Cookie"); !strings.Contains(c, "email_me_session=;") || !strings.Contains(c, "Max-Age=0") {
		t.Errorf("the session cookie must be cleared: %q", c)
	}
	if strings.Contains(p.body, "<script>") || inlineStyle.MatchString(p.body) || inlineHandler.MatchString(p.body) {
		t.Error("restarting page must be CSP-safe")
	}
	if g := d.get("/settings"); g.status != http.StatusSeeOther {
		t.Fatal("the session must end with the restart")
	}
}
