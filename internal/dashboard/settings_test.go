package dashboard_test

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

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

func TestSettingsUpstreamCardAndRestartBanner(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
	env := d.env
	if b := d.get("/agents").body; strings.Contains(b, "Restart to apply") {
		t.Fatal("no banner before anything is saved")
	}

	// A second server with other credentials: the saved settings point there.
	other := testutil.StartSMTP(t)
	other.Pass = "other-secret"
	port := strconv.Itoa(other.Port)
	body := d.saved(d.post("/settings/upstream", d.form("host", "127.0.0.1", "port", port, "security", "none",
		"username", other.User, "password", "other-secret", "timeout", "5s", "from", "gateway@example.com",
		"from_name_template", "{agent} via email-me")), "upstream")
	if !strings.Contains(body, "Upstream SMTP settings saved. Restart to apply.") || strings.Contains(body, "other-secret") ||
		!strings.Contains(body, `value="`+port+`"`) {
		t.Fatal("saved upstream settings must be shown, the password never")
	}
	if got := d.settings.Pending(); !slices.Equal(got, []string{"upstream.smtp.password", "upstream.smtp.port"}) {
		t.Fatalf("pending = %v", got)
	}
	agents := d.get("/agents").body
	for _, want := range []string{"Restart to apply.", "<code>upstream.smtp.port</code>", "<code>upstream.smtp.password</code>", "just now", `href="/settings#restart"`} {
		if !strings.Contains(agents, want) {
			t.Errorf("banner on other pages lacks %q", want)
		}
	}
	if o := d.get("/").body; !strings.Contains(o, "Saved settings are not in effect yet") {
		t.Error("pending settings must be on the attention list")
	}

	// The running sender is unchanged; the saved one can be tested.
	if !strings.Contains(body, `action="/settings/test-smtp-saved"`) {
		t.Fatal("Test saved settings is offered while upstream changes are pending")
	}
	d.post("/settings/test-smtp-saved", d.form())
	if b := d.get("/settings").body; !strings.Contains(b, "with the saved settings") {
		t.Fatal("saved settings test must reach the second server")
	}
	d.post("/settings/test-send", d.form("alias", "me"))
	if env.SMTP.Count() != 1 || other.Count() != 0 {
		t.Fatal("test send must use the running sender until a restart")
	}
	d.saved(d.post("/settings/upstream", d.form("host", "127.0.0.1", "port", port, "security", "none",
		"username", other.User, "password", "wrong", "timeout", "5s", "from", "gateway@example.com")), "upstream")
	d.post("/settings/test-smtp-saved", d.form())
	if b := d.get("/settings").body; !strings.Contains(b, "Saved SMTP settings test failed") {
		t.Fatal("a wrong saved password must fail the saved settings test")
	}

	// Removing and replacing the password at once is refused.
	p := d.post("/settings/upstream", d.form("host", "127.0.0.1", "security", "none", "password", "x", "remove_password", "on", "from", "gateway@example.com"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "not both") {
		t.Fatalf("password and remove: %d", p.status)
	}
	// A username without a password is refused by validation.
	p = d.post("/settings/upstream", d.form("host", "127.0.0.1", "security", "none", "username", "u", "remove_password", "on", "from", "gateway@example.com"))
	if p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "upstream.smtp.password is required") {
		t.Fatalf("username without password: %d", p.status)
	}

	// Reverting to the running values clears the banner.
	body = d.saved(d.post("/settings/upstream", d.form("host", env.SMTP.Host, "port", strconv.Itoa(env.SMTP.Port), "security", "none",
		"username", env.SMTP.User, "password", env.SMTP.Pass, "timeout", "5s", "from", "gateway@example.com",
		"from_name_template", "{agent} via email-me")), "upstream")
	if len(d.settings.Pending()) != 0 || strings.Contains(body, "Restart to apply.") || !strings.Contains(body, "no restart is needed") {
		t.Fatalf("reverted settings must clear the banner: %v", d.settings.Pending())
	}
}

func TestSettingsCardsValidate(t *testing.T) {
	d := newDash(t, testutil.Options{Signing: true})
	d.login()
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
	if len(d.settings.Pending()) != 0 {
		t.Fatal("rejected saves must not store anything")
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
	if got := d.settings.Pending(); !slices.Equal(got, want) {
		t.Fatalf("pending = %v", got)
	}
	if d.env.Config.API.Docs != "public" {
		t.Fatal("saving must not change the running settings")
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
	if !strings.Contains(body, "Default policy saved. Restart to apply.") || !strings.Contains(body, "do not exist and are ignored: ghost") {
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
	if !slices.Equal(d.settings.Pending(), []string{"defaults.policy.rate_limit", "defaults.policy.recipients", "defaults.policy.require_signing", "defaults.policy.services"}) {
		t.Fatalf("pending = %v", d.settings.Pending())
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
