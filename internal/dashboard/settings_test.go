package dashboard_test

import (
	"context"
	"net/http"
	"os"
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
	before, cur := d.settings.Current().Managed(), d.settings.Current()
	for _, c := range []struct {
		card string
		kv   []string
		want string
	}{
		{"api", []string{"docs", "secret"}, "api.docs must be public or authenticated"},
		{"api", []string{"docs", "public", "trusted_proxies", "10.0.0.0/8 nonsense"}, `api.trusted_proxies: &#34;nonsense&#34; is not an IP or CIDR`},
		{"api", []string{"docs", "public", "public_url", "ftp://x"}, "api.public_url must be an absolute http(s) URL"},
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
	if len(config.DiffSettings(d.settings.Current().Managed(), before)) != 0 || d.settings.Current() != cur {
		t.Fatal("rejected saves must not store or apply anything")
	}

	d.saved(d.post("/settings/api", d.form("docs", "authenticated", "trusted_proxies", "10.0.0.0/8, 192.168.1.1 172.16.0.0/12",
		"public_url", "https://gw.example.com/", "external_transport_encryption", "on")), "api")
	d.saved(d.post("/settings/audit", d.form("retention_days", "90", "log_subject", "on")), "audit")
	body := d.saved(d.post("/settings/signing", d.form("key_validity", "3y")), "signing")
	s := d.settings.Current().Managed()
	if s.API.Docs != "authenticated" || strings.Join(s.API.TrustedProxies, ",") != "10.0.0.0/8,192.168.1.1,172.16.0.0/12" ||
		s.API.PublicURL != "https://gw.example.com" || !s.API.ExternalTransportEncryption ||
		s.Audit.RetentionDays != 90 || !s.Audit.LogSubject || s.Signing.KeyValidity.String() != "3y" {
		t.Fatalf("saved: %+v", s)
	}
	for _, want := range []string{`value="90"`, `value="3y"`, `value="10.0.0.0/8, 192.168.1.1, 172.16.0.0/12"`, `<option value="authenticated" selected>`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks saved value %q", want)
		}
	}
	want := []string{"api.docs", "api.external_transport_encryption", "api.public_url", "api.trusted_proxies",
		"audit.log_subject", "audit.retention_days", "signing.key_validity"}
	if got := config.DiffSettings(before, d.settings.Current().Managed()); !slices.Equal(got, want) {
		t.Fatalf("applied = %v", got)
	}
	if !strings.Contains(body, "Signing settings saved and applied.") || d.env.Config.API.Docs != "public" {
		t.Fatal("a save applies a new configuration; the boot one is never modified")
	}

	// config.yaml holds what was saved.
	reloaded, err := config.Load(d.env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := config.DiffSettings(reloaded.Managed(), d.settings.Current().Managed()); len(got) != 0 {
		t.Fatalf("config.yaml differs: %v", got)
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
	pol := d.settings.Current().Managed().Defaults.Policy
	if pol.Recipients == nil || strings.Join(*pol.Recipients, ",") != "me,ghost" || pol.RateLimit.PerHour != 5 ||
		pol.RequireSigning == nil || *pol.RequireSigning || pol.MaxAttachments != nil {
		t.Fatalf("saved policy: %+v", pol)
	}
	if !strings.Contains(body, `name="ov_rate" checked`) || !strings.Contains(body, `name="per_hour" value="5"`) ||
		!strings.Contains(body, `name="ov_max_att" >`) {
		t.Fatal("the saved policy must round-trip into the form")
	}
	// Agents that inherit the default policy get it at once.
	if eff := d.settings.Current().Effective(policy.Policy{}); eff.RateLimit.PerHour != 5 || eff.RequireSigning || strings.Join(eff.Recipients, ",") != "me" {
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

// A hand edit of config.yaml is applied by a restart; until then the
// dashboard says so and refuses every save, which would overwrite it.
func TestHandEditRefusesSaves(t *testing.T) {
	d := newDash(t, testutil.Options{})
	d.login()
	d.saved(d.post("/settings/audit", d.form("retention_days", "60")), "audit")
	if b := d.get("/agents").body; strings.Contains(b, `id="restart-banner"`) {
		t.Fatal("dashboard saves never raise the banner")
	}
	edited := read(t, d.env.Path) + "# a hand edit\n"
	os.WriteFile(d.env.Path, []byte(edited), 0o600)
	banner := d.get("/agents").body
	if !strings.Contains(banner, `id="restart-banner"`) || !strings.Contains(banner, "email-me restart") {
		t.Fatal("every page names email-me restart")
	}
	if o := d.get("/").body; !strings.Contains(o, "Restart to apply") {
		t.Error("a hand edit must be on the attention list")
	}
	if p := d.post("/settings/audit", d.form("retention_days", "7")); p.status != http.StatusUnprocessableEntity || !strings.Contains(p.body, "run email-me restart") {
		t.Fatalf("a settings save: %d", p.status)
	}
	if p := d.post("/agents", d.form("name", "late")); p.status != http.StatusSeeOther || !strings.Contains(d.get("/agents/new").body, "run email-me restart") {
		t.Fatal("creating an agent must be refused")
	}
	if p := d.post("/recipients/ops/delete", d.form("confirm", "ops")); p.status != http.StatusSeeOther {
		t.Fatalf("deleting a recipient: %d", p.status)
	}
	if _, ok := d.settings.Current().Recipient("ops"); !ok || read(t, d.env.Path) != edited {
		t.Fatal("nothing may change while the edit is pending")
	}
}

// withoutUpstream removes the upstream section from env's config.yaml.
func withoutUpstream(t *testing.T, env *testutil.Env) {
	t.Helper()
	start, end := strings.Index(env.YAML, "upstream:\n"), strings.Index(env.YAML, "recipients:\n")
	env.YAML = env.YAML[:start] + env.YAML[end:]
	os.WriteFile(env.Path, []byte(env.YAML), 0o600)
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	env.Config = c
}

func TestSettingsUpstreamNotConfigured(t *testing.T) {
	d := newDashWith(t, testutil.Options{Signing: true}, func(env *testutil.Env, _ *store.Store) { withoutUpstream(t, env) })
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
	if _, err := d.st.ActiveKey(context.Background(), a.Name); err == nil {
		t.Fatal("no key may be generated without a From address")
	}
	sg := d.get("/agents/" + a.Name + "/signing").body
	if !strings.Contains(sg, "none is set") || strings.Contains(sg, `action="/agents/`+a.Name+`/keys"`) {
		t.Fatal("the signing tab must explain why no key can be generated")
	}
	if p := d.post("/agents/"+a.Name+"/keys", d.form()); p.status != http.StatusSeeOther || !strings.Contains(d.get("/agents/"+a.Name+"/signing").body, "no From address is configured") {
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
	if _, err := d.st.ActiveKey(context.Background(), a.Name); err != nil {
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
		if err := st.SetSMTPPassword(context.Background(), &store.SMTPPassword{Value: []byte(strings.Repeat("x", 40)), Sealed: true}); err != nil {
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
