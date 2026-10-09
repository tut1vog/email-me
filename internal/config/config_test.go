package config_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	emailme "github.com/tut1vog/email-me"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/units"
)

func TestLoadValidConfig(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true, Agents: "bot:\n  policy:\n    recipients: [me]\nidle:\n"})
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	// The password is never in the file: a username without one warns.
	if !slices.Equal(c.Warnings, []string{config.SMTPPasswordMissing}) || len(c.BootstrapWarnings) != 0 {
		t.Fatalf("warnings: %v", c.Warnings)
	}
	if !c.SigningConfigured() || len(c.KEK.Key) != 32 || c.KEK.Previous != nil {
		t.Fatal("signing should be configured")
	}
	me, ok := c.Recipient("me")
	if !ok || me.Alias != "me" || me.Fingerprint() != pgp.Fingerprint(env.MeKey) || !me.KeyUsable(time.Now()) {
		t.Fatalf("recipient me: %+v", me)
	}
	if ops, _ := c.Recipient("ops"); ops.Key != nil || ops.KeyUsable(time.Now()) {
		t.Fatal("ops has no key")
	}
	if got := strings.Join(c.Aliases(), ","); got != "me,ops,work" {
		t.Fatalf("aliases %s", got)
	}
	// An agent with nothing set is an enabled agent with the defaults.
	if got := strings.Join(c.AgentNames(), ","); got != "bot,idle" {
		t.Fatalf("agents %s", got)
	}
	if idle, ok := c.Agent("idle"); !ok || !idle.Enabled() || idle.Name != "idle" {
		t.Fatalf("idle: %+v", idle)
	}
	if bot, _ := c.Agent("bot"); !slices.Equal(c.Effective(bot.Policy).Recipients, []string{"me"}) {
		t.Fatal("bot's policy")
	}
	if !c.DefaultPolicy.RequireSigning || !c.DefaultPolicy.HasService(policy.SvcSign) {
		t.Fatal("signing must be on by default when configured")
	}
	if c.FromName("bench") != "bench via email-me" {
		t.Fatal(c.FromName("bench"))
	}
}

func TestSigningOffByDefaultWithoutSigning(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	if env.Config.DefaultPolicy.RequireSigning || env.Config.SigningConfigured() {
		t.Fatal("require_signing must default to false without signing")
	}
}

// writeConfig writes a config.yaml and an empty KEK file (no KEK) into a
// new directory.
func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "kek"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const badConfig = `
api:
  listen: "nope"
  docs: sometimes
  trusted_proxies: ["not-an-ip"]
kek:
  file: does/not/exist
upstream:
  smtp:
    host: smtp.example.com
    security: none
    username: gw
  from: "Name <a@b.c>"
recipients:
  Bad_Alias:
    address: not-an-address
  ok:
    address: ok@example.com
    require_encryption: true
defaults:
  policy:
    recipients: [ghost]
    services: [fax]
    require_signing: true
audit:
  retention_days: -1
log:
  level: loud
agents:
  Bad_Name:
    description: "two\nlines"
  e2e:
    policy:
      services: [e2e]
      require_signing: true
      rate_limit: {per_hour: 0, per_day: 1}
`

func TestValidationCollectsAllProblems(t *testing.T) {
	_, err := config.Load(writeConfig(t, badConfig))
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{
		// bootstrap
		"api.listen", "kek.file", "log.level",
		// managed settings
		"api.docs", "trusted_proxies", "security none", "upstream.from", "fax",
		"defaults.policy.require_signing is true but signing is not configured", "retention_days",
		// recipients and agents
		`"Bad_Alias"`, "recipients.Bad_Alias.address", "recipients.ok.require_encryption",
		`"Bad_Name"`, "agents.Bad_Name.description must be a single line",
		"agents.e2e.policy: rate_limit", "agents.e2e.policy: require_signing is true but signing is not configured",
		"agents.e2e.policy: require_signing and the e2e service are mutually exclusive",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in:\n%s", want, joined)
		}
	}
	// A username without a password is only a warning: it is entered on
	// the dashboard.
	if strings.Contains(joined, "password") {
		t.Errorf("password: %v", joined)
	}
}

func TestMinimalConfig(t *testing.T) {
	c, err := config.Load(writeConfig(t, ""))
	if err != nil {
		t.Fatalf("an empty file must load: %v", err)
	}
	if !slices.Equal(c.Warnings, []string{config.UpstreamNotConfigured}) {
		t.Fatalf("unconfigured upstream must be a warning: %v", c.Warnings)
	}
	if c.API.Listen != "127.0.0.1:8025" || c.Dashboard.Listen != "127.0.0.1:8026" || c.KEK.File != "kek" || c.KEK.PreviousFile != "previous_kek" {
		t.Fatalf("bootstrap defaults: %+v %+v", c.API, c.KEK)
	}
	if c.Upstream.SMTP.Port != 587 || c.API.Docs != "public" || c.Audit.RetentionDays != 30 {
		t.Fatalf("managed defaults not applied: %+v", c.Managed())
	}
	// Format is checked only when set.
	c.Upstream.SMTP.Host, c.Upstream.From = "smtp.example.com:587", "nope"
	problems, warnings := c.ValidateManaged()
	if len(problems) != 2 || len(warnings) != 0 {
		t.Fatalf("got %v %v", problems, warnings)
	}
}

func TestKEKFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	hex1 := strings.Repeat("ab", 32)
	hex2 := strings.Repeat("cd", 32)
	load := func(kek string) (*config.Config, error) {
		return config.Load(write("config.yaml", "kek:\n"+kek+"signing:\n  key_validity: 1y\n"))
	}

	// Paths are relative to the file's directory.
	write("kek", hex1+"\n")
	write("previous_kek", hex2)
	c, err := load("")
	if err != nil || !c.KEK.Configured() || c.KEK.Key[0] != 0xab || c.KEK.Previous[0] != 0xcd || !c.SigningConfigured() {
		t.Fatalf("both keys: %+v %v", c, err)
	}
	if c.Path("kek") != filepath.Join(dir, "kek") || c.Path("/abs") != "/abs" {
		t.Fatal("Path")
	}
	// An empty file is no KEK, which also leaves signing off; a missing
	// previous file is no previous KEK. The signing settings are kept for
	// when a KEK is set.
	write("empty", "\n")
	c, err = load("  file: empty\n  previous_file: absent\n")
	if err != nil || c.KEK.Key != nil || c.KEK.Previous != nil || c.SigningConfigured() {
		t.Fatalf("empty: %+v %v", c, err)
	}
	if got := c.Managed().Signing.KeyValidity.D(); got != 365*24*time.Hour {
		t.Fatalf("key_validity without a KEK: %v, want the file's 1y", got)
	}
	write("short", "abc")
	write("bad", "x")
	for kek, want := range map[string]string{
		"  file: absent\n":                      "kek.file",
		"  file: short\n":                       "kek.file: must contain 32 random bytes",
		"  previous_file: bad\n":                "kek.previous_file: must contain",
		"  file: empty\n  previous_file: kek\n": "kek.previous_file is set but kek.file is empty",
	} {
		if _, err := load(kek); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", kek, want, err)
		}
	}
}

func TestManagedRoundTrip(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{DefaultsPolicy: "recipients: [me]\nrate_limit: {per_hour: 5, per_day: 10}", TrustedProxies: []string{"10.0.0.1"}})
	c, _ := config.Load(env.Path)
	s := c.Managed()
	if c.SigningConfigured() || s.Signing.KeyValidity.D() != 2*365*24*time.Hour {
		t.Fatalf("no signing configured, key_validity defaulted: %v", s.Signing.KeyValidity)
	}
	// The copy is deep: changing it does not touch c.
	(*s.Defaults.Policy.Recipients)[0] = "changed"
	s.Defaults.Policy.RateLimit.PerHour = 99
	s.API.TrustedProxies[0] = "10.9.9.9"
	if (*c.Defaults.Policy.Recipients)[0] != "me" || c.Defaults.Policy.RateLimit.PerHour != 5 || c.API.TrustedProxies[0] != "10.0.0.1" {
		t.Fatal("Managed must return a deep copy")
	}
	s.Signing.KeyValidity = units.Duration(24 * time.Hour)
	s.Audit.RetentionDays = 7
	s.Upstream.SMTP.Password = env.SMTP.Pass
	other, _ := config.Load(env.Path)
	other.SetManaged(s)
	if other.Audit.RetentionDays != 7 || (*other.Defaults.Policy.Recipients)[0] != "changed" || other.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("SetManaged: %+v", other.Managed())
	}
	if d := config.DiffSettings(s, other.Managed()); len(d) != 0 {
		t.Fatalf("round trip differs: %v", d)
	}

	// JSON drops the password but keeps everything else.
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), env.SMTP.Pass) || strings.Contains(string(data), "password") {
		t.Fatalf("password in JSON: %s", data)
	}
	var back config.Settings
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if d := config.DiffSettings(s, back); len(d) != 0 {
		t.Fatalf("JSON round trip differs: %v", d)
	}

	signed := testutil.NewEnv(t, testutil.Options{Signing: true})
	sc, _ := config.Load(signed.Path)
	ss := sc.Managed()
	ss.Signing.KeyValidity = units.Duration(48 * time.Hour)
	sc.SetManaged(ss)
	if sc.Signing.KeyValidity.D() != 48*time.Hour || !sc.KEK.Configured() {
		t.Fatalf("signing: %+v", sc.Signing)
	}
}

func TestDiffSettings(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	c, _ := config.Load(env.Path)
	c.ValidateManaged()
	a := c.Managed()
	b := a.Clone()
	if d := config.DiffSettings(a, b); len(d) != 0 {
		t.Fatalf("equal settings differ: %v", d)
	}
	b.Upstream.SMTP.Port = 2525
	b.Upstream.SMTP.Password = "not compared"
	b.API.Docs = "authenticated"
	five := 5
	b.Defaults.Policy.MaxAttachments = &five
	b.Defaults.Policy.RateLimit = &policy.RateLimit{PerHour: 1, PerDay: 2}
	b.API.TrustedProxies = []string{}
	want := "api.docs,defaults.policy.max_attachments,defaults.policy.rate_limit,upstream.smtp.port"
	if d := config.DiffSettings(a, b); strings.Join(d, ",") != want {
		t.Fatalf("diff = %v", d)
	}
	a.Defaults.Policy.RateLimit = &policy.RateLimit{PerHour: 1, PerDay: 3}
	if d := config.DiffSettings(a, b); !slices.Contains(d, "defaults.policy.rate_limit.per_day") || slices.Contains(d, "defaults.policy.rate_limit.per_hour") {
		t.Fatalf("nested diff = %v", d)
	}
}

func TestFingerprint(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	fp, err := config.FileFingerprint(env.Path)
	if err != nil || fp == "" || fp != env.Config.Fingerprint {
		t.Fatalf("fingerprint %q (%v), loaded %q", fp, err, env.Config.Fingerprint)
	}
	if again, _ := config.FileFingerprint(env.Path); again != fp {
		t.Fatal("the fingerprint of an unchanged file is stable")
	}
	if err := os.WriteFile(env.Path, []byte(env.YAML+"# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if edited, _ := config.FileFingerprint(env.Path); edited == fp {
		t.Fatal("editing the file changes its fingerprint")
	}
	if _, err := config.FileFingerprint(filepath.Join(env.Dir, "missing.yaml")); err == nil {
		t.Fatal("a missing file has no fingerprint")
	}
}

func TestValidateManagedRepeatable(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{TrustedProxies: []string{"10.0.0.1", "192.168.0.0/16"}})
	c, _ := config.Load(env.Path)
	c.ValidateManaged()
	for range 3 {
		if problems, _ := c.ValidateManaged(); len(problems) != 0 {
			t.Fatal(problems)
		}
	}
	if len(c.API.TrustedNets) != 2 {
		t.Fatalf("TrustedNets must be assigned, not appended: %v", c.API.TrustedNets)
	}
}

func TestUnknownAliasesAreWarnings(t *testing.T) {
	c, err := config.Load(writeConfig(t, "defaults:\n  policy:\n    recipients: [ghost]\nagents:\n  bot:\n    policy:\n      recipients: [phantom]\n"))
	if err != nil {
		t.Fatalf("no recipients and unknown aliases must load: %v", err)
	}
	joined := strings.Join(c.Warnings, "\n")
	if !strings.Contains(joined, "defaults.policy.recipients names recipients that do not exist and are ignored: ghost") ||
		!strings.Contains(joined, "agent bot: its policy names recipients that do not exist and are ignored: phantom") {
		t.Fatalf("warnings: %s", joined)
	}
	bot, _ := c.Agent("bot")
	if len(c.Effective(bot.Policy).Recipients) != 0 || !slices.Equal(c.UnknownAliases(bot.Policy), []string{"phantom"}) {
		t.Fatal("unknown aliases are dropped from the effective policy")
	}
	if refs := c.ReferencingAgents("phantom"); len(refs) != 1 || refs[0].Name != "bot" || len(c.ReferencingAgents("ghost")) != 0 {
		t.Fatal("ReferencingAgents counts the agents' own policies only")
	}
}

func TestRecipientKeys(t *testing.T) {
	key := testutil.NewKey(t, "K", "k@example.com")
	expired, err := openpgp.NewEntity("E", "", "e@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600,
		Time: func() time.Time { return time.Now().Add(-48 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	block := func(armor string) string {
		return "|\n      " + strings.ReplaceAll(strings.TrimSpace(armor), "\n", "\n      ") + "\n"
	}
	recipient := func(key string) string {
		return "recipients:\n  r:\n    address: r@example.com\n    pgp_public_key: " + key
	}
	c, err := config.Load(writeConfig(t, recipient(block(testutil.ArmorPublic(t, key)))))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := c.Recipient("r"); r.Fingerprint() != pgp.Fingerprint(key) {
		t.Fatal("the key is parsed")
	}
	for armor, want := range map[string]string{
		block(testutil.ArmorPrivate(t, key)): "is a private key",
		"not a key\n":                        "recipients.r.pgp_public_key",
	} {
		if _, err := config.Load(writeConfig(t, recipient(armor))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	// A key that expired since it was added loads, with a warning.
	c, err = config.Load(writeConfig(t, recipient(block(testutil.ArmorPublic(t, expired)))))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := c.Recipient("r"); r.Key == nil || r.KeyUsable(time.Now()) || !strings.Contains(strings.Join(c.Warnings, "\n"), "recipient r:") {
		t.Fatalf("expired key: %v", c.Warnings)
	}
}

func TestExampleConfig(t *testing.T) {
	c, err := config.Parse(emailme.ExampleConfig, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "kek.file") {
		t.Fatalf("the example needs its KEK file: %v", err)
	}
	p := writeConfig(t, string(emailme.ExampleConfig))
	os.WriteFile(filepath.Join(filepath.Dir(p), "kek"), []byte(strings.Repeat("ab", 32)), 0o600)
	if c, err = config.Load(p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Warnings, []string{config.UpstreamNotConfigured}) || len(c.Recipients) != 0 || len(c.Agents) != 0 {
		t.Fatalf("example: %v", c.Warnings)
	}
	if !c.DefaultPolicy.RequireSigning || !c.DefaultPolicy.HasService(policy.SvcSign) {
		t.Fatal("the example signs by default")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	p := writeConfig(t, "api:\n  listne: x\n")
	if _, err := config.Load(p); err == nil || !strings.Contains(err.Error(), "listne") {
		t.Fatalf("unknown field must be rejected: %v", err)
	}
}

func TestDefaultsRejectE2EWithRequiredSigning(t *testing.T) {
	load := func(policy string) error {
		p := writeConfig(t, "defaults:\n  policy:\n"+policy)
		os.WriteFile(filepath.Join(filepath.Dir(p), "kek"), []byte(strings.Repeat("ab", 32)), 0o600)
		_, err := config.Load(p)
		return err
	}
	if err := load("    services: [markdown, e2e]\n"); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("e2e with default require_signing must be rejected: %v", err)
	}
	if err := load("    services: [markdown, e2e]\n    require_signing: false\n"); err != nil {
		t.Fatalf("e2e with require_signing false is valid: %v", err)
	}
}

func TestPublicURLWarning(t *testing.T) {
	managed := func(o testutil.Options) (*config.Config, []string) {
		t.Helper()
		c, err := config.Load(testutil.NewEnv(t, o).Path)
		if err != nil {
			t.Fatal(err)
		}
		c.Upstream.SMTP.Password = "set on the dashboard"
		problems, warnings := c.ValidateManaged()
		if len(problems) != 0 {
			t.Fatal(problems)
		}
		return c, warnings
	}
	if _, w := managed(testutil.Options{PublicURL: "http://gateway.example.com:8025"}); len(w) == 0 || !strings.Contains(w[0], "plain HTTP") {
		t.Fatalf("expected plain-HTTP warning, got %v", w)
	}
	if _, w := managed(testutil.Options{PublicURL: "http://gateway.example.com:8025", External: true}); len(w) != 0 {
		t.Fatalf("external_transport_encryption must silence the warning: %v", w)
	}
	if c, w := managed(testutil.Options{PublicURL: "http://localhost:8025/"}); len(w) != 0 || c.API.PublicURL != "http://localhost:8025" {
		t.Fatalf("localhost is fine: %v %q", w, c.API.PublicURL)
	}
}

func TestParseKEK(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	hex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	for _, in := range [][]byte{[]byte(hex + "\n"), []byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="), raw} {
		got, err := config.ParseKEK(in)
		if err != nil || string(got) != string(raw) {
			t.Errorf("ParseKEK(%q) = %x, %v", in, got, err)
		}
	}
	if _, err := config.ParseKEK([]byte("short")); err == nil {
		t.Error("short KEK must fail")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "LOCALHOST.": true, "127.0.0.1": true, "::1": true, "[::1]": true, "127.1.2.3": true, "example.com": false, "10.0.0.1": false, "": false} {
		if got := config.IsLoopbackHost(h); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v", h, got)
		}
	}
}

func TestPlaintextOnlyToLocalhost(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	c.Upstream.SMTP.Password = "set on the dashboard"
	for host, ok := range map[string]bool{"127.0.0.1": true, "localhost": true, "smtp.example.com": false, "10.0.0.1": false} {
		c.Upstream.SMTP.Host = host
		problems, warnings := c.ValidateManaged()
		if got := !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, "security none") }); got != ok || len(warnings) != 0 {
			t.Errorf("security none to %s: %v %v", host, problems, warnings)
		}
	}
}
