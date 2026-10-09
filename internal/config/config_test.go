package config_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/testutil"
	"github.com/tut1vog/email-me/internal/units"
)

func TestLoadValidConfig(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultPolicy.Services != nil {
		t.Fatal("Load must not resolve managed settings")
	}
	// The password is never in the file: a username without one warns.
	if problems, warnings := c.ValidateManaged(); len(problems) != 0 || !slices.Equal(warnings, []string{config.SMTPPasswordMissing}) {
		t.Fatalf("seed: %v %v", problems, warnings)
	}
	if !c.SigningConfigured() || len(c.KEK.Key) != 32 || c.KEK.Previous != nil {
		t.Fatal("signing should be configured")
	}
	if !strings.Contains(c.Recipients["me"].PublicKeyArmor, "BEGIN PGP PUBLIC KEY BLOCK") || c.Recipients["ops"].PublicKeyArmor != "" {
		t.Fatal("recipient keys loaded incorrectly")
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

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const badManaged = `
api:
  listen: "nope"
  docs: sometimes
  trusted_proxies: ["not-an-ip"]
dashboard:
  session_ttl: 30s
kek:
  file: /does/not/exist
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
`

func TestValidationCollectsAllProblems(t *testing.T) {
	_, err := config.Load(writeConfig(t, badManaged))
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{
		"api.listen", "kek.file", `"Bad_Alias"`, "recipients.Bad_Alias.address",
		"recipients.ok.require_encryption", "log.level",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing bootstrap problem %q in:\n%s", want, joined)
		}
	}
	// Managed keys are not checked by Load: only when they seed the
	// database or are saved (ValidateManaged).
	for _, managed := range []string{"api.docs", "upstream", "fax", "retention_days"} {
		if strings.Contains(joined, managed) {
			t.Errorf("Load reported managed key %q:\n%s", managed, joined)
		}
	}

	env := testutil.NewEnv(t, testutil.Options{})
	empty := filepath.Join(env.Dir, "empty_kek")
	os.WriteFile(empty, nil, 0o600)
	yaml := strings.NewReplacer(`"nope"`, `"127.0.0.1:0"`, "/does/not/exist", empty, "loud", "info").Replace(badManaged)
	start, end := strings.Index(yaml, "recipients:\n  Bad"), strings.Index(yaml, "defaults:\n")
	c, err := config.Load(writeConfig(t, yaml[:start]+yaml[end:]))
	if err != nil {
		t.Fatalf("valid bootstrap keys must load: %v", err)
	}
	problems, warnings := c.ValidateManaged()
	joined = strings.Join(problems, "\n")
	for _, want := range []string{
		"api.docs", "trusted_proxies", "session_ttl must be at least 1m", "security none",
		"upstream.from", "fax", "require_signing is true but signing is not configured", "retention_days",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing managed problem %q in:\n%s", want, joined)
		}
	}
	// A username without a password is only a warning: it is entered on
	// the dashboard.
	if strings.Contains(joined, "password") || !slices.Contains(warnings, config.SMTPPasswordMissing) {
		t.Errorf("password: %v %v", problems, warnings)
	}
}

func TestBootstrapOnlyConfig(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	yaml := fmt.Sprintf("data_dir: %q\n", env.DataDir)
	c, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("a file with only bootstrap keys must load: %v", err)
	}
	if !c.Managed().IsZero() {
		t.Fatalf("no managed keys were set: %+v", c.Managed())
	}
	problems, warnings := c.ValidateManaged()
	if len(problems) != 0 {
		t.Fatalf("defaults must be valid: %v", problems)
	}
	if len(warnings) != 1 || warnings[0] != "upstream SMTP is not configured: set it on the Settings page" {
		t.Fatalf("unconfigured upstream must be a warning: %v", warnings)
	}
	if c.Upstream.SMTP.Port != 587 || c.API.Docs != "public" || c.Dashboard.SessionTTL.D() != 12*time.Hour || c.Audit.RetentionDays != 30 {
		t.Fatalf("managed defaults not applied: %+v", c.Managed())
	}
	// Format is checked only when set.
	c.Upstream.SMTP.Host, c.Upstream.From = "smtp.example.com:587", "nope"
	problems, warnings = c.ValidateManaged()
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
		return config.Load(writeConfig(t, fmt.Sprintf("data_dir: %q\nkek:\n%ssigning:\n  key_validity: 1y\n", dir, kek)))
	}

	c, err := load(fmt.Sprintf("  file: %q\n  previous_file: %q\n", write("kek", hex1+"\n"), write("prev", hex2)))
	if err != nil || !c.KEK.Configured() || c.KEK.Key[0] != 0xab || c.KEK.Previous[0] != 0xcd || !c.SigningConfigured() {
		t.Fatalf("both keys: %+v %v", c, err)
	}
	// An empty file is no KEK (compose mounts an empty variable), which
	// also leaves signing off; a missing previous file is no previous KEK.
	c, err = load(fmt.Sprintf("  file: %q\n  previous_file: %q\n", write("empty", "\n"), filepath.Join(dir, "absent")))
	if err != nil || c.KEK.Key != nil || c.KEK.Previous != nil || c.Signing != nil || c.SigningConfigured() {
		t.Fatalf("empty: %+v %v", c, err)
	}
	for kek, want := range map[string]string{
		fmt.Sprintf("  file: %q\n", filepath.Join(dir, "absent")):                              "kek.file",
		fmt.Sprintf("  file: %q\n", write("short", "abc")):                                     "kek.file: must contain 32 random bytes",
		fmt.Sprintf("  file: %q\n  previous_file: %q\n", write("k2", hex1), write("bad", "x")): "kek.previous_file: must contain",
		fmt.Sprintf("  previous_file: %q\n", write("p2", hex2)):                                "kek.previous_file is set but kek.file is not",
	} {
		if _, err := load(kek); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", kek, want, err)
		}
	}
}

func TestManagedRoundTrip(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{DefaultsPolicy: "recipients: [me]\nrate_limit: {per_hour: 5, per_day: 10}", TrustedProxies: []string{"10.0.0.1"}})
	c, _ := config.Load(env.Path)
	c.ValidateManaged()
	s := c.Managed()
	if c.Signing != nil || s.Signing.KeyValidity != 0 {
		t.Fatal("no signing configured")
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
	if other.Signing != nil {
		t.Fatal("SetManaged must not create Signing")
	}
	if other.Audit.RetentionDays != 7 || (*other.Defaults.Policy.Recipients)[0] != "changed" || other.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("SetManaged: %+v", other.Managed())
	}
	got := other.Managed()
	got.Signing.KeyValidity = 0
	if d := config.DiffSettings(s, got); len(d) != 1 || d[0] != "signing.key_validity" {
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
	if sc.Signing == nil || sc.Signing.KeyValidity.D() != 48*time.Hour || !sc.KEK.Configured() {
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
	b.Dashboard.SessionTTL = units.Duration(time.Hour)
	five := 5
	b.Defaults.Policy.MaxAttachments = &five
	b.Defaults.Policy.RateLimit = &policy.RateLimit{PerHour: 1, PerDay: 2}
	b.API.TrustedProxies = []string{}
	want := "api.docs,dashboard.session_ttl,defaults.policy.max_attachments,defaults.policy.rate_limit,upstream.smtp.port"
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

func TestRecipientsAreOptionalSeeds(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{DefaultsPolicy: "recipients: [ghost]"})
	start := strings.Index(env.YAML, "recipients:\n")
	end := strings.Index(env.YAML, "defaults:\n")
	yaml := env.YAML[:start] + env.YAML[end:]
	c, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatalf("no recipients and an unknown default alias must load: %v", err)
	}
	if len(c.Recipients) != 0 || (*c.Defaults.Policy.Recipients)[0] != "ghost" {
		t.Fatalf("got %+v", c.Recipients)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	p := writeConfig(t, "api:\n  listne: x\n")
	if _, err := config.Load(p); err == nil || !strings.Contains(err.Error(), "listne") {
		t.Fatalf("unknown field must be rejected: %v", err)
	}
}

func TestDefaultsRejectE2EWithRequiredSigning(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	yaml := env.YAML + "defaults:\n  policy:\n    services: [markdown, e2e]\n"
	c, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if problems, _ := c.ValidateManaged(); len(problems) != 1 || !strings.Contains(problems[0], "mutually exclusive") {
		t.Fatalf("e2e with default require_signing must be rejected: %v", problems)
	}
	ok := env.YAML + "defaults:\n  policy:\n    services: [markdown, e2e]\n    require_signing: false\n"
	if c, err = config.Load(writeConfig(t, ok)); err != nil {
		t.Fatal(err)
	}
	if problems, _ := c.ValidateManaged(); len(problems) != 0 {
		t.Fatalf("e2e with require_signing false is valid: %v", problems)
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
	// Settings stored with the removed allow_plaintext override still
	// decode, and no longer allow plaintext to a remote host.
	s := c.Managed()
	if err := json.Unmarshal([]byte(`{"upstream":{"smtp":{"host":"smtp.example.com","port":25,"security":"none","timeout":"5s","allow_plaintext":true},"from":"gw@example.com"}}`), &s); err != nil {
		t.Fatal(err)
	}
	c.SetManaged(s)
	if problems, _ := c.ValidateManaged(); !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, "security none is only allowed to localhost") }) {
		t.Fatalf("allow_plaintext must be ignored: %v", problems)
	}
}
