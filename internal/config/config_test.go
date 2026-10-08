package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/testutil"
)

func TestLoadValidConfig(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	c := env.Config
	if !c.SigningConfigured() || len(c.Signing.KEK) != 32 {
		t.Fatal("signing should be configured")
	}
	if !strings.Contains(c.Recipients["me"].PublicKeyArmor, "BEGIN PGP PUBLIC KEY BLOCK") || c.Recipients["ops"].PublicKeyArmor != "" {
		t.Fatal("recipient keys loaded incorrectly")
	}
	if !auth.VerifyPassword(c.Dashboard.AdminPasswordHash, env.AdminPW) {
		t.Fatal("plaintext admin password must be hashed at load")
	}
	if c.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("SMTP password not read (trailing newline must be trimmed)")
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

func TestValidationCollectsAllProblems(t *testing.T) {
	p := writeConfig(t, `
api:
  listen: "nope"
  docs: sometimes
  trusted_proxies: ["not-an-ip"]
dashboard:
  admin_password_file: /does/not/exist
upstream:
  smtp:
    host: smtp.example.com
    security: none
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
`)
	_, err := config.Load(p)
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{
		"api.listen", "api.docs", "trusted_proxies", "admin_password_file", "security none", "upstream.from",
		`"Bad_Alias"`, "recipients.Bad_Alias.address", "recipients.ok.require_encryption",
		"fax", "require_signing is true but signing is not configured", "retention_days", "log.level",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem %q in:\n%s", want, joined)
		}
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
	_, err := config.Load(writeConfig(t, yaml))
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("e2e with default require_signing must be rejected: %v", err)
	}
	ok := env.YAML + "defaults:\n  policy:\n    services: [markdown, e2e]\n    require_signing: false\n"
	if _, err := config.Load(writeConfig(t, ok)); err != nil {
		t.Fatalf("e2e with require_signing false is valid: %v", err)
	}
}

func TestPublicURLWarning(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{PublicURL: "http://gateway.example.com:8025"})
	if len(env.Config.Warnings) == 0 || !strings.Contains(env.Config.Warnings[0], "plain HTTP") {
		t.Fatalf("expected plain-HTTP warning, got %v", env.Config.Warnings)
	}
	quiet := testutil.NewEnv(t, testutil.Options{PublicURL: "http://gateway.example.com:8025", External: true})
	if len(quiet.Config.Warnings) != 0 {
		t.Fatalf("external_transport_encryption must silence the warning: %v", quiet.Config.Warnings)
	}
	local := testutil.NewEnv(t, testutil.Options{PublicURL: "http://localhost:8025/"})
	if len(local.Config.Warnings) != 0 || local.Config.API.PublicURL != "http://localhost:8025" {
		t.Fatalf("localhost is fine: %v %q", local.Config.Warnings, local.Config.API.PublicURL)
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

func TestArgon2HashInPasswordFile(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	h, _ := auth.HashPassword("another long password")
	hp := filepath.Join(env.Dir, "admin_hash")
	os.WriteFile(hp, []byte(h+"\n"), 0o600)
	yaml := strings.Replace(env.YAML, filepath.Join(env.Dir, "admin_password"), hp, 1)
	c, err := config.Load(writeConfig(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if c.Dashboard.AdminPasswordHash != h {
		t.Fatal("PHC hash must be used as-is")
	}
	short := filepath.Join(env.Dir, "short_pw")
	os.WriteFile(short, []byte("short"), 0o600)
	yaml = strings.Replace(env.YAML, filepath.Join(env.Dir, "admin_password"), short, 1)
	if _, err := config.Load(writeConfig(t, yaml)); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("short password must be rejected: %v", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "LOCALHOST.": true, "127.0.0.1": true, "::1": true, "[::1]": true, "127.1.2.3": true, "example.com": false, "10.0.0.1": false, "": false} {
		if got := config.IsLoopbackHost(h); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v", h, got)
		}
	}
}
