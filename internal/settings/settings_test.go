package settings_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// boot loads config.yaml afresh, as a start does, and opens the manager.
func boot(t *testing.T, path string, st *store.Store, mod ...func(*config.Config)) (*settings.Manager, *config.Config) {
	t.Helper()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range mod {
		f(cfg)
	}
	kr, _, err := keyring.Open(context.Background(), st, cfg.KEK.Key, cfg.KEK.Previous)
	if err != nil {
		t.Fatal(err)
	}
	m, err := settings.Open(context.Background(), path, cfg, st, kr, testutil.DiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	return m, m.Current()
}

// noKEK boots as if kek.file were empty.
func noKEK(c *config.Config) { c.KEK.Key = nil }

// enterPassword saves the SMTP password, as the operator does on the
// dashboard.
func enterPassword(t *testing.T, m *settings.Manager, pw string) {
	t.Helper()
	if _, err := m.Save(context.Background(), m.Current().Managed(), settings.PasswordChange{Set: true, Value: pw}); err != nil {
		t.Fatal(err)
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

func TestSave(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{TrustedProxies: []string{"10.0.0.1", "192.168.0.0/16"}})
	st := testutil.OpenStore(t, env)
	m, cfg := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)
	cfg = m.Current()
	ctx := context.Background()
	orig := cfg.Managed()

	bad := cfg.Managed()
	bad.API.Docs = "sometimes"
	bad.Audit.RetentionDays = -1
	_, err := m.Save(ctx, bad, settings.PasswordChange{})
	var ve *config.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
	if m.Current() != cfg || read(t, env.Path) != env.YAML {
		t.Fatal("an invalid save must change nothing")
	}

	s := cfg.Managed()
	s.API.Docs = "authenticated"
	s.API.PublicURL = "https://gw.example.com/"
	s.API.TrustedProxies = []string{"10.0.0.0/8"}
	s.Upstream.SMTP.Port = 0 // blank: default for the security mode
	f := false
	s.Defaults.Policy.RequireSigning = &f
	s.Defaults.Policy.RateLimit = &policy.RateLimit{PerHour: 1, PerDay: 2}
	if _, err := m.Save(ctx, s, settings.PasswordChange{}); err != nil {
		t.Fatal(err)
	}
	written := read(t, env.Path)
	if _, err := m.Save(ctx, s, settings.PasswordChange{}); err != nil || read(t, env.Path) != written {
		t.Fatalf("saving the same settings again must not change the file: %v", err) // nothing accumulates
	}
	c := m.Current()
	if c.API.PublicURL != "https://gw.example.com" || c.Upstream.SMTP.Port != 25 || len(c.API.TrustedProxies) != 1 {
		t.Fatalf("saved settings must be normalized: %+v", c.Managed())
	}
	// They apply at once, derived fields included.
	if c.API.Docs != "authenticated" || len(c.API.TrustedNets) != 1 || c.API.TrustedNets[0].String() != "10.0.0.0/8" ||
		c.DefaultPolicy.RateLimit.PerHour != 1 || c.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("current = %+v", c.Managed())
	}
	if c.KEK.File != cfg.KEK.File || c.Dir != cfg.Dir || c.Fingerprint != config.Fingerprint([]byte(written)) || m.Changed() {
		t.Fatal("the bootstrap keys carry over, and the written file is the current one")
	}
	// The previous snapshot is never modified.
	if cfg.API.Docs != "public" || cfg.API.PublicURL != "" || len(cfg.API.TrustedNets) != 2 ||
		cfg.Upstream.SMTP.Port != env.SMTP.Port || cfg.DefaultPolicy.RateLimit.PerHour == 1 {
		t.Fatalf("previous snapshot changed: %+v", cfg.Managed())
	}
	// The file holds exactly what is current, and keeps its mode.
	if fi, _ := os.Stat(env.Path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	reloaded, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if d := config.DiffSettings(reloaded.Managed(), c.Managed()); len(d) != 0 {
		t.Fatalf("the file differs from the current settings: %v\n%s", d, written)
	}
	if strings.Contains(written, env.SMTP.Pass) {
		t.Fatal("the password must never be written to the file")
	}

	// A new password applies at once too; the previous snapshot keeps its own.
	if _, err := m.Save(ctx, s, settings.PasswordChange{Set: true, Value: "new-secret"}); err != nil {
		t.Fatal(err)
	}
	if m.Current().Upstream.SMTP.Password != "new-secret" || c.Upstream.SMTP.Password != env.SMTP.Pass || read(t, env.Path) != written {
		t.Fatal("password change")
	}
	if _, err := m.Save(ctx, orig, settings.PasswordChange{Set: true, Value: env.SMTP.Pass}); err != nil {
		t.Fatal(err)
	}
	if d := config.DiffSettings(m.Current().Managed(), orig); len(d) != 0 || m.Current().Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("reverted, still differs: %v", d)
	}

	// Removing the password while a username is set only warns.
	if w, err := m.Save(ctx, orig, settings.PasswordChange{Set: true}); err != nil || !slices.Contains(w, config.SMTPPasswordMissing) || m.HasPassword() || m.PasswordState() != settings.None {
		t.Fatalf("remove password: %v %v %v", w, err, m.PasswordState())
	}
	noUser := m.Current().Managed()
	noUser.Upstream.SMTP.Username = ""
	if w, err := m.Save(ctx, noUser, settings.PasswordChange{}); err != nil || slices.Contains(w, config.SMTPPasswordMissing) {
		t.Fatalf("no username: %v %v", w, err)
	}

	// The next start runs with what was saved.
	_, cfg2 := boot(t, env.Path, st)
	if cfg2.Upstream.SMTP.Username != "" || cfg2.Upstream.SMTP.Password != "" {
		t.Fatalf("after restart: %+v", cfg2.Upstream.SMTP)
	}
}

// A save rewrites only the keys it changed: the rest of the file stays as
// the operator wrote it.
func TestSaveKeepsTheRestOfTheFile(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	commented := strings.Replace(env.YAML, "audit:\n", "# Kept for a month.\naudit:\n", 1)
	commented = strings.Replace(commented, "  retention_days: 30\n", "  retention_days: 30 # days\n", 1)
	os.WriteFile(env.Path, []byte(commented), 0o600)
	m, _ := boot(t, env.Path, testutil.OpenStore(t, env))
	s := m.Current().Managed()
	s.Audit.RetentionDays = 7
	if _, err := m.Save(context.Background(), s, settings.PasswordChange{}); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(commented, "retention_days: 30 # days", "retention_days: 7 # days", 1)
	if got := read(t, env.Path); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSaveSigningRules(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	m, _ := boot(t, env.Path, testutil.OpenStore(t, env))
	s := m.Current().Managed()
	tr := true
	s.Defaults.Policy.RequireSigning = &tr
	s.Defaults.Policy.Services = &[]string{policy.SvcMarkdown}
	_, err := m.Save(context.Background(), s, settings.PasswordChange{})
	if err == nil || !strings.Contains(err.Error(), "signing is not configured") {
		t.Fatalf("require_signing without signing: %v", err)
	}
}

func TestRecipients(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	st := testutil.OpenStore(t, env)
	m, before := boot(t, env.Path, st)
	ctx := context.Background()
	key := testutil.ArmorPublic(t, testutil.NewKey(t, "New", "new@example.com"))
	r := &config.Recipient{Alias: "new", Address: "new@example.com", Description: "New inbox", PGPPublicKey: key}
	if _, err := m.PutRecipient(ctx, r, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PutRecipient(ctx, r, true); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an existing alias: %v", err)
	}
	if _, err := m.PutRecipient(ctx, &config.Recipient{Alias: "ghost", Address: "g@example.com"}, false); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a missing alias: %v", err)
	}
	got, ok := m.Current().Recipient("new")
	if !ok || got.Key == nil || got.Description != "New inbox" {
		t.Fatalf("applied at once, key parsed: %+v", got)
	}
	if _, ok := before.Recipient("new"); ok {
		t.Fatal("the previous snapshot is never modified")
	}
	// Invalid: nothing changes.
	if _, err := m.PutRecipient(ctx, &config.Recipient{Alias: "new", Address: "nope", RequireEncryption: true}, false); err == nil {
		t.Fatal("an invalid recipient must be refused")
	}
	upd := *got
	upd.Description = "Renamed"
	if _, err := m.PutRecipient(ctx, &upd, false); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteRecipient(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteRecipient(ctx, "ops"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
	// The file has it all.
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Aliases(), ","); got != "me,new,work" {
		t.Fatalf("aliases %s", got)
	}
	if r, _ := c.Recipient("new"); r.Description != "Renamed" || r.Fingerprint() != got.Fingerprint() {
		t.Fatalf("written recipient: %+v", r)
	}
}

func TestAgents(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _ := boot(t, env.Path, st)
	ctx := context.Background()
	a := testutil.AddAgent(t, m, "bench", policy.Policy{Recipients: &[]string{"me"}})
	if !a.Enabled() || a.Name != "bench" {
		t.Fatalf("added: %+v", a)
	}
	if _, err := m.PutAgent(ctx, &config.Agent{Name: "bench"}, true); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("an existing name: %v", err)
	}
	// A policy that breaks a cross-field rule is refused.
	f := false
	bad := *a
	bad.Policy = policy.Policy{Services: &[]string{policy.SvcE2E}}
	if _, err := m.PutAgent(ctx, &bad, false); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("e2e with required signing: %v", err)
	}
	upd := *a
	upd.Disabled, upd.Description = true, "Benchmarks"
	upd.Policy.RequireSigning = &f
	if _, err := m.PutAgent(ctx, &upd, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Current().Agent("bench"); got.Enabled() || got.Description != "Benchmarks" {
		t.Fatalf("updated: %+v", got)
	}
	c, err := config.Load(env.Path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := c.Agent("bench"); !ok || got.Enabled() || *got.Policy.RequireSigning || (*got.Policy.Recipients)[0] != "me" {
		t.Fatalf("written agent: %+v", got)
	}

	// Deleting an agent deletes its tokens and keys too.
	if err := st.CreateToken(ctx, &store.Token{ID: "tok1", Agent: "bench", SecretHash: []byte{1}}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteAgent(ctx, "bench"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Current().Agent("bench"); ok {
		t.Fatal("deleted")
	}
	if _, err := st.GetToken(ctx, "tok1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("the agent's tokens must be deleted")
	}
	if err := m.DeleteAgent(ctx, "bench"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
}

// While config.yaml has a hand edit the gateway has not loaded, every
// change is refused: writing would discard the edit.
func TestRefusedWhileTheFileIsEdited(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	m, _ := boot(t, env.Path, testutil.OpenStore(t, env))
	ctx := context.Background()
	if m.Changed() {
		t.Fatal("unchanged at start")
	}
	edited := env.YAML + "# a hand edit\n"
	os.WriteFile(env.Path, []byte(edited), 0o600)
	if !m.Changed() {
		t.Fatal("the edit must be noticed")
	}
	s := m.Current().Managed()
	s.Audit.RetentionDays = 7
	if _, err := m.Save(ctx, s, settings.PasswordChange{}); !errors.Is(err, settings.ErrFileChanged) {
		t.Fatalf("Save: %v", err)
	}
	if _, err := m.PutAgent(ctx, &config.Agent{Name: "x"}, true); !errors.Is(err, settings.ErrFileChanged) {
		t.Fatalf("PutAgent: %v", err)
	}
	if err := m.DeleteRecipient(ctx, "ops"); !errors.Is(err, settings.ErrFileChanged) {
		t.Fatalf("DeleteRecipient: %v", err)
	}
	if read(t, env.Path) != edited {
		t.Fatal("the hand edit must survive")
	}
	os.Remove(env.Path)
	if !m.Changed() {
		t.Fatal("a missing file counts as changed")
	}
}

func TestPasswordSealedRoundTrip(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)
	if m.PasswordState() != settings.Sealed {
		t.Fatalf("state = %v", m.PasswordState())
	}
	p, err := st.GetSMTPPassword(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Sealed || bytes.Contains(p.Value, []byte(env.SMTP.Pass)) || strings.Contains(read(t, env.Path), env.SMTP.Pass) {
		t.Fatal("the password must be stored sealed and never in the file")
	}
	if _, cfg := boot(t, env.Path, st); cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("password = %q", cfg.Upstream.SMTP.Password)
	}
}

func TestPasswordRawWithoutKEKThenResealed(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _ := boot(t, env.Path, st, noKEK)
	enterPassword(t, m, env.SMTP.Pass)
	p, _ := st.GetSMTPPassword(context.Background())
	if m.PasswordState() != settings.Unsealed || p.Sealed || string(p.Value) != env.SMTP.Pass || !slices.Contains(m.Current().Warnings, settings.PasswordUnsealed) {
		t.Fatalf("state %v, row %+v", m.PasswordState(), p)
	}
	// A KEK appears: the password is sealed at start.
	m, cfg := boot(t, env.Path, st)
	p, _ = st.GetSMTPPassword(context.Background())
	if m.PasswordState() != settings.Sealed || !p.Sealed || bytes.Contains(p.Value, []byte(env.SMTP.Pass)) {
		t.Fatalf("state %v, row %+v", m.PasswordState(), p)
	}
	if cfg.Upstream.SMTP.Password != env.SMTP.Pass || slices.Contains(cfg.Warnings, settings.PasswordUnsealed) {
		t.Fatal("password lost while resealing")
	}
}

func TestPasswordUndecryptable(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)

	// A damaged row: start anyway, without the password. (A KEK that does
	// not open the keyring never gets this far: see the keyring package.)
	ctx := context.Background()
	p, _ := st.GetSMTPPassword(ctx)
	p.Value[len(p.Value)-1] ^= 1
	if err := st.SetSMTPPassword(ctx, p); err != nil {
		t.Fatal(err)
	}
	m, cfg := boot(t, env.Path, st)
	if m.PasswordState() != settings.Undecryptable || !m.HasPassword() || cfg.Upstream.SMTP.Password != "" {
		t.Fatalf("state %v", m.PasswordState())
	}
	if !slices.Contains(cfg.Warnings, config.SMTPPasswordMissing) {
		t.Fatalf("warnings %v", cfg.Warnings)
	}
	// Saving other settings keeps the stored password as it is; entering
	// it again fixes it.
	s := cfg.Managed()
	s.Audit.RetentionDays = 7
	if _, err := m.Save(ctx, s, settings.PasswordChange{}); err != nil || m.PasswordState() != settings.Undecryptable {
		t.Fatalf("keep: %v %v", err, m.PasswordState())
	}
	if _, err := m.Save(ctx, s, settings.PasswordChange{Set: true, Value: env.SMTP.Pass}); err != nil || m.PasswordState() != settings.Sealed {
		t.Fatalf("re-enter: %v %v", err, m.PasswordState())
	}
	if m.Current().Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("a re-entered password is usable at once")
	}
	if _, cfg = boot(t, env.Path, st); cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("re-entered password not usable after restart")
	}
}
