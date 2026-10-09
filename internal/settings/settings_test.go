package settings_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

// boot loads config.yaml afresh, as a restart does, and bootstraps settings.
func boot(t *testing.T, path string, st *store.Store, mod ...func(*config.Config)) (*settings.Manager, *config.Config, bool) {
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
	m, seeded, err := settings.Bootstrap(context.Background(), st, cfg, kr, testutil.DiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	return m, cfg, seeded
}

// noKEK boots as if kek.file were not set.
func noKEK(c *config.Config) { c.KEK.Key = nil }

// enterPassword saves the SMTP password, as the operator does on the
// dashboard: it is never seeded.
func enterPassword(t *testing.T, m *settings.Manager, pw string) {
	t.Helper()
	if _, err := m.Save(context.Background(), m.Saved(), settings.PasswordChange{Set: true, Value: pw}); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p, content string) string {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSeedOnlyIntoEmpty(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{DefaultsPolicy: "recipients: [me]", TrustedProxies: []string{"10.0.0.1"}})
	st := testutil.OpenStore(t, env)
	// A database from before settings moved there: recipients, no settings.
	if _, _, err := recipients.Bootstrap(context.Background(), st, env.Config, func() policy.Effective { return env.Config.DefaultPolicy }); err != nil {
		t.Fatal(err)
	}
	m, cfg, seeded := boot(t, env.Path, st)
	if !seeded {
		t.Fatal("an empty settings table must be seeded")
	}
	r := m.Saved()
	if r.Upstream.SMTP.Host != env.SMTP.Host || r.Upstream.SMTP.Port != env.SMTP.Port || r.Upstream.From != "gateway@example.com" || r.API.Docs != "public" {
		t.Fatalf("saved = %+v", r)
	}
	if !slices.Equal(cfg.DefaultPolicy.Recipients, []string{"me"}) || len(cfg.API.TrustedNets) != 1 {
		t.Fatalf("cfg not loaded: %+v", cfg.Managed())
	}
	if m.Current() != cfg {
		t.Fatal("the loaded config is the first current one")
	}
	// The password is never seeded: the username alone is a warning.
	if len(m.LoadProblems()) != 0 || m.HasPassword() || cfg.Upstream.SMTP.Password != "" || !slices.Contains(cfg.Warnings, config.SMTPPasswordMissing) {
		t.Fatalf("problems %v, warnings %v", m.LoadProblems(), cfg.Warnings)
	}
	enterPassword(t, m, env.SMTP.Pass)

	// Later boots ignore the file's managed keys, even if they changed.
	changed := strings.Replace(env.YAML, "retention_days: 30", "retention_days: 99", 1)
	p := writeFile(t, filepath.Join(env.Dir, "changed.yaml"), changed)
	m, cfg, seeded = boot(t, p, st)
	if seeded || m.Current().Audit.RetentionDays != 30 || cfg.Audit.RetentionDays != 30 {
		t.Fatalf("second boot seeded %v, retention %d", seeded, cfg.Audit.RetentionDays)
	}
	if cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("password must come from the store")
	}
}

func TestSeedProblemsAreFatal(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	st := testutil.OpenStore(t, env)
	bad := strings.Replace(env.YAML, "docs: public", "docs: sometimes", 1)
	bad = strings.Replace(bad, "retention_days: 30", "retention_days: -1", 1)
	cfg, err := config.Load(writeFile(t, filepath.Join(env.Dir, "bad.yaml"), bad))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = settings.Bootstrap(context.Background(), st, cfg, nil, testutil.DiscardLogger())
	var ve *config.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("want both seed problems, got %v", err)
	}
	if _, err := st.GetSettings(context.Background()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("nothing must be stored")
	}
}

func TestFreshInstallWithoutUpstream(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	start, end := strings.Index(env.YAML, "upstream:\n"), strings.Index(env.YAML, "recipients:\n")
	p := writeFile(t, filepath.Join(env.Dir, "fresh.yaml"), env.YAML[:start]+env.YAML[end:])
	m, cfg, _ := boot(t, p, testutil.OpenStore(t, env))
	if !slices.Contains(cfg.Warnings, "upstream SMTP is not configured: set it on the Settings page") || len(m.LoadProblems()) != 0 {
		t.Fatalf("warnings %v, problems %v", cfg.Warnings, m.LoadProblems())
	}
	if m.HasPassword() || m.PasswordState() != settings.None || cfg.Upstream.SMTP.Port != 587 {
		t.Fatalf("state %v, smtp %+v", m.PasswordState(), cfg.Upstream.SMTP)
	}
}

func TestSave(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{TrustedProxies: []string{"10.0.0.1", "192.168.0.0/16"}})
	st := testutil.OpenStore(t, env)
	m, cfg, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)
	cfg = m.Current()
	ctx := context.Background()
	orig := m.Saved()

	bad := m.Saved()
	bad.API.Docs = "sometimes"
	bad.Dashboard.SessionTTL = 1
	_, err := m.Save(ctx, bad, settings.PasswordChange{})
	var ve *config.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 2 {
		t.Fatalf("want 2 problems, got %v", err)
	}
	if m.Current() != cfg || len(config.DiffSettings(m.Saved(), orig)) != 0 {
		t.Fatal("an invalid save must change nothing")
	}

	s := m.Saved()
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
	if _, err := m.Save(ctx, s, settings.PasswordChange{}); err != nil { // twice: nothing accumulates
		t.Fatal(err)
	}
	saved := m.Saved()
	if saved.API.PublicURL != "https://gw.example.com" || saved.Upstream.SMTP.Port != 25 || len(saved.API.TrustedProxies) != 1 {
		t.Fatalf("saved settings must be normalized: %+v", saved)
	}
	// They apply at once, derived fields included.
	c := m.Current()
	if c.API.Docs != "authenticated" || c.API.PublicURL != "https://gw.example.com" || c.Upstream.SMTP.Port != 25 ||
		len(c.API.TrustedNets) != 1 || c.API.TrustedNets[0].String() != "10.0.0.0/8" ||
		c.DefaultPolicy.RateLimit.PerHour != 1 || c.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("current = %+v", c.Managed())
	}
	if c.KEK.File != cfg.KEK.File || c.DataDir != cfg.DataDir {
		t.Fatal("the bootstrap keys carry over")
	}
	// The boot config is a snapshot of its own and is never modified.
	if cfg.API.Docs != "public" || cfg.API.PublicURL != "" || len(cfg.API.TrustedNets) != 2 ||
		cfg.Upstream.SMTP.Port != env.SMTP.Port || cfg.DefaultPolicy.RateLimit.PerHour == 1 {
		t.Fatalf("boot config changed: %+v", cfg.Managed())
	}

	// A new password applies at once too; the previous snapshot keeps its own.
	if _, err := m.Save(ctx, s, settings.PasswordChange{Set: true, Value: "new-secret"}); err != nil {
		t.Fatal(err)
	}
	if m.Current().Upstream.SMTP.Password != "new-secret" || c.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("password change")
	}
	if _, err := m.Save(ctx, orig, settings.PasswordChange{Set: true, Value: env.SMTP.Pass}); err != nil {
		t.Fatal(err)
	}
	if d := config.DiffSettings(m.Saved(), orig); len(d) != 0 || m.Current().Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("reverted, still differs: %v", d)
	}

	// Removing the password while a username is set only warns.
	if w, err := m.Save(ctx, orig, settings.PasswordChange{Set: true}); err != nil || !slices.Contains(w, config.SMTPPasswordMissing) || m.HasPassword() || m.PasswordState() != settings.None {
		t.Fatalf("remove password: %v %v %v", w, err, m.PasswordState())
	}
	noUser := m.Saved()
	noUser.Upstream.SMTP.Username = ""
	if w, err := m.Save(ctx, noUser, settings.PasswordChange{}); err != nil || slices.Contains(w, config.SMTPPasswordMissing) {
		t.Fatalf("no username: %v %v", w, err)
	}

	// The next boot runs with what was saved.
	m2, cfg2, _ := boot(t, env.Path, st)
	if cfg2.Upstream.SMTP.Username != "" || cfg2.Upstream.SMTP.Password != "" || len(m2.LoadProblems()) != 0 {
		t.Fatalf("after restart: %+v %v", cfg2.Upstream.SMTP, m2.LoadProblems())
	}
}

func TestSaveSigningRules(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	m, _, _ := boot(t, env.Path, testutil.OpenStore(t, env))
	s := m.Saved()
	tr := true
	s.Defaults.Policy.RequireSigning = &tr
	s.Defaults.Policy.Services = &[]string{policy.SvcMarkdown}
	_, err := m.Save(context.Background(), s, settings.PasswordChange{})
	if err == nil || !strings.Contains(err.Error(), "signing is not configured") {
		t.Fatalf("require_signing without signing: %v", err)
	}
}

func TestPasswordSealedRoundTrip(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)
	if m.PasswordState() != settings.Sealed {
		t.Fatalf("state = %v", m.PasswordState())
	}
	row, err := st.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !row.PasswordSealed || bytes.Contains(row.SMTPPassword, []byte(env.SMTP.Pass)) || bytes.Contains(row.Doc, []byte(env.SMTP.Pass)) {
		t.Fatal("the password must be stored sealed and never in the document")
	}
	_, cfg, _ := boot(t, env.Path, st)
	if cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("password = %q", cfg.Upstream.SMTP.Password)
	}
}

func TestPasswordRawWithoutKEKThenResealed(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _, _ := boot(t, env.Path, st, noKEK)
	enterPassword(t, m, env.SMTP.Pass)
	row, _ := st.GetSettings(context.Background())
	if m.PasswordState() != settings.Unsealed || row.PasswordSealed || string(row.SMTPPassword) != env.SMTP.Pass {
		t.Fatalf("state %v, row %+v", m.PasswordState(), row)
	}
	// A KEK appears: the password is sealed at boot.
	m, cfg, _ := boot(t, env.Path, st)
	row, _ = st.GetSettings(context.Background())
	if m.PasswordState() != settings.Sealed || !row.PasswordSealed || bytes.Contains(row.SMTPPassword, []byte(env.SMTP.Pass)) {
		t.Fatalf("state %v, row %+v", m.PasswordState(), row)
	}
	if cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("password lost while resealing")
	}
}

func TestPasswordUndecryptable(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{Signing: true})
	st := testutil.OpenStore(t, env)
	m, _, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)

	// A damaged row: boot anyway, without the password. (A KEK that does
	// not open the keyring never gets this far: see the keyring package.)
	ctx := context.Background()
	row, _ := st.GetSettings(ctx)
	row.SMTPPassword[len(row.SMTPPassword)-1] ^= 1
	if err := st.SaveSettings(ctx, row); err != nil {
		t.Fatal(err)
	}
	m, cfg, _ := boot(t, env.Path, st)
	if m.PasswordState() != settings.Undecryptable || !m.HasPassword() || cfg.Upstream.SMTP.Password != "" {
		t.Fatalf("state %v", m.PasswordState())
	}
	if len(m.LoadProblems()) != 0 || !slices.Contains(cfg.Warnings, config.SMTPPasswordMissing) {
		t.Fatalf("problems %v, warnings %v", m.LoadProblems(), cfg.Warnings)
	}
	// Saving other settings keeps the stored password as it is; entering
	// it again fixes it.
	s := m.Saved()
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
	if _, cfg, _ = boot(t, env.Path, st); cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatal("re-entered password not usable after restart")
	}
}

func TestStoredProblemsNeverBlockBoot(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	st := testutil.OpenStore(t, env)
	m, _, _ := boot(t, env.Path, st)
	enterPassword(t, m, env.SMTP.Pass)
	ctx := context.Background()
	row, _ := st.GetSettings(ctx)

	// Valid JSON, invalid settings: run with them as they are.
	row.Doc = bytes.Replace(row.Doc, []byte(`"docs":"public"`), []byte(`"docs":"sometimes"`), 1)
	if err := st.SaveSettings(ctx, row); err != nil {
		t.Fatal(err)
	}
	m, cfg, _ := boot(t, env.Path, st)
	if p := m.LoadProblems(); len(p) != 1 || !strings.Contains(p[0], "api.docs") || cfg.API.Docs != "sometimes" {
		t.Fatalf("problems %v, docs %q", p, cfg.API.Docs)
	}
	if !slices.ContainsFunc(cfg.Warnings, func(w string) bool { return strings.HasPrefix(w, "saved settings: api.docs") }) {
		t.Fatalf("warnings = %v", cfg.Warnings)
	}

	// Not even JSON: run with the file's values; the next save replaces it.
	row.Doc = []byte("{not json")
	if err := st.SaveSettings(ctx, row); err != nil {
		t.Fatal(err)
	}
	m, cfg, _ = boot(t, env.Path, st)
	if p := m.LoadProblems(); len(p) != 1 || !strings.Contains(p[0], "cannot be decoded") {
		t.Fatalf("problems = %v", p)
	}
	if cfg.Upstream.SMTP.Host != env.SMTP.Host || cfg.Upstream.SMTP.Password != env.SMTP.Pass {
		t.Fatalf("must run with config.yaml's values: %+v", cfg.Upstream.SMTP)
	}
	if _, err := m.Save(ctx, m.Saved(), settings.PasswordChange{}); err != nil {
		t.Fatal(err)
	}
	// A valid save clears the problems at once.
	if p := m.LoadProblems(); len(p) != 0 {
		t.Fatalf("after save, problems = %v", p)
	}
	if w := m.Current().Warnings; slices.ContainsFunc(w, func(w string) bool { return strings.HasPrefix(w, settings.WarningPrefix) }) {
		t.Fatalf("after save, warnings = %v", w)
	}
	if m, _, _ = boot(t, env.Path, st); len(m.LoadProblems()) != 0 {
		t.Fatalf("after save: %v", m.LoadProblems())
	}
}
