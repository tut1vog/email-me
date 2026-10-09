// Package testutil provides a fake SMTP server, throwaway OpenPGP keys, a
// config builder and a seeded state database for tests.
package testutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/tut1vog/email-me/internal/admin"
	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/settings"
	"github.com/tut1vog/email-me/internal/store"
)

// Captured is a message received by the fake SMTP server.
type Captured struct {
	From string
	To   []string
	Data []byte
}

// SMTPServer is an in-process SMTP server that records messages.
type SMTPServer struct {
	Addr     string
	Host     string
	Port     int
	mu       sync.Mutex
	messages []Captured
	failCode int
	delay    time.Duration
	User     string
	Pass     string
}

func (s *SMTPServer) Messages() []Captured {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Captured(nil), s.messages...)
}

func (s *SMTPServer) Count() int { return len(s.Messages()) }

// Last returns the most recent message (fails the test if none).
func (s *SMTPServer) Last(t testing.TB) Captured {
	t.Helper()
	m := s.Messages()
	if len(m) == 0 {
		t.Fatal("no message captured by fake SMTP server")
	}
	return m[len(m)-1]
}

// SlowDown delays every DATA command (to hold requests in flight).
func (s *SMTPServer) SlowDown(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// FailWith makes DATA fail with the given SMTP code (0 = succeed).
func (s *SMTPServer) FailWith(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failCode = code
}

type session struct {
	srv  *SMTPServer
	from string
	to   []string
}

func (se *session) AuthMechanisms() []string { return []string{sasl.Plain} }
func (se *session) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, user, pass string) error {
		if user != se.srv.User || pass != se.srv.Pass {
			return &smtp.SMTPError{Code: 535, Message: "bad credentials"}
		}
		return nil
	}), nil
}
func (se *session) Reset()        { se.from, se.to = "", nil }
func (se *session) Logout() error { return nil }
func (se *session) Mail(from string, _ *smtp.MailOptions) error {
	se.from = from
	return nil
}
func (se *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	se.to = append(se.to, to)
	return nil
}
func (se *session) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	se.srv.mu.Lock()
	delay := se.srv.delay
	se.srv.mu.Unlock()
	time.Sleep(delay)
	se.srv.mu.Lock()
	defer se.srv.mu.Unlock()
	if se.srv.failCode != 0 {
		return &smtp.SMTPError{Code: se.srv.failCode, Message: "simulated failure"}
	}
	se.srv.messages = append(se.srv.messages, Captured{From: se.from, To: se.to, Data: b})
	return nil
}

// StartSMTP starts a fake plaintext SMTP server requiring PLAIN auth.
func StartSMTP(t testing.TB) *SMTPServer {
	t.Helper()
	fs := &SMTPServer{User: "gateway@example.com", Pass: "smtp-secret"}
	be := smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) { return &session{srv: fs}, nil })
	s := smtp.NewServer(be)
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.ErrorLog = nil
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs.Addr = l.Addr().String()
	fs.Host = "127.0.0.1"
	fs.Port = l.Addr().(*net.TCPAddr).Port
	go s.Serve(l)
	t.Cleanup(func() { s.Close() })
	return fs
}

// NewKey generates an Ed25519/Curve25519 key with an encryption subkey.
func NewKey(t testing.TB, name, email string) *openpgp.Entity {
	t.Helper()
	return NewKeyWithLifetime(t, name, email, 0)
}

// NewKeyWithLifetime is NewKey with an expiry (0 = never).
func NewKeyWithLifetime(t testing.TB, name, email string, lifetime time.Duration) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", email, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: uint32(lifetime / time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ArmorPublic returns an armored public key.
func ArmorPublic(t testing.TB, e *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.String()
}

// ArmorPrivate returns an armored private key (unencrypted).
func ArmorPrivate(t testing.TB, e *openpgp.Entity) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.String()
}

// Options customize the generated config.
type Options struct {
	// Signing configures a key-encryption key, which enables signing.
	Signing bool
	// Master is a certification key for the keys manager (see SetMaster).
	Master         *openpgp.Entity
	Docs           string
	LogSubject     bool
	TrustedProxies []string
	External       bool
	PublicURL      string
	// DefaultsPolicy is raw YAML placed under defaults.policy (indented by the builder).
	DefaultsPolicy string
	// WorkRequiresEncryption sets require_encryption on the "work" alias.
	WorkRequiresEncryption bool
	// MeKeyLifetime makes the "me" recipient key expire (0 = never).
	MeKeyLifetime time.Duration
}

// Env is a generated config plus the resources it points at.
type Env struct {
	Dir     string
	DataDir string
	Path    string
	YAML    string
	Config  *config.Config
	SMTP    *SMTPServer
	MeKey   *openpgp.Entity // "me" recipient key (with private part, for decrypting in tests)
	WorkKey *openpgp.Entity
	Master  *openpgp.Entity // Options.Master
	AdminPW string          // stored by BootstrapSettings
}

// NewEnv writes key files and a config.yaml into a temp dir and loads it.
// Recipient seeds: "me" (with PGP key), "work" (with PGP key), "ops" (no
// key); Bootstrap inserts them into the state database. The managed
// settings in env.Config are validated and complete, and the credentials
// stored, only after BootstrapSettings (or Bootstrap).
func NewEnv(t testing.TB, o Options) *Env {
	t.Helper()
	dir := t.TempDir()
	env := &Env{Dir: dir, DataDir: filepath.Join(dir, "data"), AdminPW: "correct horse battery staple", Master: o.Master}
	if err := os.MkdirAll(env.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env.SMTP = StartSMTP(t)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	env.MeKey = NewKeyWithLifetime(t, "Me", "me@example.com", o.MeKeyLifetime)
	env.WorkKey = NewKey(t, "Work", "work@example.org")
	mePub := write("me.asc", ArmorPublic(t, env.MeKey))
	workPub := write("work.asc", ArmorPublic(t, env.WorkKey))

	docs := o.Docs
	if docs == "" {
		docs = "public"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "data_dir: %q\n", env.DataDir)
	fmt.Fprintf(&b, "api:\n  listen: \"127.0.0.1:0\"\n  docs: %s\n  external_transport_encryption: %v\n", docs, o.External)
	if o.PublicURL != "" {
		fmt.Fprintf(&b, "  public_url: %q\n", o.PublicURL)
	}
	if len(o.TrustedProxies) > 0 {
		fmt.Fprintf(&b, "  trusted_proxies: [%s]\n", strings.Join(quoteAll(o.TrustedProxies), ", "))
	}
	fmt.Fprintf(&b, "dashboard:\n  listen: \"127.0.0.1:0\"\n")
	fmt.Fprintf(&b, "upstream:\n  smtp:\n    host: %s\n    port: %d\n    security: none\n    username: %q\n    timeout: 5s\n",
		env.SMTP.Host, env.SMTP.Port, env.SMTP.User)
	fmt.Fprintf(&b, "  from: gateway@example.com\n")
	fmt.Fprintf(&b, "recipients:\n")
	fmt.Fprintf(&b, "  me:\n    address: me@example.com\n    description: Personal inbox\n    pgp_public_key_file: %q\n", mePub)
	fmt.Fprintf(&b, "  work:\n    address: work@example.org\n    description: Work inbox\n    pgp_public_key_file: %q\n    require_encryption: %v\n", workPub, o.WorkRequiresEncryption)
	fmt.Fprintf(&b, "  ops:\n    address: ops@example.net\n    description: Ops pager\n")
	if o.Signing {
		kek := make([]byte, 32)
		rand.Read(kek)
		kekPath := write("kek", hex.EncodeToString(kek)+"\n")
		fmt.Fprintf(&b, "kek:\n  file: %q\n", kekPath)
		fmt.Fprintf(&b, "signing:\n  key_validity: 1y\n")
	}
	if o.DefaultsPolicy != "" {
		b.WriteString("defaults:\n  policy:\n")
		for _, line := range strings.Split(strings.TrimRight(o.DefaultsPolicy, "\n"), "\n") {
			b.WriteString("    " + line + "\n")
		}
	}
	fmt.Fprintf(&b, "audit:\n  retention_days: 30\n  log_subject: %v\n", o.LogSubject)
	fmt.Fprintf(&b, "log:\n  level: error\n")

	env.YAML = b.String()
	env.Path = write("config.yaml", env.YAML)
	cfg, err := config.Load(env.Path)
	if err != nil {
		t.Fatalf("loading test config: %v\n%s", err, env.YAML)
	}
	env.Config = cfg
	return env
}

// Bootstrap opens the env's state database and loads its settings and
// recipient registry, seeding both from the config, like serve does.
func Bootstrap(t testing.TB, env *Env) (*store.Store, *recipients.Registry) {
	t.Helper()
	st := OpenStore(t, env)
	sm := BootstrapSettings(t, env, st)
	reg, _, err := recipients.Bootstrap(context.Background(), st, env.Config, DefaultPolicy(sm))
	if err != nil {
		t.Fatal(err)
	}
	return st, reg
}

// OpenStore opens the env's state database; it is closed when the test ends.
func OpenStore(t testing.TB, env *Env) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// BootstrapSettings loads the managed settings from st into env.Config,
// seeding st from the config on first use, as serve does. On first use it
// also stores the credentials an operator would enter on the dashboard:
// the fake server's SMTP password and env.AdminPW. Call it before
// recipients.Bootstrap, which needs the default policy (DefaultPolicy).
func BootstrapSettings(t testing.TB, env *Env, st *store.Store) *settings.Manager {
	t.Helper()
	ctx := context.Background()
	m, seeded, err := settings.Bootstrap(ctx, st, env.Config, Keyring(t, env, st), DiscardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if seeded {
		if _, err := m.Save(ctx, m.Saved(), settings.PasswordChange{Set: true, Value: env.SMTP.Pass}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.GetAdmin(ctx); errors.Is(err, store.ErrNotFound) {
		if err := admin.Set(ctx, st, env.AdminPW); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// Keyring opens st's keyring with env's KEK, as serve does (nil without
// one).
func Keyring(t testing.TB, env *Env, st *store.Store) *keyring.Keyring {
	t.Helper()
	kr, _, err := keyring.Open(context.Background(), st, env.Config.KEK.Key, env.Config.KEK.Previous)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// Keys returns a keys manager for env, as serve builds it: sealed under
// st's keyring, following m's From address and key validity, and with
// env.Master as its certification key.
func Keys(t testing.TB, env *Env, st *store.Store, m *settings.Manager) *keys.Manager {
	t.Helper()
	km := keys.NewManager(st, keys.Options{Keyring: Keyring(t, env, st), From: func() (string, time.Duration) {
		c := m.Current()
		if c.Signing == nil {
			return c.Upstream.From, 0
		}
		return c.Upstream.From, c.Signing.KeyValidity.D()
	}})
	if env.Master != nil {
		if _, err := km.SetMaster(context.Background(), []byte(ArmorPrivate(t, env.Master)), nil); err != nil {
			t.Fatal(err)
		}
	}
	return km
}

// SeedState prepares env's state database the way an operator's first
// session would (see BootstrapSettings), for tests that start the whole
// gateway on it.
func SeedState(t testing.TB, env *Env) {
	t.Helper()
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	BootstrapSettings(t, env, st)
}

// DefaultPolicy returns the current default policy of m, as serve passes
// it to recipients.Bootstrap.
func DefaultPolicy(m *settings.Manager) func() policy.Effective {
	return func() policy.Effective { return m.Current().DefaultPolicy }
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

// DiscardLogger returns a logger that drops everything.
func DiscardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
