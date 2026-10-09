// Package settings applies the dashboard's changes to the configuration.
// config.yaml is the source of truth for the managed settings, the
// recipients and the agents; a Manager serves the current configuration
// (Current) and every successful change validates the configuration with
// the change merged in, writes config.yaml and replaces the current
// configuration, so it applies at once.
//
// Only the keys a change touches are written: the rest of the file stays as
// the operator wrote it. A hand edit is not applied until the next start,
// and while one is pending every change is refused (ErrFileChanged), since
// writing the loaded configuration back would discard it.
//
// The SMTP password is the one managed value that is a secret, so it is not
// in config.yaml: it is kept sealed in the state database.
package settings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/store"
)

// passwordAAD binds a sealed SMTP password to its column.
const passwordAAD = "credentials.smtp_password"

// ErrFileChanged refuses a change while config.yaml differs from the file
// the gateway runs with.
var ErrFileChanged = errors.New("config.yaml was edited since email-me started; run email-me restart to apply the edit, then make this change")

// PasswordUnsealed is the warning for a password stored without a KEK.
const PasswordUnsealed = "the SMTP password is stored unencrypted in the state database; set kek.file in config.yaml to encrypt it"

// PasswordState says how the saved SMTP password is stored.
type PasswordState int

const (
	// None: no password is stored.
	None PasswordState = iota
	// Sealed: encrypted under the keyring.
	Sealed
	// Unsealed: stored raw because no key-encryption key is configured.
	Unsealed
	// Undecryptable: stored sealed, but it does not open with the keyring
	// (a damaged row). It must be entered again.
	Undecryptable
)

// PasswordChange is a Save's instruction for the SMTP password, which the
// dashboard never shows: Set false keeps the saved one, Set with an empty
// Value removes it.
type PasswordChange struct {
	Set   bool
	Value string
}

// Manager serves the current configuration and applies changes to it.
type Manager struct {
	path string
	st   *store.Store
	kr   *keyring.Keyring // nil: the password is stored raw

	// cur is the current configuration. A stored snapshot is never
	// modified: a change stores a new one, so a reader that holds one sees
	// a consistent configuration however long it keeps it.
	cur atomic.Pointer[config.Config]

	mu      sync.RWMutex // serializes changes and guards pwState
	pwState PasswordState
}

// Open makes cfg, loaded from path, the current configuration, completed
// with the SMTP password from the store. A password that cannot be
// decrypted is dropped with a warning, never a failure; one stored raw is
// sealed now if a keyring has appeared. kr nil (no key-encryption key)
// stores the password raw.
func Open(ctx context.Context, path string, cfg *config.Config, st *store.Store, kr *keyring.Keyring, log *slog.Logger) (*Manager, error) {
	m := &Manager{path: path, st: st, kr: kr}
	pw, state, err := m.openPassword(ctx, log)
	if err != nil {
		return nil, err
	}
	c := clone(cfg)
	c.Upstream.SMTP.Password = pw
	// Validated again for the warnings that depend on the password.
	_, warnings := c.ValidateManaged()
	c.Warnings = m.warnings(c, warnings, state)
	m.pwState = state
	m.cur.Store(c)
	return m, nil
}

func (m *Manager) openPassword(ctx context.Context, log *slog.Logger) (string, PasswordState, error) {
	p, err := m.st.GetSMTPPassword(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "", None, nil
	case err != nil:
		return "", None, fmt.Errorf("loading the SMTP password: %w", err)
	case !p.Sealed && m.kr == nil:
		log.Warn("the upstream SMTP password is stored unencrypted in the state database; set kek.file to encrypt it")
		return string(p.Value), Unsealed, nil
	case !p.Sealed:
		pw := string(p.Value)
		blob, err := m.kr.Seal(p.Value, passwordAAD)
		if err != nil {
			return "", None, err
		}
		if err := m.st.SetSMTPPassword(ctx, &store.SMTPPassword{Value: blob, Sealed: true}); err != nil {
			return "", None, fmt.Errorf("encrypting the stored SMTP password: %w", err)
		}
		log.Info("encrypted the stored upstream SMTP password with the keyring")
		return pw, Sealed, nil
	case m.kr == nil:
		// Not reached from run: a sealed password implies a keyring, which
		// cannot be opened without a KEK.
		log.Warn("the stored upstream SMTP password is encrypted but no key-encryption key is set; re-enter the password on the Settings page")
		return "", Undecryptable, nil
	}
	plain, err := m.kr.Unseal(p.Value, passwordAAD)
	if err != nil {
		log.Warn("the stored upstream SMTP password cannot be decrypted; re-enter it on the Settings page")
		return "", Undecryptable, nil
	}
	return string(plain), Sealed, nil
}

// warnings is a snapshot's warning list: the bootstrap keys' and the
// managed configuration's, and the password's state.
func (m *Manager) warnings(c *config.Config, managed []string, state PasswordState) []string {
	out := append(slices.Clone(c.BootstrapWarnings), managed...)
	if state == Unsealed {
		out = append(out, PasswordUnsealed)
	}
	return out
}

// Current returns the current configuration. The caller must not modify
// it. A request should read it once and use that snapshot throughout, so a
// concurrent change cannot mix two configurations in one response.
func (m *Manager) Current() *config.Config { return m.cur.Load() }

// Changed reports whether config.yaml on disk differs from the file the
// current configuration was loaded from or last written as. An unreadable
// file counts as changed.
func (m *Manager) Changed() bool {
	fp, err := config.FileFingerprint(m.path)
	return err != nil || fp != m.Current().Fingerprint
}

// HasPassword reports whether an SMTP password is stored, usable or not.
func (m *Manager) HasPassword() bool { return m.PasswordState() != None }

// PasswordState returns how the saved SMTP password is stored.
func (m *Manager) PasswordState() PasswordState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pwState
}

// Save replaces the managed settings with s and applies them. It returns
// the configuration's warnings, and a *config.ValidationError listing every
// problem if s is invalid, in which case nothing changes.
func (m *Manager) Save(ctx context.Context, s config.Settings, pw PasswordChange) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := m.pwState
	return m.commit(ctx, func(c *config.Config) error {
		c.SetManaged(s)
		if pw.Set {
			c.Upstream.SMTP.Password = pw.Value
		}
		return nil
	}, func(d *config.Document, prev, next *config.Config) error {
		ns := next.Managed()
		for _, key := range config.DiffSettings(prev.Managed(), ns) {
			path := strings.Split(key, ".")
			n, ok, err := config.ValueAt(ns, path)
			switch {
			case err != nil:
				return err
			case ok:
				d.SetNode(path, n)
			default:
				d.Delete(path)
			}
		}
		return nil
	}, func(ctx context.Context) (PasswordState, error) {
		if !pw.Set {
			return state, nil
		}
		return m.storePassword(ctx, pw.Value)
	})
}

// storePassword stores pw, sealed when there is a keyring; "" removes it.
func (m *Manager) storePassword(ctx context.Context, pw string) (PasswordState, error) {
	if pw == "" {
		return None, m.st.SetSMTPPassword(ctx, nil)
	}
	p := &store.SMTPPassword{Value: []byte(pw)}
	state := Unsealed
	if m.kr != nil {
		blob, err := m.kr.Seal(p.Value, passwordAAD)
		if err != nil {
			return m.pwState, err
		}
		p.Value, p.Sealed, state = blob, true, Sealed
	}
	if err := m.st.SetSMTPPassword(ctx, p); err != nil {
		return m.pwState, fmt.Errorf("saving the SMTP password: %w", err)
	}
	return state, nil
}

// PutRecipient adds a recipient (create) or replaces an existing one, and
// applies the change. It returns store.ErrConflict when creating an alias
// that exists, store.ErrNotFound when replacing one that does not, and a
// *config.ValidationError when the configuration would be invalid.
func (m *Manager) PutRecipient(ctx context.Context, r *config.Recipient, create bool) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commit(ctx, func(c *config.Config) error {
		if err := exists(c.Recipients, r.Alias, create); err != nil {
			return err
		}
		cp := *r
		c.Recipients[r.Alias] = &cp
		return nil
	}, func(d *config.Document, _, next *config.Config) error {
		return d.Set([]string{"recipients", r.Alias}, next.Recipients[r.Alias])
	}, nil)
}

// DeleteRecipient removes a recipient. Policies naming it are not edited:
// the alias is ignored (and flagged on the dashboard) wherever it appears.
func (m *Manager) DeleteRecipient(ctx context.Context, alias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.commit(ctx, func(c *config.Config) error {
		if err := exists(c.Recipients, alias, false); err != nil {
			return err
		}
		delete(c.Recipients, alias)
		return nil
	}, func(d *config.Document, _, _ *config.Config) error {
		d.Delete([]string{"recipients", alias})
		return nil
	}, nil)
	return err
}

// PutAgent adds an agent (create) or replaces an existing one, and applies
// the change. Errors are as for PutRecipient.
func (m *Manager) PutAgent(ctx context.Context, a *config.Agent, create bool) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.commit(ctx, func(c *config.Config) error {
		if err := exists(c.Agents, a.Name, create); err != nil {
			return err
		}
		cp := *a
		c.Agents[a.Name] = &cp
		return nil
	}, func(d *config.Document, _, next *config.Config) error {
		return d.Set([]string{"agents", a.Name}, next.Agents[a.Name])
	}, nil)
}

// DeleteAgent removes an agent from the configuration, then deletes its
// tokens and signing keys from the store.
func (m *Manager) DeleteAgent(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.commit(ctx, func(c *config.Config) error {
		if err := exists(c.Agents, name, false); err != nil {
			return err
		}
		delete(c.Agents, name)
		return nil
	}, func(d *config.Document, _, _ *config.Config) error {
		d.Delete([]string{"agents", name})
		return nil
	}, nil)
	if err != nil {
		return err
	}
	if err := m.st.DeleteAgentData(ctx, name); err != nil {
		return fmt.Errorf("deleting the agent's tokens and keys: %w", err)
	}
	return nil
}

func exists[V any](m map[string]V, key string, create bool) error {
	_, ok := m[key]
	switch {
	case create && ok:
		return store.ErrConflict
	case !create && !ok:
		return store.ErrNotFound
	}
	return nil
}

// commit applies a change under m.mu: mutate changes a copy of the current
// configuration, which is validated; edit writes the change into the file's
// document; after, if set, stores what the change keeps outside the file
// and returns the password's state. Then the copy becomes current.
func (m *Manager) commit(ctx context.Context, mutate func(*config.Config) error,
	edit func(d *config.Document, prev, next *config.Config) error,
	after func(context.Context) (PasswordState, error)) ([]string, error) {
	if m.Changed() {
		return nil, ErrFileChanged
	}
	prev := m.cur.Load()
	next := clone(prev)
	if err := mutate(next); err != nil {
		return nil, err
	}
	problems, warnings := next.ValidateManaged()
	if len(problems) > 0 {
		return warnings, &config.ValidationError{Problems: problems}
	}
	doc, err := config.ParseDocument(prev.Raw)
	if err != nil {
		return nil, fmt.Errorf("reading config.yaml: %w", err)
	}
	unedited, err := doc.Bytes()
	if err != nil {
		return nil, err
	}
	if err := edit(doc, prev, next); err != nil {
		return nil, err
	}
	data, err := doc.Bytes()
	if err != nil {
		return nil, err
	}
	// Only a change to the configuration rewrites the file, not a change
	// that touches no key (e.g. the password alone).
	if !slices.Equal(data, unedited) {
		if err := writeFile(m.path, data); err != nil {
			return nil, fmt.Errorf("writing config.yaml: %w", err)
		}
		next.Raw, next.Fingerprint = data, config.Fingerprint(data)
	}
	state := m.pwState
	if after != nil {
		if state, err = after(ctx); err != nil {
			return nil, err
		}
	}
	next.Warnings = m.warnings(next, warnings, state)
	m.pwState = state
	m.cur.Store(next)
	if state == Unsealed {
		warnings = append(warnings, PasswordUnsealed)
	}
	return warnings, nil
}

// clone copies c deeply enough to change and validate the copy: the
// managed settings, and the recipient and agent entries, which validation
// annotates.
func clone(c *config.Config) *config.Config {
	cp := *c
	cp.SetManaged(c.Managed())
	cp.Recipients = maps.Clone(c.Recipients)
	if cp.Recipients == nil {
		cp.Recipients = map[string]*config.Recipient{}
	}
	for k, r := range cp.Recipients {
		if r != nil {
			v := *r
			cp.Recipients[k] = &v
		}
	}
	cp.Agents = maps.Clone(c.Agents)
	if cp.Agents == nil {
		cp.Agents = map[string]*config.Agent{}
	}
	for k, a := range cp.Agents {
		if a != nil {
			v := *a
			cp.Agents[k] = &v
		}
	}
	cp.Warnings = nil
	return &cp
}

// writeFile replaces path with data atomically: a temporary file in the
// same directory is renamed over it, keeping the old file's mode.
func writeFile(path string, data []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".config.yaml.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after a successful rename, a no-op
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
