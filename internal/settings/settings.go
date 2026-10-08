// Package settings holds the managed settings (config.Settings). They live
// in the state database and are edited on the dashboard; the managed
// sections of config.yaml only seed an empty database. Saved settings take
// effect on the next restart, so a Manager keeps both the settings the
// process is running with and the ones saved since, and reports the keys
// that differ.
//
// Stored settings never block startup: a row that cannot be decoded or
// fails validation is reported (LoadProblems, config warnings) and the
// gateway still comes up, so the operator can fix it on the dashboard.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/store"
)

// passwordAAD binds a sealed SMTP password to its column.
const passwordAAD = "settings.smtp_password"

// passwordKey is the pending key reported when only the password changed.
const passwordKey = "upstream.smtp.password"

// PasswordState says how the saved SMTP password is stored.
type PasswordState int

const (
	// None: no password is stored.
	None PasswordState = iota
	// Sealed: encrypted under the signing key-encryption key.
	Sealed
	// Unsealed: stored raw because no key-encryption key is configured.
	Unsealed
	// Undecryptable: stored encrypted, but the key-encryption key is missing
	// or not the one it was sealed with. It must be entered again.
	Undecryptable
)

// PasswordChange is a Save's instruction for the SMTP password, which the
// dashboard never shows: Set false keeps the saved one, Set with an empty
// Value removes it.
type PasswordChange struct {
	Set   bool
	Value string
}

// Manager serves the running and saved settings and saves new ones.
type Manager struct {
	st        *store.Store
	kek       []byte         // nil: passwords are stored raw
	base      *config.Config // bootstrap keys that saved settings are validated against
	running   config.Settings
	runningPW string

	mu           sync.RWMutex // guards everything below
	saved        config.Settings
	savedPW      string
	savedBlob    []byte // stored password column, kept as-is when a Save does not change it
	savedSealed  bool
	pwState      PasswordState
	pending      []string
	savedAt      time.Time
	loadProblems []string
}

// Bootstrap loads the stored settings into cfg, seeding the store from
// cfg's managed keys if it has none yet (the first boot, or the first after
// upgrading). It reports whether it seeded.
//
// Problems in the seed are fatal (*config.ValidationError), as they were
// when config.yaml was the source of truth. Problems in stored settings
// are not: they are reported by LoadProblems and added to cfg.Warnings.
// Only a store error fails a boot with stored settings.
func Bootstrap(ctx context.Context, st *store.Store, cfg *config.Config, log *slog.Logger) (*Manager, bool, error) {
	m := &Manager{st: st, base: cfg}
	if cfg.SigningConfigured() {
		m.kek = cfg.Signing.KEK
	}
	fileManaged := !cfg.Managed().IsZero()
	row, err := st.GetSettings(ctx)
	seeded := false
	switch {
	case errors.Is(err, store.ErrNotFound):
		if seeded, err = m.seed(ctx, cfg); err != nil {
			return nil, false, err
		}
		if row, err = st.GetSettings(ctx); err != nil {
			return nil, false, fmt.Errorf("loading settings: %w", err)
		}
		switch {
		case seeded && fileManaged:
			log.Info("imported settings from config.yaml into the state database; manage them on the dashboard's Settings page from now on")
		case seeded:
			log.Info("stored default settings in the state database; manage them on the dashboard's Settings page")
		}
	case err != nil:
		return nil, false, fmt.Errorf("loading settings: %w", err)
	case fileManaged:
		log.Info("settings in config.yaml are ignored after the first boot; they are managed on the dashboard's Settings page, and only the bootstrap keys are read from the file")
	}
	if err := m.load(ctx, row, cfg, log); err != nil {
		return nil, false, err
	}
	return m, seeded, nil
}

// seed validates cfg's managed keys (reading the SMTP password file) and
// stores them if the store has no settings.
func (m *Manager) seed(ctx context.Context, cfg *config.Config) (bool, error) {
	c := scratch(cfg)
	if problems, _ := c.ValidateSeed(); len(problems) > 0 {
		return false, &config.ValidationError{Problems: problems}
	}
	row, err := m.row(c.Managed())
	if err != nil {
		return false, err
	}
	if row.SMTPPassword, row.PasswordSealed, err = m.seal(c.Upstream.SMTP.Password); err != nil {
		return false, err
	}
	ok, err := m.st.SeedSettings(ctx, row)
	if err != nil {
		return false, fmt.Errorf("seeding settings from config: %w", err)
	}
	return ok, nil
}

// load applies a stored row to cfg and records it as both running and saved.
func (m *Manager) load(ctx context.Context, row *store.Settings, cfg *config.Config, log *slog.Logger) error {
	var problems []string
	var s config.Settings
	if err := json.Unmarshal(row.Doc, &s); err != nil {
		s = cfg.Managed()
		problems = append(problems, fmt.Sprintf("the stored settings cannot be decoded (%v); running with the values in config.yaml and defaults until settings are saved again", err))
	}
	cfg.SetManaged(s)
	pw, state, err := m.openPassword(ctx, row, log)
	if err != nil {
		return err
	}
	cfg.Upstream.SMTP.Password = pw
	invalid, warnings := cfg.ValidateManaged()
	problems = append(problems, invalid...)
	cfg.Warnings = append(cfg.Warnings, warnings...)
	for _, p := range problems {
		cfg.Warnings = append(cfg.Warnings, "saved settings: "+p)
	}

	m.running, m.runningPW = cfg.Managed(), pw
	m.saved, m.savedPW = m.running.Clone(), pw
	m.savedBlob, m.savedSealed, m.pwState = row.SMTPPassword, row.PasswordSealed, state
	m.savedAt = row.UpdatedAt
	m.loadProblems = problems
	return nil
}

// openPassword reads the stored password. One that cannot be decrypted is
// dropped with a warning; a raw one is sealed now if a KEK has appeared.
func (m *Manager) openPassword(ctx context.Context, row *store.Settings, log *slog.Logger) (string, PasswordState, error) {
	switch {
	case len(row.SMTPPassword) == 0:
		return "", None, nil
	case !row.PasswordSealed && m.kek == nil:
		log.Warn("the upstream SMTP password is stored unencrypted in the state database; set signing.key_encryption_key_file to encrypt it")
		return string(row.SMTPPassword), Unsealed, nil
	case !row.PasswordSealed:
		pw := string(row.SMTPPassword)
		blob, err := keys.Seal(m.kek, row.SMTPPassword, passwordAAD)
		if err != nil {
			return "", None, err
		}
		row.SMTPPassword, row.PasswordSealed = blob, true
		if err := m.st.SaveSettings(ctx, row); err != nil {
			return "", None, fmt.Errorf("encrypting the stored SMTP password: %w", err)
		}
		log.Info("encrypted the stored upstream SMTP password with the key-encryption key")
		return pw, Sealed, nil
	case m.kek == nil:
		log.Warn("the stored upstream SMTP password is encrypted but signing.key_encryption_key_file is not set; re-enter the password on the Settings page")
		return "", Undecryptable, nil
	}
	plain, err := keys.Unseal(m.kek, row.SMTPPassword, passwordAAD)
	if err != nil {
		log.Warn("the stored upstream SMTP password cannot be decrypted (was signing.key_encryption_key_file changed?); re-enter it on the Settings page")
		return "", Undecryptable, nil
	}
	return string(plain), Sealed, nil
}

// row encodes settings for the store, without the password.
func (m *Manager) row(s config.Settings) (*store.Settings, error) {
	doc, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return &store.Settings{Doc: doc}, nil
}

// seal returns the password column for pw: nil for none, sealed under the
// KEK if there is one, raw otherwise.
func (m *Manager) seal(pw string) ([]byte, bool, error) {
	if pw == "" {
		return nil, false, nil
	}
	if m.kek == nil {
		return []byte(pw), false, nil
	}
	blob, err := keys.Seal(m.kek, []byte(pw), passwordAAD)
	return blob, true, err
}

// Save validates s against the bootstrap keys and stores it, normalized
// (defaults applied). It does not change the running settings: they apply
// on restart. It returns the settings' warnings, and a
// *config.ValidationError listing every problem if s is invalid.
func (m *Manager) Save(ctx context.Context, s config.Settings, pw PasswordChange) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := scratch(m.base)
	c.SetManaged(s)
	password := m.savedPW
	if pw.Set {
		password = pw.Value
	}
	c.Upstream.SMTP.Password = password
	problems, warnings := c.ValidateManaged()
	if len(problems) > 0 {
		return warnings, &config.ValidationError{Problems: problems}
	}
	norm := c.Managed()
	row, err := m.row(norm)
	if err != nil {
		return nil, err
	}
	row.SMTPPassword, row.PasswordSealed = m.savedBlob, m.savedSealed
	state := m.pwState
	if pw.Set {
		if row.SMTPPassword, row.PasswordSealed, err = m.seal(pw.Value); err != nil {
			return nil, err
		}
		switch {
		case pw.Value == "":
			state = None
		case row.PasswordSealed:
			state = Sealed
		default:
			state = Unsealed
			warnings = append(warnings, "the SMTP password is stored unencrypted in the state database; set signing.key_encryption_key_file in config.yaml to encrypt it")
		}
	}
	if err := m.st.SaveSettings(ctx, row); err != nil {
		return nil, fmt.Errorf("saving settings: %w", err)
	}
	m.saved, m.savedPW = norm, password
	m.savedBlob, m.savedSealed, m.pwState = row.SMTPPassword, row.PasswordSealed, state
	m.savedAt = row.UpdatedAt
	m.pending = config.DiffSettings(m.running, m.saved)
	if m.savedPW != m.runningPW {
		m.pending = append(m.pending, passwordKey)
		slices.Sort(m.pending)
	}
	return warnings, nil
}

// Running returns the settings the process is running with.
func (m *Manager) Running() config.Settings { return m.running.Clone() }

// Saved returns the saved settings, which apply on the next restart.
func (m *Manager) Saved() config.Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saved.Clone()
}

// SavedSMTP returns the saved upstream server, with its password, for
// testing it before a restart.
func (m *Manager) SavedSMTP() config.SMTP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.saved.Upstream.SMTP
	s.Password = m.savedPW
	return s
}

// Pending returns the dotted keys whose saved value differs from the
// running one, sorted; empty when no restart is needed.
func (m *Manager) Pending() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.pending)
}

// SavedAt returns when the settings were last written.
func (m *Manager) SavedAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.savedAt
}

// LoadProblems returns what was wrong with the stored settings at boot.
// The process runs regardless; saving valid settings fixes them on the
// next restart.
func (m *Manager) LoadProblems() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.loadProblems)
}

// HasPassword reports whether an SMTP password is stored, usable or not.
func (m *Manager) HasPassword() bool { return m.PasswordState() != None }

// PasswordState returns how the saved SMTP password is stored.
func (m *Manager) PasswordState() PasswordState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pwState
}

// scratch copies c so managed settings can be set and validated on it
// without touching c. Signing is the only pointer SetManaged writes through.
func scratch(c *config.Config) *config.Config {
	cp := *c
	if c.Signing != nil {
		s := *c.Signing
		cp.Signing = &s
	}
	cp.Warnings = nil
	return &cp
}
