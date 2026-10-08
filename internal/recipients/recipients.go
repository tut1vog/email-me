// Package recipients holds the recipient aliases agents may address. They
// live in the state database and are managed from the dashboard; the
// recipients section of config.yaml only seeds an empty database. A Registry
// serves an in-memory snapshot to the API and dashboard and reloads it after
// every change, so edits apply without a restart.
package recipients

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
)

// MaxDescription is the longest description, in characters.
const MaxDescription = 200

// reserved aliases cannot be created: "new" is the dashboard's form path.
var reserved = []string{"new"}

// Recipient is a stored recipient with its parsed PGP key (nil if none).
// Values handed out by a Registry are never modified.
type Recipient struct {
	store.Recipient
	Key *openpgp.Entity
}

// KeyUsable reports whether the recipient's PGP key can encrypt right now.
// Keys are checked when saved but can expire (or be found revoked) later.
func (r *Recipient) KeyUsable(now time.Time) bool {
	return r.Key != nil && pgp.CheckEncryptionKey(r.Key, now) == nil
}

// Fingerprint returns the key's fingerprint, or "" without a key.
func (r *Recipient) Fingerprint() string {
	if r.Key == nil {
		return ""
	}
	return pgp.Fingerprint(r.Key)
}

// KeyExpiry returns when the key expires; zero without a key or expiry.
func (r *Recipient) KeyExpiry() time.Time {
	if r.Key == nil {
		return time.Time{}
	}
	return pgp.KeyExpiry(r.Key)
}

// Registry is the live set of recipients, backed by the store.
type Registry struct {
	st       *store.Store
	defaults policy.Effective

	wmu sync.Mutex // serializes write + reload so snapshots never go stale

	mu      sync.RWMutex
	byAlias map[string]*Recipient
	aliases []string // sorted
}

// New returns an empty registry; call Reload to load the store's recipients.
// defaults is the configured default policy that Effective resolves against.
func New(st *store.Store, defaults policy.Effective) *Registry {
	return &Registry{st: st, defaults: defaults, byAlias: map[string]*Recipient{}}
}

// Bootstrap creates a registry, seeds the store from cfg.Recipients if it
// has no recipients yet, and loads it. It returns the aliases it seeded.
func Bootstrap(ctx context.Context, st *store.Store, cfg *config.Config) (*Registry, []string, error) {
	r := New(st, cfg.DefaultPolicy)
	seeded, err := r.SeedIfEmpty(ctx, cfg.Recipients)
	if err != nil {
		return nil, nil, err
	}
	if err := r.Reload(ctx); err != nil {
		return nil, nil, err
	}
	return r, seeded, nil
}

// SeedIfEmpty inserts seeds (validated config entries) only when the store
// has no recipients at all, so recipients deleted in the dashboard do not
// come back on restart. It returns the inserted aliases, sorted, and does
// not reload the snapshot.
func (r *Registry) SeedIfEmpty(ctx context.Context, seeds map[string]*config.Recipient) ([]string, error) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	aliases := make([]string, 0, len(seeds))
	for a := range seeds {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	rows := make([]*store.Recipient, 0, len(aliases))
	for _, a := range aliases {
		s := seeds[a]
		rows = append(rows, &store.Recipient{
			Alias: a, Address: s.Address, Description: s.Description,
			PublicKey: s.PublicKeyArmor, RequireEncryption: s.RequireEncryption,
		})
	}
	ok, err := r.st.SeedRecipients(ctx, rows)
	if err != nil {
		return nil, fmt.Errorf("seeding recipients from config: %w", err)
	}
	if !ok {
		return nil, nil
	}
	return aliases, nil
}

// Reload replaces the snapshot with the store's current recipients.
func (r *Registry) Reload(ctx context.Context) error {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	return r.reload(ctx)
}

func (r *Registry) reload(ctx context.Context) error {
	rows, err := r.st.ListRecipients(ctx)
	if err != nil {
		return fmt.Errorf("loading recipients: %w", err)
	}
	byAlias := make(map[string]*Recipient, len(rows))
	aliases := make([]string, 0, len(rows))
	for _, row := range rows {
		rc := &Recipient{Recipient: *row}
		if row.PublicKey != "" {
			// Not ParsePublicKey: a key that expired since it was saved must
			// still load, so it can be reported and replaced.
			e, err := pgp.ReadPublicKey([]byte(row.PublicKey))
			if err != nil {
				return fmt.Errorf("recipient %s: stored PGP key: %w", row.Alias, err)
			}
			rc.Key = e
		}
		byAlias[row.Alias] = rc
		aliases = append(aliases, row.Alias)
	}
	r.mu.Lock()
	r.byAlias, r.aliases = byAlias, aliases
	r.mu.Unlock()
	return nil
}

// Get returns the recipient with this alias.
func (r *Registry) Get(alias string) (*Recipient, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rc, ok := r.byAlias[alias]
	return rc, ok
}

// All returns every recipient, sorted by alias.
func (r *Registry) All() []*Recipient {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Recipient, 0, len(r.aliases))
	for _, a := range r.aliases {
		out = append(out, r.byAlias[a])
	}
	return out
}

// Aliases returns recipient aliases sorted.
func (r *Registry) Aliases() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.aliases)
}

// Len returns the number of recipients.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.aliases)
}

// Effective resolves an agent's partial policy against the configured
// defaults, dropping aliases that do not exist (any more).
func (r *Registry) Effective(p policy.Policy) policy.Effective {
	e := p.Apply(r.defaults)
	r.mu.RLock()
	defer r.mu.RUnlock()
	kept := make([]string, 0, len(e.Recipients))
	for _, a := range e.Recipients {
		if _, ok := r.byAlias[a]; ok && !slices.Contains(kept, a) {
			kept = append(kept, a)
		}
	}
	e.Recipients = kept
	return e
}

// UnknownAliases returns aliases a partial policy references that do not exist.
func (r *Registry) UnknownAliases(p policy.Policy) []string {
	var out []string
	if p.Recipients != nil {
		r.mu.RLock()
		defer r.mu.RUnlock()
		for _, a := range *p.Recipients {
			if _, ok := r.byAlias[a]; !ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// Input is a recipient as entered by the operator.
type Input struct {
	Alias       string
	Address     string
	Description string
	// PublicKeyArmor is a pasted ASCII-armored public key; empty means none.
	PublicKeyArmor string
	// KeepKey keeps the stored key on Update; PublicKeyArmor must then be empty.
	KeepKey           bool
	RequireEncryption bool
}

// ValidationError lists every problem with an Input.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid recipient: " + strings.Join(e.Problems, "; ")
}

// Validate checks in and returns the normalized row to store: a bare
// address and the key re-armored canonically. now is when the key must be
// able to encrypt. KeepKey is treated as "no key".
func Validate(in Input, now time.Time) (*store.Recipient, error) {
	return validate(in, now, "")
}

// validate is Validate with the currently stored armor, which KeepKey keeps
// without re-checking (it may have expired; replacing it is a separate step).
func validate(in Input, now time.Time, current string) (*store.Recipient, error) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	out := &store.Recipient{Alias: in.Alias, Description: in.Description, RequireEncryption: in.RequireEncryption}
	if !config.AliasPattern.MatchString(in.Alias) {
		add("Alias must be 1-32 characters of lowercase letters, digits, '-' or '_', starting with a letter or digit")
	} else if slices.Contains(reserved, in.Alias) {
		add("Alias %q is reserved", in.Alias)
	}
	if a, err := mail.ParseAddress(in.Address); err != nil || a.Name != "" {
		add("Address must be a bare email address such as you@example.com")
	} else {
		out.Address = a.Address
	}
	if utf8.RuneCountInString(in.Description) > MaxDescription {
		add("Description must be at most %d characters", MaxDescription)
	}
	if strings.ContainsAny(in.Description, "\r\n") {
		add("Description must be a single line")
	}
	switch {
	case in.KeepKey && in.PublicKeyArmor != "":
		add("Either keep the current PGP key or paste a new one, not both")
	case in.KeepKey:
		out.PublicKey = current
	case in.PublicKeyArmor != "":
		if armored, err := canonicalKey(in.PublicKeyArmor, now); err != nil {
			add("PGP public key: %v", err)
		} else {
			out.PublicKey = armored
		}
	}
	if in.RequireEncryption && out.PublicKey == "" && in.PublicKeyArmor == "" {
		add("Require encryption needs a PGP public key (nothing could ever be delivered)")
	}
	if len(problems) > 0 {
		return nil, &ValidationError{Problems: problems}
	}
	return out, nil
}

// canonicalKey parses a pasted public key, checks it can encrypt at now and
// re-armors it, dropping anything but the public key.
func canonicalKey(armor string, now time.Time) (string, error) {
	e, err := pgp.ReadPublicKey([]byte(armor))
	if err != nil {
		return "", err
	}
	if e.PrivateKey != nil {
		return "", errors.New("this is a private key; paste the public key (gpg --export --armor)")
	}
	if err := pgp.CheckEncryptionKey(e, now); err != nil {
		return "", err
	}
	return pgp.ArmorPublic(e)
}

// Create validates and stores a new recipient. It returns a
// *ValidationError or store.ErrConflict when the alias exists.
func (r *Registry) Create(ctx context.Context, in Input) (*Recipient, error) {
	row, err := Validate(in, time.Now())
	if err != nil {
		return nil, err
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.st.CreateRecipient(ctx, row); err != nil {
		return nil, err
	}
	return r.reloaded(ctx, row.Alias)
}

// Update validates and saves changes to an existing recipient. The alias
// cannot change; in.Alias is ignored. It returns a *ValidationError or
// store.ErrNotFound.
func (r *Registry) Update(ctx context.Context, alias string, in Input) (*Recipient, error) {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	cur, err := r.st.GetRecipient(ctx, alias)
	if err != nil {
		return nil, err
	}
	in.Alias = alias
	row, err := validate(in, time.Now(), cur.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := r.st.UpdateRecipient(ctx, row); err != nil {
		return nil, err
	}
	return r.reloaded(ctx, alias)
}

// Delete removes a recipient. Policies naming it are not edited: the alias
// is ignored (and flagged in the dashboard) wherever it still appears.
func (r *Registry) Delete(ctx context.Context, alias string) error {
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if err := r.st.DeleteRecipient(ctx, alias); err != nil {
		return err
	}
	return r.reload(ctx)
}

func (r *Registry) reloaded(ctx context.Context, alias string) (*Recipient, error) {
	if err := r.reload(ctx); err != nil {
		return nil, err
	}
	rc, ok := r.Get(alias)
	if !ok {
		return nil, store.ErrNotFound
	}
	return rc, nil
}

// ReferencingAgents returns the agents whose own policy names alias. Agents
// that inherit the default recipients are not included.
func ReferencingAgents(agents []*store.Agent, alias string) []*store.Agent {
	var out []*store.Agent
	for _, a := range agents {
		if a.Policy.Recipients != nil && slices.Contains(*a.Policy.Recipients, alias) {
			out = append(out, a)
		}
	}
	return out
}
