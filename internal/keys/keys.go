// Package keys manages per-agent OpenPGP signing keys and the master key
// that certifies them. Keys are generated and held by the gateway; agents
// never see them. Private keys are stored sealed under the keyring.
package keys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/store"
)

var (
	// ErrNotConfigured means signing is not configured on this gateway.
	ErrNotConfigured = errors.New("signing is not configured on this gateway")
	// ErrNoKey means the agent has no active signing key.
	ErrNoKey = errors.New("agent has no active signing key")
	// ErrExpired means the agent's active key has expired and must be rotated.
	ErrExpired = errors.New("agent signing key has expired; rotate it from the dashboard")
	// ErrNoFrom means no From address (upstream.from) is configured, so a new
	// key would carry a user ID without an address.
	ErrNoFrom = errors.New("no From address is configured: set upstream.from on the Settings page, then generate the key")
)

// Manager generates, stores and loads agent signing keys.
type Manager struct {
	store *store.Store
	kr    *keyring.Keyring
	from  func() (email string, validity time.Duration) // for new keys
	now   func() time.Time

	mu     sync.Mutex
	master *openpgp.Entity            // certifies new keys; nil: none
	cache  map[string]*openpgp.Entity // fingerprint → decrypted entity
}

// Options configure a Manager. A nil Keyring disables signing.
type Options struct {
	Keyring  *keyring.Keyring
	Validity time.Duration
	Email    string // user ID address; matches the From header

	// From, if set, replaces Email and Validity: it is called whenever a
	// key is generated or a user ID shown, so saved settings apply to the
	// next key.
	From func() (email string, validity time.Duration)
}

func NewManager(st *store.Store, o Options) *Manager {
	from := o.From
	if from == nil {
		from = func() (string, time.Duration) { return o.Email, o.Validity }
	}
	return &Manager{store: st, kr: o.Keyring, from: from, now: time.Now, cache: map[string]*openpgp.Entity{}}
}

// Enabled reports whether signing is configured.
func (m *Manager) Enabled() bool { return m != nil && m.kr != nil }

// Master returns the certification master key, if one is set.
func (m *Manager) Master() *openpgp.Entity {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.master
}

// certifyAAD binds a sealed certification key to its row.
func certifyAAD(fpr string) string { return "certify_key." + fpr }

// LoadMaster loads the stored certification master key, if any.
func (m *Manager) LoadMaster(ctx context.Context) error {
	if !m.Enabled() {
		return nil
	}
	k, err := m.store.GetCertifyKey(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	plain, err := m.kr.Unseal(k.PrivateKeyEnc, certifyAAD(k.Fingerprint))
	if err != nil {
		return fmt.Errorf("decrypting the certification key %s: %w", k.Fingerprint, err)
	}
	e, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(plain)))
	if err != nil {
		return fmt.Errorf("parsing the certification key %s: %w", k.Fingerprint, err)
	}
	m.mu.Lock()
	m.master = e
	m.mu.Unlock()
	return nil
}

// SetMaster makes an armored (or binary) private key the certification
// master key: it must decrypt with passphrase (if it has one) and be able
// to certify. It is stored sealed, without its passphrase, and certifies
// keys generated from now on.
func (m *Manager) SetMaster(ctx context.Context, data, passphrase []byte) (*openpgp.Entity, error) {
	if !m.Enabled() {
		return nil, ErrNotConfigured
	}
	e, err := pgp.ParsePrivateKey(data, passphrase)
	if err != nil {
		return nil, err
	}
	var priv bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&priv, nil); err != nil {
		return nil, fmt.Errorf("serializing the certification key: %w", err)
	}
	pub, err := pgp.ArmorPublic(e)
	if err != nil {
		return nil, err
	}
	fpr := pgp.Fingerprint(e)
	enc, err := m.kr.Seal(priv.Bytes(), certifyAAD(fpr))
	if err != nil {
		return nil, err
	}
	if err := m.store.SetCertifyKey(ctx, &store.CertifyKey{Fingerprint: fpr, PublicKey: pub, PrivateKeyEnc: enc}); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.master = e
	m.mu.Unlock()
	return e, nil
}

// RemoveMaster deletes the certification master key. Keys it certified
// keep their certification.
func (m *Manager) RemoveMaster(ctx context.Context) error {
	if err := m.store.DeleteCertifyKey(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	m.master = nil
	m.mu.Unlock()
	return nil
}

// UserID returns the OpenPGP user ID a key generated now would carry for
// an agent: it follows the current From address. Existing keys keep the
// user ID they were generated with.
func (m *Manager) UserID(agentName string) string {
	email, _ := m.from()
	return fmt.Sprintf("%s via email-me <%s>", agentName, email)
}

// generate creates (but does not store) a new key for the agent.
func (m *Manager) generate(agentName string) (*store.AgentKey, *openpgp.Entity, error) {
	email, validity := m.from()
	if email == "" {
		return nil, nil, ErrNoFrom
	}
	now := m.now()
	cfg := pgp.Config()
	cfg.Algorithm = packet.PubKeyAlgoEdDSA // v4 Ed25519 for broad client support (GnuPG 2.2+, Thunderbird)
	cfg.Curve = packet.Curve25519
	cfg.KeyLifetimeSecs = uint32(validity / time.Second)
	cfg.Time = func() time.Time { return now }

	e, err := openpgp.NewEntity(agentName+" via email-me", "", email, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key: %w", err)
	}
	// Sign-only: drop the encryption subkey NewEntity adds.
	e.Subkeys = nil

	// Pre-generate both revocation certificates (the private key of a retired
	// key is discarded, so they cannot be made later), then remove them from
	// the entity. "Retired" is a soft revocation: past signatures stay valid.
	revCert, err := revocationCert(e, cfg, packet.KeyRetired, "Agent key retired by email-me (rotated or agent deleted)")
	if err != nil {
		return nil, nil, err
	}
	revCompromised, err := revocationCert(e, cfg, packet.KeyCompromised, "Agent key compromised")
	if err != nil {
		return nil, nil, err
	}

	var priv bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&priv, cfg); err != nil {
		return nil, nil, fmt.Errorf("serializing key: %w", err)
	}

	if master := m.Master(); master != nil {
		if err := e.SignIdentity(e.PrimaryIdentity().Name, master, cfg); err != nil {
			return nil, nil, fmt.Errorf("certifying with master key: %w", err)
		}
	}
	pub, err := pgp.ArmorPublic(e)
	if err != nil {
		return nil, nil, err
	}

	fpr := pgp.Fingerprint(e)
	enc, err := m.seal(priv.Bytes(), fpr)
	if err != nil {
		return nil, nil, err
	}
	expires := pgp.KeyExpiry(e)
	return &store.AgentKey{
		Fingerprint:    fpr,
		PublicKey:      pub,
		PrivateKeyEnc:  enc,
		RevocationCert: revCert,

		RevocationCertCompromised: revCompromised,
		CreatedAt:                 now.UTC().Truncate(time.Second),
		ExpiresAt:                 expires.UTC(),
	}, e, nil
}

// Create generates and stores the first key for an agent.
func (m *Manager) Create(ctx context.Context, agent string) (*store.AgentKey, error) {
	if !m.Enabled() {
		return nil, ErrNotConfigured
	}
	k, e, err := m.generate(agent)
	if err != nil {
		return nil, err
	}
	k.Agent = agent
	if err := m.store.InsertKey(ctx, k); err != nil {
		return nil, err
	}
	m.put(k.Fingerprint, e)
	return k, nil
}

// Rotate replaces an agent's active key. The old key keeps its public key and
// revocation certificate; its private material is discarded.
func (m *Manager) Rotate(ctx context.Context, agent string) (*store.AgentKey, error) {
	if !m.Enabled() {
		return nil, ErrNotConfigured
	}
	k, e, err := m.generate(agent)
	if err != nil {
		return nil, err
	}
	k.Agent = agent
	if err := m.store.RotateKey(ctx, k); err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.cache = map[string]*openpgp.Entity{}
	m.mu.Unlock()
	m.put(k.Fingerprint, e)
	return k, nil
}

// Signer returns the agent's decrypted signing entity and its fingerprint.
func (m *Manager) Signer(ctx context.Context, agent string) (*openpgp.Entity, string, error) {
	if !m.Enabled() {
		return nil, "", ErrNotConfigured
	}
	k, err := m.store.ActiveKey(ctx, agent)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", ErrNoKey
	}
	if err != nil {
		return nil, "", err
	}
	if !m.now().Before(k.ExpiresAt) {
		return nil, k.Fingerprint, ErrExpired
	}
	m.mu.Lock()
	e, ok := m.cache[k.Fingerprint]
	m.mu.Unlock()
	if ok {
		return e, k.Fingerprint, nil
	}
	e, err = m.open(k)
	if err != nil {
		return nil, k.Fingerprint, err
	}
	m.put(k.Fingerprint, e)
	return e, k.Fingerprint, nil
}

// ActiveKey returns the stored active key row (no decryption).
func (m *Manager) ActiveKey(ctx context.Context, agent string) (*store.AgentKey, error) {
	return m.store.ActiveKey(ctx, agent)
}

// EnsureAll verifies the keyring against the agents' keys and creates keys
// for agents that lack one (e.g. signing was enabled after they were
// created, or they were added to config.yaml by hand). Without a From
// address it creates none and, once every existing key is verified, returns
// ErrNoFrom if an agent was left without a key.
func (m *Manager) EnsureAll(ctx context.Context, agents []string) (created int, err error) {
	if !m.Enabled() {
		return 0, nil
	}
	var missing error
	email, _ := m.from()
	for _, a := range agents {
		k, err := m.store.ActiveKey(ctx, a)
		if errors.Is(err, store.ErrNotFound) {
			if email == "" {
				missing = ErrNoFrom
				continue
			}
			if _, err := m.Create(ctx, a); err != nil {
				return created, fmt.Errorf("creating key for agent %s: %w", a, err)
			}
			created++
			continue
		}
		if err != nil {
			return created, err
		}
		if _, err := m.open(k); err != nil {
			return created, fmt.Errorf("agent %s: %w", a, err)
		}
	}
	return created, missing
}

func (m *Manager) put(fpr string, e *openpgp.Entity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cache[fpr] = e
}

func (m *Manager) open(k *store.AgentKey) (*openpgp.Entity, error) {
	if len(k.PrivateKeyEnc) == 0 {
		return nil, fmt.Errorf("key %s has no private material (retired)", k.Fingerprint)
	}
	plain, err := m.unseal(k.PrivateKeyEnc, k.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("decrypting signing key %s: %w", k.Fingerprint, err)
	}
	e, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(plain)))
	if err != nil {
		return nil, fmt.Errorf("parsing signing key %s: %w", k.Fingerprint, err)
	}
	return e, nil
}

// seal encrypts a private key under the keyring; the fingerprint is bound
// as AAD so a ciphertext cannot be swapped onto another key row.
func (m *Manager) seal(plain []byte, fpr string) ([]byte, error) { return m.kr.Seal(plain, fpr) }

func (m *Manager) unseal(blob []byte, fpr string) ([]byte, error) { return m.kr.Unseal(blob, fpr) }

func revocationCert(e *openpgp.Entity, cfg *packet.Config, reason packet.ReasonForRevocation, text string) (string, error) {
	if err := e.RevokeKey(reason, text, cfg); err != nil {
		return "", fmt.Errorf("creating revocation certificate: %w", err)
	}
	sig := e.Revocations[len(e.Revocations)-1]
	e.Revocations = e.Revocations[:len(e.Revocations)-1]
	return armorSignature(sig)
}

func armorSignature(sig *packet.Signature) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, map[string]string{
		"Comment": "Revocation certificate for an email-me agent key",
	})
	if err != nil {
		return "", err
	}
	if err := sig.Serialize(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	buf.WriteString("\n")
	return buf.String(), nil
}

// Bundle concatenates armored public keys (agents' and the master's).
func (m *Manager) Bundle(ctx context.Context) (string, error) {
	var b strings.Builder
	if master := m.Master(); master != nil {
		pub, err := pgp.ArmorPublic(master)
		if err != nil {
			return "", err
		}
		b.WriteString(pub)
	}
	ks, err := m.store.ListKeys(ctx, "")
	if err != nil {
		return "", err
	}
	for _, k := range ks {
		b.WriteString(k.PublicKey)
	}
	return b.String(), nil
}
