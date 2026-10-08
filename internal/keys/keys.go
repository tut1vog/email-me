// Package keys manages per-agent OpenPGP signing keys. Keys are generated
// and held by the gateway; agents never see them. Private keys are stored
// encrypted with AES-256-GCM under the key-encryption key (KEK).
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
)

// Manager generates, stores and loads agent signing keys.
type Manager struct {
	store    *store.Store
	kek      []byte
	validity time.Duration
	master   *openpgp.Entity
	email    string
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]*openpgp.Entity // fingerprint → decrypted entity
}

// Options configure a Manager. A nil/short KEK disables signing.
type Options struct {
	KEK      []byte
	Validity time.Duration
	Master   *openpgp.Entity
	Email    string // user ID address; matches the From header
}

func NewManager(st *store.Store, o Options) *Manager {
	m := &Manager{store: st, validity: o.Validity, master: o.Master, email: o.Email, now: time.Now, cache: map[string]*openpgp.Entity{}}
	if len(o.KEK) == 32 {
		m.kek = o.KEK
	}
	return m
}

// Enabled reports whether signing is configured.
func (m *Manager) Enabled() bool { return m != nil && m.kek != nil }

// Master returns the certification master key, if configured.
func (m *Manager) Master() *openpgp.Entity { return m.master }

// UserID returns the OpenPGP user ID for an agent.
func (m *Manager) UserID(agentName string) string {
	return fmt.Sprintf("%s via email-me <%s>", agentName, m.email)
}

// generate creates (but does not store) a new key for the agent.
func (m *Manager) generate(agentName string) (*store.AgentKey, *openpgp.Entity, error) {
	now := m.now()
	cfg := pgp.Config()
	cfg.Algorithm = packet.PubKeyAlgoEdDSA // v4 Ed25519 for broad client support (GnuPG 2.2+, Thunderbird)
	cfg.Curve = packet.Curve25519
	cfg.KeyLifetimeSecs = uint32(m.validity / time.Second)
	cfg.Time = func() time.Time { return now }

	e, err := openpgp.NewEntity(agentName+" via email-me", "", m.email, cfg)
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

	if m.master != nil {
		if err := e.SignIdentity(e.PrimaryIdentity().Name, m.master, cfg); err != nil {
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
func (m *Manager) Create(ctx context.Context, agentID, agentName string) (*store.AgentKey, error) {
	if !m.Enabled() {
		return nil, ErrNotConfigured
	}
	k, e, err := m.generate(agentName)
	if err != nil {
		return nil, err
	}
	k.AgentID = agentID
	if err := m.store.InsertKey(ctx, k); err != nil {
		return nil, err
	}
	m.put(k.Fingerprint, e)
	return k, nil
}

// Rotate replaces an agent's active key. The old key keeps its public key and
// revocation certificate; its private material is discarded.
func (m *Manager) Rotate(ctx context.Context, agentID, agentName string) (*store.AgentKey, error) {
	if !m.Enabled() {
		return nil, ErrNotConfigured
	}
	k, e, err := m.generate(agentName)
	if err != nil {
		return nil, err
	}
	k.AgentID = agentID
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
func (m *Manager) Signer(ctx context.Context, agentID string) (*openpgp.Entity, string, error) {
	if !m.Enabled() {
		return nil, "", ErrNotConfigured
	}
	k, err := m.store.ActiveKey(ctx, agentID)
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
func (m *Manager) ActiveKey(ctx context.Context, agentID string) (*store.AgentKey, error) {
	return m.store.ActiveKey(ctx, agentID)
}

// EnsureAll verifies the KEK against existing keys and creates keys for
// agents that lack one (e.g. signing was enabled after they were created).
func (m *Manager) EnsureAll(ctx context.Context) (created int, err error) {
	if !m.Enabled() {
		return 0, nil
	}
	agents, err := m.store.ListAgents(ctx)
	if err != nil {
		return 0, err
	}
	for _, a := range agents {
		k, err := m.store.ActiveKey(ctx, a.ID)
		if errors.Is(err, store.ErrNotFound) {
			if _, err := m.Create(ctx, a.ID, a.Name); err != nil {
				return created, fmt.Errorf("creating key for agent %s: %w", a.Name, err)
			}
			created++
			continue
		}
		if err != nil {
			return created, err
		}
		if _, err := m.open(k); err != nil {
			return created, fmt.Errorf("agent %s: %w", a.Name, err)
		}
	}
	return created, nil
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
		return nil, fmt.Errorf("decrypting signing key %s failed — is signing.key_encryption_key_file the same KEK the key was created with? (%w)", k.Fingerprint, err)
	}
	e, err := openpgp.ReadEntity(packet.NewReader(bytes.NewReader(plain)))
	if err != nil {
		return nil, fmt.Errorf("parsing signing key %s: %w", k.Fingerprint, err)
	}
	return e, nil
}

// seal encrypts a private key with the KEK; the fingerprint is bound as AAD
// so a ciphertext cannot be swapped onto another key row.
func (m *Manager) seal(plain []byte, fpr string) ([]byte, error) { return Seal(m.kek, plain, fpr) }

func (m *Manager) unseal(blob []byte, fpr string) ([]byte, error) { return Unseal(m.kek, blob, fpr) }

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
	if m.master != nil {
		pub, err := pgp.ArmorPublic(m.master)
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
