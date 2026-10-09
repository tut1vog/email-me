package keys_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

func kr(b byte) *keyring.Keyring { return keyring.New(bytes.Repeat([]byte{b}, 32)) }

// setup returns a store, a keys manager and the name of an agent, bench.
func setup(t *testing.T, master *openpgp.Entity) (*store.Store, *keys.Manager, string, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m := keys.NewManager(st, keys.Options{Keyring: kr(7), Validity: 365 * 24 * time.Hour, Email: "gateway@example.com"})
	if master != nil {
		if _, err := m.SetMaster(context.Background(), []byte(testutil.ArmorPrivate(t, master)), nil); err != nil {
			t.Fatal(err)
		}
	}
	return st, m, "bench", dbPath
}

func readPublic(t *testing.T, armored string) *openpgp.Entity {
	t.Helper()
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
	if err != nil || len(el) != 1 {
		t.Fatalf("reading public key: %v", err)
	}
	return el[0]
}

func TestCreateAndSign(t *testing.T) {
	_, m, a, _ := setup(t, nil)
	ctx := context.Background()
	k, err := m.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	pub := readPublic(t, k.PublicKey)
	if pub.PrivateKey != nil {
		t.Fatal("public key must not contain private material")
	}
	if len(pub.Subkeys) != 0 {
		t.Fatal("agent keys are sign-only (no encryption subkey)")
	}
	if uid := pub.PrimaryIdentity().Name; uid != "bench via email-me <gateway@example.com>" {
		t.Fatalf("user ID = %q", uid)
	}
	if exp := k.ExpiresAt.Sub(k.CreatedAt); exp < 364*24*time.Hour || exp > 366*24*time.Hour {
		t.Fatalf("validity = %v", exp)
	}
	signer, fpr, err := m.Signer(ctx, a)
	if err != nil || fpr != k.Fingerprint {
		t.Fatalf("Signer: %v %s", err, fpr)
	}
	var sig bytes.Buffer
	msg := []byte("hello")
	if err := openpgp.DetachSign(&sig, signer, bytes.NewReader(msg), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{pub}, bytes.NewReader(msg), &sig, nil); err != nil {
		t.Fatalf("signature must verify with the published public key: %v", err)
	}
}

func TestPrivateKeyNeverStoredInPlaintext(t *testing.T) {
	st, m, a, dbPath := setup(t, nil)
	ctx := context.Background()
	if _, err := m.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	signer, _, err := m.Signer(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	var priv bytes.Buffer
	if err := signer.PrivateKey.Serialize(&priv); err != nil {
		t.Fatal(err)
	}
	// The private key packet ends with the secret scalar; look for its tail.
	secretTail := priv.Bytes()[priv.Len()-32:]
	st.Close() // flush WAL
	for _, suffix := range []string{"", "-wal", "-shm"} {
		b, err := os.ReadFile(dbPath + suffix)
		if err != nil {
			continue
		}
		if bytes.Contains(b, secretTail) {
			t.Fatalf("private key material found in plaintext in %s", filepath.Base(dbPath+suffix))
		}
	}
}

func TestWrongKEKFailsLoudly(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	if _, err := m.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	wrong := keys.NewManager(st, keys.Options{Keyring: kr(9), Validity: time.Hour, Email: "gateway@example.com"})
	if _, err := wrong.EnsureAll(ctx, []string{a}); err == nil || !strings.Contains(err.Error(), "decrypting signing key") {
		t.Fatalf("EnsureAll with the wrong data key must fail loudly, got %v", err)
	}
	if _, _, err := wrong.Signer(ctx, a); err == nil {
		t.Fatal("Signer with wrong KEK must fail")
	}
}

func TestEnsureAllCreatesMissingKeys(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	n, err := m.EnsureAll(ctx, []string{a})
	if err != nil || n != 1 {
		t.Fatalf("EnsureAll = %d, %v", n, err)
	}
	if _, err := st.ActiveKey(ctx, a); err != nil {
		t.Fatal(err)
	}
	n, _ = m.EnsureAll(ctx, []string{a})
	if n != 0 {
		t.Fatal("second EnsureAll must not create keys")
	}
}

func TestRotateKeepsOldSignaturesVerifiable(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	old, _ := m.Create(ctx, a)
	oldSigner, _, _ := m.Signer(ctx, a)
	var sig bytes.Buffer
	openpgp.DetachSign(&sig, oldSigner, strings.NewReader("before rotation"), nil)

	nk, err := m.Rotate(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if nk.Fingerprint == old.Fingerprint {
		t.Fatal("rotation must create a new key")
	}
	ks, _ := st.ListKeys(ctx, a)
	active := 0
	for _, k := range ks {
		if k.RetiredAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("exactly one active key expected, got %d", active)
	}
	_, fpr, _ := m.Signer(ctx, a)
	if fpr != nk.Fingerprint {
		t.Fatal("signer must use the new key")
	}
	retired, _ := st.GetKey(ctx, old.Fingerprint)
	if len(retired.PrivateKeyEnc) != 0 {
		t.Fatal("retired key's private material must be discarded")
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{readPublic(t, retired.PublicKey)}, strings.NewReader("before rotation"), &sig, nil); err != nil {
		t.Fatalf("old signature must verify with retired public key: %v", err)
	}
}

func TestRevocationCertificates(t *testing.T) {
	_, m, a, _ := setup(t, nil)
	k, _ := m.Create(context.Background(), a)
	pub := readPublic(t, k.PublicKey)
	if pub.Revoked(time.Now()) {
		t.Fatal("published key must not be revoked")
	}
	for cert, want := range map[string]packet.ReasonForRevocation{
		k.RevocationCert:            packet.KeyRetired, // soft: routine rotation must not invalidate old signatures
		k.RevocationCertCompromised: packet.KeyCompromised,
	} {
		block, err := armor.Decode(strings.NewReader(cert))
		if err != nil {
			t.Fatal(err)
		}
		p, err := packet.NewReader(block.Body).Next()
		if err != nil {
			t.Fatal(err)
		}
		sig, ok := p.(*packet.Signature)
		if !ok || sig.SigType != packet.SigTypeKeyRevocation || sig.RevocationReason == nil || *sig.RevocationReason != want {
			t.Fatalf("revocation cert: %T reason=%v, want %v", p, sig.RevocationReason, want)
		}
		if err := pub.PrimaryKey.VerifyRevocationSignature(sig); err != nil {
			t.Fatalf("revocation signature must verify: %v", err)
		}
	}
}

func TestMasterCertification(t *testing.T) {
	master := testutil.NewKey(t, "email-me master", "gateway@example.com")
	_, m, a, _ := setup(t, master)
	k, err := m.Create(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	pub := readPublic(t, k.PublicKey)
	ident := pub.PrimaryIdentity()
	var certified bool
	for _, sig := range ident.Signatures {
		if sig.SigType == packet.SigTypeGenericCert && sig.IssuerKeyId != nil && *sig.IssuerKeyId == master.PrimaryKey.KeyId {
			if err := master.PrimaryKey.VerifyUserIdSignature(ident.Name, pub.PrimaryKey, sig); err != nil {
				t.Fatalf("certification does not verify: %v", err)
			}
			certified = true
		}
	}
	if !certified {
		t.Fatal("agent key must be certified by the master key")
	}
	bundle, err := m.Bundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(bundle, "BEGIN PGP PUBLIC KEY BLOCK") != 2 || strings.Contains(bundle, "PRIVATE") {
		t.Fatal("bundle must contain master and agent public keys only")
	}
	if pgp.Fingerprint(master) == k.Fingerprint {
		t.Fatal("distinct keys expected")
	}
}

// certifiedBy reports whether master certified the armored public key.
func certifiedBy(t *testing.T, armored string, master *openpgp.Entity) bool {
	t.Helper()
	pub := readPublic(t, armored)
	for _, sig := range pub.PrimaryIdentity().Signatures {
		if sig.SigType == packet.SigTypeGenericCert && sig.IssuerKeyId != nil && *sig.IssuerKeyId == master.PrimaryKey.KeyId {
			return true
		}
	}
	return false
}

func TestMasterSetLoadRemove(t *testing.T) {
	st, m, a, dbPath := setup(t, nil)
	ctx := context.Background()
	master := testutil.NewKey(t, "email-me master", "gateway@example.com")

	// A passphrase-protected key needs its passphrase.
	cfg := &packet.Config{}
	if err := master.EncryptPrivateKeys([]byte("open sesame"), cfg); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err := master.SerializePrivateWithoutSigning(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	locked := buf.Bytes()
	for pass, want := range map[string]string{"": "passphrase-protected", "wrong": "wrong passphrase"} {
		if _, err := m.SetMaster(ctx, locked, []byte(pass)); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("passphrase %q: want %q, got %v", pass, want, err)
		}
	}
	if _, err := m.SetMaster(ctx, []byte(testutil.ArmorPublic(t, master)), nil); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("a public key must be refused: %v", err)
	}
	if m.Master() != nil {
		t.Fatal("a refused key must not be set")
	}
	e, err := m.SetMaster(ctx, locked, []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := m.Create(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if !certifiedBy(t, k.PublicKey, e) {
		t.Fatal("a key generated after SetMaster must be certified")
	}

	// Stored sealed and without its passphrase: neither the private key
	// nor the passphrase is in the database files.
	row, err := st.GetCertifyKey(ctx)
	if err != nil || row.Fingerprint != pgp.Fingerprint(e) || !strings.Contains(row.PublicKey, "PUBLIC KEY") {
		t.Fatalf("stored: %+v %v", row, err)
	}
	for _, suffix := range []string{"", "-wal"} {
		b, _ := os.ReadFile(dbPath + suffix)
		if bytes.Contains(b, []byte("open sesame")) || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("certification key material in plaintext in %s", filepath.Base(dbPath+suffix))
		}
	}

	// A new manager (the next start) loads it; another data key cannot.
	again := keys.NewManager(st, keys.Options{Keyring: kr(7), Validity: 365 * 24 * time.Hour, Email: "gateway@example.com"})
	if err := again.LoadMaster(ctx); err != nil || again.Master() == nil || pgp.Fingerprint(again.Master()) != pgp.Fingerprint(e) {
		t.Fatalf("LoadMaster: %v", err)
	}
	k2, err := again.Rotate(ctx, a)
	if err != nil || !certifiedBy(t, k2.PublicKey, e) {
		t.Fatalf("the loaded key must certify: %v", err)
	}
	if err := keys.NewManager(st, keys.Options{Keyring: kr(9)}).LoadMaster(ctx); err == nil {
		t.Fatal("LoadMaster with the wrong data key must fail")
	}

	if err := again.RemoveMaster(ctx); err != nil || again.Master() != nil {
		t.Fatalf("RemoveMaster: %v", err)
	}
	k3, err := again.Rotate(ctx, a)
	if err != nil || certifiedBy(t, k3.PublicKey, e) {
		t.Fatalf("a key generated after RemoveMaster is not certified: %v", err)
	}
	if _, err := st.GetCertifyKey(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removed: %v", err)
	}
	if _, err := keys.NewManager(st, keys.Options{}).SetMaster(ctx, locked, []byte("open sesame")); !errors.Is(err, keys.ErrNotConfigured) {
		t.Fatalf("without a keyring: %v", err)
	}
}

func TestExpiredKey(t *testing.T) {
	st, _, a, _ := setup(t, nil)
	m := keys.NewManager(st, keys.Options{Keyring: kr(7), Validity: 24 * time.Hour, Email: "gateway@example.com"})
	ctx := context.Background()
	if _, err := m.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	later := keys.NewManager(st, keys.Options{Keyring: kr(7), Validity: 24 * time.Hour, Email: "gateway@example.com"})
	keys.SetNow(later, func() time.Time { return time.Now().Add(48 * time.Hour) })
	if _, _, err := later.Signer(ctx, a); !errors.Is(err, keys.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestDisabled(t *testing.T) {
	st, _, a, _ := setup(t, nil)
	m := keys.NewManager(st, keys.Options{})
	if m.Enabled() {
		t.Fatal("no KEK means disabled")
	}
	if _, _, err := m.Signer(context.Background(), a); !errors.Is(err, keys.ErrNotConfigured) {
		t.Fatal(err)
	}
}

func TestNoKeysWithoutFromAddress(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	b := "other"
	if _, err := m.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	noFrom := keys.NewManager(st, keys.Options{Keyring: kr(7), Validity: 365 * 24 * time.Hour})
	if _, err := noFrom.Create(ctx, a); !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("Create without a From address: %v", err)
	}
	if _, err := noFrom.Rotate(ctx, b); !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("Rotate without a From address: %v", err)
	}
	n, err := noFrom.EnsureAll(ctx, []string{a, b})
	if n != 0 || !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("EnsureAll without a From address: %d, %v", n, err)
	}
	if _, err := st.ActiveKey(ctx, a); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("no key may be generated without a From address")
	}
	if n, err := m.EnsureAll(ctx, []string{a}); n != 1 || err != nil {
		t.Fatalf("EnsureAll with a From address: %d, %v", n, err)
	}
}

func TestFromFollowsSettings(t *testing.T) {
	st, _, a, _ := setup(t, nil)
	ctx := context.Background()
	var from string
	validity := 24 * time.Hour
	m := keys.NewManager(st, keys.Options{Keyring: kr(7), From: func() (string, time.Duration) { return from, validity }})
	if n, err := m.EnsureAll(ctx, []string{a}); n != 0 || !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("EnsureAll without a From address: %d, %v", n, err)
	}

	// The From address is saved: the same manager generates keys with it.
	from, validity = "gateway@example.com", 48*time.Hour
	if m.UserID(a) != "bench via email-me <gateway@example.com>" {
		t.Fatalf("user ID = %q", m.UserID(a))
	}
	if n, err := m.EnsureAll(ctx, []string{a}); n != 1 || err != nil {
		t.Fatalf("EnsureAll with a From address: %d, %v", n, err)
	}
	k, err := st.ActiveKey(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(k.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if id := el[0].PrimaryIdentity(); id == nil || id.Name != m.UserID(a) {
		t.Fatalf("key user ID = %+v", id)
	}
	if got := k.ExpiresAt.Sub(k.CreatedAt); got != 48*time.Hour {
		t.Fatalf("key lifetime = %v", got)
	}
}
