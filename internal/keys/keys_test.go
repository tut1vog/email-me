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

	"github.com/tut1vog/email-me/internal/keys"
	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

func kek(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func setup(t *testing.T, master *openpgp.Entity) (*store.Store, *keys.Manager, *store.Agent, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	a, err := st.CreateAgent(context.Background(), "bench", "", policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	m := keys.NewManager(st, keys.Options{KEK: kek(7), Validity: 365 * 24 * time.Hour, Master: master, Email: "gateway@example.com"})
	return st, m, a, dbPath
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
	k, err := m.Create(ctx, a.ID, a.Name)
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
	signer, fpr, err := m.Signer(ctx, a.ID)
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
	if _, err := m.Create(ctx, a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	signer, _, err := m.Signer(ctx, a.ID)
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
	if _, err := m.Create(ctx, a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	wrong := keys.NewManager(st, keys.Options{KEK: kek(9), Validity: time.Hour, Email: "gateway@example.com"})
	if _, err := wrong.EnsureAll(ctx); err == nil || !strings.Contains(err.Error(), "same KEK") {
		t.Fatalf("EnsureAll with wrong KEK must fail loudly, got %v", err)
	}
	if _, _, err := wrong.Signer(ctx, a.ID); err == nil {
		t.Fatal("Signer with wrong KEK must fail")
	}
}

func TestEnsureAllCreatesMissingKeys(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	n, err := m.EnsureAll(ctx)
	if err != nil || n != 1 {
		t.Fatalf("EnsureAll = %d, %v", n, err)
	}
	if _, err := st.ActiveKey(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	n, _ = m.EnsureAll(ctx)
	if n != 0 {
		t.Fatal("second EnsureAll must not create keys")
	}
}

func TestRotateKeepsOldSignaturesVerifiable(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	old, _ := m.Create(ctx, a.ID, a.Name)
	oldSigner, _, _ := m.Signer(ctx, a.ID)
	var sig bytes.Buffer
	openpgp.DetachSign(&sig, oldSigner, strings.NewReader("before rotation"), nil)

	nk, err := m.Rotate(ctx, a.ID, a.Name)
	if err != nil {
		t.Fatal(err)
	}
	if nk.Fingerprint == old.Fingerprint {
		t.Fatal("rotation must create a new key")
	}
	ks, _ := st.ListKeys(ctx, a.ID)
	active := 0
	for _, k := range ks {
		if k.RetiredAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("exactly one active key expected, got %d", active)
	}
	_, fpr, _ := m.Signer(ctx, a.ID)
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
	k, _ := m.Create(context.Background(), a.ID, a.Name)
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
	k, err := m.Create(context.Background(), a.ID, a.Name)
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

func TestExpiredKey(t *testing.T) {
	st, _, a, _ := setup(t, nil)
	m := keys.NewManager(st, keys.Options{KEK: kek(7), Validity: 24 * time.Hour, Email: "gateway@example.com"})
	ctx := context.Background()
	if _, err := m.Create(ctx, a.ID, a.Name); err != nil {
		t.Fatal(err)
	}
	later := keys.NewManager(st, keys.Options{KEK: kek(7), Validity: 24 * time.Hour, Email: "gateway@example.com"})
	keys.SetNow(later, func() time.Time { return time.Now().Add(48 * time.Hour) })
	if _, _, err := later.Signer(ctx, a.ID); !errors.Is(err, keys.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestDisabled(t *testing.T) {
	st, _, a, _ := setup(t, nil)
	m := keys.NewManager(st, keys.Options{})
	if m.Enabled() {
		t.Fatal("no KEK means disabled")
	}
	if _, _, err := m.Signer(context.Background(), a.ID); !errors.Is(err, keys.ErrNotConfigured) {
		t.Fatal(err)
	}
}

func TestNoKeysWithoutFromAddress(t *testing.T) {
	st, m, a, _ := setup(t, nil)
	ctx := context.Background()
	b, err := st.CreateAgent(ctx, "other", "", policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Create(ctx, b.ID, b.Name); err != nil {
		t.Fatal(err)
	}
	noFrom := keys.NewManager(st, keys.Options{KEK: kek(7), Validity: 365 * 24 * time.Hour})
	if _, err := noFrom.Create(ctx, a.ID, a.Name); !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("Create without a From address: %v", err)
	}
	if _, err := noFrom.Rotate(ctx, b.ID, b.Name); !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("Rotate without a From address: %v", err)
	}
	n, err := noFrom.EnsureAll(ctx)
	if n != 0 || !errors.Is(err, keys.ErrNoFrom) {
		t.Fatalf("EnsureAll without a From address: %d, %v", n, err)
	}
	if _, err := st.ActiveKey(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("no key may be generated without a From address")
	}
	if n, err := m.EnsureAll(ctx); n != 1 || err != nil {
		t.Fatalf("EnsureAll with a From address: %d, %v", n, err)
	}
}
