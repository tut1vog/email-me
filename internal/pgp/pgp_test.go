package pgp_test

import (
	"bytes"
	"io"
	"mime"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/emersion/go-pgpmail"

	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/testutil"
)

const inner = "Content-Type: text/plain; charset=utf-8; protected-headers=\"v1\"\r\n" +
	"Content-Transfer-Encoding: quoted-printable\r\n" +
	"Subject: Real subject\r\n" +
	"\r\n" +
	"Hello from the agent.\r\n"

func full(mp *pgp.Multipart) []byte {
	return append([]byte("From: a@example.com\r\nContent-Type: "+mp.ContentType+"\r\n\r\n"), mp.Body...)
}

// signedPart extracts the exact bytes of the first part of a multipart
// body, independent of any MIME library.
func signedPart(t *testing.T, mp *pgp.Multipart) (part, sigPart []byte) {
	t.Helper()
	_, params, err := mime.ParseMediaType(mp.ContentType)
	if err != nil {
		t.Fatal(err)
	}
	delim := []byte("--" + params["boundary"] + "\r\n")
	body := mp.Body
	i := bytes.Index(body, delim)
	if i < 0 {
		t.Fatal("no first boundary")
	}
	rest := body[i+len(delim):]
	j := bytes.Index(rest, []byte("\r\n--"+params["boundary"]))
	if j < 0 {
		t.Fatal("no second boundary")
	}
	return rest[:j], rest[j:]
}

func TestSignVerifiesOverExactBytes(t *testing.T) {
	signer := testutil.NewKey(t, "agent", "gateway@example.com")
	mp, err := pgp.Sign([]byte(inner), signer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mp.ContentType, "multipart/signed") || !strings.Contains(mp.ContentType, "pgp-sha256") {
		t.Fatalf("content type %q", mp.ContentType)
	}
	part, rest := signedPart(t, mp)
	if string(part) != inner {
		t.Fatalf("signed part differs from inner entity:\n%q", part)
	}
	if !bytes.Contains(rest, []byte("-----BEGIN PGP SIGNATURE-----\r\n")) {
		t.Fatal("detached signature must be armored as PGP SIGNATURE with CRLF line endings")
	}
	// Independent verification with go-crypto over the raw bytes.
	sigStart := bytes.Index(rest, []byte("-----BEGIN PGP SIGNATURE"))
	block, err := armor.Decode(bytes.NewReader(rest[sigStart:]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{signer}, bytes.NewReader(part), block.Body, nil); err != nil {
		t.Fatalf("signature must verify over the exact part bytes: %v", err)
	}
	// And with go-pgpmail, as a mail client would.
	r, err := pgpmail.Read(bytes.NewReader(full(mp)), openpgp.EntityList{signer}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.MessageDetails.UnverifiedBody)
	if r.MessageDetails.SignatureError != nil || r.MessageDetails.SignedBy == nil {
		t.Fatalf("pgpmail verification failed: %v", r.MessageDetails.SignatureError)
	}
}

func TestTamperedSignatureFails(t *testing.T) {
	signer := testutil.NewKey(t, "agent", "gateway@example.com")
	mp, _ := pgp.Sign([]byte(inner), signer)
	mp.Body = bytes.Replace(mp.Body, []byte("Hello from"), []byte("Hijacked by"), 1)
	r, err := pgpmail.Read(bytes.NewReader(full(mp)), openpgp.EntityList{signer}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.MessageDetails.UnverifiedBody)
	if r.MessageDetails.SignatureError == nil {
		t.Fatal("tampered content must fail verification")
	}
}

func TestEncryptAndSign(t *testing.T) {
	signer := testutil.NewKey(t, "agent", "gateway@example.com")
	rcpt := testutil.NewKey(t, "me", "me@example.com")
	mp, err := pgp.Encrypt([]byte(inner), []*openpgp.Entity{rcpt}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(mp.Body, []byte("Hello from the agent")) || bytes.Contains(mp.Body, []byte("Real subject")) {
		t.Fatal("plaintext leaked into encrypted body")
	}
	r, err := pgpmail.Read(bytes.NewReader(full(mp)), openpgp.EntityList{rcpt, signer}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r.MessageDetails.UnverifiedBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != inner {
		t.Fatalf("decrypted entity differs:\n%q", got)
	}
	md := r.MessageDetails
	if !md.IsEncrypted || !md.IsSigned || md.SignatureError != nil || md.SignedByKeyId != signer.PrimaryKey.KeyId {
		t.Fatalf("encrypted=%v signed=%v sigErr=%v", md.IsEncrypted, md.IsSigned, md.SignatureError)
	}
}

func TestEncryptWithoutSigner(t *testing.T) {
	rcpt := testutil.NewKey(t, "me", "me@example.com")
	mp, err := pgp.Encrypt([]byte(inner), []*openpgp.Entity{rcpt}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := pgpmail.Read(bytes.NewReader(full(mp)), openpgp.EntityList{rcpt}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.MessageDetails.UnverifiedBody)
	if string(got) != inner || r.MessageDetails.IsSigned {
		t.Fatal("unsigned encryption round trip failed")
	}
}

func armoredCiphertext(t *testing.T, to *openpgp.Entity, plaintext string) string {
	t.Helper()
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
	pw, err := openpgp.Encrypt(w, []*openpgp.Entity{to}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pw.Write([]byte(plaintext))
	pw.Close()
	w.Close()
	return buf.String()
}

func TestNormalizeAndWrapCiphertext(t *testing.T) {
	rcpt := testutil.NewKey(t, "me", "me@example.com")
	ct := armoredCiphertext(t, rcpt, inner)
	clean, err := pgp.NormalizeCiphertext(ct)
	if err != nil {
		t.Fatalf("valid ciphertext rejected: %v", err)
	}
	mp := pgp.WrapCiphertext(clean)
	r, err := pgpmail.Read(bytes.NewReader(full(mp)), openpgp.EntityList{rcpt}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.MessageDetails.UnverifiedBody)
	if string(got) != inner {
		t.Fatalf("wrapped e2e message does not decrypt to the agent's entity: %q", got)
	}

	var signedOnly bytes.Buffer
	w, _ := armor.Encode(&signedOnly, "PGP MESSAGE", nil)
	sw, _ := openpgp.Sign(w, rcpt, nil, nil)
	sw.Write([]byte("not encrypted"))
	sw.Close()
	w.Close()

	pub := testutil.ArmorPublic(t, rcpt)
	truncated := ct[:len(ct)/2]
	for name, bad := range map[string]string{
		"garbage": "hello", "signed only": signedOnly.String(), "public key": pub, "truncated": truncated,
		"session key followed by plaintext": eskThenLiteral(t, ct, "PLAINTEXT-SMUGGLE"),
	} {
		if _, err := pgp.NormalizeCiphertext(bad); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

// Text around the armor and armor headers must never reach the mail provider.
func TestNormalizeDropsSmuggledPlaintext(t *testing.T) {
	rcpt := testutil.NewKey(t, "me", "me@example.com")
	ct := armoredCiphertext(t, rcpt, inner)
	withComment := strings.Replace(ct, "-----BEGIN PGP MESSAGE-----\n", "-----BEGIN PGP MESSAGE-----\nComment: HEADER-SECRET\n", 1)
	smuggled := "LEADING-SECRET\n\n" + withComment + "\nTRAILING-SECRET\n"
	clean, err := pgp.NormalizeCiphertext(smuggled)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"LEADING-SECRET", "HEADER-SECRET", "TRAILING-SECRET", "Comment"} {
		if strings.Contains(clean, leak) {
			t.Errorf("%q survived normalization", leak)
		}
	}
	for _, line := range strings.Split(clean, "\r\n") {
		if len(line) > 76 {
			t.Fatalf("re-armored line too long: %d", len(line))
		}
	}
}

// eskThenLiteral builds a message whose first packet is a real encrypted
// session key but whose data is an unencrypted literal packet.
func eskThenLiteral(t *testing.T, ct, plaintext string) string {
	t.Helper()
	block, err := armor.Decode(strings.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(block.Body).Next()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
	if err := op.Serialize(w); err != nil {
		t.Fatal(err)
	}
	lw, err := packet.SerializeLiteral(w, true, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	lw.Write([]byte(plaintext))
	lw.Close()
	w.Close()
	return buf.String()
}

func TestParseKeys(t *testing.T) {
	k := testutil.NewKey(t, "me", "me@example.com")
	pub, err := pgp.ParsePublicKey([]byte(testutil.ArmorPublic(t, k)))
	if err != nil || pgp.Fingerprint(pub) != pgp.Fingerprint(k) {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if _, err := pgp.ParsePublicKey([]byte("nope")); err == nil {
		t.Fatal("garbage must fail")
	}
	priv, err := pgp.ParsePrivateKey([]byte(testutil.ArmorPrivate(t, k)), nil)
	if err != nil || priv.PrivateKey == nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if _, err := pgp.ParsePrivateKey([]byte(testutil.ArmorPublic(t, k)), nil); err == nil {
		t.Fatal("public key is not a private key")
	}
}
