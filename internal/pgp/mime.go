package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/tut1vog/email-me/internal/ids"
)

// Multipart is a top-level multipart body: its Content-Type header value and
// the encoded body (boundaries and parts, CRLF line endings).
type Multipart struct {
	ContentType string
	Body        []byte
}

func newBoundary() string { return "=_email-me_" + ids.Random(24) }

// Sign produces a PGP/MIME multipart/signed body (RFC 3156 §5) over inner,
// which must be a complete, 7-bit-clean MIME entity with CRLF line endings.
// The signature is a detached binary signature over exactly those bytes.
func Sign(inner []byte, signer *openpgp.Entity) (*Multipart, error) {
	if signer == nil {
		return nil, errors.New("pgp: no signer")
	}
	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, signer, bytes.NewReader(inner), Config()); err != nil {
		return nil, fmt.Errorf("pgp: signing: %w", err)
	}
	armored, err := armorCRLF(openpgp.SignatureType, sig.Bytes())
	if err != nil {
		return nil, err
	}
	b := newBoundary()
	var body bytes.Buffer
	fmt.Fprintf(&body, "--%s\r\n", b)
	body.Write(inner)
	fmt.Fprintf(&body, "\r\n--%s\r\n", b)
	body.WriteString("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n")
	body.WriteString("Content-Description: OpenPGP digital signature\r\n")
	body.WriteString("Content-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n")
	body.Write(armored)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", b)
	ct := mime.FormatMediaType("multipart/signed", map[string]string{
		"protocol": "application/pgp-signature",
		"micalg":   "pgp-sha256",
		"boundary": b,
	})
	return &Multipart{ContentType: ct, Body: body.Bytes()}, nil
}

// Encrypt produces a PGP/MIME multipart/encrypted body (RFC 3156 §4) holding
// inner encrypted to recipients, and signed inside the ciphertext if signer
// is non-nil (RFC 3156 §6.2 combined method).
func Encrypt(inner []byte, recipients []*openpgp.Entity, signer *openpgp.Entity) (*Multipart, error) {
	if len(recipients) == 0 {
		return nil, errors.New("pgp: no recipients")
	}
	var ct bytes.Buffer
	w, err := openpgp.Encrypt(&ct, recipients, signer, nil, Config())
	if err != nil {
		return nil, fmt.Errorf("pgp: encrypting: %w", err)
	}
	if _, err := w.Write(inner); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	armored, err := armorCRLF("PGP MESSAGE", ct.Bytes())
	if err != nil {
		return nil, err
	}
	return wrapEncrypted(armored), nil
}

// WrapCiphertext wraps ciphertext (as returned by NormalizeCiphertext) as
// multipart/encrypted.
func WrapCiphertext(armoredCRLF string) *Multipart { return wrapEncrypted([]byte(armoredCRLF)) }

func wrapEncrypted(armoredCRLF []byte) *Multipart {
	b := newBoundary()
	var body bytes.Buffer
	body.WriteString("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n")
	fmt.Fprintf(&body, "--%s\r\n", b)
	body.WriteString("Content-Type: application/pgp-encrypted\r\n")
	body.WriteString("Content-Description: PGP/MIME version identification\r\n\r\n")
	body.WriteString("Version: 1\r\n")
	fmt.Fprintf(&body, "\r\n--%s\r\n", b)
	body.WriteString("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n")
	body.WriteString("Content-Description: OpenPGP encrypted message\r\n")
	body.WriteString("Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
	body.Write(armoredCRLF)
	fmt.Fprintf(&body, "\r\n--%s--\r\n", b)
	ct := mime.FormatMediaType("multipart/encrypted", map[string]string{
		"protocol": "application/pgp-encrypted",
		"boundary": b,
	})
	return &Multipart{ContentType: ct, Body: body.Bytes()}
}

// OpenPGP packet tags accepted in agent-supplied (e2e) ciphertext.
const (
	tagPKESK  = 1  // public-key encrypted session key
	tagSKESK  = 3  // symmetric-key encrypted session key
	tagSEIPD  = 18 // symmetrically encrypted, integrity protected data
	tagAEADv5 = 20 // LibrePGP OCB encrypted data (GnuPG 2.4+)
)

// NormalizeCiphertext checks that s is ASCII-armored OpenPGP ciphertext and
// returns a fresh CRLF armoring of the decoded packets. The packet sequence
// must be one or more encrypted-session-key packets followed by exactly one
// integrity-protected encrypted data packet. Anything the agent put outside
// the packets (text around the armor, armor headers such as Comment) is
// dropped, so no plaintext can ride along to the mail provider.
func NormalizeCiphertext(s string) (string, error) {
	block, err := armor.Decode(strings.NewReader(strings.TrimSpace(s)))
	if err != nil {
		return "", fmt.Errorf("not ASCII-armored OpenPGP data: %v", err)
	}
	if block.Type != "PGP MESSAGE" {
		return "", fmt.Errorf("armor type is %q, expected \"PGP MESSAGE\"", block.Type)
	}
	data, err := io.ReadAll(block.Body)
	if err != nil {
		return "", fmt.Errorf("corrupt armor: %v", err)
	}
	r := packet.NewOpaqueReader(bytes.NewReader(data))
	var esk, encrypted int
	for {
		op, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("unreadable OpenPGP packet: %v", err)
		}
		switch {
		case (op.Tag == tagPKESK || op.Tag == tagSKESK) && encrypted == 0:
			esk++
		case (op.Tag == tagSEIPD || op.Tag == tagAEADv5) && esk > 0 && encrypted == 0:
			encrypted++
		default:
			return "", fmt.Errorf("unexpected OpenPGP packet (tag %d); expected encrypted session keys followed by one integrity-protected encrypted data packet", op.Tag)
		}
	}
	if esk == 0 || encrypted != 1 {
		return "", errors.New("message is not encrypted to a recipient key")
	}
	out, err := armorCRLF("PGP MESSAGE", data)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func armorCRLF(blockType string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, blockType, nil)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	out := bytes.ReplaceAll(buf.Bytes(), []byte("\r\n"), []byte("\n"))
	out = bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n"))
	if !bytes.HasSuffix(out, []byte("\r\n")) {
		out = append(out, '\r', '\n')
	}
	return out, nil
}
