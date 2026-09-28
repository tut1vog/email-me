// Package pgp builds PGP/MIME messages (RFC 3156) and loads OpenPGP keys.
package pgp

import (
	"bytes"
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Config is the OpenPGP configuration used for all operations.
func Config() *packet.Config {
	return &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionNone,
	}
}

// ParsePublicKey parses a single armored (or binary) public key that must
// have a usable encryption key.
func ParsePublicKey(data []byte) (*openpgp.Entity, error) {
	el, err := readKeyRing(data)
	if err != nil {
		return nil, err
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("expected exactly one key, found %d", len(el))
	}
	e := el[0]
	if e.Revoked(time.Now()) {
		return nil, fmt.Errorf("key %s is revoked", Fingerprint(e))
	}
	if _, ok := e.EncryptionKey(time.Now()); !ok {
		return nil, fmt.Errorf("key %s has no valid (unexpired) encryption key", Fingerprint(e))
	}
	return e, nil
}

// ParsePrivateKey parses a single private key and decrypts it with passphrase
// if needed. The key must be able to certify.
func ParsePrivateKey(data, passphrase []byte) (*openpgp.Entity, error) {
	el, err := readKeyRing(data)
	if err != nil {
		return nil, err
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("expected exactly one key, found %d", len(el))
	}
	e := el[0]
	if e.PrivateKey == nil {
		return nil, fmt.Errorf("file contains a public key, not a private key")
	}
	if e.PrivateKey.Encrypted {
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("private key is passphrase-protected but no passphrase_file is set")
		}
		if err := e.DecryptPrivateKeys(passphrase); err != nil {
			return nil, fmt.Errorf("decrypting private key: %w", err)
		}
	}
	if _, ok := e.CertificationKey(time.Now()); !ok {
		return nil, fmt.Errorf("key %s cannot certify (expired, revoked, or missing certify flag)", Fingerprint(e))
	}
	return e, nil
}

func readKeyRing(data []byte) (openpgp.EntityList, error) {
	if bytes.Contains(data, []byte("-----BEGIN PGP")) {
		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("reading armored key: %w", err)
		}
		return el, nil
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}
	return el, nil
}

// Fingerprint returns the uppercase hex fingerprint of an entity's primary key.
func Fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(fmt.Sprintf("%x", e.PrimaryKey.Fingerprint))
}

// ArmorPublic returns the ASCII-armored public key of an entity.
func ArmorPublic(e *openpgp.Entity) (string, error) {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return "", err
	}
	if err := e.Serialize(w); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	buf.WriteString("\n")
	return buf.String(), nil
}

// KeyExpiry returns the primary key's expiry time, or zero if it never expires.
func KeyExpiry(e *openpgp.Entity) time.Time {
	sig, _ := e.PrimarySelfSignature()
	if sig == nil || sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
		return time.Time{}
	}
	return e.PrimaryKey.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
}
