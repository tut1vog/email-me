// Package auth handles agent bearer tokens, and dashboard sessions with the
// console's one-time login links.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"regexp"
	"strings"

	"github.com/tut1vog/email-me/internal/ids"
)

const (
	tokenPrefix   = "em_"
	tokenIDLen    = 12
	tokenSecretLn = 52 // 32 random bytes in unpadded base32
)

var tokenPattern = regexp.MustCompile(`^em_([a-z2-7]{12})_([a-z2-7]{52})$`)

// ErrMalformedToken is returned for strings that are not email-me tokens.
var ErrMalformedToken = errors.New("malformed token")

// NewToken returns a fresh token (shown to the operator once), its public ID,
// and the hash to store.
func NewToken() (token, id string, hash []byte) {
	id = ids.Random(tokenIDLen)
	secret := ids.Random(tokenSecretLn)
	return tokenPrefix + id + "_" + secret, id, HashSecret(secret)
}

// ParseToken splits a token into its ID and secret.
func ParseToken(token string) (id, secret string, err error) {
	m := tokenPattern.FindStringSubmatch(strings.TrimSpace(token))
	if m == nil {
		return "", "", ErrMalformedToken
	}
	return m[1], m[2], nil
}

// HashSecret hashes a token secret. The secret carries 256 bits of entropy,
// so a single SHA-256 is sufficient (no slow KDF needed).
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// SecretMatches compares a presented secret with a stored hash in constant time.
func SecretMatches(secret string, hash []byte) bool {
	return subtle.ConstantTimeCompare(HashSecret(secret), hash) == 1
}
