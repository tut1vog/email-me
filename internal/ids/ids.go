// Package ids generates random identifiers.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// Random returns n characters of lowercase base32 from a CSPRNG.
func Random(n int) string {
	b := make([]byte, (n*5+7)/8)
	if _, err := rand.Read(b); err != nil {
		panic("ids: crypto/rand failed: " + err.Error())
	}
	return strings.ToLower(enc.EncodeToString(b))[:n]
}

// New returns prefix + "_" + 16 random characters, e.g. "ag_k3j...".
func New(prefix string) string { return prefix + "_" + Random(16) }
