// Package recipients validates recipients as the operator enters them on
// the dashboard. Recipients live in config.yaml (see config.Recipient); the
// settings package applies the changes.
package recipients

import (
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/pgp"
)

// reserved aliases cannot be created: "new" is the dashboard's form path.
var reserved = []string{"new"}

// Input is a recipient as entered by the operator.
type Input struct {
	Alias       string
	Address     string
	Description string
	// PublicKeyArmor is a pasted ASCII-armored public key; empty means none.
	PublicKeyArmor string
	// KeepKey keeps the current key on an update; PublicKeyArmor must then
	// be empty.
	KeepKey           bool
	RequireEncryption bool
}

// ValidationError lists every problem with an Input.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid recipient: " + strings.Join(e.Problems, "; ")
}

// Validate checks in and returns the normalized recipient: a bare address
// and the key re-armored canonically. now is when a new key must be able to
// encrypt. KeepKey keeps current's key without checking it again (it may
// have expired; replacing it is a separate step); current is nil for a new
// recipient.
func Validate(in Input, current *config.Recipient, now time.Time) (*config.Recipient, error) {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	out := &config.Recipient{Alias: in.Alias, Description: in.Description, RequireEncryption: in.RequireEncryption}
	if !config.AliasPattern.MatchString(in.Alias) {
		add("Alias must be 1-32 characters of lowercase letters, digits, '-' or '_', starting with a letter or digit")
	} else if current == nil && slices.Contains(reserved, in.Alias) {
		add("Alias %q is reserved", in.Alias)
	}
	if a, err := mail.ParseAddress(in.Address); err != nil || a.Name != "" {
		add("Address must be a bare email address such as you@example.com")
	} else {
		out.Address = a.Address
	}
	if utf8.RuneCountInString(in.Description) > config.MaxDescription {
		add("Description must be at most %d characters", config.MaxDescription)
	}
	if strings.ContainsAny(in.Description, "\r\n") {
		add("Description must be a single line")
	}
	switch {
	case in.KeepKey && in.PublicKeyArmor != "":
		add("Either keep the current PGP key or paste a new one, not both")
	case in.KeepKey && current != nil:
		out.PGPPublicKey = current.PGPPublicKey
	case in.PublicKeyArmor != "":
		if armored, err := canonicalKey(in.PublicKeyArmor, now); err != nil {
			add("PGP public key: %v", err)
		} else {
			out.PGPPublicKey = armored
		}
	}
	if in.RequireEncryption && out.PGPPublicKey == "" && in.PublicKeyArmor == "" {
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
