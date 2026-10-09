// Package keyring holds the data key (DEK) that seals every credential
// stored in the state database: the SMTP password, agent signing keys and
// the certification master key. The DEK is random, generated on the first
// start that has a key-encryption key (KEK), and stored wrapped by the KEK.
// Only the KEK lives outside the database, so rotating it rewraps one row.
package keyring

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/tut1vog/email-me/internal/store"
)

// dekAAD binds the wrapped data key to its table.
const dekAAD = "keyring.dek"

// Keyring seals and unseals credentials under the data key.
type Keyring struct{ dek []byte }

// New returns a keyring for a known data key (tests).
func New(dek []byte) *Keyring { return &Keyring{dek: dek} }

// Seal encrypts plain under the data key; aad names the row and column the
// ciphertext belongs to.
func (k *Keyring) Seal(plain []byte, aad string) ([]byte, error) { return Seal(k.dek, plain, aad) }

// Unseal reverses Seal.
func (k *Keyring) Unseal(blob []byte, aad string) ([]byte, error) { return Unseal(k.dek, blob, aad) }

// Event says what Open did besides opening the keyring.
type Event int

const (
	// Opened: the keyring opened with the KEK.
	Opened Event = iota
	// Created: there was none; a new data key was stored.
	Created
	// Rewrapped: it opened only with the previous KEK and is now wrapped
	// by the current one.
	Rewrapped
)

var (
	// ErrNoKEK: the database holds a keyring but no KEK is configured.
	ErrNoKEK = errors.New("the state database holds credentials encrypted with a key-encryption key, but kek.file is empty: write that key to it. If the key is lost, `email-me reset-keyring --yes` discards those credentials")
	// ErrWrongKEK: neither KEK opens the keyring.
	ErrWrongKEK = errors.New("kek.file does not open the state database's keyring. To rotate the KEK, keep the old key in kek.previous_file (previous_kek beside kek) for one start. If the key is lost, `email-me reset-keyring --yes` discards the credentials it protected")
)

// Open opens the keyring with kek, falling back to previous (and then
// rewrapping under kek), or creates one if there is none. Without a KEK it
// returns a nil keyring, or ErrNoKEK if the database has one.
func Open(ctx context.Context, st *store.Store, kek, previous []byte) (*Keyring, Event, error) {
	row, err := st.GetKeyring(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if kek == nil {
			return nil, Opened, nil
		}
		dek := make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return nil, Opened, err
		}
		wrapped, err := Seal(kek, dek, dekAAD)
		if err != nil {
			return nil, Opened, err
		}
		if err := st.CreateKeyring(ctx, wrapped); err != nil {
			return nil, Opened, fmt.Errorf("storing the keyring: %w", err)
		}
		return &Keyring{dek: dek}, Created, nil
	case err != nil:
		return nil, Opened, fmt.Errorf("reading the keyring: %w", err)
	}
	dek, current, err := unwrap(row, kek, previous)
	if err != nil {
		return nil, Opened, err
	}
	if current {
		return &Keyring{dek: dek}, Opened, nil
	}
	wrapped, err := Seal(kek, dek, dekAAD)
	if err != nil {
		return nil, Opened, err
	}
	if err := st.RewrapKeyring(ctx, wrapped); err != nil {
		return nil, Opened, fmt.Errorf("rewrapping the keyring under the new KEK: %w", err)
	}
	return &Keyring{dek: dek}, Rewrapped, nil
}

// Verify checks that Open would succeed with kek and previous, without
// writing anything.
func Verify(ctx context.Context, st *store.Store, kek, previous []byte) error {
	row, err := st.GetKeyring(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the keyring: %w", err)
	}
	_, _, err = unwrap(row, kek, previous)
	return err
}

// unwrap opens the stored data key with kek or else previous, reporting
// whether kek did.
func unwrap(row *store.Keyring, kek, previous []byte) ([]byte, bool, error) {
	if kek == nil {
		return nil, false, ErrNoKEK
	}
	if dek, err := Unseal(kek, row.DEKWrapped, dekAAD); err == nil {
		return dek, true, nil
	}
	if previous != nil {
		if dek, err := Unseal(previous, row.DEKWrapped, dekAAD); err == nil {
			return dek, false, nil
		}
	}
	return nil, false, ErrWrongKEK
}
