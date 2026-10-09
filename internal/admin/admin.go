// Package admin manages the dashboard's admin password, stored as an
// argon2id hash in the state database. A fresh install gets a random setup
// password that the first login must replace; a forgotten password is
// replaced the same way with Reset.
package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/tut1vog/email-me/internal/auth"
	"github.com/tut1vog/email-me/internal/ids"
	"github.com/tut1vog/email-me/internal/store"
)

// MinLength is the minimum length of a chosen password, in characters.
const MinLength = 12

// ErrTooShort rejects a password shorter than MinLength.
var ErrTooShort = fmt.Errorf("the password must be at least %d characters", MinLength)

// Ensure gives a gateway that has no chosen password a new setup password
// and returns it, to be shown to the operator once. It returns "" when the
// admin has chosen a password. A setup password is replaced at every call
// while it is pending, so a lost one costs a restart.
func Ensure(ctx context.Context, st *store.Store) (string, error) {
	a, err := st.GetAdmin(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return "", fmt.Errorf("reading the admin password: %w", err)
	case !a.MustChange:
		return "", nil
	}
	return Reset(ctx, st)
}

// Reset stores a new setup password, which the next login must replace,
// and returns it.
func Reset(ctx context.Context, st *store.Store) (string, error) {
	pw := ids.Random(24)
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := st.SetAdmin(ctx, hash, true); err != nil {
		return "", fmt.Errorf("storing the admin password: %w", err)
	}
	return pw, nil
}

// Set stores a password the admin chose.
func Set(ctx context.Context, st *store.Store, password string) error {
	if len([]rune(password)) < MinLength {
		return ErrTooShort
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	return st.SetAdmin(ctx, hash, false)
}

// Verify checks password against the stored hash. It reports whether it
// matches and, if so, whether it is a setup password that must be
// replaced. The hash is read on every call, so Reset applies at once.
func Verify(ctx context.Context, st *store.Store, password string) (ok, mustChange bool, err error) {
	a, err := st.GetAdmin(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !auth.VerifyPassword(a.PasswordHash, password) {
		return false, false, nil
	}
	return true, a.MustChange, nil
}

// Pending reports whether the admin password is still a setup password.
func Pending(ctx context.Context, st *store.Store) bool {
	a, err := st.GetAdmin(ctx)
	return err == nil && a.MustChange
}
