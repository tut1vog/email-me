package keyring_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tut1vog/email-me/internal/keyring"
	"github.com/tut1vog/email-me/internal/store"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestOpen(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)

	// No KEK and no keyring: none, and nothing stored.
	kr, _, err := keyring.Open(ctx, st, nil, nil)
	if kr != nil || err != nil {
		t.Fatalf("no KEK: %v %v", kr, err)
	}
	if _, err := st.GetKeyring(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("no keyring may be stored without a KEK")
	}

	// The first start with a KEK creates one.
	kr, ev, err := keyring.Open(ctx, st, key(1), nil)
	if err != nil || ev != keyring.Created {
		t.Fatalf("create: %v %v", ev, err)
	}
	blob, err := kr.Seal([]byte("smtp-secret"), "settings.smtp_password")
	if err != nil {
		t.Fatal(err)
	}
	row, _ := st.GetKeyring(ctx)
	if bytes.Contains(row.DEKWrapped, key(1)) || row.RotatedAt != nil {
		t.Fatalf("stored keyring: %+v", row)
	}
	opens := func(kr *keyring.Keyring) bool {
		got, err := kr.Unseal(blob, "settings.smtp_password")
		return err == nil && string(got) == "smtp-secret"
	}

	// The same KEK opens it; a previous KEK alongside is not needed.
	for _, prev := range [][]byte{nil, key(9)} {
		kr, ev, err = keyring.Open(ctx, st, key(1), prev)
		if err != nil || ev != keyring.Opened || !opens(kr) {
			t.Fatalf("reopen (previous %v): %v %v", prev != nil, ev, err)
		}
	}

	// No KEK, or the wrong one, is fatal; nothing is changed.
	if _, _, err := keyring.Open(ctx, st, nil, nil); !errors.Is(err, keyring.ErrNoKEK) {
		t.Fatalf("no KEK with a keyring: %v", err)
	}
	if _, _, err := keyring.Open(ctx, st, key(2), key(3)); !errors.Is(err, keyring.ErrWrongKEK) {
		t.Fatalf("wrong KEK: %v", err)
	}
	if err := keyring.Verify(ctx, st, key(2), nil); !errors.Is(err, keyring.ErrWrongKEK) {
		t.Fatalf("Verify wrong KEK: %v", err)
	}

	// Rotation: the new KEK with the previous one rewraps; Verify alone
	// does not.
	if err := keyring.Verify(ctx, st, key(2), key(1)); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.GetKeyring(ctx); !bytes.Equal(again.DEKWrapped, row.DEKWrapped) {
		t.Fatal("Verify must not write")
	}
	kr, ev, err = keyring.Open(ctx, st, key(2), key(1))
	if err != nil || ev != keyring.Rewrapped || !opens(kr) {
		t.Fatalf("rotate: %v %v", ev, err)
	}
	if row, _ = st.GetKeyring(ctx); row.RotatedAt == nil {
		t.Fatal("rotated_at must be set")
	}
	// From now on the new KEK alone opens it, and the old one does not.
	kr, ev, err = keyring.Open(ctx, st, key(2), nil)
	if err != nil || ev != keyring.Opened || !opens(kr) {
		t.Fatalf("after rotation: %v %v", ev, err)
	}
	if _, _, err := keyring.Open(ctx, st, key(1), nil); !errors.Is(err, keyring.ErrWrongKEK) {
		t.Fatalf("the old KEK must no longer open it: %v", err)
	}
	if err := keyring.Verify(ctx, st, nil, nil); !errors.Is(err, keyring.ErrNoKEK) {
		t.Fatalf("Verify without a KEK: %v", err)
	}
}

func TestVerifyWithoutKeyring(t *testing.T) {
	st := openStore(t)
	if err := keyring.Verify(context.Background(), st, nil, nil); err != nil {
		t.Fatal(err)
	}
}
