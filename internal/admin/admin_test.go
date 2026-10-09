package admin_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tut1vog/email-me/internal/admin"
	"github.com/tut1vog/email-me/internal/store"
)

func TestSetupPasswordLifecycle(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if ok, _, err := admin.Verify(ctx, st, "anything"); ok || err != nil || admin.Pending(ctx, st) {
		t.Fatal("no admin before the first start")
	}
	first, err := admin.Ensure(ctx, st)
	if err != nil || len(first) != 24 {
		t.Fatalf("setup password %q: %v", first, err)
	}
	if ok, must, _ := admin.Verify(ctx, st, first); !ok || !must || !admin.Pending(ctx, st) {
		t.Fatal("the setup password logs in and must be changed")
	}
	// Every start replaces a pending setup password.
	second, _ := admin.Ensure(ctx, st)
	if second == "" || second == first {
		t.Fatal("a pending setup password is regenerated")
	}
	if ok, _, _ := admin.Verify(ctx, st, first); ok {
		t.Fatal("the previous setup password stops working")
	}

	if err := admin.Set(ctx, st, "too short"); !errors.Is(err, admin.ErrTooShort) {
		t.Fatalf("short: %v", err)
	}
	if err := admin.Set(ctx, st, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if ok, must, _ := admin.Verify(ctx, st, "correct horse battery staple"); !ok || must || admin.Pending(ctx, st) {
		t.Fatal("a chosen password logs in without a forced change")
	}
	if pw, err := admin.Ensure(ctx, st); pw != "" || err != nil {
		t.Fatal("a chosen password is left alone")
	}

	reset, err := admin.Reset(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, _ := admin.Verify(ctx, st, "correct horse battery staple"); ok {
		t.Fatal("Reset replaces the chosen password")
	}
	if ok, must, _ := admin.Verify(ctx, st, reset); !ok || !must {
		t.Fatal("Reset stores a setup password")
	}
}
