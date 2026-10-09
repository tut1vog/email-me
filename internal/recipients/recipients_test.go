package recipients_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/tut1vog/email-me/internal/pgp"
	"github.com/tut1vog/email-me/internal/policy"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/store"
	"github.com/tut1vog/email-me/internal/testutil"
)

func TestEffectiveDropsUnknownAliases(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	_, reg := testutil.Bootstrap(t, env)
	rc := []string{"me", "ghost", "me"}
	e := reg.Effective(policy.Policy{Recipients: &rc})
	if strings.Join(e.Recipients, ",") != "me" {
		t.Fatalf("got %v", e.Recipients)
	}
	if u := reg.UnknownAliases(policy.Policy{Recipients: &rc}); len(u) != 1 || u[0] != "ghost" {
		t.Fatalf("unknown = %v", u)
	}
}

func TestEffectiveDropsUnknownDefaultAliases(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{DefaultsPolicy: "recipients: [me, ghost]"})
	_, reg := testutil.Bootstrap(t, env)
	if e := reg.Effective(policy.Policy{}); strings.Join(e.Recipients, ",") != "me" {
		t.Fatalf("got %v", e.Recipients)
	}
	if u := reg.UnknownAliases(env.Config.Defaults.Policy); len(u) != 1 || u[0] != "ghost" {
		t.Fatalf("unknown = %v", u)
	}
}

// defaults is the env's default policy, as it was loaded.
func defaults(env *testutil.Env) func() policy.Effective {
	return func() policy.Effective { return env.Config.DefaultPolicy }
}

func TestEffectiveFollowsDefaults(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	st := testutil.OpenStore(t, env)
	cur := policy.Builtin(false)
	reg, _, err := recipients.Bootstrap(context.Background(), st, env.Config, func() policy.Effective { return cur })
	if err != nil {
		t.Fatal(err)
	}
	if e := reg.Effective(policy.Policy{}); len(e.Recipients) != 0 || e.RateLimit.PerHour != cur.RateLimit.PerHour {
		t.Fatalf("built-in defaults: %+v", e)
	}
	// The defaults change (a saved default policy): the next resolution
	// uses them, without a new registry.
	cur.Recipients, cur.RateLimit.PerHour = []string{"me", "ops"}, 1
	if e := reg.Effective(policy.Policy{}); strings.Join(e.Recipients, ",") != "me,ops" || e.RateLimit.PerHour != 1 {
		t.Fatalf("changed defaults: %+v", e)
	}
}

func TestSeedOnlyWhenEmpty(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	ctx := context.Background()
	st, err := store.Open(filepath.Join(env.DataDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reg, seeded, err := recipients.Bootstrap(ctx, st, env.Config, defaults(env))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(seeded, ",") != "me,ops,work" || strings.Join(reg.Aliases(), ",") != "me,ops,work" || reg.Len() != 3 {
		t.Fatalf("seeded %v, aliases %v", seeded, reg.Aliases())
	}
	me, _ := reg.Get("me")
	if me.Key == nil || me.Fingerprint() != pgp.Fingerprint(env.MeKey) || me.Address != "me@example.com" || me.Description != "Personal inbox" {
		t.Fatalf("seeded me = %+v", me)
	}
	if ops, _ := reg.Get("ops"); ops.Key != nil || ops.Fingerprint() != "" || !ops.KeyExpiry().IsZero() {
		t.Fatal("ops has no key")
	}
	if err := reg.Delete(ctx, "ops"); err != nil {
		t.Fatal(err)
	}
	// A restart with the same config must not bring the deleted alias back.
	again, seeded, err := recipients.Bootstrap(ctx, st, env.Config, defaults(env))
	if err != nil {
		t.Fatal(err)
	}
	if len(seeded) != 0 || strings.Join(again.Aliases(), ",") != "me,work" {
		t.Fatalf("second boot seeded %v, aliases %v", seeded, again.Aliases())
	}
}

func TestValidate(t *testing.T) {
	now := time.Now()
	key := testutil.ArmorPublic(t, testutil.NewKey(t, "K", "k@example.com"))
	ok := recipients.Input{Alias: "me", Address: "me@example.com", Description: "Inbox", PublicKeyArmor: key, RequireEncryption: true}
	row, err := recipients.Validate(ok, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.PublicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") || row.Address != "me@example.com" {
		t.Fatalf("normalized = %+v", row)
	}
	if row, err := recipients.Validate(recipients.Input{Alias: "me", Address: "<me@example.com>"}, now); err != nil || row.Address != "me@example.com" {
		t.Fatalf("angle brackets are a bare address: %+v %v", row, err)
	}
	private := testutil.ArmorPrivate(t, testutil.NewKey(t, "P", "p@example.com"))
	for name, tc := range map[string]struct {
		in   recipients.Input
		want string
	}{
		"bad alias":         {recipients.Input{Alias: "Bad_Alias", Address: "a@example.com"}, "Alias must be"},
		"reserved alias":    {recipients.Input{Alias: "new", Address: "a@example.com"}, "reserved"},
		"display name":      {recipients.Input{Alias: "a", Address: "Me <a@example.com>"}, "bare email address"},
		"not an address":    {recipients.Input{Alias: "a", Address: "nope"}, "bare email address"},
		"long description":  {recipients.Input{Alias: "a", Address: "a@example.com", Description: strings.Repeat("x", 201)}, "at most 200"},
		"multi-line":        {recipients.Input{Alias: "a", Address: "a@example.com", Description: "a\nb"}, "single line"},
		"garbage key":       {recipients.Input{Alias: "a", Address: "a@example.com", PublicKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnope\n"}, "PGP public key"},
		"private key":       {recipients.Input{Alias: "a", Address: "a@example.com", PublicKeyArmor: private}, "private key"},
		"require, no key":   {recipients.Input{Alias: "a", Address: "a@example.com", RequireEncryption: true}, "needs a PGP public key"},
		"keep and new key":  {recipients.Input{Alias: "a", Address: "a@example.com", PublicKeyArmor: key, KeepKey: true}, "not both"},
		"expired key (now)": {recipients.Input{Alias: "a", Address: "a@example.com", PublicKeyArmor: testutil.ArmorPublic(t, testutil.NewKeyWithLifetime(t, "E", "e@example.com", time.Hour))}, "unexpired"},
	} {
		at := now
		if name == "expired key (now)" {
			at = now.Add(2 * time.Hour)
		}
		_, err := recipients.Validate(tc.in, at)
		var ve *recipients.ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
	// Every problem is reported at once.
	_, err = recipients.Validate(recipients.Input{Alias: "", Address: "", RequireEncryption: true}, now)
	var ve *recipients.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 3 {
		t.Fatalf("want 3 problems, got %v", err)
	}
}

func TestCreateUpdateDeleteReload(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{})
	st, reg := testutil.Bootstrap(t, env)
	ctx := context.Background()
	k1 := testutil.NewKey(t, "One", "one@example.com")
	rc, err := reg.Create(ctx, recipients.Input{Alias: "pager", Address: "pager@example.com", Description: "Pager", PublicKeyArmor: testutil.ArmorPublic(t, k1)})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Fingerprint() != pgp.Fingerprint(k1) || !rc.KeyUsable(time.Now()) {
		t.Fatalf("created %+v", rc)
	}
	if _, err := reg.Create(ctx, recipients.Input{Alias: "pager", Address: "x@example.com"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate alias: %v", err)
	}
	k2 := testutil.NewKey(t, "Two", "two@example.com")
	if _, err := reg.Update(ctx, "pager", recipients.Input{Alias: "renamed", Address: "pager@example.com", PublicKeyArmor: testutil.ArmorPublic(t, k2)}); err != nil {
		t.Fatal(err)
	}
	got, ok := reg.Get("pager")
	if !ok || got.Fingerprint() != pgp.Fingerprint(k2) {
		t.Fatalf("replaced key not reflected: %+v", got)
	}
	if _, ok := reg.Get("renamed"); ok {
		t.Fatal("alias is immutable")
	}
	// Another registry on the same store sees the same state.
	other := recipients.New(st, defaults(env))
	if err := other.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if o, _ := other.Get("pager"); o.Fingerprint() != pgp.Fingerprint(k2) {
		t.Fatal("store not updated")
	}
	// KeepKey keeps the key; an empty, non-kept key removes it.
	if got, err := reg.Update(ctx, "pager", recipients.Input{Address: "pager@example.com", Description: "new", KeepKey: true}); err != nil || got.Fingerprint() != pgp.Fingerprint(k2) || got.Description != "new" {
		t.Fatalf("keep key: %+v %v", got, err)
	}
	if _, err := reg.Update(ctx, "pager", recipients.Input{Address: "pager@example.com", RequireEncryption: true}); err == nil {
		t.Fatal("removing the key while requiring encryption must fail")
	}
	if got, err := reg.Update(ctx, "pager", recipients.Input{Address: "pager@example.com"}); err != nil || got.Key != nil {
		t.Fatalf("remove key: %+v %v", got, err)
	}
	if _, err := reg.Update(ctx, "ghost", recipients.Input{Address: "g@example.com"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := reg.Delete(ctx, "pager"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Get("pager"); ok || reg.Len() != 3 {
		t.Fatal("delete not reflected")
	}
	if err := reg.Delete(ctx, "pager"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestKeyUsableAndExpiredStoredKey(t *testing.T) {
	env := testutil.NewEnv(t, testutil.Options{MeKeyLifetime: time.Hour})
	st, reg := testutil.Bootstrap(t, env)
	ctx := context.Background()
	me, _ := reg.Get("me")
	now := time.Now()
	if !me.KeyUsable(now) || me.KeyUsable(now.Add(2*time.Hour)) || me.KeyExpiry().IsZero() {
		t.Fatalf("me key: usable now %v, later %v, expiry %v", me.KeyUsable(now), me.KeyUsable(now.Add(2*time.Hour)), me.KeyExpiry())
	}
	// A key that expired after it was saved still loads, so it can be
	// reported and replaced, and other fields stay editable.
	old, err := openpgp.NewEntity("Old", "", "old@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600,
		Time: func() time.Time { return time.Now().Add(-48 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateRecipient(ctx, &store.Recipient{Alias: "old", Address: "old@example.com", PublicKey: testutil.ArmorPublic(t, old)}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(ctx); err != nil {
		t.Fatalf("expired stored key must load: %v", err)
	}
	rc, _ := reg.Get("old")
	if rc.Key == nil || rc.KeyUsable(time.Now()) {
		t.Fatal("expired key must load but not be usable")
	}
	if _, err := reg.Update(ctx, "old", recipients.Input{Address: "old@example.com", Description: "still editable", KeepKey: true}); err != nil {
		t.Fatalf("keeping an expired key: %v", err)
	}
}

func TestReferencingAgents(t *testing.T) {
	rc := []string{"me", "ops"}
	none := []string{}
	agents := []*store.Agent{
		{Name: "a", Policy: policy.Policy{Recipients: &rc}},
		{Name: "b", Policy: policy.Policy{}},
		{Name: "c", Policy: policy.Policy{Recipients: &none}},
	}
	got := recipients.ReferencingAgents(agents, "ops")
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("got %v", got)
	}
}
