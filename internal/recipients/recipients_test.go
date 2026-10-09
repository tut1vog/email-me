package recipients_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/tut1vog/email-me/internal/config"
	"github.com/tut1vog/email-me/internal/recipients"
	"github.com/tut1vog/email-me/internal/testutil"
)

func TestValidate(t *testing.T) {
	now := time.Now()
	key := testutil.ArmorPublic(t, testutil.NewKey(t, "K", "k@example.com"))
	ok := recipients.Input{Alias: "me", Address: "me@example.com", Description: "Inbox", PublicKeyArmor: key, RequireEncryption: true}
	row, err := recipients.Validate(ok, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(row.PGPPublicKey, "-----BEGIN PGP PUBLIC KEY BLOCK-----") || row.Address != "me@example.com" {
		t.Fatalf("normalized = %+v", row)
	}
	if row, err := recipients.Validate(recipients.Input{Alias: "me", Address: "<me@example.com>"}, nil, now); err != nil || row.Address != "me@example.com" {
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
		_, err := recipients.Validate(tc.in, nil, at)
		var ve *recipients.ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
	// Every problem is reported at once.
	_, err = recipients.Validate(recipients.Input{Alias: "", Address: "", RequireEncryption: true}, nil, now)
	var ve *recipients.ValidationError
	if !errors.As(err, &ve) || len(ve.Problems) != 3 {
		t.Fatalf("want 3 problems, got %v", err)
	}
}

// KeepKey keeps the current key without checking it again: one that has
// expired since it was added does not stop the other fields being edited.
func TestKeepKey(t *testing.T) {
	old, err := openpgp.NewEntity("Old", "", "old@example.com", &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 3600,
		Time: func() time.Time { return time.Now().Add(-48 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	cur := &config.Recipient{Alias: "old", Address: "old@example.com", PGPPublicKey: testutil.ArmorPublic(t, old)}
	in := recipients.Input{Alias: "old", Address: "old@example.com", Description: "still editable", KeepKey: true}
	got, err := recipients.Validate(in, cur, time.Now())
	if err != nil || got.PGPPublicKey != cur.PGPPublicKey || got.Description != "still editable" {
		t.Fatalf("keeping an expired key: %+v %v", got, err)
	}
	// An existing recipient may keep a now-reserved alias.
	if _, err := recipients.Validate(recipients.Input{Alias: "new", Address: "n@example.com"}, &config.Recipient{Alias: "new"}, time.Now()); err != nil {
		t.Fatalf("existing alias: %v", err)
	}
}
