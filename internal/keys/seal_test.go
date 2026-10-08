package keys_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/tut1vog/email-me/internal/keys"
)

func TestSealUnseal(t *testing.T) {
	kek, other := make([]byte, 32), make([]byte, 32)
	rand.Read(kek)
	rand.Read(other)
	plain := []byte("smtp-secret")
	blob, err := keys.Seal(kek, plain, "settings.smtp_password")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, plain) {
		t.Fatal("sealed blob contains the plaintext")
	}
	again, _ := keys.Seal(kek, plain, "settings.smtp_password")
	if bytes.Equal(blob, again) {
		t.Fatal("each seal must use a fresh nonce")
	}
	got, err := keys.Unseal(kek, blob, "settings.smtp_password")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
	if _, err := keys.Unseal(other, blob, "settings.smtp_password"); err == nil {
		t.Error("wrong KEK must fail")
	}
	if _, err := keys.Unseal(kek, blob, "another.field"); err == nil {
		t.Error("wrong AAD must fail")
	}
	if _, err := keys.Unseal(kek, blob[:5], "settings.smtp_password"); err == nil {
		t.Error("truncated blob must fail")
	}
	if _, err := keys.Seal(kek[:7], plain, "x"); err == nil {
		t.Error("a short KEK must fail")
	}
}
