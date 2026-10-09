package auth

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	tok, id, hash := NewToken()
	if !strings.HasPrefix(tok, "em_"+id+"_") {
		t.Fatalf("token %q does not embed id %q", tok, id)
	}
	gotID, secret, err := ParseToken(tok)
	if err != nil || gotID != id {
		t.Fatalf("ParseToken = %q, %v", gotID, err)
	}
	if !SecretMatches(secret, hash) {
		t.Fatal("secret must match its hash")
	}
	if SecretMatches(secret+"x", hash) {
		t.Fatal("different secret must not match")
	}
	if strings.Contains(string(hash), secret) {
		t.Fatal("hash must not contain the secret")
	}
	tok2, id2, _ := NewToken()
	if tok2 == tok || id2 == id {
		t.Fatal("tokens must be unique")
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	good, _, _ := NewToken()
	for _, bad := range []string{"", "em_", "Bearer " + good, good + "x", strings.ToUpper(good), "xx" + good[2:], strings.Replace(good, "_", "-", 1)} {
		if _, _, err := ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) should fail", bad)
		}
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions()
	link := s.NewLink()
	if _, ok := s.Redeem("nope"); ok {
		t.Fatal("an unknown link must not log in")
	}
	sess, ok := s.Redeem(link)
	if !ok {
		t.Fatal("a fresh link must log in")
	}
	if _, ok := s.Redeem(link); ok {
		t.Fatal("a link works once")
	}
	if got, ok := s.Get(sess.ID); !ok || got != sess {
		t.Fatal("session must be found")
	}
	if !sess.ValidCSRF(sess.CSRF) || sess.ValidCSRF("") || sess.ValidCSRF(sess.CSRF+"x") {
		t.Fatal("CSRF validation wrong")
	}
	sess.AddFlash("ok", "hello")
	if f := sess.PopFlash(); len(f) != 1 || f[0].Message != "hello" {
		t.Fatalf("flash = %v", f)
	}
	if f := sess.PopFlash(); len(f) != 0 {
		t.Fatal("flash must be one-shot")
	}
	s.Delete(sess.ID)
	if _, ok := s.Get(sess.ID); ok {
		t.Fatal("deleted session must not be found")
	}
	other, _ := s.Redeem(s.NewLink())
	unspent := s.NewLink()
	s.Clear()
	if _, ok := s.Get(other.ID); ok {
		t.Fatal("Clear must end every session")
	}
	if _, ok := s.Redeem(unspent); ok {
		t.Fatal("Clear must void unspent links")
	}
}
