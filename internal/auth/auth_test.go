package auth

import (
	"strings"
	"testing"
	"time"
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

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !IsArgon2Hash(h) || ValidateHash(h) != nil {
		t.Fatalf("bad hash %q", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("password must verify")
	}
	if VerifyPassword(h, "wrong") || VerifyPassword("garbage", "x") {
		t.Fatal("wrong password must not verify")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salts must differ")
	}
	for _, bad := range []string{"$argon2id$v=19$m=0,t=1,p=1$AAAA$AAAA", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA", "$argon2id$v=19$m=65536,t=3,p=2$@@$AA"} {
		if ValidateHash(bad) == nil {
			t.Errorf("ValidateHash(%q) should fail", bad)
		}
	}
}

func TestSessions(t *testing.T) {
	s := NewSessions(time.Hour)
	now := time.Now()
	s.now = func() time.Time { return now }
	sess := s.Create()
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
	now = now.Add(2 * time.Hour)
	if _, ok := s.Get(sess.ID); ok {
		t.Fatal("expired session must not be found")
	}
	sess2 := s.Create()
	s.Delete(sess2.ID)
	if _, ok := s.Get(sess2.ID); ok {
		t.Fatal("deleted session must not be found")
	}
}

func TestLoginThrottle(t *testing.T) {
	th := NewLoginThrottle(3, time.Minute)
	now := time.Now()
	th.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := th.Allowed("1.2.3.4"); !ok {
			t.Fatalf("attempt %d should be allowed", i)
		}
		th.Failure("1.2.3.4")
	}
	if ok, _ := th.Allowed("1.2.3.4"); ok {
		t.Fatal("should be locked after free failures are used")
	}
	if ok, _ := th.Allowed("5.6.7.8"); !ok {
		t.Fatal("other IPs unaffected")
	}
	now = now.Add(2 * time.Second)
	if ok, _ := th.Allowed("1.2.3.4"); !ok {
		t.Fatal("lock should expire")
	}
	for i := 0; i < 20; i++ {
		th.Failure("1.2.3.4")
	}
	if _, wait := th.Allowed("1.2.3.4"); wait > time.Minute {
		t.Fatalf("backoff must be capped, got %v", wait)
	}
	th.Success("1.2.3.4")
	if ok, _ := th.Allowed("1.2.3.4"); !ok {
		t.Fatal("success must reset")
	}
}
