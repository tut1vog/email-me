package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationsIdempotent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(p)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version = %d, %v", v, err)
	}
}

func TestSMTPPassword(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, err := s.GetSMTPPassword(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty table: %v", err)
	}
	if err := s.SetSMTPPassword(ctx, &SMTPPassword{Value: []byte{0, 1, 2}, Sealed: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSMTPPassword(ctx)
	if err != nil || string(got.Value) != "\x00\x01\x02" || !got.Sealed || got.UpdatedAt.IsZero() {
		t.Fatalf("GetSMTPPassword = %+v, %v", got, err)
	}
	if err := s.SetSMTPPassword(ctx, &SMTPPassword{Value: []byte("raw")}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetSMTPPassword(ctx); string(got.Value) != "raw" || got.Sealed {
		t.Fatalf("after replace: %+v", got)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&n); err != nil || n != 1 {
		t.Fatalf("credentials is a single row: %d %v", n, err)
	}
	if err := s.SetSMTPPassword(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSMTPPassword(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed: %v", err)
	}
}

func TestAgentData(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateToken(ctx, &Token{ID: "tok1", Agent: "bench", SecretHash: []byte{1}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []*AgentKey{
		{Fingerprint: "F1", Agent: "bench", PublicKey: "p", PrivateKeyEnc: []byte{1}, RevocationCert: "r", RevocationCertCompromised: "rc", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
		{Fingerprint: "F2", Agent: "keys-only", PublicKey: "p", PrivateKeyEnc: []byte{1}, RevocationCert: "r", RevocationCertCompromised: "rc", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
	} {
		if err := s.InsertKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if names, err := s.AgentsWithData(ctx); err != nil || len(names) != 2 || names[0] != "bench" || names[1] != "keys-only" {
		t.Fatalf("AgentsWithData = %v, %v", names, err)
	}
	if err := s.DeleteAgentData(ctx, "bench"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("tokens must be deleted")
	}
	if _, err := s.GetKey(ctx, "F1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("keys must be deleted")
	}
	if names, _ := s.AgentsWithData(ctx); len(names) != 1 || names[0] != "keys-only" {
		t.Fatalf("other agents are kept: %v", names)
	}
}

func TestTokens(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tok := &Token{ID: "abc", Agent: "a", SecretHash: []byte("h"), Label: "l", AllowedCIDRs: []string{"10.0.0.0/8"}, CreatedAt: time.Now(), ExpiresAt: &exp}
	if err := s.CreateToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetToken(ctx, "abc")
	if err != nil || got.AllowedCIDRs[0] != "10.0.0.0/8" || !got.ExpiresAt.Equal(exp) || !got.Active(time.Now()) {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Active(exp.Add(time.Second)) {
		t.Fatal("expired token must be inactive")
	}
	if err := s.TouchToken(ctx, "abc", "10.1.2.3", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, "other-agent", "abc"); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoking via another agent must fail")
	}
	if err := s.RevokeToken(ctx, "a", "abc"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetToken(ctx, "abc")
	if got.Active(time.Now()) || got.LastUsedIP != "10.1.2.3" {
		t.Fatalf("%+v", got)
	}
}

func TestKeysOneActive(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mk := func(fpr string) *AgentKey {
		return &AgentKey{Fingerprint: fpr, Agent: "a", PublicKey: "pub-" + fpr, PrivateKeyEnc: []byte("secret"), RevocationCert: "rev", RevocationCertCompromised: "rev-c", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	}
	if err := s.InsertKey(ctx, mk("K1")); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertKey(ctx, mk("K2")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second active key must conflict: %v", err)
	}
	if err := s.RotateKey(ctx, mk("K2")); err != nil {
		t.Fatal(err)
	}
	act, _ := s.ActiveKey(ctx, "a")
	if act.Fingerprint != "K2" {
		t.Fatal(act.Fingerprint)
	}
	old, _ := s.GetKey(ctx, "K1")
	if old.RetiredAt == nil || len(old.PrivateKeyEnc) != 0 || old.PublicKey != "pub-K1" || old.RevocationCert != "rev" || old.RevocationCertCompromised != "rev-c" {
		t.Fatalf("retired key: %+v", old)
	}
	ks, _ := s.ListKeys(ctx, "a")
	if len(ks) != 2 {
		t.Fatal(len(ks))
	}
}

func TestResetKeyring(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.CreateKeyring(ctx, []byte("wrapped")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateKeyring(ctx, []byte("again")); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second keyring must conflict: %v", err)
	}
	if err := s.SetSMTPPassword(ctx, &SMTPPassword{Value: []byte("sealed"), Sealed: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCertifyKey(ctx, &CertifyKey{Fingerprint: "M", PublicKey: "pub-M", PrivateKeyEnc: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	key := &AgentKey{Fingerprint: "K1", Agent: "a", PublicKey: "pub-K1", PrivateKeyEnc: []byte("sealed"), RevocationCert: "rev", RevocationCertCompromised: "rev-c", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.InsertKey(ctx, key); err != nil {
		t.Fatal(err)
	}

	d, err := s.ResetKeyring(ctx)
	if err != nil || !d.SMTPPassword || !d.CertifyKey || d.AgentKeys != 1 {
		t.Fatalf("ResetKeyring = %+v, %v", d, err)
	}
	if _, err := s.GetKeyring(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatal("keyring kept")
	}
	if _, err := s.GetSMTPPassword(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatal("sealed SMTP password kept")
	}
	if _, err := s.GetCertifyKey(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatal("certification key kept")
	}
	if _, err := s.ActiveKey(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the agent key must be retired")
	}
	if old, _ := s.GetKey(ctx, "K1"); old.RetiredAt == nil || len(old.PrivateKeyEnc) != 0 || old.RevocationCert != "rev" {
		t.Fatalf("retired key: %+v", old)
	}
	// A raw password (no keyring) is not the keyring's to discard.
	s.SetSMTPPassword(ctx, &SMTPPassword{Value: []byte("raw")})
	if d, _ := s.ResetKeyring(ctx); d.SMTPPassword {
		t.Fatal("a raw password is kept")
	}
}

func TestAudit(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	add := func(agent, status string, ago time.Duration, transport string) {
		if err := s.InsertAudit(ctx, &AuditEntry{TS: now.Add(-ago), Agent: agent, Status: status, Recipients: []string{"me"}, Transport: transport}); err != nil {
			t.Fatal(err)
		}
	}
	add("a1", StatusSent, 10*time.Minute, "local")
	add("a1", StatusSent, 50*time.Minute, "insecure")
	add("a1", StatusSent, 2*time.Hour, "tls")
	add("a1", StatusRejected, time.Minute, "tls")
	add("a2", StatusFailed, time.Minute, "tls")
	add("a2", StatusSent, 40*24*time.Hour, "insecure")

	n, oldest, err := s.SentSince(ctx, "a1", now.Add(-time.Hour))
	if err != nil || n != 2 || oldest.Unix() != now.Add(-50*time.Minute).Unix() {
		t.Fatalf("SentSince = %d %v %v", n, oldest, err)
	}
	nth, err := s.NthOldestSent(ctx, "a1", now.Add(-time.Hour), 2)
	if err != nil || nth.Unix() != now.Add(-10*time.Minute).Unix() {
		t.Fatalf("NthOldestSent = %v %v", nth, err)
	}
	stats, _ := s.StatsSince(ctx, now.Add(-24*time.Hour))
	if stats["a1"].Sent != 3 || stats["a1"].Rejected != 1 || stats["a2"].Failed != 1 || stats["a2"].Sent != 0 {
		t.Fatalf("stats = %+v %+v", stats["a1"], stats["a2"])
	}
	ins, _ := s.InsecureAgents(ctx, now.Add(-7*24*time.Hour))
	if len(ins) != 1 || ins[0] != "a1" {
		t.Fatalf("insecure = %v", ins)
	}
	rows, _ := s.ListAudit(ctx, AuditFilter{Agent: "a1", Status: StatusSent, Limit: 10})
	if len(rows) != 3 || rows[0].Recipients[0] != "me" || !rows[0].TS.After(rows[1].TS) {
		t.Fatalf("ListAudit = %d rows", len(rows))
	}
	pruned, _ := s.PruneAudit(ctx, now.Add(-30*24*time.Hour))
	if pruned != 1 {
		t.Fatalf("pruned %d", pruned)
	}
}
