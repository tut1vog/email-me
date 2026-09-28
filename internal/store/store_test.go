package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tut1vog/email-me/internal/policy"
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
	s.Close()
}

func TestAgentsCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	rc := []string{"me"}
	a, err := s.CreateAgent(ctx, "bench", "desc", policy.Policy{Recipients: &rc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAgent(ctx, "bench", "", policy.Policy{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	got, err := s.GetAgent(ctx, a.ID)
	if err != nil || got.Name != "bench" || !got.Enabled || got.Policy.Recipients == nil || (*got.Policy.Recipients)[0] != "me" {
		t.Fatalf("GetAgent = %+v, %v", got, err)
	}
	if err := s.UpdateAgent(ctx, a.ID, "new", false); err != nil {
		t.Fatal(err)
	}
	f := false
	if err := s.UpdateAgentPolicy(ctx, a.ID, policy.Policy{RequireSigning: &f}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAgent(ctx, a.ID)
	if got.Enabled || got.Description != "new" || got.Policy.Recipients != nil || got.Policy.RequireSigning == nil {
		t.Fatalf("after update: %+v", got)
	}
	if err := s.UpdateAgent(ctx, "ag_missing", "", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	list, _ := s.ListAgents(ctx)
	if len(list) != 1 {
		t.Fatal(list)
	}
	// Deleting cascades to tokens and keys.
	if err := s.CreateToken(ctx, &Token{ID: "tok1", AgentID: a.ID, SecretHash: []byte{1}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertKey(ctx, &AgentKey{Fingerprint: "F1", AgentID: a.ID, PublicKey: "p", PrivateKeyEnc: []byte{1}, RevocationCert: "r", RevocationCertCompromised: "rc", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAgent(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("token must cascade")
	}
	if _, err := s.GetKey(ctx, "F1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("key must cascade")
	}
}

func TestTokens(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	a, _ := s.CreateAgent(ctx, "a", "", policy.Policy{})
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	tok := &Token{ID: "abc", AgentID: a.ID, SecretHash: []byte("h"), Label: "l", AllowedCIDRs: []string{"10.0.0.0/8"}, CreatedAt: time.Now(), ExpiresAt: &exp}
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
	if err := s.RevokeToken(ctx, a.ID, "abc"); err != nil {
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
	a, _ := s.CreateAgent(ctx, "a", "", policy.Policy{})
	mk := func(fpr string) *AgentKey {
		return &AgentKey{Fingerprint: fpr, AgentID: a.ID, PublicKey: "pub-" + fpr, PrivateKeyEnc: []byte("secret"), RevocationCert: "rev", RevocationCertCompromised: "rev-c", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
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
	act, _ := s.ActiveKey(ctx, a.ID)
	if act.Fingerprint != "K2" {
		t.Fatal(act.Fingerprint)
	}
	old, _ := s.GetKey(ctx, "K1")
	if old.RetiredAt == nil || len(old.PrivateKeyEnc) != 0 || old.PublicKey != "pub-K1" || old.RevocationCert != "rev" || old.RevocationCertCompromised != "rev-c" {
		t.Fatalf("retired key: %+v", old)
	}
	ks, _ := s.ListKeys(ctx, a.ID)
	if len(ks) != 2 {
		t.Fatal(len(ks))
	}
}

func TestAudit(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	now := time.Now()
	add := func(agent, status string, ago time.Duration, transport string) {
		if err := s.InsertAudit(ctx, &AuditEntry{TS: now.Add(-ago), AgentID: agent, Status: status, Recipients: []string{"me"}, Transport: transport}); err != nil {
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
	rows, _ := s.ListAudit(ctx, AuditFilter{AgentID: "a1", Status: StatusSent, Limit: 10})
	if len(rows) != 3 || rows[0].Recipients[0] != "me" || !rows[0].TS.After(rows[1].TS) {
		t.Fatalf("ListAudit = %d rows", len(rows))
	}
	pruned, _ := s.PruneAudit(ctx, now.Add(-30*24*time.Hour))
	if pruned != 1 {
		t.Fatalf("pruned %d", pruned)
	}
}
