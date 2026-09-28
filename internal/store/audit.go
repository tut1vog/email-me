package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

// Audit statuses.
const (
	StatusSent     = "sent"
	StatusRejected = "rejected"
	StatusFailed   = "failed"
)

// AuditEntry is metadata about one send attempt. It never contains message
// content; Subject is only populated when audit.log_subject is enabled.
type AuditEntry struct {
	ID              int64
	TS              time.Time
	AgentID         string
	TokenID         string
	SourceIP        string
	Recipients      []string
	SizeBytes       int64
	AttachmentCount int
	Services        []string
	Encrypted       bool
	Signed          bool
	SigningKeyFpr   string
	Transport       string
	Status          string
	ErrorCode       string
	UpstreamCode    int
	MessageID       string
	Subject         string
}

const auditCols = "id, ts, agent_id, token_id, source_ip, recipients, size_bytes, attachment_count, services, encrypted, signed, signing_key_fpr, transport, status, error_code, upstream_code, message_id, subject"

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) InsertAudit(ctx context.Context, e *AuditEntry) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	rcpt, _ := json.Marshal(nonNil(e.Recipients))
	svc, _ := json.Marshal(nonNil(e.Services))
	var upstream sql.NullInt64
	if e.UpstreamCode != 0 {
		upstream = sql.NullInt64{Int64: int64(e.UpstreamCode), Valid: true}
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO audit (ts, agent_id, token_id, source_ip, recipients, size_bytes, attachment_count, services, encrypted, signed, signing_key_fpr, transport, status, error_code, upstream_code, message_id, subject) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		unix(e.TS), nullStr(e.AgentID), nullStr(e.TokenID), nullStr(e.SourceIP), string(rcpt), e.SizeBytes, e.AttachmentCount, string(svc),
		b2i(e.Encrypted), b2i(e.Signed), nullStr(e.SigningKeyFpr), nullStr(e.Transport), e.Status, nullStr(e.ErrorCode), upstream,
		nullStr(e.MessageID), nullStr(e.Subject))
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// AuditFilter selects audit rows. Zero values mean "any".
type AuditFilter struct {
	AgentID string
	Status  string
	Since   time.Time
	Until   time.Time
	Limit   int
	Offset  int
}

func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]*AuditEntry, error) {
	var where []string
	var args []any
	if f.AgentID != "" {
		where = append(where, "agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.Status != "" {
		where = append(where, "status = ?")
		args = append(args, f.Status)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, unix(f.Since))
	}
	if !f.Until.IsZero() {
		where = append(where, "ts < ?")
		args = append(args, unix(f.Until))
	}
	q := "SELECT " + auditCols + " FROM audit"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY ts DESC, id DESC"
	if f.Limit > 0 {
		q += " LIMIT ? OFFSET ?"
		args = append(args, f.Limit, f.Offset)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		var agent, token, ip, fpr, transport, errCode, msgID, subject sql.NullString
		var rcpt, svc string
		var enc, signed int
		var upstream sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &agent, &token, &ip, &rcpt, &e.SizeBytes, &e.AttachmentCount, &svc, &enc, &signed,
			&fpr, &transport, &e.Status, &errCode, &upstream, &msgID, &subject); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0).UTC()
		e.AgentID, e.TokenID, e.SourceIP = agent.String, token.String, ip.String
		e.SigningKeyFpr, e.Transport, e.ErrorCode = fpr.String, transport.String, errCode.String
		e.MessageID, e.Subject = msgID.String, subject.String
		e.UpstreamCode = int(upstream.Int64)
		e.Encrypted, e.Signed = enc == 1, signed == 1
		_ = json.Unmarshal([]byte(rcpt), &e.Recipients)
		_ = json.Unmarshal([]byte(svc), &e.Services)
		out = append(out, &e)
	}
	return out, rows.Err()
}

// SentSince counts an agent's successful sends since t and returns the
// timestamp of the oldest one (for Retry-After).
func (s *Store) SentSince(ctx context.Context, agentID string, t time.Time) (int, time.Time, error) {
	var n int
	var oldest sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		"SELECT COUNT(*), MIN(ts) FROM audit WHERE agent_id = ? AND status = 'sent' AND ts >= ?",
		agentID, unix(t)).Scan(&n, &oldest)
	if err != nil {
		return 0, time.Time{}, err
	}
	var o time.Time
	if oldest.Valid {
		o = time.Unix(oldest.Int64, 0)
	}
	return n, o, nil
}

// OldestSentInWindow returns the timestamp of the k-th newest successful send
// since t (1-based from the oldest), used to compute when a slot frees up.
func (s *Store) NthOldestSent(ctx context.Context, agentID string, since time.Time, n int) (time.Time, error) {
	var ts int64
	err := s.db.QueryRowContext(ctx,
		"SELECT ts FROM audit WHERE agent_id = ? AND status = 'sent' AND ts >= ? ORDER BY ts ASC LIMIT 1 OFFSET ?",
		agentID, unix(since), n-1).Scan(&ts)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(ts, 0), nil
}

// Counts are per-status totals.
type Counts struct{ Sent, Rejected, Failed int }

// StatsSince returns per-agent counts since t.
func (s *Store) StatsSince(ctx context.Context, t time.Time) (map[string]*Counts, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT COALESCE(agent_id, ''), status, COUNT(*) FROM audit WHERE ts >= ? GROUP BY agent_id, status", unix(t))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Counts{}
	for rows.Next() {
		var agent, status string
		var n int
		if err := rows.Scan(&agent, &status, &n); err != nil {
			return nil, err
		}
		c := out[agent]
		if c == nil {
			c = &Counts{}
			out[agent] = c
		}
		switch status {
		case StatusSent:
			c.Sent = n
		case StatusRejected:
			c.Rejected = n
		case StatusFailed:
			c.Failed = n
		}
	}
	return out, rows.Err()
}

// InsecureAgents lists agent IDs that sent over an insecure transport since t.
func (s *Store) InsecureAgents(ctx context.Context, t time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT DISTINCT agent_id FROM audit WHERE transport = 'insecure' AND ts >= ? AND agent_id IS NOT NULL ORDER BY agent_id", unix(t))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// PruneAudit deletes rows older than t.
func (s *Store) PruneAudit(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, "DELETE FROM audit WHERE ts < ?", unix(t))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
