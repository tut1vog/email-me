package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

type Token struct {
	ID           string
	AgentID      string
	SecretHash   []byte
	Label        string
	AllowedCIDRs []string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	RevokedAt    *time.Time
	LastUsedAt   *time.Time
	LastUsedIP   string
}

// Active reports whether the token is neither revoked nor expired.
func (t *Token) Active(now time.Time) bool {
	return t.RevokedAt == nil && (t.ExpiresAt == nil || now.Before(*t.ExpiresAt))
}

const tokenCols = "id, agent_id, secret_hash, label, allowed_cidrs, created_at, expires_at, revoked_at, last_used_at, last_used_ip"

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var cidrs string
	var created int64
	var expires, revoked, lastUsed sql.NullInt64
	var lastIP sql.NullString
	if err := row.Scan(&t.ID, &t.AgentID, &t.SecretHash, &t.Label, &cidrs, &created, &expires, &revoked, &lastUsed, &lastIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(cidrs), &t.AllowedCIDRs); err != nil {
		return nil, err
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.ExpiresAt, t.RevokedAt, t.LastUsedAt = fromNullUnix(expires), fromNullUnix(revoked), fromNullUnix(lastUsed)
	t.LastUsedIP = lastIP.String
	return &t, nil
}

func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	if t.AllowedCIDRs == nil {
		t.AllowedCIDRs = []string{}
	}
	cidrs, err := json.Marshal(t.AllowedCIDRs)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO tokens (id, agent_id, secret_hash, label, allowed_cidrs, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		t.ID, t.AgentID, t.SecretHash, t.Label, string(cidrs), unix(t.CreatedAt), nullUnix(t.ExpiresAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) GetToken(ctx context.Context, id string) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE id = ?", id))
}

func (s *Store) ListTokens(ctx context.Context, agentID string) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE agent_id = ? ORDER BY created_at DESC", agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken marks a token revoked; revoking twice is a no-op.
func (s *Store) RevokeToken(ctx context.Context, agentID, id string) error {
	return s.execOne(ctx, "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND agent_id = ?", unix(time.Now()), id, agentID)
}

// TouchToken records the last use of a token.
func (s *Store) TouchToken(ctx context.Context, id, ip string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?", unix(at), ip, id)
	return err
}
