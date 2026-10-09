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
	Agent        string
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

const tokenCols = "id, agent, secret_hash, label, allowed_cidrs, created_at, expires_at, revoked_at, last_used_at, last_used_ip"

func scanToken(row interface{ Scan(...any) error }) (*Token, error) {
	var t Token
	var cidrs string
	var created int64
	var expires, revoked, lastUsed sql.NullInt64
	var lastIP sql.NullString
	if err := row.Scan(&t.ID, &t.Agent, &t.SecretHash, &t.Label, &cidrs, &created, &expires, &revoked, &lastUsed, &lastIP); err != nil {
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
		"INSERT INTO tokens (id, agent, secret_hash, label, allowed_cidrs, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		t.ID, t.Agent, t.SecretHash, t.Label, string(cidrs), unix(t.CreatedAt), nullUnix(t.ExpiresAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) GetToken(ctx context.Context, id string) (*Token, error) {
	return scanToken(s.db.QueryRowContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE id = ?", id))
}

func (s *Store) ListTokens(ctx context.Context, agent string) ([]*Token, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+tokenCols+" FROM tokens WHERE agent = ? ORDER BY created_at DESC", agent)
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
func (s *Store) RevokeToken(ctx context.Context, agent, id string) error {
	return s.execOne(ctx, "UPDATE tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND agent = ?", unix(time.Now()), id, agent)
}

// TouchToken records the last use of a token.
func (s *Store) TouchToken(ctx context.Context, id, ip string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?", unix(at), ip, id)
	return err
}

// DeleteAgentData deletes an agent's tokens and signing keys, retired ones
// included, for an agent deleted from the configuration.
func (s *Store) DeleteAgentData(ctx context.Context, agent string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{"DELETE FROM tokens WHERE agent = ?", "DELETE FROM agent_keys WHERE agent = ?"} {
		if _, err := tx.ExecContext(ctx, q, agent); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AgentsWithData lists, sorted, the agents that have tokens or signing
// keys stored, so data left by an agent removed from the configuration can
// be found.
func (s *Store) AgentsWithData(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT agent FROM tokens UNION SELECT agent FROM agent_keys ORDER BY 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
