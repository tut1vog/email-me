package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AgentKey is an agent's signing key. PrivateKeyEnc is AES-GCM ciphertext
// under the KEK; it is emptied when the key is retired.
type AgentKey struct {
	Fingerprint   string
	Agent         string
	PublicKey     string
	PrivateKeyEnc []byte
	// RevocationCert revokes with reason "retired" (soft: signatures made
	// before the revocation stay valid). Use it after rotation or deletion.
	RevocationCert string
	// RevocationCertCompromised revokes with reason "compromised" (hard: all
	// signatures become invalid). Use it only if the key may have leaked.
	RevocationCertCompromised string
	CreatedAt                 time.Time
	ExpiresAt                 time.Time
	RetiredAt                 *time.Time
}

const keyCols = "fingerprint, agent, public_key, private_key_enc, revocation_cert, revocation_cert_compromised, created_at, expires_at, retired_at"

func scanKey(row interface{ Scan(...any) error }) (*AgentKey, error) {
	var k AgentKey
	var created, expires int64
	var retired sql.NullInt64
	if err := row.Scan(&k.Fingerprint, &k.Agent, &k.PublicKey, &k.PrivateKeyEnc, &k.RevocationCert, &k.RevocationCertCompromised, &created, &expires, &retired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0).UTC()
	k.ExpiresAt = time.Unix(expires, 0).UTC()
	k.RetiredAt = fromNullUnix(retired)
	return &k, nil
}

func insertKey(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, k *AgentKey) error {
	_, err := ex.ExecContext(ctx,
		"INSERT INTO agent_keys ("+keyCols+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
		k.Fingerprint, k.Agent, k.PublicKey, k.PrivateKeyEnc, k.RevocationCert, k.RevocationCertCompromised, unix(k.CreatedAt), unix(k.ExpiresAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// InsertKey adds an active key; fails with ErrConflict if the agent already has one.
func (s *Store) InsertKey(ctx context.Context, k *AgentKey) error { return insertKey(ctx, s.db, k) }

// RotateKey retires the agent's active key (dropping its private material)
// and inserts k as the new active key, atomically.
func (s *Store) RotateKey(ctx context.Context, k *AgentKey) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		"UPDATE agent_keys SET retired_at = ?, private_key_enc = x'' WHERE agent = ? AND retired_at IS NULL",
		unix(time.Now()), k.Agent); err != nil {
		return err
	}
	if err := insertKey(ctx, tx, k); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ActiveKey(ctx context.Context, agent string) (*AgentKey, error) {
	return scanKey(s.db.QueryRowContext(ctx, "SELECT "+keyCols+" FROM agent_keys WHERE agent = ? AND retired_at IS NULL", agent))
}

func (s *Store) GetKey(ctx context.Context, fingerprint string) (*AgentKey, error) {
	return scanKey(s.db.QueryRowContext(ctx, "SELECT "+keyCols+" FROM agent_keys WHERE fingerprint = ?", fingerprint))
}

// ListKeys returns an agent's keys (or all keys if agent is empty), newest first.
func (s *Store) ListKeys(ctx context.Context, agent string) ([]*AgentKey, error) {
	q := "SELECT " + keyCols + " FROM agent_keys"
	var args []any
	if agent != "" {
		q += " WHERE agent = ?"
		args = append(args, agent)
	}
	q += " ORDER BY created_at DESC, fingerprint"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AgentKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
