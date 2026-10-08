package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Recipient is an alias agents address and the real address behind it.
// PublicKey is the ASCII-armored PGP public key, or empty.
type Recipient struct {
	Alias             string
	Address           string
	Description       string
	PublicKey         string
	RequireEncryption bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

const recipientCols = "alias, address, description, pgp_public_key, require_encryption, created_at, updated_at"

func scanRecipient(row interface{ Scan(...any) error }) (*Recipient, error) {
	var r Recipient
	var key sql.NullString
	var reqEnc int
	var created, updated int64
	if err := row.Scan(&r.Alias, &r.Address, &r.Description, &key, &reqEnc, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.PublicKey = key.String
	r.RequireEncryption = reqEnc == 1
	r.CreatedAt = time.Unix(created, 0).UTC()
	r.UpdatedAt = time.Unix(updated, 0).UTC()
	return &r, nil
}

func insertRecipient(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, r *Recipient) error {
	now := time.Now().UTC().Truncate(time.Second)
	r.CreatedAt, r.UpdatedAt = now, now
	_, err := ex.ExecContext(ctx,
		"INSERT INTO recipients ("+recipientCols+") VALUES (?, ?, ?, ?, ?, ?, ?)",
		r.Alias, r.Address, r.Description, nullStr(r.PublicKey), b2i(r.RequireEncryption), unix(now), unix(now))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// CreateRecipient inserts a recipient; fails with ErrConflict if the alias exists.
func (s *Store) CreateRecipient(ctx context.Context, r *Recipient) error {
	return insertRecipient(ctx, s.db, r)
}

// SeedRecipients inserts rs only if the table is empty, atomically. It
// reports whether anything was inserted.
func (s *Store) SeedRecipients(ctx context.Context, rs []*Recipient) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM recipients").Scan(&n); err != nil {
		return false, err
	}
	if n > 0 || len(rs) == 0 {
		return false, nil
	}
	for _, r := range rs {
		if err := insertRecipient(ctx, tx, r); err != nil {
			return false, err
		}
	}
	return true, tx.Commit()
}

func (s *Store) GetRecipient(ctx context.Context, alias string) (*Recipient, error) {
	return scanRecipient(s.db.QueryRowContext(ctx, "SELECT "+recipientCols+" FROM recipients WHERE alias = ?", alias))
}

func (s *Store) ListRecipients(ctx context.Context) ([]*Recipient, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+recipientCols+" FROM recipients ORDER BY alias")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Recipient
	for rows.Next() {
		r, err := scanRecipient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRecipient changes everything but the alias. Aliases are immutable
// because agent policies and audit rows reference them by name.
func (s *Store) UpdateRecipient(ctx context.Context, r *Recipient) error {
	return s.execOne(ctx,
		"UPDATE recipients SET address = ?, description = ?, pgp_public_key = ?, require_encryption = ?, updated_at = ? WHERE alias = ?",
		r.Address, r.Description, nullStr(r.PublicKey), b2i(r.RequireEncryption), unix(time.Now()), r.Alias)
}

// DeleteRecipient removes a recipient. Policies naming it are left as they
// are; the alias is then ignored wherever it appears.
func (s *Store) DeleteRecipient(ctx context.Context, alias string) error {
	return s.execOne(ctx, "DELETE FROM recipients WHERE alias = ?", alias)
}

func (s *Store) CountRecipients(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM recipients").Scan(&n)
	return n, err
}
