package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Settings is the single row of managed settings. Doc is the JSON settings
// document; the SMTP password is kept apart so the document can be shown
// and compared. SMTPPassword is sealed under the KEK when PasswordSealed,
// raw otherwise, and empty when there is none.
type Settings struct {
	Doc            []byte
	SMTPPassword   []byte
	PasswordSealed bool
	UpdatedAt      time.Time
}

// GetSettings returns the stored settings, or ErrNotFound before the first
// boot has seeded them.
func (s *Store) GetSettings(ctx context.Context) (*Settings, error) {
	var r Settings
	var sealed int
	var updated int64
	err := s.db.QueryRowContext(ctx,
		"SELECT doc, smtp_password, smtp_password_sealed, updated_at FROM settings WHERE id = 1").
		Scan(&r.Doc, &r.SMTPPassword, &sealed, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.PasswordSealed = sealed == 1
	r.UpdatedAt = time.Unix(updated, 0).UTC()
	return &r, nil
}

const upsertSettings = `INSERT INTO settings (id, doc, smtp_password, smtp_password_sealed, updated_at) VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET doc = excluded.doc, smtp_password = excluded.smtp_password,
  smtp_password_sealed = excluded.smtp_password_sealed, updated_at = excluded.updated_at`

func writeSettings(ctx context.Context, ex interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, r *Settings) error {
	r.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	var pw any
	if len(r.SMTPPassword) > 0 {
		pw = r.SMTPPassword
	}
	_, err := ex.ExecContext(ctx, upsertSettings, string(r.Doc), pw, b2i(r.PasswordSealed), unix(r.UpdatedAt))
	return err
}

// SeedSettings stores r only if no settings are stored yet, atomically. It
// reports whether it did.
func (s *Store) SeedSettings(ctx context.Context, r *Settings) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM settings").Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if err := writeSettings(ctx, tx, r); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// SaveSettings stores r, replacing any stored settings, and sets UpdatedAt.
func (s *Store) SaveSettings(ctx context.Context, r *Settings) error {
	return writeSettings(ctx, s.db, r)
}
