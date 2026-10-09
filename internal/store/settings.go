package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SMTPPassword is the upstream SMTP password, the one managed setting that
// is a secret and so is kept here rather than in config.yaml. Value is
// sealed under the keyring's data key when Sealed, raw otherwise.
type SMTPPassword struct {
	Value     []byte
	Sealed    bool
	UpdatedAt time.Time
}

// GetSMTPPassword returns the stored password, or ErrNotFound if none is.
func (s *Store) GetSMTPPassword(ctx context.Context) (*SMTPPassword, error) {
	var p SMTPPassword
	var sealed int
	var updated int64
	err := s.db.QueryRowContext(ctx,
		"SELECT smtp_password, smtp_password_sealed, updated_at FROM credentials WHERE id = 1 AND smtp_password IS NOT NULL").
		Scan(&p.Value, &sealed, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Sealed = sealed == 1
	p.UpdatedAt = time.Unix(updated, 0).UTC()
	return &p, nil
}

// SetSMTPPassword stores p, replacing any stored password; nil removes it.
func (s *Store) SetSMTPPassword(ctx context.Context, p *SMTPPassword) error {
	if p == nil || len(p.Value) == 0 {
		_, err := s.db.ExecContext(ctx, "DELETE FROM credentials")
		return err
	}
	p.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	_, err := s.db.ExecContext(ctx, `INSERT INTO credentials (id, smtp_password, smtp_password_sealed, updated_at) VALUES (1, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET smtp_password = excluded.smtp_password,
  smtp_password_sealed = excluded.smtp_password_sealed, updated_at = excluded.updated_at`,
		p.Value, b2i(p.Sealed), unix(p.UpdatedAt))
	return err
}
