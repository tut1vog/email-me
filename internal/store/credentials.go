package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Keyring is the data key (DEK) that seals every stored credential,
// wrapped by the key-encryption key.
type Keyring struct {
	DEKWrapped []byte
	CreatedAt  time.Time
	RotatedAt  *time.Time
}

// GetKeyring returns the keyring, or ErrNotFound before the first start
// with a KEK.
func (s *Store) GetKeyring(ctx context.Context) (*Keyring, error) {
	var k Keyring
	var created int64
	var rotated sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT dek_wrapped, created_at, rotated_at FROM keyring WHERE id = 1").
		Scan(&k.DEKWrapped, &created, &rotated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0).UTC()
	k.RotatedAt = fromNullUnix(rotated)
	return &k, nil
}

// CreateKeyring stores a new keyring; ErrConflict if there is one.
func (s *Store) CreateKeyring(ctx context.Context, wrapped []byte) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO keyring (id, dek_wrapped, created_at) VALUES (1, ?, ?)", wrapped, unix(time.Now()))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// RewrapKeyring replaces the wrapped data key after a KEK rotation.
func (s *Store) RewrapKeyring(ctx context.Context, wrapped []byte) error {
	res, err := s.db.ExecContext(ctx, "UPDATE keyring SET dek_wrapped = ?, rotated_at = ? WHERE id = 1", wrapped, unix(time.Now()))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Discarded counts what ResetKeyring removed.
type Discarded struct {
	SMTPPassword bool
	CertifyKey   bool
	AgentKeys    int // active agent keys retired
}

// ResetKeyring deletes the keyring and everything sealed under it, in one
// transaction: the sealed SMTP password, the certification key, and the
// private material of every active agent key, which is retired (its public
// key and revocation certificates stay).
func (s *Store) ResetKeyring(ctx context.Context) (Discarded, error) {
	var d Discarded
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM keyring"); err != nil {
		return d, err
	}
	res, err := tx.ExecContext(ctx, "DELETE FROM credentials WHERE smtp_password_sealed = 1")
	if err != nil {
		return d, err
	}
	n, _ := res.RowsAffected()
	d.SMTPPassword = n > 0
	if res, err = tx.ExecContext(ctx, "DELETE FROM certify_key"); err != nil {
		return d, err
	}
	n, _ = res.RowsAffected()
	d.CertifyKey = n > 0
	if res, err = tx.ExecContext(ctx, "UPDATE agent_keys SET retired_at = ?, private_key_enc = x'' WHERE retired_at IS NULL", unix(time.Now())); err != nil {
		return d, err
	}
	n, _ = res.RowsAffected()
	d.AgentKeys = int(n)
	return d, tx.Commit()
}

// CertifyKey is the master key that certifies new agent keys.
// PrivateKeyEnc is sealed under the data key.
type CertifyKey struct {
	Fingerprint   string
	PublicKey     string
	PrivateKeyEnc []byte
	CreatedAt     time.Time
}

// GetCertifyKey returns the certification key, or ErrNotFound if none is set.
func (s *Store) GetCertifyKey(ctx context.Context) (*CertifyKey, error) {
	var k CertifyKey
	var created int64
	err := s.db.QueryRowContext(ctx, "SELECT fingerprint, public_key, private_key_enc, created_at FROM certify_key WHERE id = 1").
		Scan(&k.Fingerprint, &k.PublicKey, &k.PrivateKeyEnc, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0).UTC()
	return &k, nil
}

// SetCertifyKey stores k as the certification key, replacing any.
func (s *Store) SetCertifyKey(ctx context.Context, k *CertifyKey) error {
	k.CreatedAt = time.Now().UTC().Truncate(time.Second)
	_, err := s.db.ExecContext(ctx, `INSERT INTO certify_key (id, fingerprint, public_key, private_key_enc, created_at) VALUES (1, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET fingerprint = excluded.fingerprint, public_key = excluded.public_key,
  private_key_enc = excluded.private_key_enc, created_at = excluded.created_at`,
		k.Fingerprint, k.PublicKey, k.PrivateKeyEnc, unix(k.CreatedAt))
	return err
}

// DeleteCertifyKey removes the certification key, if any.
func (s *Store) DeleteCertifyKey(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM certify_key")
	return err
}
