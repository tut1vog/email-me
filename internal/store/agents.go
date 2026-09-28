package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/tut1vog/email-me/internal/ids"
	"github.com/tut1vog/email-me/internal/policy"
)

type Agent struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	Policy      policy.Policy
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const agentCols = "id, name, description, enabled, policy, created_at, updated_at"

func scanAgent(row interface{ Scan(...any) error }) (*Agent, error) {
	var a Agent
	var enabled int
	var pol string
	var created, updated int64
	if err := row.Scan(&a.ID, &a.Name, &a.Description, &enabled, &pol, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	a.Enabled = enabled == 1
	if err := json.Unmarshal([]byte(pol), &a.Policy); err != nil {
		return nil, err
	}
	a.CreatedAt = time.Unix(created, 0).UTC()
	a.UpdatedAt = time.Unix(updated, 0).UTC()
	return &a, nil
}

// CreateAgent inserts an enabled agent.
func (s *Store) CreateAgent(ctx context.Context, name, description string, p policy.Policy) (*Agent, error) {
	pol, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	a := &Agent{ID: ids.New("ag"), Name: name, Description: description, Enabled: true, Policy: p, CreatedAt: now, UpdatedAt: now}
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO agents ("+agentCols+") VALUES (?, ?, ?, 1, ?, ?, ?)",
		a.ID, a.Name, a.Description, string(pol), unix(now), unix(now))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) GetAgent(ctx context.Context, id string) (*Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, "SELECT "+agentCols+" FROM agents WHERE id = ?", id))
}

func (s *Store) ListAgents(ctx context.Context) ([]*Agent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+agentCols+" FROM agents ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAgent changes the description and enabled flag. Names are immutable
// because they appear in signing-key user IDs and inbox filter headers.
func (s *Store) UpdateAgent(ctx context.Context, id, description string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	return s.execOne(ctx, "UPDATE agents SET description = ?, enabled = ?, updated_at = ? WHERE id = ?",
		description, en, unix(time.Now()), id)
}

func (s *Store) UpdateAgentPolicy(ctx context.Context, id string, p policy.Policy) error {
	pol, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.execOne(ctx, "UPDATE agents SET policy = ?, updated_at = ? WHERE id = ?", string(pol), unix(time.Now()), id)
}

// DeleteAgent removes the agent, its tokens and its keys.
func (s *Store) DeleteAgent(ctx context.Context, id string) error {
	return s.execOne(ctx, "DELETE FROM agents WHERE id = ?", id)
}

func (s *Store) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
