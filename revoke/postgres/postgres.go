// Package postgres provides a durable, shared revoke.Source backed by a SQL database
// (Postgres). All gateway replicas and the admin/control plane point their kill-switch at
// one such Source; the shared table is how a revocation written by one process reaches
// every replica (ADR-004, NFR-2). The gateway wraps it in a revoke.CachedStore so the hot
// path stays a local map lookup and never makes a database call that could soft-fail open
// (FR-20, NFR-1); this Source is consulted only on writes and on the cache refresh.
//
// It is written against the standard database/sql interface, so it works with any driver.
// The gateway and admin commands register the pgx driver (github.com/jackc/pgx/v5/stdlib)
// and open with sql.Open("pgx", dsn).
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"time"

	"github.com/getsanad/sanad/revoke"
)

// Store is a revoke.Source backed by a SQL table.
type Store struct {
	db      *sql.DB
	table   string
	timeout time.Duration
}

// Compile-time check: Store is a durable kill-switch Source.
var _ revoke.Source = (*Store)(nil)

// safeIdent guards the table name, which is interpolated into SQL (database/sql cannot
// parameterize identifiers). It comes from operator config, never from request data, but we
// validate it anyway.
var safeIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Option configures a Store.
type Option func(*Store)

// WithTable overrides the table name (default "passport_revocations").
func WithTable(name string) Option { return func(s *Store) { s.table = name } }

// WithTimeout sets the per-query timeout (default 5s).
func WithTimeout(d time.Duration) Option { return func(s *Store) { s.timeout = d } }

// New returns a Store over db. It does not create the table; call Migrate once at startup.
func New(db *sql.DB, opts ...Option) (*Store, error) {
	s := &Store{db: db, table: "passport_revocations", timeout: 5 * time.Second}
	for _, opt := range opts {
		opt(s)
	}
	if !safeIdent.MatchString(s.table) {
		return nil, fmt.Errorf("postgres: unsafe table name %q", s.table)
	}
	return s, nil
}

// migrateLockKey is a fixed advisory-lock key so concurrent migrations serialize. Postgres's
// CREATE TABLE IF NOT EXISTS is not race-free (two processes racing can collide on internal
// type creation, SQLSTATE 23505); the gateway and admin both migrate at startup, so we take
// a session-level advisory lock first. The value is arbitrary but must be stable.
const migrateLockKey = 0x50415353 // "PASS"

// Migrate creates the revocations table if it does not already exist. Safe to call on every
// startup and from multiple processes concurrently (serialized via an advisory lock).
func (s *Store) Migrate(ctx context.Context) error {
	// A single connection so the lock and the DDL run on the same session, then release.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		return fmt.Errorf("postgres: migrate lock: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, migrateLockKey) }()

	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id         TEXT PRIMARY KEY,
		revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`, s.table)
	if _, err := conn.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("postgres: migrate: %w", err)
	}
	return nil
}

func (s *Store) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// Revoke adds ids to the deny list, atomically: a cascade (a principal plus every agent
// under it, FR-19) is one transaction, so a failure part-way through cannot leave some
// descendants revoked and others still operating. Idempotent: revoking an already-revoked id
// is a no-op.
func (s *Store) Revoke(ids ...string) error {
	return s.write("revoke", `INSERT INTO %s (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, ids)
}

// Restore removes ids from the deny list, atomically and idempotently.
func (s *Store) Restore(ids ...string) error {
	return s.write("restore", `DELETE FROM %s WHERE id = $1`, ids)
}

// write applies a single-id statement to every id, all-or-nothing. A batch of one is a plain
// Exec; anything larger runs inside a transaction. It repeats a parameterized statement per
// id rather than binding an array because array parameters are driver-specific and this
// package targets plain database/sql (see the package doc) — and a batch here is a principal
// and its agents, tens of rows at most, so the extra round-trips do not matter.
func (s *Store) write(op, query string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	ctx, cancel := s.ctx()
	defer cancel()
	q := fmt.Sprintf(query, s.table)

	if len(ids) == 1 {
		if _, err := s.db.ExecContext(ctx, q, ids[0]); err != nil {
			return fmt.Errorf("postgres: %s %q: %w", op, ids[0], err)
		}
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: %s: begin: %w", op, err)
	}
	// Rolls the batch back on any early return; a no-op once Commit has succeeded.
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("postgres: %s %q (batch of %d rolled back): %w", op, id, len(ids), err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("postgres: %s: commit batch of %d: %w", op, len(ids), err)
	}
	return nil
}

// List returns the revoked ids in sorted order.
func (s *Store) List() ([]string, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	q := fmt.Sprintf(`SELECT id FROM %s ORDER BY id`, s.table)
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("postgres: list: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("postgres: list scan: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list rows: %w", err)
	}
	return out, nil
}
