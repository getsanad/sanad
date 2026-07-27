package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/getsanad/sanad/revoke"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
)

// TestStore is an integration test that runs only when PASSPORT_TEST_POSTGRES_DSN points at
// a real Postgres (e.g. the docker-compose db). Without it the test is skipped so `go test
// ./...` stays green in environments with no database.
//
//	PASSPORT_TEST_POSTGRES_DSN=postgres://passport:passport@localhost:5432/passport?sslmode=disable go test ./revoke/postgres/
func TestStore(t *testing.T) {
	dsn := os.Getenv("PASSPORT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set PASSPORT_TEST_POSTGRES_DSN to run the Postgres integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Use a throwaway table so we never clobber real data.
	s, err := New(db, WithTable("passport_revocations_test"), WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS passport_revocations_test"); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = db.ExecContext(c, "DROP TABLE IF EXISTS passport_revocations_test")
	})

	// Empty to start.
	if ids, err := s.List(); err != nil || len(ids) != 0 {
		t.Fatalf("List() = %v, %v; want empty", ids, err)
	}

	// Revoke is idempotent.
	if err := s.Revoke("agent-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke("agent-1"); err != nil {
		t.Fatalf("second revoke should be a no-op: %v", err)
	}
	if err := s.Revoke("principal-9"); err != nil {
		t.Fatal(err)
	}
	ids, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "agent-1" || ids[1] != "principal-9" {
		t.Fatalf("List() = %v; want [agent-1 principal-9] (sorted)", ids)
	}

	// A cascade is written as one batch, in a transaction (all-or-nothing).
	if err := s.Revoke("principal-2", "agent-20", "agent-21"); err != nil {
		t.Fatalf("batch revoke: %v", err)
	}
	if ids, err := s.List(); err != nil || len(ids) != 5 {
		t.Fatalf("List() = %v, %v; want 5 ids after the batch", ids, err)
	}
	if err := s.Restore("principal-2", "agent-20", "agent-21"); err != nil {
		t.Fatalf("batch restore: %v", err)
	}
	if ids, err := s.List(); err != nil || len(ids) != 2 {
		t.Fatalf("List() = %v, %v; want the batch gone again", ids, err)
	}

	// A CachedStore over this Source resolves the hot path locally and refreshes.
	cs, err := revoke.NewCachedStore(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !cs.Revoked("agent-1") {
		t.Fatal("cached store should see agent-1 as revoked")
	}
	if cs.Revoked("nobody") {
		t.Fatal("unrevoked id must not read as revoked")
	}

	// Restore, then confirm a refresh clears it (cross-process propagation).
	if err := s.Restore("agent-1"); err != nil {
		t.Fatal(err)
	}
	if err := cs.Refresh(); err != nil {
		t.Fatal(err)
	}
	if cs.Revoked("agent-1") {
		t.Fatal("agent-1 should be restored after refresh")
	}
}
