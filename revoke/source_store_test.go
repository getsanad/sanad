package revoke

import (
	"errors"
	"testing"
)

// failSource is a Source whose writes fail, to prove SyncStore surfaces errors.
type failSource struct{ err error }

func (f failSource) Revoke(string) error   { return f.err }
func (f failSource) Restore(string) error  { return f.err }
func (f failSource) List() ([]string, error) { return nil, f.err }

func TestSyncStoreOverMemSource(t *testing.T) {
	src := NewMemSource()
	s := NewSyncStore(src, func(op, id string, err error) {
		t.Fatalf("unexpected error on %s %q: %v", op, id, err)
	})

	if s.Revoked("p1") {
		t.Fatal("nothing revoked yet")
	}
	s.Revoke("p1")
	if !s.Revoked("p1") {
		t.Fatal("p1 should be revoked")
	}
	if got := s.List(); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("List() = %v; want [p1]", got)
	}
	s.Restore("p1")
	if s.Revoked("p1") {
		t.Fatal("p1 should be restored")
	}

	// The write reached the underlying Source (shared with the gateway's CachedStore).
	if ids, _ := src.List(); len(ids) != 0 {
		t.Fatalf("source should be empty after restore, got %v", ids)
	}
}

func TestSyncStoreReportsErrors(t *testing.T) {
	want := errors.New("db down")
	var gotOps []string
	s := NewSyncStore(failSource{err: want}, func(op, _ string, err error) {
		if !errors.Is(err, want) {
			t.Fatalf("op %s: got %v, want %v", op, err, want)
		}
		gotOps = append(gotOps, op)
	})

	s.Revoke("x")
	s.Restore("x")
	if got := s.List(); got != nil {
		t.Fatalf("List() on error should be nil, got %v", got)
	}
	if s.Revoked("x") {
		t.Fatal("Revoked() on a failing source must not invent a revocation")
	}

	// revoke, restore, and the two List() calls (List + inside Revoked) all report.
	if len(gotOps) < 3 {
		t.Fatalf("expected error reports for revoke/restore/list, got %v", gotOps)
	}
}
