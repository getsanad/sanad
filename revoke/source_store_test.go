package revoke

import (
	"errors"
	"testing"
)

// failSource is a Source whose writes fail, to prove SyncStore surfaces errors.
type failSource struct{ err error }

func (f failSource) Revoke(...string) error  { return f.err }
func (f failSource) Restore(...string) error { return f.err }
func (f failSource) List() ([]string, error) { return nil, f.err }

func TestSyncStoreOverMemSource(t *testing.T) {
	src := NewMemSource()
	s := NewSyncStore(src, func(op, id string, err error) {
		t.Fatalf("unexpected error on %s %q: %v", op, id, err)
	})

	if s.Revoked("p1") {
		t.Fatal("nothing revoked yet")
	}
	if err := s.Revoke("p1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !s.Revoked("p1") {
		t.Fatal("p1 should be revoked")
	}
	if got := s.List(); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("List() = %v; want [p1]", got)
	}
	if err := s.Restore("p1"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if s.Revoked("p1") {
		t.Fatal("p1 should be restored")
	}

	// The write reached the underlying Source (shared with the gateway's CachedStore).
	if ids, _ := src.List(); len(ids) != 0 {
		t.Fatalf("source should be empty after restore, got %v", ids)
	}
}

// recordingSource counts the write calls it receives, so a test can prove a whole cascade
// reaches the Source as ONE call — that single call is where the Source's atomicity applies.
type recordingSource struct {
	*MemSource
	calls [][]string
}

func (r *recordingSource) Revoke(ids ...string) error {
	r.calls = append(r.calls, ids)
	return r.MemSource.Revoke(ids...)
}

func TestSyncStorePassesBatchThroughInOneCall(t *testing.T) {
	src := &recordingSource{MemSource: NewMemSource()}
	s := NewSyncStore(src, nil)

	if err := s.Revoke("p1", "a1", "a2"); err != nil {
		t.Fatalf("batch revoke: %v", err)
	}
	if len(src.calls) != 1 || len(src.calls[0]) != 3 {
		t.Fatalf("cascade reached the source as %v; want a single 3-id call", src.calls)
	}
	for _, id := range []string{"p1", "a1", "a2"} {
		if !s.Revoked(id) {
			t.Fatalf("%s should be revoked", id)
		}
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

	// The failure is returned to the caller, not just handed to the alerting hook: the
	// admin API turns it into a 5xx instead of telling the operator the id was revoked.
	if err := s.Revoke("x"); !errors.Is(err, want) {
		t.Fatalf("Revoke() = %v; want the source error %v returned to the caller", err, want)
	}
	if err := s.Restore("x"); !errors.Is(err, want) {
		t.Fatalf("Restore() = %v; want the source error %v returned to the caller", err, want)
	}
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
