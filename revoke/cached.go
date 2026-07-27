package revoke

import (
	"sort"
	"sync"
	"time"
)

// Source is the shared, durable backing store for the kill-switch — Postgres or Redis in
// production (ADR-004). All gateway replicas and the admin/control plane share one Source;
// that shared state is how a revocation reaches every replica (NFR-2).
type Source interface {
	Revoke(id string) error
	Restore(id string) error
	List() ([]string, error)
}

// MemSource is an in-memory Source for development, tests, and single-process deployments.
type MemSource struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// NewMemSource returns an empty in-memory Source.
func NewMemSource() *MemSource { return &MemSource{set: map[string]struct{}{}} }

// Revoke implements Source.
func (s *MemSource) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.set[id] = struct{}{}
	return nil
}

// Restore implements Source.
func (s *MemSource) Restore(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.set, id)
	return nil
}

// List implements Source.
func (s *MemSource) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.set))
	for id := range s.set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// CachedStore serves Revoked() from a local snapshot of a shared Source, refreshed
// periodically. The hot path is a local map lookup — never a network call that could
// soft-fail open (FR-20, NFR-1). Writes go through to the Source and update the local
// snapshot at once; other replicas converge on their next refresh, so cross-replica
// propagation is bounded by the refresh interval (keep it well under the revocation target,
// NFR-4). Safe for concurrent use; satisfies Checker (and principal.StatusChecker).
type CachedStore struct {
	src      Source
	mu       sync.RWMutex
	snapshot map[string]struct{}
	stop     chan struct{}
	stopped  bool
}

// NewCachedStore loads the initial snapshot from src and, if refresh > 0, starts a
// background goroutine that re-reads it every refresh interval (stop it with Close).
func NewCachedStore(src Source, refresh time.Duration) (*CachedStore, error) {
	c := &CachedStore{src: src, snapshot: map[string]struct{}{}, stop: make(chan struct{})}
	if err := c.Refresh(); err != nil {
		return nil, err
	}
	if refresh > 0 {
		go c.loop(refresh)
	}
	return c, nil
}

func (c *CachedStore) loop(d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			_ = c.Refresh()
		}
	}
}

// Refresh reloads the local snapshot from the Source.
func (c *CachedStore) Refresh() error {
	ids, err := c.src.List()
	if err != nil {
		return err
	}
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	c.mu.Lock()
	c.snapshot = m
	c.mu.Unlock()
	return nil
}

// Revoked reports whether id is revoked, from the local snapshot (hot path, no network).
func (c *CachedStore) Revoked(id string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.snapshot[id]
	return ok
}

// Revoke writes through to the Source, then updates the local snapshot. On a Source error
// the local snapshot is left unchanged (all-or-nothing) so it never diverges from durable
// state.
func (c *CachedStore) Revoke(id string) error {
	if err := c.src.Revoke(id); err != nil {
		return err
	}
	c.mu.Lock()
	c.snapshot[id] = struct{}{}
	c.mu.Unlock()
	return nil
}

// Restore writes through to the Source, then updates the local snapshot.
func (c *CachedStore) Restore(id string) error {
	if err := c.src.Restore(id); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.snapshot, id)
	c.mu.Unlock()
	return nil
}

// Close stops the background refresh goroutine.
func (c *CachedStore) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		close(c.stop)
		c.stopped = true
	}
}
