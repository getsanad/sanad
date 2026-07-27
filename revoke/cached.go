package revoke

import (
	"errors"
	"fmt"
	"log"
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

// DefaultMaxStaleness bounds how long a CachedStore keeps answering from a snapshot it has
// not managed to re-read from the Source. It is deliberately the NFR-4 number itself
// (effective revocation ≤ 60 seconds end-to-end): a snapshot older than that is precisely
// the case where this replica can no longer honour the target, so rather than serve an
// answer of unbounded age it stops answering (CheckFresh). At the gateway's default 2s
// refresh interval that tolerates ~30 consecutive failed refreshes, which rides out a
// Postgres failover or a network blip without a false denial, and keeps the operator-facing
// promise crisp: either a revocation took effect within 60s, or the gateway is refusing
// traffic and saying so.
const DefaultMaxStaleness = 60 * time.Second

// failureLogInterval rate-limits the "still failing" line so a sustained Source outage
// leaves a heartbeat in the log rather than one line per refresh interval.
const failureLogInterval = 60 * time.Second

// ErrStale is wrapped by CheckFresh once the local snapshot is older than MaxStaleness.
var ErrStale = errors.New("kill-switch snapshot is stale")

// CachedStore serves Revoked() from a local snapshot of a shared Source, refreshed
// periodically. The hot path is a local map lookup — never a network call that could
// soft-fail open (FR-20, NFR-1). Writes go through to the Source and update the local
// snapshot at once; other replicas converge on their next refresh, so cross-replica
// propagation is bounded by the refresh interval (keep it well under the revocation target,
// NFR-4). Safe for concurrent use; satisfies Checker, FreshnessChecker (and
// principal.StatusChecker).
//
// Background refresh failures are not fatal on their own — the point of the local snapshot
// is to keep serving through a brief Source outage — but they are bounded: the time of the
// last successful refresh is recorded, failures are logged, and past MaxStaleness the store
// reports itself stale so callers fail closed instead of serving a snapshot of unbounded
// age (see CheckFresh and Stage).
type CachedStore struct {
	// Immutable after construction, so they need no lock.
	src      Source
	maxStale time.Duration
	now      func() time.Time
	logf     func(format string, args ...any)

	mu          sync.RWMutex
	snapshot    map[string]struct{}
	lastOK      time.Time // time of the last successful refresh
	fails       int       // consecutive failed refreshes
	staleLogged bool      // the crossing-the-bound line has already been logged
	lastLog     time.Time // last sustained-failure heartbeat

	stop    chan struct{}
	stopped bool
}

// Option configures a CachedStore.
type Option func(*CachedStore)

// WithMaxStaleness sets how old the local snapshot may get before the store reports itself
// stale and revocation checks start denying (CheckFresh). A value ≤ 0 disables the bound,
// which is only safe for a Source that cannot go stale (an in-process MemSource with no
// background refresh).
func WithMaxStaleness(d time.Duration) Option {
	return func(c *CachedStore) { c.maxStale = d }
}

// WithLogger replaces the destination for refresh-failure lines (default log.Printf).
func WithLogger(f func(format string, args ...any)) Option {
	return func(c *CachedStore) {
		if f != nil {
			c.logf = f
		}
	}
}

// WithClock replaces the time source used for staleness accounting. Tests inject a
// manually advanced clock so they can cross the bound without sleeping.
func WithClock(now func() time.Time) Option {
	return func(c *CachedStore) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCachedStore loads the initial snapshot from src and, if refresh > 0, starts a
// background goroutine that re-reads it every refresh interval (stop it with Close).
// Startup is fail-closed: an unreadable Source is an error, not an empty deny list.
//
// With refresh > 0 the snapshot is only as good as the last successful re-read, so
// DefaultMaxStaleness applies. With refresh ≤ 0 there is no background re-read to fail —
// the caller drives Refresh itself, or the Source is the in-process MemSource this store
// writes through to — so no bound is applied unless WithMaxStaleness asks for one.
func NewCachedStore(src Source, refresh time.Duration, opts ...Option) (*CachedStore, error) {
	c := &CachedStore{
		src:      src,
		snapshot: map[string]struct{}{},
		now:      time.Now,
		logf:     log.Printf,
		stop:     make(chan struct{}),
	}
	if refresh > 0 {
		c.maxStale = DefaultMaxStaleness
	}
	for _, opt := range opts {
		opt(c)
	}
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
			// Refresh records and logs its own failures; what protects the gateway is the
			// staleness bound they feed (CheckFresh), not this return value. Swallowing the
			// error here silently — with no bound behind it — is how a kill-switch turns into
			// a permanently frozen snapshot.
			_ = c.Refresh()
		}
	}
}

// Refresh reloads the local snapshot from the Source. On success it stamps the
// last-successful-refresh time, which is what bounds staleness (CheckFresh, Staleness); on
// failure it leaves the snapshot in place and records the failure.
func (c *CachedStore) Refresh() error {
	ids, err := c.src.List()
	if err != nil {
		c.refreshFailed(err)
		return err
	}
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	now := c.now()

	c.mu.Lock()
	c.snapshot = m
	fails, wasStale := c.fails, c.staleLogged
	age := now.Sub(c.lastOK)
	c.lastOK, c.fails, c.staleLogged = now, 0, false
	c.mu.Unlock()

	// Recovery is a state transition worth exactly one line: it closes the failure window
	// and tells the operator when denials (if any) stopped.
	if fails > 0 {
		denials := ""
		if wasStale {
			denials = "; revocation checks are serving again"
		}
		c.logf("revoke: kill-switch snapshot refreshed after %d failed attempts (%s stale)%s",
			fails, age.Round(time.Second), denials)
	}
	return nil
}

// refreshFailed records a failed refresh. It logs on state transitions only — the first
// failure of an outage and the moment the staleness bound is crossed — plus a heartbeat at
// most every failureLogInterval, so a Source that is down for hours does not drown the log
// while still remaining visible in it.
func (c *CachedStore) refreshFailed(err error) {
	now := c.now()

	c.mu.Lock()
	c.fails++
	fails, age := c.fails, now.Sub(c.lastOK)
	first := fails == 1
	crossed := c.maxStale > 0 && age > c.maxStale && !c.staleLogged
	if crossed {
		c.staleLogged = true
	}
	heartbeat := !first && !crossed && now.Sub(c.lastLog) >= failureLogInterval
	if first || crossed || heartbeat {
		c.lastLog = now
	}
	c.mu.Unlock()

	bound := "no bound configured"
	if c.maxStale > 0 {
		bound = c.maxStale.String()
	}
	switch {
	case crossed:
		c.logf("revoke: kill-switch snapshot is STALE after %d failed refreshes: last good refresh %s ago (max %s) — revocation checks now DENY every request until the source recovers (NFR-4): %v",
			fails, age.Round(time.Second), bound, err)
	case first:
		c.logf("revoke: kill-switch refresh failed, still serving a snapshot from %s ago (denying past %s): %v",
			age.Round(time.Second), bound, err)
	case heartbeat:
		c.logf("revoke: kill-switch refresh still failing (%d consecutive, last good refresh %s ago): %v",
			fails, age.Round(time.Second), err)
	}
}

// CheckFresh reports whether the local snapshot is recent enough to be trusted, returning
// an error wrapping ErrStale once the last successful refresh is older than MaxStaleness.
// It implements FreshnessChecker, so Stage consults it on every request and denies outright
// when it fails: past the bound "id is not on the deny list" no longer means "id is not
// revoked", it means "unknown", and a kill-switch that cannot see its deny list must stop
// the traffic it guards rather than wave it through (FR-20, NFR-4).
func (c *CachedStore) CheckFresh() error {
	if c.maxStale <= 0 {
		return nil
	}
	if age := c.Staleness(); age > c.maxStale {
		return fmt.Errorf("%w: last successful refresh %s ago (max %s)",
			ErrStale, age.Round(time.Second), c.maxStale)
	}
	return nil
}

// LastRefresh returns the time of the last successful refresh from the Source.
// NewCachedStore only returns a store whose first refresh succeeded, so this is never zero.
func (c *CachedStore) LastRefresh() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastOK
}

// Staleness returns how long ago the snapshot was last successfully refreshed. It is the
// observable form of the revocation window (NFR-4): export it as a gauge and check it on
// /readyz so a Source outage is visible before it becomes a denial.
func (c *CachedStore) Staleness() time.Duration { return c.now().Sub(c.LastRefresh()) }

// MaxStaleness returns the configured staleness bound (0 = unbounded).
func (c *CachedStore) MaxStaleness() time.Duration { return c.maxStale }

// Revoked reports whether id is revoked, from the local snapshot (hot path, no network).
// It answers from whatever the snapshot holds regardless of its age — the freshness of that
// answer is a separate question, asked by CheckFresh, because a bool cannot express
// "unknown" without lying about some id.
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
