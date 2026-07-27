package revoke

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

var _ Checker = (*CachedStore)(nil)
var _ Checker = (*MemStore)(nil)
var _ FreshnessChecker = (*CachedStore)(nil)

func TestCachedStoreReadWrite(t *testing.T) {
	c, err := NewCachedStore(NewMemSource(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revoked("x") {
		t.Fatal("nothing revoked yet")
	}
	if err := c.Revoke("x"); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked("x") {
		t.Fatal("x should be revoked locally right after write-through")
	}
	if err := c.Restore("x"); err != nil {
		t.Fatal(err)
	}
	if c.Revoked("x") {
		t.Fatal("x should be restored")
	}
}

// TestCachedStoreCrossReplica simulates two gateway replicas over one shared Source: a
// revocation written by one replica reaches the other after its next refresh.
func TestCachedStoreCrossReplica(t *testing.T) {
	src := NewMemSource()
	replicaA, _ := NewCachedStore(src, 0)
	replicaB, _ := NewCachedStore(src, 0)

	if err := replicaA.Revoke("agent-1"); err != nil {
		t.Fatal(err)
	}
	// B hasn't refreshed yet, so it doesn't see it (bounded staleness).
	if replicaB.Revoked("agent-1") {
		t.Fatal("replica B should not see the revocation before refreshing")
	}
	if err := replicaB.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !replicaB.Revoked("agent-1") {
		t.Fatal("replica B must see the revocation after refreshing from the shared source")
	}
}

func TestCachedStoreBackgroundRefresh(t *testing.T) {
	src := NewMemSource()
	c, err := NewCachedStore(src, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write directly to the shared source (as another replica / the admin plane would).
	_ = src.Revoke("agent-9")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Revoked("agent-9") {
			return // background refresh picked it up
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background refresh did not pick up the revocation")
}

// --- staleness: bounding how long a frozen snapshot may be served (NFR-4) ---

// testClock is a manually advanced clock, so the staleness tests cross a 60s bound in
// microseconds and stay deterministic (no real sleeps, no flakes).
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// outageSource wraps a Source and fails List() while it is "down", standing in for Postgres
// becoming unreachable under a running gateway. Writes still reach the wrapped Source, so a
// revocation made during the outage is there to be found on recovery.
type outageSource struct {
	Source
	mu   sync.Mutex
	down error
}

func (s *outageSource) setDown(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = err
}

func (s *outageSource) List() ([]string, error) {
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down != nil {
		return nil, down
	}
	return s.Source.List()
}

// logCapture collects the store's log lines so a test can assert an outage is *visible*.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func (l *logCapture) count(substr string) int {
	n := 0
	for _, line := range l.all() {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// staleFixture builds a CachedStore over a source that can be taken down, driven by a fake
// clock and a captured log. refresh is 0 so the test drives Refresh itself — the background
// loop's only job is to call Refresh on a ticker, which TestCachedStoreBackgroundRefresh
// already covers.
func staleFixture(t *testing.T, maxStale time.Duration) (*CachedStore, *outageSource, *testClock, *logCapture) {
	t.Helper()
	src := &outageSource{Source: NewMemSource()}
	clk := newTestClock()
	logs := &logCapture{}
	c, err := NewCachedStore(src, 0,
		WithMaxStaleness(maxStale),
		WithClock(clk.Now),
		WithLogger(logs.logf),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, src, clk, logs
}

// request is an authenticated request for the revocation stage to judge.
func request() *gateway.Request {
	return &gateway.Request{
		Principal: &types.Principal{ID: "p1"},
		Agent:     &types.Agent{ID: "a1", BlueprintID: "bp1"},
	}
}

// TestCachedStoreServesThenDeniesPastMaxStaleness is the core of the fix: a Source that
// starts failing is tolerated for a while (that is what the local snapshot is for) but not
// forever. Past MaxStaleness the kill-switch can no longer promise a revocation has reached
// this replica, so the stage denies rather than answering from a snapshot of unbounded age.
func TestCachedStoreServesThenDeniesPastMaxStaleness(t *testing.T) {
	const maxStale = 60 * time.Second
	c, src, clk, logs := staleFixture(t, maxStale)
	stage := Stage(c)

	if err := stage.Handle(context.Background(), request()); err != nil {
		t.Fatalf("fresh snapshot must serve normally: %v", err)
	}

	src.setDown(errors.New("dial tcp 10.0.0.5:5432: connect: connection refused"))

	// Well inside the bound: refreshes fail, but the snapshot is still trustworthy enough.
	clk.Advance(30 * time.Second)
	if err := c.Refresh(); err == nil {
		t.Fatal("Refresh must report the source failure to its caller")
	}
	if err := c.CheckFresh(); err != nil {
		t.Fatalf("30s into a 60s bound the snapshot is still fresh: %v", err)
	}
	if err := stage.Handle(context.Background(), request()); err != nil {
		t.Fatalf("requests must be served normally before the bound: %v", err)
	}

	// Past the bound: the same failure now denies.
	clk.Advance(31 * time.Second)
	_ = c.Refresh()
	err := c.CheckFresh()
	if err == nil {
		t.Fatal("61s into a 60s bound the snapshot must be reported stale")
	}
	if !errors.Is(err, ErrStale) {
		t.Fatalf("CheckFresh error must wrap ErrStale, got %v", err)
	}
	serr := stage.Handle(context.Background(), request())
	if serr == nil {
		t.Fatal("a stale kill-switch must deny the request, not wave it through")
	}
	if !errors.Is(serr, ErrStale) {
		t.Fatalf("stage denial must carry the staleness cause for the audit log, got %v", serr)
	}

	// The denial applies to everyone, including a principal that is not on the deny list —
	// "not in the snapshot" is exactly the answer that can no longer be trusted.
	if c.Revoked("p1") {
		t.Fatal("p1 was never revoked; the snapshot itself must stay honest")
	}

	// ...and it was never silent. Both transitions are in the log.
	if logs.count("refresh failed") != 1 {
		t.Fatalf("want exactly one first-failure line, got %v", logs.all())
	}
	if logs.count("STALE") != 1 {
		t.Fatalf("want exactly one bound-crossed line, got %v", logs.all())
	}
	if !strings.Contains(strings.Join(logs.all(), "\n"), "connection refused") {
		t.Fatalf("the underlying source error must reach the operator, got %v", logs.all())
	}
}

// TestCachedStoreRecoversAfterOutage: denial is a state, not a latch. When the Source comes
// back the store resumes serving — and picks up whatever was revoked while it was blind.
func TestCachedStoreRecoversAfterOutage(t *testing.T) {
	const maxStale = 60 * time.Second
	c, src, clk, logs := staleFixture(t, maxStale)
	stage := Stage(c)

	src.setDown(errors.New("db down"))
	clk.Advance(90 * time.Second)
	_ = c.Refresh()
	if err := stage.Handle(context.Background(), request()); err == nil {
		t.Fatal("stage should be denying while stale")
	}

	// The admin plane revoked an agent during the outage (the write reached Postgres).
	if err := src.Source.Revoke("a1"); err != nil {
		t.Fatal(err)
	}
	src.setDown(nil)

	clk.Advance(2 * time.Second)
	if err := c.Refresh(); err != nil {
		t.Fatalf("refresh should succeed once the source is back: %v", err)
	}
	if err := c.CheckFresh(); err != nil {
		t.Fatalf("a just-refreshed snapshot must be fresh again: %v", err)
	}
	if c.Staleness() != 0 {
		t.Fatalf("staleness after a successful refresh = %s, want 0", c.Staleness())
	}
	// Normal operation resumes: the request is judged on merit again — and the revocation
	// written during the outage is now enforced.
	if err := stage.Handle(context.Background(), request()); err == nil {
		t.Fatal("a1 was revoked during the outage; it must be blocked after recovery")
	}
	clean := &gateway.Request{Principal: &types.Principal{ID: "p2"}, Agent: &types.Agent{ID: "a2"}}
	if err := stage.Handle(context.Background(), clean); err != nil {
		t.Fatalf("an unrevoked request must be served again after recovery: %v", err)
	}

	if logs.count("refreshed after") != 1 {
		t.Fatalf("recovery must be logged exactly once, got %v", logs.all())
	}
	if logs.count("serving again") != 1 {
		t.Fatalf("recovery from a *denying* state must say so, got %v", logs.all())
	}
}

// TestCachedStoreFailureLoggingIsRateLimited: a Postgres outage lasting hours must stay
// visible without producing a line per refresh interval (one every 2s by default).
func TestCachedStoreFailureLoggingIsRateLimited(t *testing.T) {
	c, src, clk, logs := staleFixture(t, 60*time.Second)
	src.setDown(errors.New("db down"))

	// Two hours of a 2s refresh loop.
	for i := 0; i < 3600; i++ {
		clk.Advance(2 * time.Second)
		_ = c.Refresh()
	}

	lines := logs.all()
	// 1 first-failure + 1 bound-crossed + one heartbeat per failureLogInterval (~120).
	if got, want := len(lines), 3600; got >= want {
		t.Fatalf("logged %d lines for %d failed refreshes: not rate-limited", got, want)
	}
	if len(lines) < 3 {
		t.Fatalf("a sustained outage must keep a heartbeat in the log, got %v", lines)
	}
	if logs.count("STALE") != 1 {
		t.Fatalf("the bound is crossed once, so it is announced once, got %d", logs.count("STALE"))
	}
	if logs.count("still failing") == 0 {
		t.Fatal("a sustained outage must log periodic heartbeats")
	}
}

// TestCachedStoreNoBoundWithoutBackgroundRefresh guards the dev/single-process wiring: a
// MemSource-backed store with no refresh loop has nothing to fall out of sync with, so it
// must not start denying an hour after startup.
func TestCachedStoreNoBoundWithoutBackgroundRefresh(t *testing.T) {
	clk := newTestClock()
	c, err := NewCachedStore(NewMemSource(), 0, WithClock(clk.Now))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.MaxStaleness() != 0 {
		t.Fatalf("MaxStaleness() = %s, want 0 (no background refresh, no bound)", c.MaxStaleness())
	}
	clk.Advance(24 * time.Hour)
	if err := c.CheckFresh(); err != nil {
		t.Fatalf("an in-process kill-switch must never go stale: %v", err)
	}
	if err := Stage(c).Handle(context.Background(), request()); err != nil {
		t.Fatalf("dev wiring must keep serving: %v", err)
	}
}

// TestCachedStoreDefaultsToNFR4Bound: the bound is on by default whenever a background
// refresh exists, so forgetting to configure it cannot reopen the unbounded-staleness hole.
func TestCachedStoreDefaultsToNFR4Bound(t *testing.T) {
	c, err := NewCachedStore(NewMemSource(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.MaxStaleness() != DefaultMaxStaleness {
		t.Fatalf("MaxStaleness() = %s, want the NFR-4 default %s", c.MaxStaleness(), DefaultMaxStaleness)
	}
	if DefaultMaxStaleness > 60*time.Second {
		t.Fatalf("DefaultMaxStaleness = %s exceeds the NFR-4 revocation target of 60s", DefaultMaxStaleness)
	}
}

// TestCachedStoreExposesStaleness covers the observability surface /readyz and the metrics
// gauge read.
func TestCachedStoreExposesStaleness(t *testing.T) {
	c, src, clk, _ := staleFixture(t, 60*time.Second)

	start := c.LastRefresh()
	if start.IsZero() {
		t.Fatal("a constructed store has always had one successful refresh")
	}
	if c.Staleness() != 0 {
		t.Fatalf("Staleness() = %s right after construction, want 0", c.Staleness())
	}

	src.setDown(errors.New("db down"))
	clk.Advance(45 * time.Second)
	_ = c.Refresh()
	if got := c.Staleness(); got != 45*time.Second {
		t.Fatalf("Staleness() = %s, want 45s", got)
	}
	if !c.LastRefresh().Equal(start) {
		t.Fatal("a failed refresh must not advance the last-successful-refresh time")
	}
}

// TestCachedStoreStalenessRace runs readers, the freshness check, and refreshes against a
// flapping source concurrently (run with -race).
func TestCachedStoreStalenessRace(t *testing.T) {
	src := &outageSource{Source: NewMemSource()}
	c, err := NewCachedStore(src, time.Millisecond, WithLogger(func(string, ...any) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { // flap the source
		defer wg.Done()
		for i := 0; i < 200; i++ {
			src.setDown(errors.New("down"))
			src.setDown(nil)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = c.CheckFresh()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = c.Staleness()
			_ = c.LastRefresh()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = c.Revoked("a1")
		}
	}()
	wg.Wait()
}
