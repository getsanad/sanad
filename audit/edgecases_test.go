package audit

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// errSink fails every Write; used to prove a sink failure does not lose the recorded entry.
type errSink struct{ writes int }

func (s *errSink) Write(Entry) error { s.writes++; return errors.New("sink down") }

// countingSink records every entry it receives (thread-safe for the concurrency test).
type countingSink struct {
	mu      sync.Mutex
	entries []Entry
}

func (s *countingSink) Write(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}

func (s *countingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// --- tamper / delete / reorder at each position -------------------------------------

func TestTamperAtEachPosition(t *testing.T) {
	for _, pos := range []int{0, 1, 2} {
		pos := pos
		t.Run([]string{"first", "middle", "last"}[pos], func(t *testing.T) {
			l := NewHashChainLog(nil)
			appendN(t, l, 3)
			entries := l.Entries()
			entries[pos].Reason = "tampered"
			if err := VerifyChain(entries); err == nil {
				t.Fatalf("tampering entry %d must break the chain", pos)
			}
		})
	}
}

func TestDeleteAtEachPosition(t *testing.T) {
	tests := map[string][]int{
		"delete first":  {1, 2},
		"delete middle": {0, 2},
		"delete last":   {0, 1},
	}
	for name, keep := range tests {
		keep := keep
		t.Run(name, func(t *testing.T) {
			l := NewHashChainLog(nil)
			appendN(t, l, 3)
			full := l.Entries()
			var sub []Entry
			for _, i := range keep {
				sub = append(sub, full[i])
			}
			// Deleting the last entry leaves a still-intact prefix chain, which is the
			// documented limit of a pure hash chain (no length commitment): assert that.
			err := VerifyChain(sub)
			if name == "delete last" {
				if err != nil {
					t.Fatalf("a truncated-tail prefix still verifies as a hash chain: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s must break the chain", name)
			}
		})
	}
}

func TestReorderDetected(t *testing.T) {
	l := NewHashChainLog(nil)
	appendN(t, l, 3)
	entries := l.Entries()
	entries[0], entries[2] = entries[2], entries[0]
	if err := VerifyChain(entries); err == nil {
		t.Fatal("reordering entries must break the chain")
	}
}

// --- fields inside the hash break the chain when changed ----------------------------

func TestPassportIDInsideHash(t *testing.T) {
	l := NewHashChainLog(nil)
	_ = l.Append(context.Background(), Entry{Action: "allow", PassportID: "pp-1"})
	entries := l.Entries()
	entries[0].PassportID = "pp-2"
	if err := VerifyChain(entries); err == nil {
		t.Fatal("changing PassportID must break the chain (it is inside the hash)")
	}
}

func TestDelegationInsideHash(t *testing.T) {
	l := NewHashChainLog(nil)
	_ = l.Append(context.Background(), Entry{Action: "allow", Delegation: []string{"p1", "a1"}})
	entries := l.Entries()
	entries[0].Delegation = []string{"p1", "a1", "a2"}
	if err := VerifyChain(entries); err == nil {
		t.Fatal("changing Delegation must break the chain (it is inside the hash)")
	}
}

func TestDecisionInsideHash(t *testing.T) {
	l := NewHashChainLog(nil)
	_ = l.Append(context.Background(), Entry{
		Action: "allow", Decision: &types.Decision{Effect: types.EffectAllow, Reason: "ok"},
	})
	entries := l.Entries()
	entries[0].Decision = &types.Decision{Effect: types.EffectDeny, Reason: "ok"}
	if err := VerifyChain(entries); err == nil {
		t.Fatal("changing the Decision effect must break the chain")
	}
}

// --- sink behavior ------------------------------------------------------------------

func TestSinkErrorDoesNotLoseEntry(t *testing.T) {
	sink := &errSink{}
	l := NewHashChainLog(sink)
	// Append returns the sink error...
	if err := l.Append(context.Background(), Entry{Action: "allow", Principal: "p1"}); err == nil {
		t.Fatal("Append should surface the sink write error")
	}
	// ...but the entry is still recorded in the system of record, and the chain is intact.
	if got := l.Entries(); len(got) != 1 {
		t.Fatalf("entry must be recorded even when the sink fails: got %d", len(got))
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("chain must remain intact after a sink failure: %v", err)
	}
	if sink.writes != 1 {
		t.Fatalf("sink should have been called once, got %d", sink.writes)
	}
}

func TestSinkReceivesEntryContent(t *testing.T) {
	sink := &countingSink{}
	l := NewHashChainLog(sink)
	_ = l.Append(context.Background(), Entry{Action: "allow", Principal: "p1", PassportID: "pp-1"})
	if sink.count() != 1 {
		t.Fatalf("sink should have received 1 entry, got %d", sink.count())
	}
	sink.mu.Lock()
	got := sink.entries[0]
	sink.mu.Unlock()
	if got.PassportID != "pp-1" || got.Principal != "p1" {
		t.Fatalf("sink received wrong content: %+v", got)
	}
	if len(got.Hash) == 0 {
		t.Fatal("sink should receive the entry with its computed hash")
	}
}

// --- Entries() returns a copy -------------------------------------------------------

func TestEntriesReturnsCopy(t *testing.T) {
	l := NewHashChainLog(nil)
	appendN(t, l, 2)

	got := l.Entries()
	got[0].Principal = "mutated"
	got[0].Hash = []byte("garbage")

	// A second read must be unaffected, and the log must still verify.
	fresh := l.Entries()
	if fresh[0].Principal == "mutated" {
		t.Fatal("mutating the returned slice must not corrupt the log")
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("log must still verify after caller mutated its copy: %v", err)
	}
}

// --- Investigate duplicate / found / not found --------------------------------------

func TestInvestigateDuplicatePassportIDsReturnsFirst(t *testing.T) {
	l := NewHashChainLog(nil)
	ctx := context.Background()
	_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1", Agent: "a1", PassportID: "dup"})
	_ = l.Append(ctx, Entry{Action: "deny", Principal: "p2", Agent: "a2", PassportID: "dup"})

	rep, err := l.Investigate("dup")
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	// Documented behavior: the first matching record wins.
	if rep.Principal != "p1" || rep.Action != "allow" {
		t.Fatalf("expected the first matching entry, got %+v", rep)
	}
}

func TestInvestigateReportsIntactIntegrity(t *testing.T) {
	// Investigate sets IntegrityOK from VerifyChain over the log's own (private) entries.
	// There is no public API to corrupt that internal slice, so we assert the intact path
	// here; the IntegrityOK=false branch is covered indirectly by the VerifyChain tamper
	// tests above.
	l := NewHashChainLog(nil)
	_ = l.Append(context.Background(), Entry{Action: "allow", Principal: "p1", PassportID: "pp-1"})
	rep, err := l.Investigate("pp-1")
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if !rep.IntegrityOK {
		t.Fatal("intact log should report IntegrityOK=true")
	}
}

func TestByPrincipalEmptyAndMissing(t *testing.T) {
	l := NewHashChainLog(nil)
	if got := l.ByPrincipal("nobody"); got != nil {
		t.Fatalf("ByPrincipal on an empty log should be nil, got %v", got)
	}
	_ = l.Append(context.Background(), Entry{Action: "allow", Principal: "p1"})
	if got := l.ByPrincipal("p2"); len(got) != 0 {
		t.Fatalf("ByPrincipal for an unknown principal should be empty, got %d", len(got))
	}
}

// --- GatewayHook path construction --------------------------------------------------

func TestGatewayHookDenyRecorded(t *testing.T) {
	l := NewHashChainLog(nil)
	hook := GatewayHook(l)
	req := &gateway.Request{
		Server:   "demo",
		Decision: &types.Decision{Effect: types.EffectDeny, Reason: "not allowlisted"},
	}
	hook(req, false, "denied")

	entries := l.Entries()
	if len(entries) != 1 || entries[0].Action != "deny" {
		t.Fatalf("expected one deny entry, got %+v", entries)
	}
	if entries[0].Reason != "denied" {
		t.Fatalf("reason not recorded: %q", entries[0].Reason)
	}
}

func TestGatewayHookRecordsPassportID(t *testing.T) {
	l := NewHashChainLog(nil)
	hook := GatewayHook(l)
	req := &gateway.Request{
		Server:    "demo",
		Principal: &types.Principal{ID: "p1"},
		Agent:     &types.Agent{ID: "a1"},
		Passport:  &types.Passport{ID: "pp-77"},
	}
	hook(req, true, "ok")

	if got := l.Entries()[0].PassportID; got != "pp-77" {
		t.Fatalf("passport id not recorded: %q", got)
	}
}

func TestGatewayHookBuildsDelegationPath(t *testing.T) {
	l := NewHashChainLog(nil)
	hook := GatewayHook(l)
	req := &gateway.Request{
		Server:    "demo",
		Principal: &types.Principal{ID: "p1"},
		Delegation: &types.DelegationChain{Hops: []types.DelegationHop{
			{Delegator: "p1", Delegate: "a1"},
			{Delegator: "a1", Delegate: "a2"},
		}},
	}
	hook(req, true, "ok")

	path := l.Entries()[0].Delegation
	want := []string{"p1", "a1", "a2"}
	if len(path) != len(want) {
		t.Fatalf("delegation path = %v, want %v", path, want)
	}
	for i := range want {
		if path[i] != want[i] {
			t.Fatalf("delegation path[%d] = %q, want %q", i, path[i], want[i])
		}
	}
}

func TestGatewayHookNilDelegationLeavesPathEmpty(t *testing.T) {
	l := NewHashChainLog(nil)
	GatewayHook(l)(&gateway.Request{Server: "demo"}, true, "ok")
	if path := l.Entries()[0].Delegation; path != nil {
		t.Fatalf("no delegation should leave path nil, got %v", path)
	}
}

func TestGatewayHookEmptyDelegationHopsLeavesPathEmpty(t *testing.T) {
	l := NewHashChainLog(nil)
	req := &gateway.Request{Server: "demo", Delegation: &types.DelegationChain{}}
	GatewayHook(l)(req, true, "ok")
	if path := l.Entries()[0].Delegation; path != nil {
		t.Fatalf("an empty delegation chain should leave path nil, got %v", path)
	}
}

// --- concurrency --------------------------------------------------------------------

func TestConcurrentAppendIsRaceFreeAndIntact(t *testing.T) {
	sink := &countingSink{}
	l := NewHashChainLog(sink)

	const goroutines, perG = 8, 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				if err := l.Append(context.Background(), Entry{Action: "allow", Principal: "p1"}); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	total := goroutines * perG
	if got := len(l.Entries()); got != total {
		t.Fatalf("got %d entries, want %d", got, total)
	}
	if got := sink.count(); got != total {
		t.Fatalf("sink got %d entries, want %d", got, total)
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("concurrently built chain must verify: %v", err)
	}
}
