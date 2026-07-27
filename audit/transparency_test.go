package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
)

func newTLog(t *testing.T) (*TransparencyLog, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewTransparencyLog(priv, "ckpt-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	return l, pub
}

func TestTransparencyInclusionAndCheckpoint(t *testing.T) {
	l, pub := newTLog(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := l.Append(ctx, Entry{Action: "allow", Principal: "p1", PassportID: string(rune('a' + i))}); err != nil {
			t.Fatal(err)
		}
	}

	cp := l.Checkpoint()
	if cp.Size != 5 || !VerifyCheckpoint(pub, cp) {
		t.Fatalf("checkpoint invalid: %+v", cp)
	}

	leaf, proof, err := l.InclusionProof(2)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion(leaf, 2, cp.Size, proof, cp.Root) {
		t.Fatal("inclusion proof should verify against the checkpoint root")
	}
}

func TestTransparencyConsistencyAcrossGrowth(t *testing.T) {
	l, _ := newTLog(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1"})
	}
	old := l.Checkpoint() // size 4

	for i := 0; i < 3; i++ {
		_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1"})
	}
	cur := l.Checkpoint() // size 7

	proof, err := l.ConsistencyProof(old.Size)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyConsistency(old.Size, cur.Size, proof, old.Root, cur.Root) {
		t.Fatal("the grown log must be consistent with its earlier checkpoint")
	}
}

func TestCheckpointTamperRejected(t *testing.T) {
	l, pub := newTLog(t)
	_ = l.Append(context.Background(), Entry{Action: "allow"})
	cp := l.Checkpoint()
	cp.Size = 999 // forge the size
	if VerifyCheckpoint(pub, cp) {
		t.Fatal("a tampered checkpoint must not verify")
	}
}

// TestTransparencyConcurrentAppendKeepsLeavesInStepWithChain is the transparency-log
// counterpart to TestConcurrentAppendIsRaceFreeAndIntact. Any HTTP-served deployment
// appends from many goroutines at once, and the tree has to survive that: every entry gets
// its own leaf, at the index the chain gave it, or the log proves inclusion of the wrong
// record while still looking well-formed.
func TestTransparencyConcurrentAppendKeepsLeavesInStepWithChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{}
	l, err := NewTransparencyLog(priv, "ckpt-1", sink)
	if err != nil {
		t.Fatal(err)
	}

	const n = 250
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			e := Entry{Action: "allow", Principal: "p1", PassportID: fmt.Sprintf("jti-%d", i)}
			if err := l.Append(context.Background(), e); err != nil {
				t.Errorf("append %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if got := l.Size(); got != n {
		t.Fatalf("log size = %d, want %d (leaves were lost)", got, n)
	}
	if got := sink.count(); got != n {
		t.Fatalf("sink got %d entries, want %d", got, n)
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("concurrently built chain must verify: %v", err)
	}

	entries := l.Entries()
	if len(entries) != n {
		t.Fatalf("chain has %d entries, want %d", len(entries), n)
	}
	cp := l.Checkpoint()
	if cp.Size != n || !VerifyCheckpoint(pub, cp) {
		t.Fatalf("checkpoint invalid: %+v", cp)
	}

	// Every leaf commits to the entry at its own index, appears exactly once, and proves
	// its inclusion against the checkpoint root.
	seen := make(map[string]int, n)
	for i := range entries {
		leaf, proof, err := l.InclusionProof(i)
		if err != nil {
			t.Fatalf("inclusion proof %d: %v", i, err)
		}
		if !bytes.Equal(leaf, entries[i].Hash) {
			t.Fatalf("leaf %d does not commit to entry %d", i, i)
		}
		if dup, ok := seen[string(leaf)]; ok {
			t.Fatalf("leaf %d duplicates leaf %d", i, dup)
		}
		seen[string(leaf)] = i
		if !VerifyInclusion(leaf, i, cp.Size, proof, cp.Root) {
			t.Fatalf("entry %d has no valid inclusion proof against the checkpoint root", i)
		}
	}
}

// TransparencyLog must be usable as a drop-in audit Log.
var _ Log = (*TransparencyLog)(nil)
