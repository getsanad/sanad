package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

// TransparencyLog must be usable as a drop-in audit Log.
var _ Log = (*TransparencyLog)(nil)
