package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/getsanad/sanad/internal/sigctx"
)

func witnessKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestWitnessCosignsAndVerifies(t *testing.T) {
	log, _ := newTLog(t)
	ctx := context.Background()
	for range 3 {
		_ = log.Append(ctx, Entry{Action: "allow"})
	}
	cp := log.Checkpoint()

	wPub, wPriv := witnessKeys(t)
	w, err := NewWitness(wPriv, "witness-1", log.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := w.Witness(cp, nil)
	if err != nil {
		t.Fatalf("first witness: %v", err)
	}
	if !VerifyWitness(wPub, cp, sig) {
		t.Fatal("witness co-signature should verify")
	}
}

func TestWitnessAcceptsConsistentGrowth(t *testing.T) {
	log, _ := newTLog(t)
	ctx := context.Background()
	for range 3 {
		_ = log.Append(ctx, Entry{Action: "allow"})
	}
	_, wPriv := witnessKeys(t)
	w, _ := NewWitness(wPriv, "witness-1", log.PublicKey())

	if _, err := w.Witness(log.Checkpoint(), nil); err != nil {
		t.Fatal(err)
	}

	old := 3
	for range 4 {
		_ = log.Append(ctx, Entry{Action: "allow"})
	}
	cp2 := log.Checkpoint()
	proof, _ := log.ConsistencyProof(old)
	if _, err := w.Witness(cp2, proof); err != nil {
		t.Fatalf("witness should accept a consistent extension: %v", err)
	}
}

// TestWitnessRejectsRewrite is the core guarantee: a forked checkpoint at the same size
// with a different root (history rewrite) is refused.
func TestWitnessRejectsRewrite(t *testing.T) {
	log, _ := newTLog(t)
	ctx := context.Background()
	for range 3 {
		_ = log.Append(ctx, Entry{Action: "allow", Principal: "p1"})
	}
	_, wPriv := witnessKeys(t)
	w, _ := NewWitness(wPriv, "witness-1", log.PublicKey())
	if _, err := w.Witness(log.Checkpoint(), nil); err != nil {
		t.Fatal(err)
	}

	// A second, divergent log of the same size (different entries -> different root),
	// signed by the same operator key. This simulates a rewrite/fork.
	fork, _ := NewTransparencyLog(forgeSameKey(t, log), "ckpt-1", nil)
	for range 3 {
		_ = fork.Append(ctx, Entry{Action: "allow", Principal: "attacker"})
	}
	forkCP := fork.Checkpoint()

	if _, err := w.Witness(forkCP, nil); err == nil {
		t.Fatal("witness must reject a same-size checkpoint with a divergent root (rewrite)")
	}
}

// forgeSameKey returns the operator's signing key so the fork is signed by the same
// identity (only the contents differ) — exercising the witness's consistency check rather
// than the signature check.
func forgeSameKey(t *testing.T, l *TransparencyLog) ed25519.PrivateKey {
	t.Helper()
	return l.signer
}

func TestWitnessRejectsShrink(t *testing.T) {
	log, _ := newTLog(t)
	ctx := context.Background()
	for range 5 {
		_ = log.Append(ctx, Entry{Action: "allow"})
	}
	_, wPriv := witnessKeys(t)
	w, _ := NewWitness(wPriv, "witness-1", log.PublicKey())
	if _, err := w.Witness(log.Checkpoint(), nil); err != nil {
		t.Fatal(err)
	}

	// A checkpoint claiming a smaller size must be refused.
	smaller := SignedCheckpoint{Size: 2, Root: Root(nil), KeyID: "ckpt-1"}
	smaller.Signature = sigctx.Sign(sigctx.AuditCheckpoint, log.signer, checkpointMsg(smaller))
	if _, err := w.Witness(smaller, nil); err == nil {
		t.Fatal("witness must reject a checkpoint smaller than the last one it saw")
	}
}
