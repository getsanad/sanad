package audit

// Cross-context tests for the checkpoint signature pair. The operator and every witness sign
// the SAME checkpointMsg bytes, so without distinct contexts a witness co-signature and the
// operator's own commitment are interchangeable — and an operator with no witness at all
// could present its own signature as independent corroboration, which is the one thing a
// witness exists to prevent.

import (
	"context"
	"testing"
)

func TestOperatorSignatureIsNotAWitnessCoSignature(t *testing.T) {
	log, _ := newTLog(t)
	ctx := context.Background()
	for range 3 {
		_ = log.Append(ctx, Entry{Action: "allow"})
	}
	cp := log.Checkpoint()

	// The operator co-signing itself: its own checkpoint signature, presented as a witness
	// co-signature and checked against the operator's key.
	self := WitnessSignature{KeyID: "ckpt-1", Size: cp.Size, Signature: cp.Signature}
	if VerifyWitness(log.PublicKey(), cp, self) {
		t.Fatal("an operator checkpoint signature was accepted as a witness co-signature")
	}

	// A real witness co-signature still verifies.
	wPub, wPriv := witnessKeys(t)
	w, err := NewWitness(wPriv, "witness-1", log.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ws, err := w.Witness(cp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyWitness(wPub, cp, ws) {
		t.Fatal("a genuine witness co-signature must still verify")
	}
}

func TestWitnessCoSignatureIsNotAnOperatorCheckpoint(t *testing.T) {
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
	ws, err := w.Witness(cp, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The witness's co-signature, presented as the operator's own commitment to the log.
	forged := cp
	forged.Signature = ws.Signature
	if VerifyCheckpoint(wPub, forged) {
		t.Fatal("a witness co-signature was accepted as an operator checkpoint signature")
	}
	if !VerifyCheckpoint(log.PublicKey(), cp) {
		t.Fatal("a genuine checkpoint must still verify")
	}
}
