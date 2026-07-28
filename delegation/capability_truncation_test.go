package delegation

// Truncation tests for the offline capability.
//
// Blocks chain forwards, so every PREFIX of a valid capability used to be a valid capability
// — and the shortest prefix carries the BROADEST grant. A recipient handed a token narrowed
// to ["a"] could drop the last block and present the parent's ["a","b"]:
//
//	TRUNCATED capability verifies=<nil> grant={Tools:[a b]}
//
// The only thing that stood between that and an authorization decision was CapabilityStage
// remembering to call VerifyHolder. Nothing here calls VerifyHolder: these tests assert that
// Verify ALONE refuses a truncated token, so the compensating control is no longer the
// control. See Capability's doc comment for how the Seal does it.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestTruncatedCapabilityDoesNotVerify is the PoC, inverted. No VerifyHolder anywhere.
func TestTruncatedCapabilityDoesNotVerify(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	broad, s0, err := NewCapability(rootPriv, Grant{Tools: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	narrow, _, err := broad.Attenuate(rootPub, s0, Grant{Tools: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}

	// Everything the recipient of `narrow` could try. They hold `narrow` and its final secret;
	// they have never seen `broad`, so they do not have its seal or s0.
	cases := []struct {
		name string
		cap  Capability
	}{
		{"blocks dropped, no seal", Capability{Blocks: narrow.Blocks[:1]}},
		{"blocks dropped, seal kept", Capability{Blocks: narrow.Blocks[:1], Seal: narrow.Seal}},
		{"seal dropped only", Capability{Blocks: narrow.Blocks}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := tc.cap.Verify(rootPub, time.Now())
			if err == nil {
				t.Fatalf("a truncated capability verified, carrying grant %+v", g)
			}
			if len(g.Tools) != 0 {
				t.Fatalf("a rejected capability must yield no grant, got %v", g.Tools)
			}
		})
	}

	// And the honest tokens both still verify, so the seal did not simply break capabilities.
	if g, err := narrow.Verify(rootPub, time.Now()); err != nil || len(g.Tools) != 1 {
		t.Fatalf("the narrowed capability must verify to [a]: grant=%v err=%v", g.Tools, err)
	}
	if g, err := broad.Verify(rootPub, time.Now()); err != nil || len(g.Tools) != 2 {
		t.Fatalf("the parent capability must verify to [a b]: grant=%v err=%v", g.Tools, err)
	}
}

// TestTruncatedCapabilityCannotBeResealed: the recipient holds the FINAL secret, so the one
// key they could seal with is the wrong one for a prefix — a prefix's seal must be made by
// the secret behind its last block's next-key, which is the parent's, not theirs.
func TestTruncatedCapabilityCannotBeResealed(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	broad, s0, err := NewCapability(rootPriv, Grant{Tools: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	narrow, s1, err := broad.Attenuate(rootPub, s0, Grant{Tools: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}

	prefix := narrow.Blocks[:1]
	forged := Capability{Blocks: prefix, Seal: seal(s1, rootPub, prefix)}
	if _, err := forged.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a prefix re-sealed with the recipient's own secret must not verify")
	}

	// A seal over the right length but signed by a key nobody authorized is no better.
	_, attacker := rootKeys(t)
	forged.Seal = seal(attacker, rootPub, prefix)
	if _, err := forged.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a prefix sealed with an unrelated key must not verify")
	}
}

// TestCapabilityBlockCannotBeRegrafted: with the index and the previous signature inside the
// block's signing input, a block only verifies at the position it was signed for, in the
// capability it was signed for. This is the property Chain already had from prevSig.
func TestCapabilityBlockCannotBeRegrafted(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)

	// One holder, two capabilities from the same root, so the same next-key signs in both and
	// the splice is not stopped by key mismatch alone.
	a, aSecret, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	b, bSecret, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	aNarrow, _, err := a.Attenuate(rootPub, aSecret, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	bNarrow, _, err := b.Attenuate(rootPub, bSecret, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}

	// b's block 1, pasted into a. It is a real block, signed by a real holder, at the same
	// index — but under a different predecessor.
	spliced := Capability{Blocks: []Block{aNarrow.Blocks[0], bNarrow.Blocks[1]}, Seal: bNarrow.Seal}
	if _, err := spliced.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a block spliced from another capability must be rejected (prev-signature binding)")
	}

	// Block 0 replayed at index 1 of its own capability: same signer key, same predecessor
	// slot, different index.
	reindexed := Capability{Blocks: []Block{aNarrow.Blocks[0], aNarrow.Blocks[0]}, Seal: aNarrow.Seal}
	if _, err := reindexed.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a block replayed at a different index must be rejected (index binding)")
	}
}

// TestCapabilityIsBoundToItsRootKey: block signatures name the anchor they hang from, so a
// capability minted under one root is not a capability under another even where the later
// blocks' signers would line up.
func TestCapabilityIsBoundToItsRootKey(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	otherPub, _ := rootKeys(t)

	c, s0, err := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	narrowed, _, err := c.Attenuate(rootPub, s0, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := narrowed.Verify(otherPub, time.Now()); err == nil {
		t.Fatal("a capability must not verify under a different root key")
	}

	// Attenuating under the wrong anchor produces a block bound to that anchor, so the result
	// verifies under neither: not under rootPub (the new block names otherPub) and not under
	// otherPub (block 0 was signed by rootPriv).
	wrongAnchor, _, err := c.Attenuate(otherPub, s0, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongAnchor.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a block attenuated under the wrong anchor must not verify under the real one")
	}
	if _, err := wrongAnchor.Verify(otherPub, time.Now()); err == nil {
		t.Fatal("a capability rooted elsewhere must not verify under the anchor its tail names")
	}
}

// TestTruncatedCapabilityIsRejectedByTheStage closes the loop: the same truncation presented
// on a real request is denied by CapabilityStage, and denied by the capability check rather
// than by the holder proof — the request carries a holder proof the recipient can genuinely
// make, so the proof is not what refuses it.
func TestTruncatedCapabilityIsRejectedByTheStage(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	broad, s0, err := NewCapability(rootPriv, Grant{Tools: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	narrow, s1, err := broad.Attenuate(rootPub, s0, Grant{Tools: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}

	truncated := Capability{Blocks: narrow.Blocks[:1], Seal: narrow.Seal}
	enc, err := EncodeCapability(truncated)
	if err != nil {
		t.Fatal(err)
	}
	req := capRequest(t, enc, func(r *http.Request) string { return capProof(t, s1, r, nil) })
	err = CapabilityStage(rootPub).Handle(context.Background(), req)
	if err == nil {
		t.Fatal("a truncated capability must be denied by the stage")
	}
	if strings.Contains(err.Error(), "holder proof") {
		t.Fatalf("the truncation must be caught by Verify, not by the holder proof: %v", err)
	}
	if req.Scope.Tools != nil {
		t.Fatalf("a rejected request must carry no scope: %v", req.Scope.Tools)
	}
}
