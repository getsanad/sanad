package audit

import (
	"bytes"
	"fmt"
	"testing"
)

func leaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("entry-%d", i))
	}
	return out
}

// TestInclusionExhaustive verifies every leaf in every tree size up to 33.
func TestInclusionExhaustive(t *testing.T) {
	for n := 1; n <= 33; n++ {
		ls := leaves(n)
		root := Root(ls)
		for i := range ls {
			proof, err := InclusionProof(ls, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyInclusion(ls[i], i, n, proof, root) {
				t.Fatalf("n=%d i=%d: valid inclusion proof failed", n, i)
			}
			// A wrong leaf must not verify.
			if VerifyInclusion([]byte("forged"), i, n, proof, root) {
				t.Fatalf("n=%d i=%d: forged leaf verified", n, i)
			}
		}
	}
}

// TestConsistencyExhaustive verifies consistency proofs for all old<=new up to 33,
// against independently-computed roots, and rejects a tampered new root.
func TestConsistencyExhaustive(t *testing.T) {
	for n := 1; n <= 33; n++ {
		full := leaves(n)
		newRoot := Root(full)
		for m := 1; m <= n; m++ {
			oldRoot := Root(full[:m])
			proof, err := ConsistencyProof(full, m)
			if err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if !VerifyConsistency(m, n, proof, oldRoot, newRoot) {
				t.Fatalf("n=%d m=%d: valid consistency proof failed", n, m)
			}
			if m < n {
				bad := append([]byte(nil), newRoot...)
				bad[0] ^= 0x01
				if VerifyConsistency(m, n, proof, oldRoot, bad) {
					t.Fatalf("n=%d m=%d: consistency verified against a tampered new root", n, m)
				}
			}
		}
	}
}

// TestTruncationDetected is the key property: a log that dropped trailing entries is NOT
// consistent with the checkpoint that committed to them.
func TestTruncationDetected(t *testing.T) {
	full := leaves(10)
	committedRoot := Root(full) // a witness saw size 10

	truncated := full[:7] // attacker drops the last 3 entries
	truncatedRoot := Root(truncated)

	// Trying to prove the truncated (size 7) is consistent with the committed size-10
	// checkpoint must fail — there is no valid proof that 10 is a prefix of 7.
	proof, _ := ConsistencyProof(truncated, 10) // out of range -> nil proof
	if VerifyConsistency(10, 7, proof, committedRoot, truncatedRoot) {
		t.Fatal("a truncated log must not verify as consistent with a larger checkpoint")
	}
}

func TestRootStable(t *testing.T) {
	a := Root(leaves(5))
	b := Root(leaves(5))
	if !bytes.Equal(a, b) {
		t.Fatal("Root must be deterministic")
	}
	if bytes.Equal(a, Root(leaves(6))) {
		t.Fatal("different sizes must give different roots")
	}
}
