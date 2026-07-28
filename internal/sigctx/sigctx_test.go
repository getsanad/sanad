package sigctx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// The labels are the separation. Two contexts sharing a string share a message space.
func TestContextsAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All {
		if c == "" {
			t.Fatal("empty context label")
		}
		if seen[c] {
			t.Fatalf("duplicate context label %q", c)
		}
		seen[c] = true
	}
}

// The documented layout, byte for byte: an 8-byte big-endian length, the label, the message.
func TestMessageLayout(t *testing.T) {
	got := Message("abc", []byte("xy"))
	want := append([]byte{0, 0, 0, 0, 0, 0, 0, 3}, "abcxy"...)
	if !bytes.Equal(got, want) {
		t.Fatalf("Message = %x, want %x", got, want)
	}
}

// The reason for the length prefix: without it ("ab","c") and ("a","bc") would be the same
// bytes, and a label could be read as the head of a message.
func TestLengthPrefixIsUnambiguous(t *testing.T) {
	if bytes.Equal(Message("ab", []byte("c")), Message("a", []byte("bc"))) {
		t.Fatal("split between context and message must not be ambiguous")
	}
	if bytes.Equal(Message("", []byte("sanad/instance-proof/v1")), Message("sanad/instance-proof/v1", nil)) {
		t.Fatal("a context must not be reproducible as message content")
	}
}

// The property the whole system leans on: one key, one message, every context — a signature
// only ever verifies under the context it was made for.
func TestSignatureNeverVerifiesUnderAnotherContext(t *testing.T) {
	pub, priv := testKey(t)
	msg := []byte("the same bytes signed for different purposes")

	for _, signCtx := range All {
		sig := Sign(signCtx, priv, msg)
		if !Verify(signCtx, pub, msg, sig) {
			t.Fatalf("%s: a signature must verify under its own context", signCtx)
		}
		for _, verifyCtx := range All {
			if verifyCtx == signCtx {
				continue
			}
			if Verify(verifyCtx, pub, msg, sig) {
				t.Fatalf("a %s signature verified as %s", signCtx, verifyCtx)
			}
		}
	}
}

// A raw ed25519.Sign over the bare message — the pre-domain-separation form — must not pass
// for any context, so old signatures and any un-tagged signing oracle are both refused.
func TestUntaggedSignatureIsRejected(t *testing.T) {
	pub, priv := testKey(t)
	msg := []byte("legacy signing input")
	sig := ed25519.Sign(priv, msg)

	for _, c := range All {
		if Verify(c, pub, msg, sig) {
			t.Fatalf("an untagged signature verified as %s", c)
		}
	}
}

// Verification runs on attacker-supplied keys, so a malformed one fails closed instead of
// panicking inside ed25519.Verify.
func TestVerifyRejectsMalformedKey(t *testing.T) {
	_, priv := testKey(t)
	msg := []byte("msg")
	sig := Sign(InstanceProof, priv, msg)

	for _, pub := range []ed25519.PublicKey{nil, {}, make([]byte, 31), make([]byte, 33)} {
		if Verify(InstanceProof, pub, msg, sig) {
			t.Fatal("a malformed public key must not verify")
		}
	}
}
