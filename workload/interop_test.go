package workload

// Cross-language interop vectors. The TypeScript and Python SDKs produce the instance proof
// and the bootstrap evidence themselves and must match Go byte-for-byte, but their test
// suites are not part of CI — so without pinning the same bytes here, a change to either
// construction passes CI green while silently breaking every SDK-based agent in the field.
//
// The identical vectors live in sdks/typescript/test/{interop.test.ts,vectors.mjs} and
// sdks/python/tests/test_interop.py. Changing a value here is a wire break: regenerate it
// from this test's failure output and update all three, in the same commit.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/getsanad/sanad/internal/sigctx"
)

const (
	// The 32-byte seed 0x01..0x20 and its public key, base64url (no padding).
	vecSeedB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	vecPrivB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA"
	vecPubB64  = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"

	// Proof("test-principal-token"), and the domain-separated input it signs:
	// 8-byte big-endian length || "sanad/instance-proof/v1" || token.
	vecPrincipalToken = "test-principal-token"
	vecProofInputHex  = "000000000000001773616e61642f696e7374616e63652d70726f6f662f7631746573742d7072696e636970616c2d746f6b656e"
	vecProof          = "_xyI6J0jruF9VJx5RZimoWtBtrH_7lFTueCgCdeSllnwDcTP5bxCQ9ponOj9OZSbidfO-89TiuC8QYwKBYmlDw"

	// BootstrapEvidence("boot-token", nonce 0x00..0x1f, vecPub).
	vecNonceB64    = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	vecEvidenceB64 = "umfR1kxOzPGX1ZFOK5pgnnRtnxSm-q3nE-Qx6DPsI1o"
)

func vecKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(vecSeedB64)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if got := base64.RawURLEncoding.EncodeToString(priv); got != vecPrivB64 {
		t.Fatalf("64-byte key form = %s, want %s", got, vecPrivB64)
	}
	if got := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)); got != vecPubB64 {
		t.Fatalf("public key = %s, want %s", got, vecPubB64)
	}
	return priv
}

func TestInteropInstanceProofVector(t *testing.T) {
	priv := vecKey(t)

	// The signing input first, so a mismatch says which half moved: the context encoding or
	// the signature over it.
	input := sigctx.Message(sigctx.InstanceProof, []byte(vecPrincipalToken))
	if got := hex.EncodeToString(input); got != vecProofInputHex {
		t.Fatalf("proof signing input = %s, want %s", got, vecProofInputHex)
	}
	if got := Proof(priv, vecPrincipalToken); got != vecProof {
		t.Fatalf("Proof = %s, want %s", got, vecProof)
	}
}

func TestInteropBootstrapEvidenceVector(t *testing.T) {
	priv := vecKey(t)
	nonce, err := base64.RawURLEncoding.DecodeString(vecNonceB64)
	if err != nil {
		t.Fatal(err)
	}
	got := BootstrapEvidence("boot-token", nonce, priv.Public().(ed25519.PublicKey))
	if base64.RawURLEncoding.EncodeToString(got) != vecEvidenceB64 {
		t.Fatalf("BootstrapEvidence = %s, want %s", base64.RawURLEncoding.EncodeToString(got), vecEvidenceB64)
	}
}
