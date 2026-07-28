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
	"time"

	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
)

const (
	// The 32-byte seed 0x01..0x20 and its public key, base64url (no padding).
	vecSeedB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	vecPrivB64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA"
	vecPubB64  = "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"

	// The request one instance proof is bound to. The proof is per-request now, so a vector
	// has to pin the request too — and, because a real proof carries a random jti and the
	// current time, it is built from a FIXED Binding rather than from Proof itself. Proof's
	// own contract (it produces exactly this shape, for the request it was given) is covered
	// by TestProofIsBoundToTheRequest in replay_test.go.
	vecPrincipalToken = "test-principal-token"
	vecMethod         = "POST"
	vecTarget         = "/servers/demo/mcp"
	vecBody           = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	vecIAT            = 1767225600 // 2026-01-01T00:00:00Z
	vecJTI            = "AAECAwQFBgcICQoLDA0ODw"

	// The derived claim values: base64url(SHA-256(...)) of the token and of the body, plus
	// the empty-body hash a GET carries.
	vecATH       = "eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI"
	vecBH        = "qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw"
	vecBHEmpty   = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
	vecPayload   = `{"ath":"eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI","bh":"qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw","htm":"POST","htu":"/servers/demo/mcp","iat":1767225600,"jti":"AAECAwQFBgcICQoLDA0ODw"}`
	vecPayloadB6 = "eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0"

	// The domain-separated input the signature covers: 8-byte big-endian length ||
	// "sanad/instance-proof/v2" || payload.
	vecProofInputHex = "000000000000001773616e61642f696e7374616e63652d70726f6f662f76327b22617468223a22656156646332344d463572624b70545857444935572d7458484e6641312d7176466a7751344749686a6c49222c226268223a2271584462625362414941717454705f706146544435474b334670445055794d666477334d2d426557705777222c2268746d223a22504f5354222c22687475223a222f736572766572732f64656d6f2f6d6370222c22696174223a313736373232353630302c226a7469223a2241414543417751464267634943516f4c4441304f4477227d"

	// The full X-Agent-Proof header value: base64url(payload) "." base64url(signature).
	vecProof = "eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0.xDlJ_BHqkqNCj1L4e4RqJsHSO_DE71uRiqALR6CRFdMSC-ICPY8rojK3uyy_coSbhDFQBT1mpL0ECFk8sIlpBw"

	// The same payload signed as a CAPABILITY holder proof (X-Agent-Capability-Proof). It
	// differs only in the context label, which is the whole point of sigctx.
	vecHolderProof = "eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0.y-dA1G8M220lQyMubM0EyB8V2qAfznj-PA2WWHMYvmmgye7iNT60q4xXJW73e5hux4niRagPGEYNDYz7HQ5DAw"

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

// vecBinding is the fixed Binding the proof vectors are built from.
func vecBinding() pop.Binding {
	return pop.Binding{ATH: vecATH, BH: vecBH, HTM: vecMethod, HTU: vecTarget, IAT: vecIAT, JTI: vecJTI}
}

// The claim values, first: a mismatch here says the hashing moved rather than the signing.
func TestInteropProofClaimVectors(t *testing.T) {
	if got := pop.Hash([]byte(vecPrincipalToken)); got != vecATH {
		t.Fatalf("ath = %s, want %s", got, vecATH)
	}
	if got := pop.Hash([]byte(vecBody)); got != vecBH {
		t.Fatalf("bh = %s, want %s", got, vecBH)
	}
	// A request with no body still commits to one: the hash of zero bytes.
	if got := pop.Hash(nil); got != vecBHEmpty {
		t.Fatalf("bh(empty) = %s, want %s", got, vecBHEmpty)
	}
}

// The canonical payload encoding: field order, compact separators, and no HTML escaping.
// This is what the three languages have to agree on to produce identical bytes.
func TestInteropProofPayloadVector(t *testing.T) {
	payload, err := pop.Encode(vecBinding())
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != vecPayload {
		t.Fatalf("payload = %s, want %s", payload, vecPayload)
	}
	if got := base64.RawURLEncoding.EncodeToString(payload); got != vecPayloadB6 {
		t.Fatalf("base64url(payload) = %s, want %s", got, vecPayloadB6)
	}
}

func TestInteropInstanceProofVector(t *testing.T) {
	priv := vecKey(t)
	payload, err := pop.Encode(vecBinding())
	if err != nil {
		t.Fatal(err)
	}

	// The signing input first, so a mismatch says which half moved: the context encoding or
	// the signature over it.
	input := sigctx.Message(sigctx.InstanceProof, payload)
	if got := hex.EncodeToString(input); got != vecProofInputHex {
		t.Fatalf("proof signing input = %s, want %s", got, vecProofInputHex)
	}
	got, err := pop.Sign(sigctx.InstanceProof, priv, vecBinding())
	if err != nil {
		t.Fatal(err)
	}
	if got != vecProof {
		t.Fatalf("proof = %s, want %s", got, vecProof)
	}
}

// The capability holder proof is the same payload under a different context label, and the
// two must not be interchangeable — the SDKs sign both with keys that can coincide.
func TestInteropHolderProofVector(t *testing.T) {
	priv := vecKey(t)
	got, err := pop.Sign(sigctx.CapabilityHolderProof, priv, vecBinding())
	if err != nil {
		t.Fatal(err)
	}
	if got != vecHolderProof {
		t.Fatalf("holder proof = %s, want %s", got, vecHolderProof)
	}
	if got == vecProof {
		t.Fatal("the instance proof and the holder proof over one payload must differ")
	}
}

// Proof produces exactly the pinned header for the pinned request, once its two
// non-deterministic inputs (iat, jti) are held fixed. That is what ties the vector — which
// is built from a Binding — to the function the SDKs actually mirror.
func TestInteropProofMatchesTheVectorForAFixedBindingAndTime(t *testing.T) {
	priv := vecKey(t)
	b, err := pop.NewBinding(vecMethod, vecTarget, vecPrincipalToken, []byte(vecBody), time.Unix(vecIAT, 0))
	if err != nil {
		t.Fatal(err)
	}
	if b.ATH != vecATH || b.BH != vecBH || b.HTM != vecMethod || b.HTU != vecTarget || b.IAT != vecIAT {
		t.Fatalf("NewBinding disagrees with the vector: %+v", b)
	}
	b.JTI = vecJTI // the one field that is random per proof
	got, err := pop.Sign(sigctx.InstanceProof, priv, b)
	if err != nil {
		t.Fatal(err)
	}
	if got != vecProof {
		t.Fatalf("proof from NewBinding = %s, want %s", got, vecProof)
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
