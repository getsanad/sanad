package passport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// enc is the same RawURLEncoding the package uses on the wire.
var enc = base64.RawURLEncoding.EncodeToString

func at(year int) time.Time { return time.Date(year, 6, 16, 12, 0, 0, 0, time.UTC) }

// --- Sign: key length hygiene -------------------------------------------------------

func TestSignRejectsWrongLengthPrivateKey(t *testing.T) {
	now := at(2026)
	cases := []struct {
		name string
		priv ed25519.PrivateKey
	}{
		{"nil", nil},
		{"empty", ed25519.PrivateKey{}},
		{"too short", make([]byte, ed25519.PrivateKeySize-1)},
		{"too long", make([]byte, ed25519.PrivateKeySize+1)},
		{"public-key length", make([]byte, ed25519.PublicKeySize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.priv, "kid-1", sampleClaims(now)); err == nil {
				t.Fatal("expected error for invalid private key length")
			}
		})
	}
}

// --- Verify: public key length hygiene ----------------------------------------------

func TestVerifyRejectsWrongLengthPublicKey(t *testing.T) {
	_, priv := newKey(t)
	now := at(2026)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))

	cases := []struct {
		name string
		pub  ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"too short", make([]byte, ed25519.PublicKeySize-1)},
		{"too long", make([]byte, ed25519.PublicKeySize+1)},
		{"private-key length", make([]byte, ed25519.PrivateKeySize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.pub, tok, "server-a", now); err == nil {
				t.Fatal("expected error for invalid public key length")
			}
		})
	}
}

// --- Verify: structural / segment-count validation ----------------------------------

func TestVerifyRejectsMalformedSegmentCounts(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	valid, _ := Sign(priv, "kid-1", sampleClaims(now))
	parts := strings.Split(valid, ".")

	cases := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"zero segments is one empty segment", ""},
		{"one segment", parts[0]},
		{"two segments", parts[0] + "." + parts[1]},
		{"four segments", valid + "." + parts[2]},
		{"only dots two", ".."},
		{"only dots three", "..."},
		{"trailing dot", valid + "."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(pub, tc.raw, "server-a", now); err == nil {
				t.Fatalf("expected error for %q", tc.raw)
			}
		})
	}
}

// --- Verify: non-base64 segments ----------------------------------------------------

func TestVerifyRejectsNonBase64Segments(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	valid, _ := Sign(priv, "kid-1", sampleClaims(now))
	parts := strings.Split(valid, ".")

	// "!" is not in the RawURLEncoding alphabet.
	cases := []struct {
		name string
		raw  string
	}{
		{"bad header", "!!!." + parts[1] + "." + parts[2]},
		{"bad payload", parts[0] + ".!!!." + parts[2]},
		{"bad signature", parts[0] + "." + parts[1] + ".!!!"},
		// Standard base64 padding "=" is illegal under RawURLEncoding.
		{"padded header", parts[0] + "==." + parts[1] + "." + parts[2]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(pub, tc.raw, "server-a", now); err == nil {
				t.Fatalf("expected error for non-base64 in %s", tc.name)
			}
		})
	}
}

// --- Verify: header content (alg / typ / json) --------------------------------------

func TestVerifyAlgHeaderHygiene(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	c := sampleClaims(now)

	// Properly-signed-but-wrong-alg tokens: sign with the real key, then rewrite the
	// header to a forbidden alg. This isolates the alg check from the signature check.
	signWithHeader := func(h header) string {
		hb, _ := json.Marshal(h)
		pb, _ := json.Marshal(c)
		signingInput := enc(hb) + "." + enc(pb)
		sig := ed25519.Sign(priv, []byte(signingInput))
		return signingInput + "." + enc(sig)
	}

	cases := []struct {
		name string
		alg  string
		ok   bool
	}{
		{"empty alg", "", false},
		{"none", "none", false},
		{"HS256", "HS256", false},
		{"RS256", "RS256", false},
		{"lowercase eddsa", "eddsa", false}, // alg is case-sensitive; must be exactly EdDSA
		{"correct EdDSA", "EdDSA", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signWithHeader(header{Alg: tc.alg, Typ: typ, Kid: "kid-1"})
			_, err := Verify(pub, tok, "server-a", now)
			if tc.ok && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected rejection for alg %q", tc.alg)
			}
		})
	}
}

// TestVerifyEnforcesTyp checks the hardened behavior: only the correct `typ` verifies;
// a wrong or empty typ is rejected (defense in depth against cross-token-type confusion).
func TestVerifyEnforcesTyp(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	c := sampleClaims(now)

	signWithHeader := func(h header) string {
		hb, _ := json.Marshal(h)
		pb, _ := json.Marshal(c)
		signingInput := enc(hb) + "." + enc(pb)
		sig := ed25519.Sign(priv, []byte(signingInput))
		return signingInput + "." + enc(sig)
	}

	cases := map[string]bool{"": false, "JWT": false, "wrong+jwt": false, "passport+jwt": true}
	for typVal, wantOK := range cases {
		t.Run("typ="+typVal, func(t *testing.T) {
			tok := signWithHeader(header{Alg: alg, Typ: typVal, Kid: "kid-1"})
			_, err := Verify(pub, tok, "server-a", now)
			if wantOK && err != nil {
				t.Fatalf("typ %q should verify, got: %v", typVal, err)
			}
			if !wantOK && err == nil {
				t.Fatalf("typ %q should be rejected", typVal)
			}
		})
	}
}

func TestVerifyRejectsNonJSONHeader(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	valid, _ := Sign(priv, "kid-1", sampleClaims(now))
	parts := strings.Split(valid, ".")

	// Replace header with base64 of bytes that are not valid JSON.
	bad := enc([]byte("not json")) + "." + parts[1] + "." + parts[2]
	if _, err := Verify(pub, bad, "server-a", now); err == nil {
		t.Fatal("non-JSON header must be rejected")
	}
}

// --- Verify: tampered payload changes claims => signature breaks ---------------------

func TestVerifyTamperedPayloadRejected(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))
	parts := strings.Split(tok, ".")

	// Re-encode a payload that escalates audience; signature was over the original.
	tampered := sampleClaims(now)
	tampered.Audience = "server-EVIL"
	pb, _ := json.Marshal(tampered)
	forged := parts[0] + "." + enc(pb) + "." + parts[2]

	if _, err := Verify(pub, forged, "server-EVIL", now); err == nil {
		t.Fatal("tampered payload (changed audience) must fail signature verification")
	}
}

func TestVerifyNonJSONPayloadRejected(t *testing.T) {
	// A correctly-signed token whose payload is not JSON: signature passes, JSON decode
	// must fail. We sign over a non-JSON payload directly to exercise that branch.
	pub, priv := newKey(t)
	now := at(2026)

	hb, _ := json.Marshal(header{Alg: alg, Typ: typ, Kid: "kid-1"})
	payload := enc([]byte("definitely-not-json"))
	signingInput := enc(hb) + "." + payload
	sig := ed25519.Sign(priv, []byte(signingInput))
	tok := signingInput + "." + enc(sig)

	if _, err := Verify(pub, tok, "", now); err == nil {
		t.Fatal("non-JSON payload must be rejected even with a valid signature")
	}
}

// --- Verify: expiry boundary --------------------------------------------------------

func TestVerifyExpiryBoundary(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	c := sampleClaims(now) // ExpiresAt = now + 2m
	tok, _ := Sign(priv, "kid-1", c)
	exp := time.Unix(c.ExpiresAt, 0).UTC()

	cases := []struct {
		name string
		when time.Time
		ok   bool
	}{
		{"one second before expiry", exp.Add(-time.Second), true},
		{"exactly at expiry rejected (now.Unix() >= exp)", exp, false},
		{"one second after expiry", exp.Add(time.Second), false},
		// Sub-second before the boundary: Unix() truncates, so this is still < exp.
		{"500ms before expiry", exp.Add(-500 * time.Millisecond), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(pub, tok, "server-a", tc.when)
			if tc.ok && err != nil {
				t.Fatalf("expected valid at %v, got %v", tc.when, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected expired at %v", tc.when)
			}
		})
	}
}

// --- Verify: audience matrix --------------------------------------------------------

func TestVerifyAudienceMatrix(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)

	signAud := func(tokenAud string) string {
		c := sampleClaims(now)
		c.Audience = tokenAud
		tok, _ := Sign(priv, "kid-1", c)
		return tok
	}

	cases := []struct {
		name      string
		tokenAud  string
		expectAud string
		ok        bool
	}{
		{"match", "server-a", "server-a", true},
		{"mismatch", "server-a", "server-b", false},
		{"expected empty skips check (token has aud)", "server-a", "", true},
		{"expected empty skips check (token empty aud)", "", "", true},
		// Token has empty aud but a concrete audience is required: must reject.
		{"empty token aud vs concrete expected", "", "server-a", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signAud(tc.tokenAud)
			_, err := Verify(pub, tok, tc.expectAud, now)
			if tc.ok && err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected audience rejection")
			}
		})
	}
}

// --- KeyID ---------------------------------------------------------------------------

func TestKeyID(t *testing.T) {
	_, priv := newKey(t)
	now := at(2026)
	tok, _ := Sign(priv, "kid-xyz", sampleClaims(now))

	kid, err := KeyID(tok)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if kid != "kid-xyz" {
		t.Fatalf("kid = %q, want kid-xyz", kid)
	}
}

func TestKeyIDEmptyWhenAbsent(t *testing.T) {
	// Sign with an empty kid; header omits it (omitempty), KeyID returns "".
	_, priv := newKey(t)
	now := at(2026)
	tok, _ := Sign(priv, "", sampleClaims(now))
	kid, err := KeyID(tok)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if kid != "" {
		t.Fatalf("kid = %q, want empty", kid)
	}
}

func TestKeyIDMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"one segment", "abc"},
		{"two segments", "abc.def"},
		{"four segments", "a.b.c.d"},
		{"non-base64 header", "!!!.b.c"},
		{"non-json header", enc([]byte("not json")) + ".b.c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := KeyID(tc.raw); err == nil {
				t.Fatalf("expected error from KeyID(%q)", tc.raw)
			}
		})
	}
}

// --- ToClaims / ToPassport round-trip ----------------------------------------------

func TestToClaimsToPassportRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   types.Passport
	}{
		{
			name: "without budget",
			in: types.Passport{
				ID:          "jti-1",
				PrincipalID: "principal-1",
				AgentID:     "agent-1",
				Audience:    "server-a",
				Scope:       types.Scope{Tools: []string{"read", "list"}},
				IssuedAt:    at(2026),
				ExpiresAt:   at(2026).Add(2 * time.Minute),
			},
		},
		{
			name: "with budget",
			in: types.Passport{
				ID:          "jti-2",
				PrincipalID: "principal-2",
				AgentID:     "agent-2",
				Audience:    "server-b",
				Scope:       types.Scope{Tools: []string{"write"}, Budget: &types.Budget{Limit: 100, Unit: "usd"}},
				IssuedAt:    at(2026),
				ExpiresAt:   at(2026).Add(time.Minute),
			},
		},
		{
			name: "no agent, empty scope",
			in: types.Passport{
				ID:          "jti-3",
				PrincipalID: "principal-3",
				Audience:    "server-c",
				IssuedAt:    at(2026),
				ExpiresAt:   at(2026).Add(time.Minute),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ToClaims(tc.in, "sanad").ToPassport()

			if got.ID != tc.in.ID || got.PrincipalID != tc.in.PrincipalID ||
				got.AgentID != tc.in.AgentID || got.Audience != tc.in.Audience {
				t.Fatalf("identity fields did not round-trip: %+v vs %+v", got, tc.in)
			}
			if !got.IssuedAt.Equal(tc.in.IssuedAt) || !got.ExpiresAt.Equal(tc.in.ExpiresAt) {
				t.Fatalf("times did not round-trip: got iat=%v exp=%v", got.IssuedAt, got.ExpiresAt)
			}
			if strings.Join(got.Scope.Tools, ",") != strings.Join(tc.in.Scope.Tools, ",") {
				t.Fatalf("tools did not round-trip: %v vs %v", got.Scope.Tools, tc.in.Scope.Tools)
			}

			// Budget is now carried in the wire Claims and must round-trip faithfully.
			switch {
			case tc.in.Scope.Budget == nil && got.Scope.Budget != nil:
				t.Fatalf("Budget appeared from nowhere: %+v", got.Scope.Budget)
			case tc.in.Scope.Budget != nil:
				if got.Scope.Budget == nil || *got.Scope.Budget != *tc.in.Scope.Budget {
					t.Fatalf("Budget did not round-trip: got %+v want %+v", got.Scope.Budget, tc.in.Scope.Budget)
				}
			}

			// Issuer is set on the Claims (not back on the Passport).
			if iss := ToClaims(tc.in, "sanad").Issuer; iss != "sanad" {
				t.Fatalf("issuer = %q, want sanad", iss)
			}
		})
	}
}

// TestToClaimsToPassportCarriesDelegation is the inverse of the loss this codec used to
// document: the delegation must reach the resource server, or "a signed chain from the
// accountable human to the action" stops at the gateway's own log.
//
// What crosses is the summary — the ordered path plus a digest of the full signed chain —
// not the hops themselves; see types.DelegationRef for why. So the assertions are: the path
// arrives intact, it is anchored at the principal and the acting agent, and the digest still
// identifies the exact chain it was minted from.
func TestToClaimsToPassportCarriesDelegation(t *testing.T) {
	chain := &types.DelegationChain{Hops: []types.DelegationHop{
		{Delegator: "p", Delegate: "a", Scope: types.Scope{Tools: []string{"read", "write"}}, Signature: []byte("sig-1")},
		{Delegator: "a", Delegate: "sub", Scope: types.Scope{Tools: []string{"read"}}, Signature: []byte("sig-2")},
	}}
	in := types.Passport{
		ID:          "jti-d",
		PrincipalID: "p",
		AgentID:     "sub",
		Audience:    "server-a",
		Scope:       types.Scope{Tools: []string{"read"}},
		Delegation:  chain,
		IssuedAt:    at(2026),
		ExpiresAt:   at(2026).Add(time.Minute),
	}

	got := ToClaims(in, "iss").ToPassport()
	if got.DelegationRef == nil {
		t.Fatal("the delegation was dropped: the resource server cannot see who delegated what to whom")
	}
	want := []string{"p", "a", "sub"}
	if strings.Join(got.DelegationRef.Path, ",") != strings.Join(want, ",") {
		t.Fatalf("delegation path = %v, want %v", got.DelegationRef.Path, want)
	}
	// The path must be anchored at both ends by claims the server already trusts, or it is
	// an unattached list of names.
	if got.DelegationRef.Path[0] != got.PrincipalID {
		t.Fatalf("path root %q is not the accountable principal %q", got.DelegationRef.Path[0], got.PrincipalID)
	}
	if last := got.DelegationRef.Path[len(got.DelegationRef.Path)-1]; last != got.AgentID {
		t.Fatalf("path ends at %q, not the acting agent %q", last, got.AgentID)
	}
	// The digest ties the passport to that exact chain and no other.
	if !chain.Matches(got.DelegationRef) {
		t.Fatalf("digest does not identify the chain it was minted from: %+v", got.DelegationRef)
	}
	altered := &types.DelegationChain{Hops: []types.DelegationHop{
		{Delegator: "p", Delegate: "a", Scope: types.Scope{Tools: []string{"read", "write"}}, Signature: []byte("sig-1")},
		{Delegator: "a", Delegate: "sub", Scope: types.Scope{Tools: []string{"read", "delete"}}, Signature: []byte("sig-2")},
	}}
	if altered.Matches(got.DelegationRef) {
		t.Fatal("a chain with a widened hop must not match the passport's digest")
	}

	// Re-encoding a passport that came back off the wire is stable: it still carries the
	// summary it arrived with, rather than losing it for want of a full chain.
	again := ToClaims(got, "iss").ToPassport()
	if again.DelegationRef == nil || again.DelegationRef.Digest != got.DelegationRef.Digest {
		t.Fatalf("re-encode lost the delegation: %+v", again.DelegationRef)
	}
}

// TestToClaimsNoDelegationOmitsTheClaim: a passport with no chain must not grow an empty
// `dlg` object, which would read as "there was a delegation" to anything inspecting it.
func TestToClaimsNoDelegationOmitsTheClaim(t *testing.T) {
	for name, in := range map[string]types.Passport{
		"nil chain":   {ID: "j", PrincipalID: "p", Audience: "a"},
		"empty chain": {ID: "j", PrincipalID: "p", Audience: "a", Delegation: &types.DelegationChain{}},
	} {
		t.Run(name, func(t *testing.T) {
			c := ToClaims(in, "iss")
			if c.Delegation != nil {
				t.Fatalf("dlg = %+v, want absent", c.Delegation)
			}
			pb, _ := json.Marshal(c)
			if strings.Contains(string(pb), "dlg") {
				t.Fatalf("dlg must be omitted from the wire form, got %s", pb)
			}
		})
	}
}

// TestSignVerifyPreservesNilVsEmptyTools is a small fidelity check: a passport with no
// tools should not gain or lose a scope after a full sign/verify cycle.
func TestSignVerifyEmptyTools(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	c := sampleClaims(now)
	c.Tools = nil
	tok, err := Sign(priv, "kid-1", c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(pub, tok, "server-a", now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(got.Tools) != 0 {
		t.Fatalf("expected no tools, got %v", got.Tools)
	}
}
