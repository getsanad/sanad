// Package passport implements the hardened EdDSA-JWS encoding of an Sanad
// (ADR-002): the short-lived, audience-bound, task-scoped credential the gateway mints
// and an MCP server verifies offline (PRD FR-7, FR-9, SEC-2).
//
// The algorithm is pinned to Ed25519. The token's `alg` header is validated for hygiene
// but is NEVER used to select a verification algorithm — Ed25519 is always used — so
// `alg:none` and RS256↔HS256 confusion attacks are impossible by construction.
//
// Domain separation. Every other signature in Sanad is tagged with an explicit context label
// (internal/sigctx); the passport deliberately is not, because it is already separated twice
// over and wrapping it would break the JWS. Structurally, the signing input is a JWS with an
// explicit type — `typ:"passport+jwt"` — which Verify enforces, the explicit-typing defence
// RFC 8725 §3.11 prescribes for exactly this problem; a signature over some other JWT cannot
// be a passport, because its header decodes to a different typ. Encoding-wise, a JWS signing
// input is ASCII base64url with a '.' separator, while a sigctx input begins with an 8-byte
// big-endian length whose leading bytes are NUL — no byte string is both, so the two spaces
// are disjoint and a passport signature can never be replayed as a delegation hop, capability
// block or checkpoint (or the reverse). Adding a sigctx wrapper here would buy nothing and
// would make passports unverifiable by the standard JOSE libraries the MCP servers that
// verify them offline are expected to use.
package passport

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// alg is the only permitted signature algorithm (ADR-002). typ tags the token kind.
const (
	alg = "EdDSA"
	typ = "passport+jwt"
)

// header is the JWS header. We emit alg/typ (and kid for rotation) but never trust the
// inbound alg to choose a verifier.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Claims is the on-the-wire passport payload: a deliberately small JWT claim set.
//
// `dlg` is the delegation chain (PRD FR-10), and it is a SUMMARY — the ordered path of
// parties plus a digest of the full signed chain — not the chain itself. A passport is sent
// on every request, so the claim set is sized for the hot path: see types.DelegationRef for
// what the resource server can and cannot conclude from it, and why the hop signatures are
// not here.
type Claims struct {
	ID         string               `json:"jti"`
	Issuer     string               `json:"iss"`
	Principal  string               `json:"sub"`
	Audience   string               `json:"aud"` // single target MCP server (SEC-2)
	Agent      string               `json:"agent,omitempty"`
	Tools      []string             `json:"scope,omitempty"`
	Budget     *types.Budget        `json:"budget,omitempty"` // granted/attenuated budget (FR-11)
	Delegation *types.DelegationRef `json:"dlg,omitempty"`    // delegation path + chain digest (FR-10)
	IssuedAt   int64                `json:"iat"`
	ExpiresAt  int64                `json:"exp"`
}

// Sign encodes claims as a compact JWS signed with priv (Ed25519). kid is embedded so
// the verifier can resolve the right key from a JWKS during rotation (P1-05/P1-12).
func Sign(priv ed25519.PrivateKey, kid string, c Claims) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("passport: invalid Ed25519 private key")
	}
	return SignWith(kid, c, func(msg []byte) ([]byte, error) { return ed25519.Sign(priv, msg), nil })
}

// SignWith builds the compact JWS and obtains the signature from sign, which signs the
// signing input bytes. This is the seam for KMS/HSM-backed signing (SEC-4): the private
// key never needs to be in this process — sign forwards the bytes to the KMS/HSM.
func SignWith(kid string, c Claims, sign func(msg []byte) ([]byte, error)) (string, error) {
	hb, err := json.Marshal(header{Alg: alg, Typ: typ, Kid: kid})
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64(hb) + "." + b64(pb)
	sig, err := sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64(sig), nil
}

// Verify checks the signature with pub (Ed25519), enforces the pinned algorithm, and
// validates audience and expiry against now. expectedAudience must match the passport's
// `aud` (pass "" only in tests/tools that intentionally skip the audience check).
func Verify(pub ed25519.PublicKey, raw, expectedAudience string, now time.Time) (Claims, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Claims{}, errors.New("passport: invalid Ed25519 public key")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("passport: malformed token")
	}

	hb, err := unb64(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("passport: bad header encoding: %w", err)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, fmt.Errorf("passport: bad header: %w", err)
	}
	// Pinned-algorithm check. We reject anything that isn't EdDSA outright; we do NOT
	// switch verifier based on this value (that is the whole point — see package doc).
	if h.Alg != alg {
		return Claims{}, fmt.Errorf("passport: unexpected alg %q (only %s permitted)", h.Alg, alg)
	}
	// Enforce the token type to resist cross-token-type confusion (defense in depth).
	if h.Typ != typ {
		return Claims{}, fmt.Errorf("passport: unexpected typ %q (only %s permitted)", h.Typ, typ)
	}

	sig, err := unb64(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("passport: bad signature encoding: %w", err)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return Claims{}, errors.New("passport: signature verification failed")
	}

	pb, err := unb64(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("passport: bad payload encoding: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Claims{}, fmt.Errorf("passport: bad payload: %w", err)
	}

	if expectedAudience != "" && c.Audience != expectedAudience {
		return Claims{}, fmt.Errorf("passport: wrong audience %q (want %q)", c.Audience, expectedAudience)
	}
	if now.Unix() >= c.ExpiresAt {
		return Claims{}, errors.New("passport: expired")
	}
	return c, nil
}

// KeyID returns the `kid` from a compact JWS header WITHOUT verifying the token. The
// verifier uses it only to select which key to verify against; the token is still fully
// verified by Verify afterwards.
func KeyID(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("passport: malformed token")
	}
	hb, err := unb64(parts[0])
	if err != nil {
		return "", fmt.Errorf("passport: bad header encoding: %w", err)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return "", fmt.Errorf("passport: bad header: %w", err)
	}
	return h.Kid, nil
}

// ToClaims maps a types.Passport into wire claims under the given issuer.
//
// The delegation is summarized, not copied: a passport minted gateway-side carries the full
// verified chain, and `dlg` gets its path + digest. A passport that came back off the wire
// already has only the summary, so it is carried through unchanged and re-encoding is
// stable.
func ToClaims(p types.Passport, issuer string) Claims {
	ref := p.DelegationRef
	if summary := p.Delegation.Ref(); summary != nil {
		ref = summary
	}
	return Claims{
		ID:         p.ID,
		Issuer:     issuer,
		Principal:  p.PrincipalID,
		Audience:   p.Audience,
		Agent:      p.AgentID,
		Tools:      p.Scope.Tools,
		Budget:     p.Scope.Budget,
		Delegation: ref,
		IssuedAt:   p.IssuedAt.Unix(),
		ExpiresAt:  p.ExpiresAt.Unix(),
	}
}

// ToPassport maps wire claims back into a types.Passport (used by the verify library).
// Delegation lands on DelegationRef, never on Delegation: the token carries the path and a
// digest, so reconstructing a *DelegationChain here would fabricate hops whose empty
// Signature fields would read as verified-and-unsigned.
func (c Claims) ToPassport() types.Passport {
	return types.Passport{
		ID:            c.ID,
		PrincipalID:   c.Principal,
		AgentID:       c.Agent,
		Audience:      c.Audience,
		Scope:         types.Scope{Tools: c.Tools, Budget: c.Budget},
		DelegationRef: c.Delegation,
		IssuedAt:      time.Unix(c.IssuedAt, 0).UTC(),
		ExpiresAt:     time.Unix(c.ExpiresAt, 0).UTC(),
	}
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
