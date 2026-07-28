package delegation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

// Capability is an offline-attenuable delegation token (Biscuit-style, PRD FR-12b /
// ADR-002). Unlike Chain — which needs every delegator's key in a registry — a Capability
// verifies against a SINGLE root public key and can be narrowed by its holder OFFLINE,
// with no issuer contact, so it works across trust boundaries.
//
// Each block carries the public key authorized to sign the next block, and is itself
// signed by the previous block's next-key (the root key signs block 0). Thus only the root
// key is a trust anchor; every later key is authenticated by the chain. To *use* a
// capability the presenter must also prove possession of the final next-key (HolderProof),
// which is what prevents a recipient from broadening it: they lack the earlier next-secrets.
type Capability struct {
	Blocks []Block `json:"blocks"`
}

// Block is one segment of a Capability.
type Block struct {
	Grant     Grant             `json:"grant"`
	NextPub   ed25519.PublicKey `json:"next"`
	Signature []byte            `json:"sig"`
}

// NewCapability mints a root capability granting g, signed by the root key. It returns the
// token and the holder secret needed to attenuate or use it.
func NewCapability(rootPriv ed25519.PrivateKey, g Grant) (Capability, ed25519.PrivateKey, error) {
	if len(rootPriv) != ed25519.PrivateKeySize {
		return Capability{}, nil, errors.New("delegation: invalid root key")
	}
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Capability{}, nil, err
	}
	sig := sigctx.Sign(sigctx.CapabilityBlock, rootPriv, blockMsg(g, nextPub))
	return Capability{Blocks: []Block{{Grant: g, NextPub: nextPub, Signature: sig}}}, nextPriv, nil
}

// Attenuate appends a narrowed block signed with the current holder secret, returning the
// new token and the new holder secret. Narrowing is enforced locally (and re-checked by
// Verify). It runs entirely offline.
func (c Capability) Attenuate(holderSecret ed25519.PrivateKey, g Grant) (Capability, ed25519.PrivateKey, error) {
	if len(c.Blocks) == 0 {
		return Capability{}, nil, errors.New("delegation: empty capability")
	}
	last := c.Blocks[len(c.Blocks)-1]
	if !holderSecret.Public().(ed25519.PublicKey).Equal(last.NextPub) {
		return Capability{}, nil, errors.New("delegation: holder secret does not match the capability")
	}
	if err := attenuates(last.Grant, g); err != nil {
		return Capability{}, nil, fmt.Errorf("delegation: attenuation: %w", err)
	}
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Capability{}, nil, err
	}
	sig := sigctx.Sign(sigctx.CapabilityBlock, holderSecret, blockMsg(g, nextPub))
	blocks := append(append([]Block(nil), c.Blocks...), Block{Grant: g, NextPub: nextPub, Signature: sig})
	return Capability{Blocks: blocks}, nextPriv, nil
}

// Verify checks the capability against the root public key (the only trust anchor) and
// returns the effective (most-narrowed) grant. It is fully offline. NOTE: for an access
// decision, pair this with VerifyHolder — Verify alone proves the token is well-formed and
// attenuating, not that the presenter is entitled to wield it.
func (c Capability) Verify(rootPub ed25519.PublicKey, now time.Time) (Grant, error) {
	if len(c.Blocks) == 0 {
		return Grant{}, errors.New("delegation: empty capability")
	}
	signer := rootPub
	var prevGrant Grant
	for i, b := range c.Blocks {
		if len(b.NextPub) != ed25519.PublicKeySize {
			return Grant{}, fmt.Errorf("delegation: block %d has an invalid next key", i)
		}
		if !sigctx.Verify(sigctx.CapabilityBlock, signer, blockMsg(b.Grant, b.NextPub), b.Signature) {
			return Grant{}, fmt.Errorf("delegation: capability block %d has an invalid signature", i)
		}
		if i > 0 {
			if err := attenuates(prevGrant, b.Grant); err != nil {
				return Grant{}, fmt.Errorf("delegation: capability block %d widens scope: %w", i, err)
			}
		}
		if !b.Grant.NotAfter.IsZero() && !now.Before(b.Grant.NotAfter) {
			return Grant{}, fmt.Errorf("delegation: capability block %d has expired", i)
		}
		signer = b.NextPub
		prevGrant = b.Grant
	}
	return c.Blocks[len(c.Blocks)-1].Grant, nil
}

// HolderProof produces the proof that the presenter holds this capability, bound to ONE
// request: method, target, a hash of the body, a hash of the principal bearer token, a
// creation time and a unique id. It is the same construction as workload.Proof — DPoP
// (RFC 9449) in Sanad's signature format — for the same reason.
//
// The reason applies here in full. A holder proof over the bare principal token is one fixed
// value for that token's lifetime, so a captured X-Agent-Capability-Proof, paired with the
// X-Agent-Capability sitting next to it in the same headers, let anyone wield the capability
// — which is precisely the property VerifyHolder exists to deny (Capability's doc comment:
// a recipient cannot broaden a capability because they lack the earlier next-secrets; that
// argument is worth nothing if the proof they DO need is copyable off the wire).
//
// It is domain-separated from block signatures (sigctx.CapabilityHolderProof vs
// CapabilityBlock) because the holder secret signs both: it proves possession here and signs
// the next block in Attenuate. Untagged, proving possession over caller-supplied bytes is a
// signing oracle for blocks — feed it the bytes of blockMsg and the proof comes back as a
// valid attenuation, letting whoever chose the message re-point the capability at their own key.
func HolderProof(holderSecret ed25519.PrivateKey, method, target, principalToken string, body []byte) (string, error) {
	b, err := pop.NewBinding(method, target, principalToken, body, time.Now())
	if err != nil {
		return "", err
	}
	return pop.Sign(sigctx.CapabilityHolderProof, holderSecret, b)
}

// ProofTarget is the htu value to sign for a request URL: the origin-form target the gateway
// will see. It is the same string workload.ProofTarget returns — one definition, in
// internal/pop — re-exported here so neither package has to import the other.
func ProofTarget(u *url.URL) string { return pop.Target(u) }

// HolderProofVerifier checks holder proofs: the signature, the request binding it commits to,
// the freshness window, and the replay cache. It is an ALIAS of the shared implementation in
// internal/pop, so the capability side and the instance side (workload.InstanceStage) cannot
// drift into two different readings of the same wire format.
type HolderProofVerifier = pop.Verifier

// NewHolderProofVerifier returns the verifier CapabilityStage uses. Each one owns its replay
// cache, which is per-process — see pop.ReplayCache.
func NewHolderProofVerifier(opts ...StageOption) *HolderProofVerifier {
	return pop.NewVerifier(sigctx.CapabilityHolderProof, newStageOptions(opts).proof...)
}

// VerifyHolder checks a holder proof against the capability's final next-key and the request
// it arrived on. body is the buffered request body (nil when there is none) and token the
// principal bearer token the proof must accompany. It returns an error rather than a bool
// because "why" now has several answers — wrong key, wrong request, stale, replayed — and a
// denial that cannot say which is not debuggable.
func (c Capability) VerifyHolder(v *HolderProofVerifier, proof string, r *http.Request, body []byte, token string) error {
	if len(c.Blocks) == 0 {
		return errors.New("delegation: empty capability")
	}
	if v == nil {
		return errors.New("delegation: no holder proof verifier")
	}
	return v.Check(c.Blocks[len(c.Blocks)-1].NextPub, proof, r, body, token)
}

// EncodeCapability serializes a capability for transport.
func EncodeCapability(c Capability) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeCapability parses a capability from its transport form.
func DecodeCapability(s string) (Capability, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Capability{}, fmt.Errorf("delegation: bad capability encoding: %w", err)
	}
	var c Capability
	if err := json.Unmarshal(b, &c); err != nil {
		return Capability{}, fmt.Errorf("delegation: bad capability: %w", err)
	}
	return c, nil
}

// Headers the SDK uses to present an offline capability.
const (
	HeaderCapability      = "X-Agent-Capability"
	HeaderCapabilityProof = "X-Agent-Capability-Proof"
)

// CapabilityStage is the offline delegation mode (FR-12b): an alternative to Stage. It
// verifies a presented capability against rootPub and a holder proof bound to THIS request,
// then narrows the request scope to the effective grant. Fails closed. A request with no
// capability lets the principal act directly unless WithRequireChain is set, which rejects it.
func CapabilityStage(rootPub ed25519.PublicKey, opts ...StageOption) gateway.Stage {
	o := newStageOptions(opts)
	verifier := pop.NewVerifier(sigctx.CapabilityHolderProof, o.proof...)
	return gateway.NewStage("capability", func(_ context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("delegation: no authenticated principal")
		}
		if req.HTTP == nil {
			return errors.New("delegation: no request")
		}
		raw := req.HTTP.Header.Get(HeaderCapability)
		if raw == "" {
			if o.requireChain {
				return errors.New("delegation: no capability presented (a capability is required)")
			}
			return nil // no capability presented; principal acts directly
		}
		c, err := DecodeCapability(raw)
		if err != nil {
			return err
		}
		grant, err := c.Verify(rootPub, time.Now())
		if err != nil {
			return err
		}
		// Same rule as workload.InstanceStage: a body the gateway did not buffer is a body no
		// proof committed to, and it is refused rather than authorized on a partial binding.
		if req.Body == nil && req.HTTP.ContentLength != 0 && req.HTTP.Body != nil && req.HTTP.Body != http.NoBody {
			return errors.New("delegation: request carries a body the capability holder proof cannot cover")
		}
		// Exactly one proof header, per RFC 9449 §4.3 step 1 — see workload.InstanceStage for
		// why taking the first of several silently is a parser differential.
		if n := len(req.HTTP.Header.Values(HeaderCapabilityProof)); n != 1 {
			return fmt.Errorf("delegation: expected exactly one %s header, got %d", HeaderCapabilityProof, n)
		}
		if err := c.VerifyHolder(verifier, req.HTTP.Header.Get(HeaderCapabilityProof), req.HTTP, req.Body, bearer(req.HTTP)); err != nil {
			return fmt.Errorf("delegation: capability holder proof failed: %w", err)
		}
		if err := checkServer(grant, req); err != nil {
			return err // fail closed
		}
		req.Scope = grant.Scope()
		return nil
	})
}

// bearer extracts the Authorization bearer token (the principal credential), which the
// capability holder proof is computed over.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}

func blockMsg(g Grant, nextPub ed25519.PublicKey) []byte {
	return append(grantCanonical(g), nextPub...)
}

func grantCanonical(g Grant) []byte {
	var notAfter int64
	if !g.NotAfter.IsZero() {
		notAfter = g.NotAfter.Unix()
	}
	b, _ := json.Marshal(struct {
		Tools    []string      `json:"tools"`
		Servers  []string      `json:"servers"`
		NotAfter int64         `json:"not_after"`
		Budget   *types.Budget `json:"budget,omitempty"`
	}{sortedCopy(g.Tools), sortedCopy(g.Servers), notAfter, g.Budget})
	return b
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}
