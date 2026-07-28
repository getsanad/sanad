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
// Each block carries the public key authorized to sign the next block, and is itself signed
// by the previous block's next-key (the root key signs block 0), over its own index and the
// previous block's signature — so a block is fixed to one position in one capability under
// one root, exactly as Chain's prevSig fixes a hop. To *use* a capability the presenter must
// additionally prove possession of the final next-key on the request (HolderProof).
//
// # Why there is a Seal
//
// Block signatures chain forwards, and a forward chain cannot see its own tail being cut
// off: every PREFIX of a valid capability is itself a valid capability, and the shortest
// prefix carries the broadest grant. So a recipient handed a token narrowed to ["read"]
// could drop the last block and present the parent's ["read","write"] — well-formed, fully
// verifying, and broader than anything they were given. Chaining the previous signature into
// each block (as Chain does with prevSig) does not close that, because the prefix is not
// altered by the truncation; nothing in a block can commit to a block that did not exist
// when it was signed. The commitment has to come from the END. The Seal is it: a signature
// by the final next-key over how many blocks there are, which only the current holder can
// produce and which no prefix satisfies. It is the same move audit/merkle.go makes for the
// same reason — a hash chain detects rewriting but not tail-truncation, so the length is
// committed to separately.
//
// The Seal is NOT a substitute for VerifyHolder and not a proof of entitlement: it travels
// with the token, so anyone who copies the token copies the seal. It answers "is this the
// whole capability", where HolderProof answers "is the presenter its holder, on THIS
// request". Verify needs the first to be safe on its own; a decision needs both.
type Capability struct {
	Blocks []Block `json:"blocks"`
	Seal   []byte  `json:"seal"`
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
	rootPub := rootPriv.Public().(ed25519.PublicKey)
	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Capability{}, nil, err
	}
	sig := sigctx.Sign(sigctx.CapabilityBlock, rootPriv, blockMsg(rootPub, 0, nil, g, nextPub))
	blocks := []Block{{Grant: g, NextPub: nextPub, Signature: sig}}
	return Capability{Blocks: blocks, Seal: seal(nextPriv, rootPub, blocks)}, nextPriv, nil
}

// Attenuate appends a narrowed block signed with the current holder secret, returning the
// new token and the new holder secret. Narrowing is enforced locally (and re-checked by
// Verify). It runs entirely offline.
//
// It re-seals: the seal commits to the block count, so the old one is void the moment a
// block is appended. rootPub has to be passed in because a capability does not carry its own
// trust anchor — it is the one thing the verifier supplies — and every block signature, seal
// included, is bound to it.
func (c Capability) Attenuate(rootPub ed25519.PublicKey, holderSecret ed25519.PrivateKey, g Grant) (Capability, ed25519.PrivateKey, error) {
	if len(c.Blocks) == 0 {
		return Capability{}, nil, errors.New("delegation: empty capability")
	}
	if len(c.Blocks)+1 > MaxDepth {
		return Capability{}, nil, fmt.Errorf("%w: attenuating would make %d blocks, the maximum is %d", ErrTooDeep, len(c.Blocks)+1, MaxDepth)
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
	sig := sigctx.Sign(sigctx.CapabilityBlock, holderSecret, blockMsg(rootPub, len(c.Blocks), last.Signature, g, nextPub))
	blocks := append(append([]Block(nil), c.Blocks...), Block{Grant: g, NextPub: nextPub, Signature: sig})
	return Capability{Blocks: blocks, Seal: seal(nextPriv, rootPub, blocks)}, nextPriv, nil
}

// Verify checks the capability against the root public key (the only trust anchor) and
// returns the effective (most-narrowed) grant. It is fully offline.
//
// The depth ceiling is checked FIRST, before any signature: a capability is presented in a
// header by an unauthenticated caller, so the block count is attacker-chosen and must not be
// allowed to choose how much work this does (see MaxDepth).
//
// NOTE: for an access decision, pair this with VerifyHolder — Verify proves the token is
// whole, well-formed and attenuating, not that the PRESENTER is entitled to wield it.
func (c Capability) Verify(rootPub ed25519.PublicKey, now time.Time, opts ...VerifyOption) (Grant, error) {
	if len(c.Blocks) == 0 {
		return Grant{}, errors.New("delegation: empty capability")
	}
	if limit := newVerifyOptions(opts).maxDepth; len(c.Blocks) > limit {
		return Grant{}, fmt.Errorf("%w: capability has %d blocks, the maximum is %d", ErrTooDeep, len(c.Blocks), limit)
	}
	signer := rootPub
	var prevSig []byte
	var prevGrant Grant
	for i, b := range c.Blocks {
		if len(b.NextPub) != ed25519.PublicKeySize {
			return Grant{}, fmt.Errorf("delegation: block %d has an invalid next key", i)
		}
		if !sigctx.Verify(sigctx.CapabilityBlock, signer, blockMsg(rootPub, i, prevSig, b.Grant, b.NextPub), b.Signature) {
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
		prevSig = b.Signature
		prevGrant = b.Grant
	}
	// Last, because the key it verifies against is the final next-key, and that key is only
	// authenticated by the loop above. This is the check that makes a truncated capability
	// fail: a prefix's seal would have to be made by an earlier next-secret, which is held by
	// the party who attenuated, not by the recipient who was handed the narrowed token.
	if !sigctx.Verify(sigctx.CapabilitySeal, signer, sealMsg(rootPub, len(c.Blocks), prevSig), c.Seal) {
		return Grant{}, errors.New("delegation: capability seal is missing or invalid (a truncated capability cannot be re-sealed)")
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

// DecodeCapability parses a capability from its transport form. Like DecodeChain it refuses
// an over-long token at the transport boundary, before it reaches any verification.
func DecodeCapability(s string) (Capability, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Capability{}, fmt.Errorf("delegation: bad capability encoding: %w", err)
	}
	var c Capability
	if err := json.Unmarshal(b, &c); err != nil {
		return Capability{}, fmt.Errorf("delegation: bad capability: %w", err)
	}
	if len(c.Blocks) > MaxDepth {
		return Capability{}, fmt.Errorf("%w: capability has %d blocks, the maximum is %d", ErrTooDeep, len(c.Blocks), MaxDepth)
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
		grant, err := c.Verify(rootPub, time.Now(), o.verify...)
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

// blockMsg is the signing input for one block. It commits to everything that fixes the
// block's PLACE as well as its content: the root key the capability hangs from, the block's
// index, and the previous block's signature (nil for block 0, where the signer is the root
// key itself). That is the same chaining Chain.canonical gets from prevSig, and it is what
// makes a block un-reorderable and un-graftable: a block signed as "block 2 of the
// capability whose block 1 signature was S, anchored at root R" verifies nowhere else.
//
// It is JSON rather than a concatenation because the parts are variable-length: prevSig ||
// nextPub and a longer prevSig with a shorter nextPub would otherwise be the same bytes.
// (The v1 encoding was grantCanonical(g) || nextPub, which was unambiguous only because
// nextPub had a fixed size — a property that does not survive adding a field.)
func blockMsg(rootPub ed25519.PublicKey, index int, prevSig []byte, g Grant, nextPub ed25519.PublicKey) []byte {
	b, _ := json.Marshal(struct {
		Root  []byte          `json:"root"`
		Index int             `json:"i"`
		Prev  []byte          `json:"prev,omitempty"`
		Grant json.RawMessage `json:"grant"`
		Next  []byte          `json:"next"`
	}{rootPub, index, prevSig, grantCanonical(g), nextPub})
	return b
}

// seal signs the capability's length with the final next-secret. See Capability's doc
// comment for why the length needs its own commitment.
func seal(nextPriv ed25519.PrivateKey, rootPub ed25519.PublicKey, blocks []Block) []byte {
	return sigctx.Sign(sigctx.CapabilitySeal, nextPriv, sealMsg(rootPub, len(blocks), blocks[len(blocks)-1].Signature))
}

// sealMsg is the signing input for the seal: the trust anchor, the number of blocks, and the
// last block's signature. The last signature already commits to every block before it
// (blockMsg chains them), so those two values pin the capability exactly — a prefix has a
// different count AND a different final signature.
func sealMsg(rootPub ed25519.PublicKey, blocks int, lastSig []byte) []byte {
	b, _ := json.Marshal(struct {
		Root   []byte `json:"root"`
		Blocks int    `json:"n"`
		Last   []byte `json:"last"`
	}{rootPub, blocks, lastSig})
	return b
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
