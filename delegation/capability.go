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
	"sort"
	"strings"
	"time"

	"github.com/getsanad/sanad/gateway"
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
	sig := ed25519.Sign(rootPriv, blockMsg(g, nextPub))
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
	sig := ed25519.Sign(holderSecret, blockMsg(g, nextPub))
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
		if !ed25519.Verify(signer, blockMsg(b.Grant, b.NextPub), b.Signature) {
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

// HolderProof signs msg with the holder secret to prove possession of the capability.
func HolderProof(holderSecret ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(holderSecret, msg)
}

// VerifyHolder checks a holder proof over msg against the capability's final next-key.
func (c Capability) VerifyHolder(msg, proof []byte) bool {
	if len(c.Blocks) == 0 {
		return false
	}
	return ed25519.Verify(c.Blocks[len(c.Blocks)-1].NextPub, msg, proof)
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
// verifies a presented capability against rootPub and a holder proof over the principal's
// bearer token, then narrows the request scope to the effective grant. Fails closed. A
// request with no capability lets the principal act directly unless WithRequireChain is
// set, which rejects it.
func CapabilityStage(rootPub ed25519.PublicKey, opts ...StageOption) gateway.Stage {
	o := newStageOptions(opts)
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
		token := bearer(req.HTTP)
		proof, err := base64.RawURLEncoding.DecodeString(req.HTTP.Header.Get(HeaderCapabilityProof))
		if err != nil {
			return fmt.Errorf("delegation: bad capability proof: %w", err)
		}
		if token == "" || !c.VerifyHolder([]byte(token), proof) {
			return errors.New("delegation: capability holder proof failed")
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
