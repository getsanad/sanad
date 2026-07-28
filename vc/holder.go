package vc

import (
	"crypto/ed25519"
	"net/url"
	"time"

	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
)

// HeaderPrincipalProof carries the holder binding: the presenter's proof of possession of
// the credential subject's did:key private key, bound to this request. It is the principal's
// counterpart to workload.HeaderProof (the agent instance) and
// delegation.HeaderCapabilityProof (the capability holder).
const HeaderPrincipalProof = "X-Principal-Proof"

// HolderProof is what the holder of a principal credential presents alongside it: a
// signature, with the SUBJECT's did:key private key, over this request's binding — method,
// target, a hash of the body, a hash of the credential being presented, a creation time and a
// unique id.
//
// credential is the exact string sent as the bearer token, so the proof commits to the
// credential it accompanies (RFC 9449's `ath`). It is not enough to prove possession of some
// key: the statement has to be "I hold the subject key of THIS credential, and I am making
// THIS request".
//
// # Why not a VerifiablePresentation with a server-issued challenge
//
// The W3C way to say this is a VerifiablePresentation: wrap the credential, sign the wrapper
// with the subject's key, set proofPurpose to `authentication`, and cover a `challenge` the
// verifier issued plus a `domain`. That is the conventional construction and it was the
// starting point; it is not what this does, for three reasons.
//
// A server-issued challenge needs server state. The gateway's hot path is stateless by
// design: the caller either arrives with everything needed to decide, or it takes a round
// trip to fetch a nonce first. A nonce endpoint doubles the request count on every call and
// adds a shared, replicated nonce table to a path NFR-1 caps at ~50ms p95 — the same
// trade the enrollment path DOES accept, because enrollment happens once per instance
// lifetime rather than once per tool call. RFC 9449 §11.1 makes exactly this argument for
// DPoP and settles on a client-chosen `jti` plus a tight `iat` window, which is what
// internal/pop already implements, replay cache and all.
//
// A challenge is also weaker than what is already here. A challenge proves freshness and
// nothing else: a presentation replayed within its window still authorizes any request, since
// the challenge says nothing about the method, the path or the body. In MCP streamable HTTP
// every JSON-RPC message is POSTed to one endpoint, so "some request from this principal,
// recently" is close to no constraint at all. The request binding covers the request, and the
// jti gives the freshness the challenge would have given.
//
// And it is one construction rather than two. The instance proof, the capability holder proof
// and this proof are now the same payload under three sigctx labels. That is one wire format
// to implement in Go, TypeScript and Python, one replay cache to reason about, and one place
// for a bug — instead of a second serialization (JSON-LD proof sets over a VP graph) that the
// SDKs would have to reproduce byte-for-byte and that this package does not canonicalize
// anyway (see the package doc).
//
// What is given up is spec conformance for the presentation object, which is given up
// already for the credential's proof, and is stated rather than papered over. The semantics
// are preserved exactly: sigctx.VCHolderProof IS the proofPurpose, the request binding IS the
// challenge and domain, and the credential hash IS the presented credential.
func HolderProof(principalKey ed25519.PrivateKey, method, target, credential string, body []byte) (string, error) {
	b, err := pop.NewBinding(method, target, credential, body, time.Now())
	if err != nil {
		return "", err
	}
	return pop.Sign(sigctx.VCHolderProof, principalKey, b)
}

// ProofTarget is the htu value to sign for a request URL: the origin-form target the gateway
// will see. It is workload.ProofTarget under another name, exported here so a caller holding
// only a principal key does not have to import the workload package to build a proof.
func ProofTarget(u *url.URL) string { return pop.Target(u) }
