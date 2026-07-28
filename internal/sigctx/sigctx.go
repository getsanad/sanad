// Package sigctx gives every signature in Sanad its own message space.
//
// One Ed25519 key here signs several different kinds of thing. An agent's instance key
// proves possession of itself over a request binding AND authenticates the delegation hops
// that agent signs; a capability holder secret signs the next capability block AND the holder
// proofs that wield the capability. With nothing in the bytes saying which is which, those
// are one signing oracle: a signature obtained for one purpose is simply accepted for the
// other. A proof of possession over attacker-chosen bytes is then also a valid delegation hop
// granting whatever those bytes encoded.
//
// So every signature commits to a context label naming what is being signed:
//
//	uint64be(len(ctx)) || ctx || msg
//
// The length prefix is what makes the encoding unambiguous. It fixes exactly where the label
// ends, so the byte string parses back to exactly one (ctx, msg) pair: the label can never be
// read as the head of a message, nor a message as the tail of a longer label. Plain ctx || msg
// would not do — ("ab", "c") and ("a", "bc") produce identical bytes — and a separator byte
// only works until a message contains it. Distinct labels therefore give disjoint message
// spaces, and a signature made under one context cannot verify under another for any key.
//
// Labels are versioned. Changing what a context covers means minting a vN+1 label rather than
// silently reinterpreting the old one, so stale signatures stop verifying instead of verifying
// against new semantics.
package sigctx

import (
	"crypto/ed25519"
	"encoding/binary"
)

// Context labels: one per distinct thing a key in this system signs. They must stay pairwise
// distinct (TestContextsAreDistinct enforces it) — that is the entire security property.
const (
	// InstanceProof is an agent instance proving possession of its workload key over a
	// request-bound proof payload (workload.Proof / InstanceStage). v2: v1 signed the bare
	// principal token, which is one deterministic value for the token's whole lifetime; v2
	// signs the method, target, body hash, token hash, iat and jti of one request (internal/pop).
	// The label moved so a captured v1 proof cannot be replayed against the new semantics —
	// it now verifies under no context at all.
	InstanceProof = "sanad/instance-proof/v2"

	// WorkloadCredential is the authority CA's signature over an issued workload credential
	// (workload.Authority.Issue / workload.Verify).
	WorkloadCredential = "sanad/workload-credential/v1"

	// AttestationQuote is the platform attestation key's signature over a measured-boot quote
	// (workload.SignQuote / MeasuredAttestor.Attest).
	AttestationQuote = "sanad/attestation-quote/v1"

	// BootstrapEvidence is the dev/self-host attestor's HMAC over the enrollment nonce and the
	// key being enrolled (workload.BootstrapEvidence). It is a MAC keyed by the bootstrap
	// token, not an Ed25519 signature, and carries its label inside its own canonical JSON
	// rather than through Message — see BootstrapEvidence for why. Listed here so every
	// context label in the system is registered in one place.
	BootstrapEvidence = "sanad/bootstrap-evidence/v1"

	// DelegationHop is a delegator's signature over one hop of a delegation chain
	// (delegation.NewRoot / Chain.Extend / Verify).
	DelegationHop = "sanad/delegation-hop/v1"

	// CapabilityBlock is the root or holder signature over one block of an offline capability
	// (delegation.NewCapability / Capability.Attenuate / Verify). v2: v1 signed only (grant,
	// nextPub), so a block was a free-floating object — nothing tied it to a position, to the
	// block before it, or to the root key it hung from. v2 signs the root key, the block index
	// and the previous block's signature as well, which is the same chaining Chain gets from
	// prevSig. The label moved because a v1 block signature is a valid signature over a
	// DIFFERENT statement than a v2 verifier reads it as; it now verifies under no context.
	CapabilityBlock = "sanad/capability-block/v2"

	// CapabilitySeal is the final holder's signature over the capability's own length
	// (delegation.NewCapability / Capability.Attenuate / Verify). Block signatures chain
	// forwards, and a forward chain cannot see its own tail being cut off — every prefix of a
	// valid capability is itself a valid capability. The seal is the commitment to where the
	// chain ENDS, and it must be its own context because the final next-secret already signs
	// two other things: the next block (CapabilityBlock) and holder proofs
	// (CapabilityHolderProof).
	CapabilitySeal = "sanad/capability-seal/v1"

	// CapabilityHolderProof is a capability holder proving possession of the final next-key
	// (delegation.HolderProof / Capability.VerifyHolder). v2 for the same reason as
	// InstanceProof: it is now a request-bound payload, not a signature over the bare token.
	CapabilityHolderProof = "sanad/capability-holder-proof/v2"

	// ExchangeToken is the exchange authority's signature over a centrally-issued delegation
	// token (delegation.ExchangeAuthority).
	ExchangeToken = "sanad/exchange-token/v1"

	// AuditCheckpoint is the log operator's signature over a transparency-log checkpoint
	// (audit.TransparencyLog.Checkpoint / VerifyCheckpoint).
	AuditCheckpoint = "sanad/audit-checkpoint/v1"

	// AuditWitness is a witness's co-signature over the same checkpoint (audit.Witness). It
	// must differ from AuditCheckpoint: co-signing the operator's exact bytes would let the
	// operator pass its own checkpoint signature off as independent corroboration.
	AuditWitness = "sanad/audit-witness/v1"

	// VCProof is a credential issuer's proof over a verifiable credential (vc.Issue / Verify).
	VCProof = "sanad/vc-proof/v1"

	// VCHolderProof is the PRESENTER of a principal credential proving possession of the
	// credential subject's did:key private key, over a request-bound payload (vc.HolderProof /
	// vc.Authenticator). It is the W3C `proofPurpose: authentication` of a verifiable
	// presentation, expressed as a label rather than as a JSON-LD term.
	//
	// It must differ from VCProof, and from DelegationHop: a principal's did:key signs all
	// three (it roots delegation chains, and a self-issued credential makes issuer and subject
	// the same key), so one untagged signature would be readable as any of them — a holder
	// proof over attacker-chosen bytes would be a valid delegation from that principal.
	VCHolderProof = "sanad/vc-holder-proof/v1"
)

// All is every registered context label. It exists so tests can assert the properties that
// hold across the whole set (distinctness, and that no context verifies another's messages).
var All = []string{
	InstanceProof,
	WorkloadCredential,
	AttestationQuote,
	BootstrapEvidence,
	DelegationHop,
	CapabilityBlock,
	CapabilitySeal,
	CapabilityHolderProof,
	ExchangeToken,
	AuditCheckpoint,
	AuditWitness,
	VCProof,
	VCHolderProof,
}

// Message returns the domain-separated signing input for msg under ctx:
// uint64be(len(ctx)) || ctx || msg. See the package doc for why it is unambiguous.
func Message(ctx string, msg []byte) []byte {
	out := make([]byte, 8, 8+len(ctx)+len(msg))
	binary.BigEndian.PutUint64(out, uint64(len(ctx)))
	out = append(out, ctx...)
	return append(out, msg...)
}

// Sign signs msg under ctx with priv. Like ed25519.Sign it panics on a malformed private key;
// every caller validates the key first.
func Sign(ctx string, priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, Message(ctx, msg))
}

// Verify reports whether sig is pub's signature over msg under ctx. A signature made under any
// other context fails here, which is the whole point of the package. A public key of the wrong
// size is rejected rather than passed to ed25519.Verify, which would panic — verification runs
// on attacker-supplied keys (capability next-keys, registry entries) and must fail closed.
func Verify(ctx string, pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, Message(ctx, msg), sig)
}
