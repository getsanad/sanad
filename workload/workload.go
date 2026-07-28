// Package workload issues short-lived, per-instance workload credentials via attestation
// (PRD FR-1, FR-4, SEC-1). An agent instance generates an ephemeral key pair at startup
// and proves itself to the Authority, which returns a signed credential binding the agent
// id to that public key for a short time. There is no long-lived shared secret.
//
// Enrolling takes two steps: the instance fetches a single-use nonce from the Authority,
// then presents attestation evidence covering both that nonce and the public key it is
// enrolling. Evidence that does not cover the key would let anyone who captured one
// attestation mint a credential for that agent id bound to their own key.
//
// Instance mTLS (P2-02) will present this credential at the gateway; the KeyStore feeds
// verified agent keys into delegation verification (P2-04), which is what makes multi-hop
// delegation work end-to-end. Hardware-backed attestation is the high-assurance tier (P3-01);
// here the Attestor is pluggable and TokenAttestor is a development implementation.
package workload

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

// DefaultTTL is the credential lifetime when none is configured. Short by design (FR-4).
const DefaultTTL = time.Hour

// NonceTTL bounds how long an enrollment nonce stays usable. It only has to cover one round
// trip — fetch the nonce, build evidence over it, enroll — so it is deliberately tiny.
const NonceTTL = 2 * time.Minute

// nonceSize is the length of an enrollment nonce; EAT wants 8–64 bytes (RFC 9711 §4.1).
const nonceSize = 32

// maxOutstandingNonces caps the outstanding-nonce table. /enroll/nonce is unauthenticated,
// so without a cap a caller could grow it without bound.
const maxOutstandingNonces = 4096

// MaxAgentIDLen bounds an agent id. It is a name an operator picks for a workload, not a
// payload, and an unbounded one is just something to put in a log line and a map key.
const MaxAgentIDLen = 128

// ValidAgentID reports whether id may name an agent. Agent ids and principal ids are separate
// namespaces — KeyStore keeps their keys in separate maps — and this keeps them separate to
// the eye as well as to the map: an agent id is a local, operator-chosen name (a leading
// alphanumeric, then alphanumerics, '.', '_' or '-'), while every principal id Sanad accepts
// is a URI-shaped global identifier: a did:key from a VC, an OIDC issuer/subject. No DID
// method survives the charset, because every one of them carries the ':' that a scheme needs.
//
// It is a positive charset rather than a "reject anything starting did:" deny-list because a
// deny-list only knows the id formats that exist today — adding did:web, a urn: or an
// https:// principal id later would silently re-admit exactly the collision this rejects. The
// same rule keeps agent ids clear of the ',' and '=' that PASSPORT_BOOTSTRAP_TOKENS parsing
// splits on, and of whitespace and control characters, which make an audit line ambiguous.
//
// The namespaces would be separate without this: a DID-named agent gets a key in the agent
// map and still cannot answer a principal lookup. This is the second lock — an agent that
// prints in an audit trail as a principal is a lie about who is accountable even when it
// resolves nothing.
func ValidAgentID(id string) error {
	if id == "" {
		return errors.New("workload: agent id is empty")
	}
	if len(id) > MaxAgentIDLen {
		return fmt.Errorf("workload: agent id is longer than %d bytes", MaxAgentIDLen)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return fmt.Errorf("workload: agent id %q must be alphanumerics, '.', '_' or '-' and start with an alphanumeric "+
				"(principal ids such as did:key:... are a different namespace and cannot be used to name an agent)", id)
		}
	}
	return nil
}

// Attestor verifies attestation evidence and returns the agent id it proves. The evidence
// must cryptographically cover BOTH nonce — the single-use challenge the Authority issued
// for this enrollment — and pubKey, the instance key the credential will be bound to. An
// implementation that ignores either lets a quote captured from the network, a log or a CI
// artifact be replayed to mint a credential for that agent id bound to an attacker's key.
// Real implementations validate node/TEE/TPM attestation (P3-01).
type Attestor interface {
	Attest(evidence, nonce []byte, pubKey ed25519.PublicKey) (agentID string, err error)
}

// TokenAttestor maps pre-registered bootstrap tokens to agent ids — a simple dev/self-host
// attestor. Its evidence is an HMAC keyed by the bootstrap token over the enrollment nonce
// and the instance key (see BootstrapEvidence), so the token never crosses the wire and a
// captured blob is worthless with any other key or nonce. It is concurrency-safe.
type TokenAttestor struct {
	mu     sync.RWMutex
	tokens map[string]string // bootstrap token -> agentID
}

// NewTokenAttestor returns an empty TokenAttestor.
func NewTokenAttestor() *TokenAttestor {
	return &TokenAttestor{tokens: map[string]string{}}
}

// Register binds a bootstrap token to an agent id. It rejects an id that is not a valid agent
// name (ValidAgentID) — notably one shaped like a principal's DID — so a mistyped or hostile
// entry fails where it is configured rather than at some later enrollment.
func (a *TokenAttestor) Register(token, agentID string) error {
	if err := ValidAgentID(agentID); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[token] = agentID
	return nil
}

// BootstrapEvidence builds the evidence a TokenAttestor accepts: an HMAC, keyed by the
// bootstrap token, over the authority-issued nonce and the public key being enrolled. The
// token stays on the client, and the result only enrolls that key against that nonce.
//
// It carries its context label as a JSON member rather than going through sigctx.Message:
// this is a MAC keyed by the bootstrap token, which is never an Ed25519 key and so shares no
// message space with any signature here, and the JSON encoding is already unambiguous — the
// label sits in its own quoted field and cannot absorb bytes from nonce or pub. Keeping it as
// it is also keeps the SDK enrollment vectors stable.
//
// The token is still a shared secret whose holder can enroll at will — making bootstrap
// tokens single-use and expiring is a separate item; this only stops a captured enrollment
// from being replayed with someone else's key.
func BootstrapEvidence(token string, nonce []byte, pub ed25519.PublicKey) []byte {
	msg, _ := json.Marshal(struct {
		Ctx   string `json:"ctx"`
		Nonce []byte `json:"nonce"`
		Pub   []byte `json:"pub"`
	}{sigctx.BootstrapEvidence, nonce, pub})
	m := hmac.New(sha256.New, []byte(token))
	m.Write(msg)
	return m.Sum(nil)
}

// Attest implements Attestor. It trials each registered token: the token is not on the wire
// to look up, and a dev/self-host attestor holds a handful of them.
func (a *TokenAttestor) Attest(evidence, nonce []byte, pubKey ed25519.PublicKey) (string, error) {
	if len(pubKey) != ed25519.PublicKeySize || len(nonce) == 0 {
		return "", errors.New("workload: attestation rejected")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for token, id := range a.tokens {
		if id != "" && hmac.Equal(evidence, BootstrapEvidence(token, nonce, pubKey)) {
			return id, nil
		}
	}
	return "", errors.New("workload: attestation rejected")
}

// Credential is a short-lived, CA-signed assertion binding an agent id to a public key.
type Credential struct {
	AgentID   string
	PublicKey ed25519.PublicKey
	IssuedAt  time.Time
	NotAfter  time.Time
	KeyID     string // id of the issuing CA key
	Signature []byte
}

// Authority issues credentials after attestation, signing with its CA key. It also issues
// the single-use nonces that attestation evidence must cover.
type Authority struct {
	caPriv ed25519.PrivateKey
	kid    string
	att    Attestor
	ttl    time.Duration
	now    func() time.Time

	// Outstanding enrollment nonces (nonce -> expiry). This state is PROCESS-LOCAL: a nonce
	// minted by one authority replica is unknown to every other, so enrollment across
	// replicas only works if the two requests land on the same process. A single authority
	// process is the supported deployment for now; sharing this table (with the KeyStore) is
	// a Phase 3 durability item.
	nonceMu  sync.Mutex
	nonces   map[string]time.Time
	nonceTTL time.Duration
}

// NewAuthority returns an Authority that signs with caPriv (key id kid) and attests via att.
func NewAuthority(caPriv ed25519.PrivateKey, kid string, att Attestor, ttl time.Duration) (*Authority, error) {
	if len(caPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("workload: invalid CA private key")
	}
	if att == nil {
		return nil, errors.New("workload: nil attestor")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Authority{
		caPriv: caPriv, kid: kid, att: att, ttl: ttl, now: time.Now,
		nonces: map[string]time.Time{}, nonceTTL: NonceTTL,
	}, nil
}

// CAPublicKey returns the key used to verify issued credentials.
func (a *Authority) CAPublicKey() ed25519.PublicKey {
	return a.caPriv.Public().(ed25519.PublicKey)
}

// Nonce issues a single-use enrollment challenge — the nonce freshness model of the RATS
// architecture (RFC 9334 §10.1), carried in the quote as EAT's eat_nonce. The evidence
// presented to Issue must cover it, and it is accepted exactly once within NonceTTL, so a
// quote captured from an earlier enrollment can never be presented again.
func (a *Authority) Nonce() ([]byte, error) {
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	now := a.now().UTC()

	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	for k, exp := range a.nonces { // sweep: an expired nonce can never be used again
		if !now.Before(exp) {
			delete(a.nonces, k)
		}
	}
	if len(a.nonces) >= maxOutstandingNonces {
		return nil, errors.New("workload: too many outstanding enrollment nonces")
	}
	a.nonces[string(n)] = now.Add(a.nonceTTL)
	return n, nil
}

// consumeNonce accepts a nonce exactly once, inside its window. It is spent whether or not
// the enrollment that follows succeeds, so a caller cannot retry attestations against one
// challenge; an unknown, expired or already-spent nonce fails closed.
func (a *Authority) consumeNonce(nonce []byte) error {
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	exp, ok := a.nonces[string(nonce)]
	if !ok {
		return errors.New("workload: unknown or already-used enrollment nonce")
	}
	delete(a.nonces, string(nonce))
	if !a.now().UTC().Before(exp) {
		return errors.New("workload: enrollment nonce expired")
	}
	return nil
}

// Issue spends the enrollment nonce, verifies that the attestation evidence covers both that
// nonce and pubKey, and returns a short-lived credential binding the attested agent id to
// pubKey. Evidence that does not cover this exact key is rejected, so a captured quote
// cannot be re-presented with an attacker's key.
func (a *Authority) Issue(evidence, nonce []byte, pubKey ed25519.PublicKey) (Credential, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return Credential{}, errors.New("workload: invalid instance public key")
	}
	if err := a.consumeNonce(nonce); err != nil {
		return Credential{}, err
	}
	agentID, err := a.att.Attest(evidence, nonce, pubKey)
	if err != nil {
		return Credential{}, err
	}
	// The authority is the only place an agent id becomes a signed identity, so it is where
	// the name is held to the agent namespace — whatever Attestor produced it, including one
	// an operator plugged in themselves. A credential is a CA signature over "this key IS this
	// agent"; issuing one for a name that reads as a principal is issuing the wrong claim.
	if err := ValidAgentID(agentID); err != nil {
		return Credential{}, err
	}
	now := a.now().UTC()
	c := Credential{
		AgentID:   agentID,
		PublicKey: pubKey,
		IssuedAt:  now,
		NotAfter:  now.Add(a.ttl),
		KeyID:     a.kid,
	}
	c.Signature = sigctx.Sign(sigctx.WorkloadCredential, a.caPriv, canonical(c))
	return c, nil
}

// Verify checks a credential's CA signature and validity window at time now.
func Verify(caPub ed25519.PublicKey, c Credential, now time.Time) error {
	if len(caPub) != ed25519.PublicKeySize {
		return errors.New("workload: invalid CA public key")
	}
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return errors.New("workload: credential has invalid public key")
	}
	// The verifier re-checks the agent id it is being asked to trust rather than assuming the
	// issuing authority checked it: a credential with an empty id would otherwise register a
	// key under "" in the KeyStore, and one named like a DID would put a principal id in
	// req.Agent and in every audit line the request produces.
	if err := ValidAgentID(c.AgentID); err != nil {
		return err
	}
	if !sigctx.Verify(sigctx.WorkloadCredential, caPub, canonical(c), c.Signature) {
		return errors.New("workload: bad credential signature")
	}
	if now.Before(c.IssuedAt) {
		return errors.New("workload: credential not yet valid")
	}
	if !now.Before(c.NotAfter) {
		return errors.New("workload: credential expired")
	}
	return nil
}

// canonical is the deterministic signing input for a credential.
func canonical(c Credential) []byte {
	b, _ := json.Marshal(struct {
		AgentID  string `json:"agent_id"`
		Pub      []byte `json:"pub"`
		IssuedAt int64  `json:"iat"`
		NotAfter int64  `json:"exp"`
		KeyID    string `json:"kid"`
	}{c.AgentID, c.PublicKey, c.IssuedAt.Unix(), c.NotAfter.Unix(), c.KeyID})
	return b
}
