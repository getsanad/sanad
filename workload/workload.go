// Package workload issues short-lived, per-instance workload credentials via attestation
// (PRD FR-1, FR-4, SEC-1). An agent instance generates an ephemeral key pair at startup
// and proves itself to the Authority, which returns a signed credential binding the agent
// id to that public key for a short time. There is no long-lived shared secret.
//
// Instance mTLS (P2-02) will present this credential at the gateway; the KeyStore feeds
// verified agent keys into delegation verification (P2-04), which is what makes multi-hop
// delegation work end-to-end. Hardware-backed attestation is the high-assurance tier (P3-01);
// here the Attestor is pluggable and TokenAttestor is a development implementation.
package workload

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// DefaultTTL is the credential lifetime when none is configured. Short by design (FR-4).
const DefaultTTL = time.Hour

// Attestor verifies attestation evidence and returns the agent id it proves. Real
// implementations validate node/TEE/TPM attestation (P3-01).
type Attestor interface {
	Attest(evidence []byte) (agentID string, err error)
}

// TokenAttestor maps pre-registered bootstrap tokens to agent ids — a simple dev/self-host
// attestor. It is concurrency-safe.
type TokenAttestor struct {
	mu     sync.RWMutex
	tokens map[string]string // bootstrap token -> agentID
}

// NewTokenAttestor returns an empty TokenAttestor.
func NewTokenAttestor() *TokenAttestor {
	return &TokenAttestor{tokens: map[string]string{}}
}

// Register binds a bootstrap token to an agent id.
func (a *TokenAttestor) Register(token, agentID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[token] = agentID
}

// Attest implements Attestor.
func (a *TokenAttestor) Attest(evidence []byte) (string, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	id, ok := a.tokens[string(evidence)]
	if !ok || id == "" {
		return "", errors.New("workload: attestation rejected")
	}
	return id, nil
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

// Authority issues credentials after attestation, signing with its CA key.
type Authority struct {
	caPriv ed25519.PrivateKey
	kid    string
	att    Attestor
	ttl    time.Duration
	now    func() time.Time
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
	return &Authority{caPriv: caPriv, kid: kid, att: att, ttl: ttl, now: time.Now}, nil
}

// CAPublicKey returns the key used to verify issued credentials.
func (a *Authority) CAPublicKey() ed25519.PublicKey {
	return a.caPriv.Public().(ed25519.PublicKey)
}

// Issue verifies the attestation evidence and returns a short-lived credential binding the
// attested agent id to pubKey.
func (a *Authority) Issue(evidence []byte, pubKey ed25519.PublicKey) (Credential, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return Credential{}, errors.New("workload: invalid instance public key")
	}
	agentID, err := a.att.Attest(evidence)
	if err != nil {
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
	c.Signature = ed25519.Sign(a.caPriv, canonical(c))
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
	if !ed25519.Verify(caPub, canonical(c), c.Signature) {
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
