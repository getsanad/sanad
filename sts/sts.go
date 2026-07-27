// Package sts is the security token service that mints short-lived, audience-bound,
// task-scoped passports (PRD FR-7). Token isolation — never forwarding the inbound
// principal/agent credentials (FR-8) — is enforced by the gateway mint stage in
// proxy wiring. Signing keys move to KMS/HSM in P1-12; the default LocalSigner holds an
// in-process Ed25519 key for development and self-host.
package sts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

// DefaultTTL is the passport lifetime when Config.TTL is unset. Short by design so
// non-renewal is the primary revocation lever (PRD FR-17).
const DefaultTTL = 2 * time.Minute

// IssueRequest carries the verified inputs needed to mint a passport.
type IssueRequest struct {
	Principal  *types.Principal
	Agent      *types.Agent
	Audience   string // single target MCP server
	Scope      types.Scope
	Delegation *types.DelegationChain // verified chain (P2-04), if any
}

// Minted is the result of issuing a passport: the structured passport plus its signed,
// compact JWS form — the only credential forwarded to the MCP server (FR-8).
type Minted struct {
	Passport types.Passport
	Token    string
}

// Issuer mints passports for verified, authorized requests.
type Issuer interface {
	Issue(ctx context.Context, r IssueRequest) (Minted, error)
}

// Signer abstracts the passport signing key. P1-12 backs this with KMS/HSM.
type Signer interface {
	KeyID() string
	Sign(c passport.Claims) (string, error)
}

// Config configures an EdDSAIssuer.
type Config struct {
	Issuer string        // the `iss` claim
	TTL    time.Duration // passport lifetime; defaults to DefaultTTL
}

// EdDSAIssuer mints EdDSA-signed passports via a Signer.
type EdDSAIssuer struct {
	signer Signer
	cfg    Config
	now    func() time.Time // injectable clock (tests)
}

// New returns an EdDSAIssuer. TTL defaults to DefaultTTL when unset.
func New(signer Signer, cfg Config) *EdDSAIssuer {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	return &EdDSAIssuer{signer: signer, cfg: cfg, now: time.Now}
}

// Issue mints a passport for the verified principal/agent, bound to a single audience.
func (i *EdDSAIssuer) Issue(_ context.Context, r IssueRequest) (Minted, error) {
	if r.Principal == nil || r.Principal.ID == "" {
		return Minted{}, errors.New("sts: missing principal")
	}
	if r.Audience == "" {
		return Minted{}, errors.New("sts: missing audience")
	}

	now := i.now().UTC()
	jti, err := newID()
	if err != nil {
		return Minted{}, err
	}
	var agentID string
	if r.Agent != nil {
		agentID = r.Agent.ID
	}

	p := types.Passport{
		ID:          jti,
		PrincipalID: r.Principal.ID,
		AgentID:     agentID,
		Audience:    r.Audience,
		Scope:       r.Scope,
		Delegation:  r.Delegation,
		IssuedAt:    now,
		ExpiresAt:   now.Add(i.cfg.TTL),
	}
	tok, err := i.signer.Sign(passport.ToClaims(p, i.cfg.Issuer))
	if err != nil {
		return Minted{}, err
	}
	return Minted{Passport: p, Token: tok}, nil
}

// LocalSigner signs with an in-process Ed25519 key. It is for development and
// self-hosted deployments without an HSM; P1-12 introduces a KMS/HSM-backed signer.
type LocalSigner struct {
	kid  string
	priv ed25519.PrivateKey
}

// NewLocalSigner generates a fresh Ed25519 signing key under the given key id. The key is
// ephemeral — use LoadSigner (or a KMS-backed RemoteSigner) so the published JWKS is stable
// across restarts and identical across replicas.
func NewLocalSigner(kid string) (*LocalSigner, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &LocalSigner{kid: kid, priv: priv}, nil
}

// LoadSigner builds a signer from a fixed 32-byte Ed25519 seed, so the signing key — and
// therefore the published JWKS — is stable across restarts and identical across replicas
// (P1-12). The seed is the secret; protect it like any signing key.
func LoadSigner(kid string, seed []byte) (*LocalSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("sts: signing seed must be 32 bytes")
	}
	return &LocalSigner{kid: kid, priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// RemoteSigner is a Signer whose private key lives outside the process — in a KMS/HSM
// (SEC-4). It delegates the raw byte-signing to sign; the gateway never holds the key.
// A KMS client implements sign by forwarding the bytes to the KMS and returning the
// Ed25519 signature; pub is the corresponding public key (published via JWKS).
type RemoteSigner struct {
	kid  string
	pub  ed25519.PublicKey
	sign func(msg []byte) ([]byte, error)
}

// NewRemoteSigner wires a KMS/HSM-backed signer.
func NewRemoteSigner(kid string, pub ed25519.PublicKey, sign func(msg []byte) ([]byte, error)) (*RemoteSigner, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("sts: invalid public key")
	}
	if sign == nil {
		return nil, errors.New("sts: nil sign function")
	}
	return &RemoteSigner{kid: kid, pub: pub, sign: sign}, nil
}

// KeyID implements Signer.
func (s *RemoteSigner) KeyID() string { return s.kid }

// Public returns the verification key (for JWKS publication).
func (s *RemoteSigner) Public() ed25519.PublicKey { return s.pub }

// Sign implements Signer by delegating the signature to the KMS/HSM.
func (s *RemoteSigner) Sign(c passport.Claims) (string, error) {
	return passport.SignWith(s.kid, c, s.sign)
}

func (s *LocalSigner) KeyID() string { return s.kid }

// Public returns the verification key (for JWKS publication / offline verify).
func (s *LocalSigner) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

func (s *LocalSigner) Sign(c passport.Claims) (string, error) {
	return passport.Sign(s.priv, s.kid, c)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
