package vc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// KeyRegistrar receives a principal's key on successful authentication so delegation
// chains rooted at that principal can be verified (PRD FR-10). workload.KeyStore satisfies
// it, closing the principal-key gap noted in P2-02. The method names the namespace it writes
// to: a principal key is registered where only a principal lookup reads, never where an agent
// id could reach it.
type KeyRegistrar interface {
	AddPrincipalKey(id string, pub ed25519.PublicKey, notAfter time.Time)
}

// Authenticator verifies a presented principal VC and maps it to a types.Principal. It
// implements principal.Authenticator, so it drops into the gateway principal-auth stage as
// an alternative to OIDC.
type Authenticator struct {
	trust     TrustStore
	now       func() time.Time
	registrar KeyRegistrar // optional
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithKeyRegistrar registers each authenticated principal's did:key public key.
func WithKeyRegistrar(r KeyRegistrar) Option { return func(a *Authenticator) { a.registrar = r } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(a *Authenticator) { a.now = now } }

// NewAuthenticator returns an Authenticator that accepts credentials from trusted issuers.
func NewAuthenticator(trust TrustStore, opts ...Option) *Authenticator {
	a := &Authenticator{trust: trust, now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Authenticate verifies a presented credential (raw JSON or base64url(JSON)) and returns
// the accountable principal. If a registrar is set, the principal's did:key public key is
// registered (expiring with the credential).
func (a *Authenticator) Authenticate(_ context.Context, raw string) (*types.Principal, error) {
	c, err := decodeCredential(raw)
	if err != nil {
		return nil, err
	}
	subject, err := Verify(c, a.trust, a.now())
	if err != nil {
		return nil, err
	}
	pub, err := PublicKeyFromDID(subject.ID)
	if err != nil {
		return nil, err
	}
	if a.registrar != nil {
		var exp time.Time
		if c.ExpirationDate != "" {
			exp, _ = time.Parse(time.RFC3339, c.ExpirationDate)
		}
		a.registrar.AddPrincipalKey(subject.ID, pub, exp)
	}
	return &types.Principal{ID: subject.ID, Subject: subject.ID, Assurance: subject.Assurance}, nil
}

// decodeCredential accepts either base64url(JSON) (how the SDK presents it in a bearer) or
// raw JSON.
func decodeCredential(raw string) (Credential, error) {
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		var c Credential
		if json.Unmarshal(b, &c) == nil && c.Issuer != "" {
			return c, nil
		}
	}
	var c Credential
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return Credential{}, fmt.Errorf("vc: bad credential: %w", err)
	}
	return c, nil
}
