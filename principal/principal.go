// Package principal authenticates the accountable principal behind a request (PRD FR-6)
// by verifying the IdP's OIDC ID token and mapping it to a types.Principal. It plugs into
// the gateway as the principal-auth stage. Instance identity (the agent itself) is P2-02;
// VC-based principals are P2-08.
package principal

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// Authenticator verifies a raw credential and returns the accountable principal.
type Authenticator interface {
	Authenticate(ctx context.Context, rawToken string) (*types.Principal, error)
}

// RequestAuthenticator is an Authenticator whose credential cannot be checked from the token
// alone. A credential the holder must prove possession of a key for — a VC over a did:key,
// vc.Authenticator — binds that proof to the request in front of the verifier, so it needs
// the request and the buffered body, not just the bearer string. Stage prefers this method
// whenever the authenticator offers it, and there is deliberately no fallback: an
// authenticator that requires the binding must not be reachable through the path that skips
// it.
type RequestAuthenticator interface {
	Authenticator
	AuthenticateRequest(ctx context.Context, rawToken string, r *http.Request, body []byte) (*types.Principal, error)
}

// StatusChecker reports whether a principal has been revoked/disabled (the kill-switch,
// P1-07). Authentication fails closed when a principal is revoked.
type StatusChecker interface {
	Revoked(principalID string) bool
}

// OIDCAuthenticator verifies an OIDC ID token via go-oidc and maps it to a Principal.
type OIDCAuthenticator struct {
	verifier  *oidc.IDTokenVerifier
	assurance types.AssuranceLevel
	status    StatusChecker // optional
}

// Option configures an OIDCAuthenticator.
type Option func(*OIDCAuthenticator)

// WithAssurance sets the assurance level recorded on authenticated principals (FR-2/R4).
func WithAssurance(a types.AssuranceLevel) Option {
	return func(o *OIDCAuthenticator) { o.assurance = a }
}

// WithStatusChecker wires a kill-switch/deny-list check into authentication.
func WithStatusChecker(s StatusChecker) Option {
	return func(o *OIDCAuthenticator) { o.status = s }
}

// NewOIDC builds an authenticator over a prepared go-oidc verifier (the verifier already
// enforces issuer, audience, expiry, and signature). Tests inject a verifier built from a
// static key set; production wiring uses Verifier for network discovery.
func NewOIDC(verifier *oidc.IDTokenVerifier, opts ...Option) *OIDCAuthenticator {
	a := &OIDCAuthenticator{verifier: verifier, assurance: types.AssuranceUnverified}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Verifier constructs a network-backed OIDC verifier by discovering issuerURL and
// requiring clientID as the audience.
func Verifier(ctx context.Context, issuerURL, clientID string) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	return provider.Verifier(&oidc.Config{ClientID: clientID}), nil
}

// Authenticate verifies the token and returns the principal, failing closed on any error
// or if the principal has been revoked.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, raw string) (*types.Principal, error) {
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if idt.Subject == "" {
		return nil, errors.New("principal: token has no subject")
	}
	if a.status != nil && a.status.Revoked(idt.Subject) {
		return nil, errors.New("principal: revoked")
	}
	return &types.Principal{
		ID:        idt.Subject,
		Subject:   idt.Subject,
		Assurance: a.assurance,
	}, nil
}

// Stage returns the gateway principal-auth stage: it reads the inbound bearer token,
// authenticates the principal, and sets it on the request — failing closed if the token
// is missing or invalid. The mint stage (sts.MintStage) later strips this inbound token
// and forwards only the minted passport (FR-8).
//
// An authenticator that also implements RequestAuthenticator is given the request and the
// buffered body, so it can check a proof of possession bound to them.
func Stage(a Authenticator) gateway.Stage {
	return gateway.NewStage("principal", func(ctx context.Context, req *gateway.Request) error {
		if req.HTTP == nil {
			return errors.New("principal: no request to authenticate")
		}
		raw, ok := bearer(req.HTTP)
		if !ok {
			return errors.New("principal: missing bearer token")
		}
		p, err := authenticate(ctx, a, raw, req)
		if err != nil {
			return err
		}
		req.Principal = p
		return nil
	})
}

// authenticate picks the richer method when the authenticator has one.
func authenticate(ctx context.Context, a Authenticator, raw string, req *gateway.Request) (*types.Principal, error) {
	if ra, ok := a.(RequestAuthenticator); ok {
		return ra.AuthenticateRequest(ctx, raw, req.HTTP, req.Body)
	}
	return a.Authenticate(ctx, raw)
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}
