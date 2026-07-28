package vc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
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

// StatusChecker reports whether a principal has been revoked/disabled (the kill-switch,
// P1-07). It is the same contract as principal.StatusChecker and revoke.Checker, redeclared
// here so this package does not import either.
type StatusChecker interface {
	Revoked(principalID string) bool
}

// Authenticator verifies a presented principal VC — the issuer's signature AND the
// presenter's possession of the subject's did:key — and maps it to a types.Principal. It
// implements principal.RequestAuthenticator, so it drops into the gateway principal-auth
// stage as an alternative to OIDC.
type Authenticator struct {
	trust     TrustStore
	now       func() time.Time
	registrar KeyRegistrar  // optional
	status    StatusChecker // optional
	proof     []pop.Option
	verifier  *pop.Verifier
}

// Option configures an Authenticator.
type Option func(*Authenticator)

// WithKeyRegistrar registers each authenticated principal's did:key public key.
func WithKeyRegistrar(r KeyRegistrar) Option { return func(a *Authenticator) { a.registrar = r } }

// WithStatusChecker wires the kill-switch into VC authentication, as principal.WithStatusChecker
// does for OIDC. A revoked principal then fails to authenticate at all, rather than
// authenticating and being stopped further down the pipeline.
func WithStatusChecker(s StatusChecker) Option { return func(a *Authenticator) { a.status = s } }

// WithClock overrides the clock, for tests. It moves the holder-proof verifier's clock too:
// one authenticator has one notion of now, or a test that fast-forwards past a credential's
// expiry would find its proofs stale against a different one.
func WithClock(now func() time.Time) Option {
	return func(a *Authenticator) {
		a.now = now
		a.proof = append(a.proof, pop.WithClock(now))
	}
}

// WithProofWindow sets how old a holder proof may be and how far ahead its iat may sit. The
// defaults (pop.DefaultMaxAge / pop.DefaultSkew) are what deployments should use.
func WithProofWindow(maxAge, skew time.Duration) Option {
	return func(a *Authenticator) { a.proof = append(a.proof, pop.WithWindow(maxAge, skew)) }
}

// WithProofCacheEntries caps the per-process holder-proof replay cache. See pop.ReplayCache
// for how to size it and what a second replica does not know.
func WithProofCacheEntries(n int) Option {
	return func(a *Authenticator) { a.proof = append(a.proof, pop.WithCacheEntries(n)) }
}

// NewAuthenticator returns an Authenticator that accepts credentials from trusted issuers.
// The holder-proof verifier is built after every option has run, so the window and cache
// options compose in any order.
func NewAuthenticator(trust TrustStore, opts ...Option) *Authenticator {
	a := &Authenticator{trust: trust, now: time.Now}
	for _, opt := range opts {
		opt(a)
	}
	a.verifier = pop.NewVerifier(sigctx.VCHolderProof, a.proof...)
	return a
}

// errNoRequest is what the token-only path answers with. It is a sentence rather than a
// sentinel because nothing branches on it: there is no fallback to fall back to.
var errNoRequest = errors.New("vc: a principal credential cannot be authenticated from the token alone; " +
	"it must be presented on a request, with a holder proof (use AuthenticateRequest)")

// Authenticate satisfies principal.Authenticator and always fails.
//
// A credential verified without the request it arrived on is a credential verified without
// holder binding, which is precisely the bearer-blob behaviour this package no longer has.
// Keeping the method (rather than dropping off the interface) means a pipeline wired the old
// way fails closed and says why, instead of compiling into silent impersonation.
func (a *Authenticator) Authenticate(context.Context, string) (*types.Principal, error) {
	return nil, errNoRequest
}

// AuthenticateRequest verifies a presented credential (raw JSON or base64url(JSON)) together
// with the holder proof on r, and returns the accountable principal.
//
// Two independent things have to hold. The ISSUER must have signed the credential (Verify:
// trusted issuer, intact signature, right type, inside its window), and the PRESENTER must
// hold the subject's did:key private key and have used it on this request (HolderProof). The
// first without the second is a bearer token, and body is the request body the gateway
// buffered, because the proof covers it.
//
// If a registrar is set, the principal's public key is registered for delegation, expiring
// with the credential.
func (a *Authenticator) AuthenticateRequest(_ context.Context, raw string, r *http.Request, body []byte) (*types.Principal, error) {
	if r == nil {
		return nil, errNoRequest
	}
	c, err := decodeCredential(raw)
	if err != nil {
		return nil, err
	}
	subject, notAfter, err := Verify(c, a.trust, a.now())
	if err != nil {
		return nil, err
	}
	pub, err := PublicKeyFromDID(subject.ID)
	if err != nil {
		return nil, err
	}

	// Same rule as workload.InstanceStage: a body the gateway did not buffer is a body no
	// proof committed to, and it is refused rather than authenticated on a partial binding.
	if body == nil && r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
		return nil, errors.New("vc: request carries a body the holder proof cannot cover")
	}
	// Exactly one proof header, per RFC 9449 §4.3 step 1 — see workload.InstanceStage for why
	// taking the first of several silently is a parser differential.
	if n := len(r.Header.Values(HeaderPrincipalProof)); n != 1 {
		return nil, fmt.Errorf("vc: expected exactly one %s header, got %d", HeaderPrincipalProof, n)
	}
	// raw is the credential as presented, and the proof's ath commits to those exact bytes, so
	// a proof made for one credential cannot carry another.
	if err := a.verifier.Check(pub, r.Header.Get(HeaderPrincipalProof), r, body, raw); err != nil {
		return nil, fmt.Errorf("vc: principal holder proof failed: %w", err)
	}

	// The kill-switch, after the proof: only a presenter who has proven control of the subject
	// key learns anything from this answer.
	if a.status != nil && a.status.Revoked(subject.ID) {
		return nil, fmt.Errorf("vc: principal %q is revoked", subject.ID)
	}

	if a.registrar != nil {
		// notAfter comes from Verify, which refuses a credential without a parseable expiry, so
		// this cannot be the zero time — which KeyStore reads as "never expires".
		a.registrar.AddPrincipalKey(subject.ID, pub, notAfter)
	}
	return &types.Principal{ID: subject.ID, Subject: subject.ID, Assurance: subject.Assurance}, nil
}

// decodeCredential accepts either base64url(JSON) (how the SDK presents it in a bearer) or
// raw JSON.
//
// Raw JSON always begins with "{", which is not in the base64url alphabet, so a successful
// base64 decode means the caller meant base64 — and a parse failure there is reported as
// itself rather than retried as JSON, which would bury the real reason under an encoding
// complaint.
func decodeCredential(raw string) (Credential, error) {
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil {
		c, derr := unmarshalCredential(b)
		if derr != nil {
			return Credential{}, fmt.Errorf("vc: bad credential: %w", derr)
		}
		if c.Issuer != "" {
			return c, nil
		}
	}
	c, err := unmarshalCredential([]byte(raw))
	if err != nil {
		return Credential{}, fmt.Errorf("vc: bad credential: %w", err)
	}
	return c, nil
}

// unmarshalCredential parses a credential and REFUSES any property Credential does not model.
// The signature covers a marshal of this struct (see canonical), so an unmodelled property is
// an unsigned one: json.Unmarshal would drop it silently, and the credential would verify as
// something other than the document that was presented. Rejecting is the only reading that
// keeps "what was signed" and "what was sent" the same object.
func unmarshalCredential(b []byte) (Credential, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Credential
	if err := dec.Decode(&c); err != nil {
		return Credential{}, err
	}
	if dec.More() {
		return Credential{}, errors.New("trailing data after the credential")
	}
	return c, nil
}
