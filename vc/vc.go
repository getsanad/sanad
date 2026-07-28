package vc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

const (
	contextVC     = "https://www.w3.org/2018/credentials/v1"
	typeVC        = "VerifiableCredential"
	typePrincipal = "PrincipalCredential"

	// proofType names the suite in use, and deliberately does NOT claim
	// "Ed25519Signature2020". That suite is defined over JSON-LD canonicalization (URDNA2015)
	// of the credential graph; canonical below signs a Go struct marshal. Claiming the
	// registered name would be wrong in both directions: a conformant verifier would
	// canonicalize before checking and get different bytes, and a reader would believe
	// properties this struct does not model are covered when they are not. The name says what
	// the bytes are, and the package doc says what the profile does and does not promise.
	proofType = "SanadEd25519StructProof2026"
)

// Subject is the credential subject: the principal DID and its assurance level (FR-2).
type Subject struct {
	ID        string               `json:"id"` // principal DID (did:key)
	Assurance types.AssuranceLevel `json:"assuranceLevel"`
}

// Proof is the issuer's Ed25519 signature over the credential.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"` // issuer DID
	ProofValue         string `json:"proofValue,omitempty"`
}

// Credential is a (minimal) W3C-shaped Verifiable Credential for a principal.
type Credential struct {
	Context        []string `json:"@context"`
	Type           []string `json:"type"`
	Issuer         string   `json:"issuer"` // issuer DID (did:key)
	IssuanceDate   string   `json:"issuanceDate"`
	ExpirationDate string   `json:"expirationDate"`
	Subject        Subject  `json:"credentialSubject"`
	Proof          Proof    `json:"proof"`
}

// TrustStore decides whether an issuer DID is trusted to vouch for principals.
type TrustStore interface {
	Trusted(issuerDID string) bool
}

// StaticTrust is a fixed set of trusted issuer DIDs.
type StaticTrust map[string]bool

// Trusted implements TrustStore.
func (s StaticTrust) Trusted(issuerDID string) bool { return s[issuerDID] }

// Issue signs a principal credential. issuerDID must be the did:key of issuerKey, and ttl
// must be positive: every credential expires. An unbounded credential is unbounded
// impersonation — Verify refuses one, so issuing one would only produce a credential that
// can never be presented.
func Issue(issuerDID string, issuerKey ed25519.PrivateKey, subject Subject, ttl time.Duration, now time.Time) (Credential, error) {
	pub, err := PublicKeyFromDID(issuerDID)
	if err != nil {
		return Credential{}, err
	}
	if !pub.Equal(issuerKey.Public()) {
		return Credential{}, errors.New("vc: issuer DID does not match the signing key")
	}
	if ttl <= 0 {
		return Credential{}, errors.New("vc: a principal credential must expire (ttl must be positive)")
	}
	c := Credential{
		Context:        []string{contextVC},
		Type:           []string{typeVC, typePrincipal},
		Issuer:         issuerDID,
		IssuanceDate:   now.UTC().Format(time.RFC3339),
		ExpirationDate: now.Add(ttl).UTC().Format(time.RFC3339),
		Subject:        subject,
		Proof:          Proof{Type: proofType, Created: now.UTC().Format(time.RFC3339), VerificationMethod: issuerDID},
	}
	msg, err := canonical(c)
	if err != nil {
		return Credential{}, err
	}
	c.Proof.ProofValue = base64.RawURLEncoding.EncodeToString(sigctx.Sign(sigctx.VCProof, issuerKey, msg))
	return c, nil
}

// Verify checks that the credential IS a principal credential (its @context and type), that
// its issuer is trusted, that the issuer's signature is intact, and that it is inside its
// validity window. It returns the verified subject and the credential's expiry.
//
// The expiry is returned rather than left to the caller to re-parse. There is then exactly
// one parse of it in the system, and no path on which a credential verifies while its expiry
// reads as the zero time — which is how a credential with no usable expiration date came to
// register a principal key that never expired.
//
// It does NOT establish that whoever presented the credential is its subject. A credential on
// its own is a bearer blob; the holder binding is Authenticator.AuthenticateRequest.
func Verify(c Credential, trust TrustStore, now time.Time) (Subject, time.Time, error) {
	// Shape first: it is a string comparison, it decides whether this document is even the
	// kind of thing being asked about, and it costs an unauthenticated caller a signature
	// verification to get past. Without it, ANY credential a trusted issuer signed — for any
	// purpose, with any subject — was accepted here as a principal credential.
	if len(c.Context) == 0 || c.Context[0] != contextVC {
		return Subject{}, time.Time{}, fmt.Errorf("vc: @context must begin with %q", contextVC)
	}
	if !slices.Contains(c.Type, typeVC) || !slices.Contains(c.Type, typePrincipal) {
		return Subject{}, time.Time{}, fmt.Errorf("vc: type must contain %q and %q, got %v", typeVC, typePrincipal, c.Type)
	}
	if c.Proof.Type != proofType {
		return Subject{}, time.Time{}, fmt.Errorf("vc: unsupported proof type %q, want %q", c.Proof.Type, proofType)
	}
	if c.Issuer == "" {
		return Subject{}, time.Time{}, errors.New("vc: missing issuer")
	}
	if trust == nil || !trust.Trusted(c.Issuer) {
		return Subject{}, time.Time{}, fmt.Errorf("vc: issuer %q is not trusted", c.Issuer)
	}
	issuerPub, err := PublicKeyFromDID(c.Issuer)
	if err != nil {
		return Subject{}, time.Time{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Proof.ProofValue)
	if err != nil {
		return Subject{}, time.Time{}, fmt.Errorf("vc: bad proof value: %w", err)
	}
	msg, err := canonical(c)
	if err != nil {
		return Subject{}, time.Time{}, err
	}
	if !sigctx.Verify(sigctx.VCProof, issuerPub, msg, sig) {
		return Subject{}, time.Time{}, errors.New("vc: signature verification failed")
	}

	// Both dates are REQUIRED and must parse. An optional expiration date is a credential that
	// never stops being valid, i.e. permanent impersonation of the subject from a single
	// leaked blob; and an issuance date that failed to parse used to be skipped silently,
	// which quietly disabled the not-yet-valid check.
	iat, err := time.Parse(time.RFC3339, c.IssuanceDate)
	if err != nil {
		return Subject{}, time.Time{}, fmt.Errorf("vc: issuance date must be RFC3339: %w", err)
	}
	if now.Before(iat) {
		return Subject{}, time.Time{}, errors.New("vc: not yet valid")
	}
	exp, err := time.Parse(time.RFC3339, c.ExpirationDate)
	if err != nil {
		return Subject{}, time.Time{}, fmt.Errorf("vc: expiration date must be RFC3339: %w", err)
	}
	if !now.Before(exp) {
		return Subject{}, time.Time{}, errors.New("vc: credential expired")
	}

	if c.Subject.ID == "" {
		return Subject{}, time.Time{}, errors.New("vc: missing subject id")
	}
	if _, err := PublicKeyFromDID(c.Subject.ID); err != nil {
		return Subject{}, time.Time{}, fmt.Errorf("vc: subject id is not a did:key: %w", err)
	}
	return c.Subject, exp, nil
}

// canonical is the deterministic signing input: the credential with an empty proofValue. It
// is signed under sigctx.VCProof, so an issuer key that is also a principal key (it vouches
// for did:key subjects, and did:key principals root delegation chains) cannot have one of its
// signatures read as the other kind.
//
// It is a struct marshal, not a JSON-LD canonicalization — see proofType and the package doc.
// What keeps that honest is decodeCredential, which refuses any property this struct does not
// model, so "signed over the struct" and "signed over the document" cannot diverge.
func canonical(c Credential) ([]byte, error) {
	c.Proof.ProofValue = "" // value copy; does not affect the caller
	return json.Marshal(c)
}
