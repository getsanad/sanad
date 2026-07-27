package vc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

const (
	contextVC     = "https://www.w3.org/2018/credentials/v1"
	typeVC        = "VerifiableCredential"
	typePrincipal = "PrincipalCredential"
	proofType     = "Ed25519Signature2020"
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

// Credential is a (minimal) W3C Verifiable Credential for a principal.
type Credential struct {
	Context        []string `json:"@context"`
	Type           []string `json:"type"`
	Issuer         string   `json:"issuer"` // issuer DID (did:key)
	IssuanceDate   string   `json:"issuanceDate"`
	ExpirationDate string   `json:"expirationDate,omitempty"`
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

// Issue signs a principal credential. issuerDID must be the did:key of issuerKey.
func Issue(issuerDID string, issuerKey ed25519.PrivateKey, subject Subject, ttl time.Duration, now time.Time) (Credential, error) {
	pub, err := PublicKeyFromDID(issuerDID)
	if err != nil {
		return Credential{}, err
	}
	if !pub.Equal(issuerKey.Public()) {
		return Credential{}, errors.New("vc: issuer DID does not match the signing key")
	}
	c := Credential{
		Context:      []string{contextVC},
		Type:         []string{typeVC, typePrincipal},
		Issuer:       issuerDID,
		IssuanceDate: now.UTC().Format(time.RFC3339),
		Subject:      subject,
		Proof:        Proof{Type: proofType, Created: now.UTC().Format(time.RFC3339), VerificationMethod: issuerDID},
	}
	if ttl > 0 {
		c.ExpirationDate = now.Add(ttl).UTC().Format(time.RFC3339)
	}
	msg, err := canonical(c)
	if err != nil {
		return Credential{}, err
	}
	c.Proof.ProofValue = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, msg))
	return c, nil
}

// Verify checks the issuer's signature, that the issuer is trusted, and the validity
// window, returning the verified subject. The subject ID must be a resolvable did:key.
func Verify(c Credential, trust TrustStore, now time.Time) (Subject, error) {
	if c.Issuer == "" {
		return Subject{}, errors.New("vc: missing issuer")
	}
	if trust == nil || !trust.Trusted(c.Issuer) {
		return Subject{}, fmt.Errorf("vc: issuer %q is not trusted", c.Issuer)
	}
	issuerPub, err := PublicKeyFromDID(c.Issuer)
	if err != nil {
		return Subject{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(c.Proof.ProofValue)
	if err != nil {
		return Subject{}, fmt.Errorf("vc: bad proof value: %w", err)
	}
	msg, err := canonical(c)
	if err != nil {
		return Subject{}, err
	}
	if !ed25519.Verify(issuerPub, msg, sig) {
		return Subject{}, errors.New("vc: signature verification failed")
	}

	if c.IssuanceDate != "" {
		if iat, perr := time.Parse(time.RFC3339, c.IssuanceDate); perr == nil && now.Before(iat) {
			return Subject{}, errors.New("vc: not yet valid")
		}
	}
	if c.ExpirationDate != "" {
		exp, perr := time.Parse(time.RFC3339, c.ExpirationDate)
		if perr != nil {
			return Subject{}, errors.New("vc: bad expiration date")
		}
		if !now.Before(exp) {
			return Subject{}, errors.New("vc: credential expired")
		}
	}
	if c.Subject.ID == "" {
		return Subject{}, errors.New("vc: missing subject id")
	}
	if _, err := PublicKeyFromDID(c.Subject.ID); err != nil {
		return Subject{}, fmt.Errorf("vc: subject id is not a did:key: %w", err)
	}
	return c.Subject, nil
}

// canonical is the deterministic signing input: the credential with an empty proofValue.
func canonical(c Credential) ([]byte, error) {
	c.Proof.ProofValue = "" // value copy; does not affect the caller
	return json.Marshal(c)
}
