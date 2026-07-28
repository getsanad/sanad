package workload

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MeasuredAttestor is a RATS-style attestor for the high-assurance tier (PRD FR-26, P3-01).
// It verifies a quote — signed by a trusted attestation key (a TEE/TPM platform identity) —
// asserting that the agent runs an approved build (measurement), that it is answering this
// enrollment's challenge, and that the key being enrolled is the one it speaks for. It
// rejects quotes signed by an untrusted key, carrying an unrecognized measurement, that are
// stale, or that name a different nonce or key. A real deployment sources the quote from
// hardware; here the quote is an Ed25519-signed assertion.
type MeasuredAttestor struct {
	attKey   ed25519.PublicKey
	approved map[string]struct{}
	maxAge   time.Duration
	now      func() time.Time
}

// Quote is the attestation evidence: the agent identity, the measured build, the challenge
// it answers, the key it speaks for, when it was produced, and a signature by the
// attestation key.
//
// This is a JSON stand-in for a hardware quote rather than a wire-format EAT, but it borrows
// the IETF EAT claim names (RFC 9711) for the two fields that carry the security property:
// eat_nonce is the verifier-supplied freshness challenge, and cnf is the confirmation claim
// (RFC 8747) naming the key the credential will be bound to. Both are covered by Signature,
// so neither can be swapped after the fact.
type Quote struct {
	AgentID     string    `json:"agent_id"`
	Measurement string    `json:"measurement"`
	Nonce       []byte    `json:"eat_nonce"`
	Confirm     Confirm   `json:"cnf"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   []byte    `json:"sig"`
}

// Confirm is the EAT/CWT confirmation claim (RFC 8747 §3.1), naming the public key the
// quote speaks for.
type Confirm struct {
	JWK JWK `json:"jwk"`
}

// JWK is the OKP JSON Web Key of an Ed25519 public key (RFC 8037 §2).
type JWK struct {
	Kty string `json:"kty"` // "OKP"
	Crv string `json:"crv"` // "Ed25519"
	X   string `json:"x"`   // base64url public key
}

// confirmKey builds the cnf claim for an Ed25519 public key.
func confirmKey(pub ed25519.PublicKey) Confirm {
	return Confirm{JWK: JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}}
}

// PublicKey returns the confirmed Ed25519 key, or an error if the claim names anything else.
func (c Confirm) PublicKey() (ed25519.PublicKey, error) {
	if c.JWK.Kty != "OKP" || c.JWK.Crv != "Ed25519" {
		return nil, fmt.Errorf("workload: unsupported confirmation key %s/%s", c.JWK.Kty, c.JWK.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.JWK.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("workload: bad confirmation key")
	}
	return ed25519.PublicKey(raw), nil
}

// NewMeasuredAttestor trusts attKey and the given approved measurements. maxAge bounds how
// stale a quote may be (0 = no freshness check).
func NewMeasuredAttestor(attKey ed25519.PublicKey, approvedMeasurements []string, maxAge time.Duration) (*MeasuredAttestor, error) {
	if len(attKey) != ed25519.PublicKeySize {
		return nil, errors.New("workload: invalid attestation key")
	}
	approved := make(map[string]struct{}, len(approvedMeasurements))
	for _, m := range approvedMeasurements {
		approved[m] = struct{}{}
	}
	return &MeasuredAttestor{attKey: attKey, approved: approved, maxAge: maxAge, now: time.Now}, nil
}

// SignQuote builds the attestation evidence an agent presents (signed by the attestation
// key), committing to the authority-issued nonce and the instance key being enrolled.
// Returns the JSON evidence bytes to pass to Authority.Issue.
func SignQuote(attKey ed25519.PrivateKey, agentID, measurement string, nonce []byte, pub ed25519.PublicKey, issuedAt time.Time) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("workload: invalid instance public key")
	}
	q := Quote{
		AgentID:     agentID,
		Measurement: measurement,
		Nonce:       nonce,
		Confirm:     confirmKey(pub),
		IssuedAt:    issuedAt.UTC(),
	}
	q.Signature = ed25519.Sign(attKey, quoteMsg(q))
	return json.Marshal(q)
}

// Attest verifies the quote and returns the attested agent id (implements Attestor). The
// quote must answer this enrollment's nonce and speak for pubKey; a quote for either a
// different challenge or a different key is evidence of a replay and is refused.
func (m *MeasuredAttestor) Attest(evidence, nonce []byte, pubKey ed25519.PublicKey) (string, error) {
	var q Quote
	if err := json.Unmarshal(evidence, &q); err != nil {
		return "", fmt.Errorf("workload: bad attestation evidence: %w", err)
	}
	if !ed25519.Verify(m.attKey, quoteMsg(q), q.Signature) {
		return "", errors.New("workload: attestation quote signature invalid")
	}
	if subtle.ConstantTimeCompare(q.Nonce, nonce) != 1 {
		return "", errors.New("workload: attestation quote answers a different nonce")
	}
	confirmed, err := q.Confirm.PublicKey()
	if err != nil {
		return "", err
	}
	if !confirmed.Equal(pubKey) {
		return "", errors.New("workload: attestation quote is bound to a different public key")
	}
	if _, ok := m.approved[q.Measurement]; !ok {
		return "", fmt.Errorf("workload: unrecognized build measurement %q", q.Measurement)
	}
	if m.maxAge > 0 && m.now().UTC().Sub(q.IssuedAt) > m.maxAge {
		return "", errors.New("workload: stale attestation quote")
	}
	if q.AgentID == "" {
		return "", errors.New("workload: attestation quote has no agent id")
	}
	return q.AgentID, nil
}

func quoteMsg(q Quote) []byte {
	b, _ := json.Marshal(struct {
		AgentID     string `json:"agent_id"`
		Measurement string `json:"measurement"`
		Nonce       []byte `json:"eat_nonce"`
		Confirm     JWK    `json:"cnf"`
		IssuedAt    int64  `json:"issued_at"`
	}{q.AgentID, q.Measurement, q.Nonce, q.Confirm.JWK, q.IssuedAt.Unix()})
	return b
}
