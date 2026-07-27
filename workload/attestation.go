package workload

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// MeasuredAttestor is a RATS-style attestor for the high-assurance tier (PRD FR-26, P3-01).
// It verifies a quote — signed by a trusted attestation key (a TEE/TPM platform identity) —
// asserting that the agent runs an approved build (measurement). It rejects quotes signed
// by an untrusted key, carrying an unrecognized measurement, or that are stale. A real
// deployment sources the quote from hardware; here the quote is an Ed25519-signed assertion.
type MeasuredAttestor struct {
	attKey   ed25519.PublicKey
	approved map[string]struct{}
	maxAge   time.Duration
	now      func() time.Time
}

// Quote is the attestation evidence: the agent identity, the measured build, when it was
// produced, and a signature by the attestation key.
type Quote struct {
	AgentID     string    `json:"agent_id"`
	Measurement string    `json:"measurement"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   []byte    `json:"sig"`
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
// key). Returns the JSON evidence bytes to pass to Authority.Issue.
func SignQuote(attKey ed25519.PrivateKey, agentID, measurement string, issuedAt time.Time) ([]byte, error) {
	q := Quote{AgentID: agentID, Measurement: measurement, IssuedAt: issuedAt.UTC()}
	q.Signature = ed25519.Sign(attKey, quoteMsg(q))
	return json.Marshal(q)
}

// Attest verifies the quote and returns the attested agent id (implements Attestor).
func (m *MeasuredAttestor) Attest(evidence []byte) (string, error) {
	var q Quote
	if err := json.Unmarshal(evidence, &q); err != nil {
		return "", fmt.Errorf("workload: bad attestation evidence: %w", err)
	}
	if !ed25519.Verify(m.attKey, quoteMsg(q), q.Signature) {
		return "", errors.New("workload: attestation quote signature invalid")
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
		IssuedAt    int64  `json:"issued_at"`
	}{q.AgentID, q.Measurement, q.IssuedAt.Unix()})
	return b
}
