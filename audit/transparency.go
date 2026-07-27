package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

// SignedCheckpoint is a signed commitment to the log at a point in time: its size and
// Merkle root, signed by the operator (PRD FR-25). Witnesses co-sign these (P3-03) so
// external parties can confirm the log has not been rewritten.
type SignedCheckpoint struct {
	Size      int    `json:"size"`
	Root      []byte `json:"root"`
	KeyID     string `json:"kid"`
	Signature []byte `json:"sig"`
}

// TransparencyLog is the high-assurance audit log (ADR-003, P3-02): a hash-chained,
// SIEM-streamed log (as before) PLUS a Merkle tree that yields inclusion and consistency
// proofs and signed checkpoints. It implements Log, so it can back the gateway hook.
type TransparencyLog struct {
	chain  *HashChainLog
	signer ed25519.PrivateKey
	kid    string

	leaves [][]byte // leaf data = each entry's chain hash (a commitment to the entry)
}

// NewTransparencyLog returns a transparency log signing checkpoints with signer.
func NewTransparencyLog(signer ed25519.PrivateKey, kid string, sink Sink) (*TransparencyLog, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: invalid checkpoint signing key")
	}
	return &TransparencyLog{chain: NewHashChainLog(sink), signer: signer, kid: kid}, nil
}

// Append records an entry (chain + sink) and adds its commitment as a Merkle leaf.
func (l *TransparencyLog) Append(ctx context.Context, e Entry) error {
	if err := l.chain.Append(ctx, e); err != nil {
		return err
	}
	entries := l.chain.Entries()
	l.leaves = append(l.leaves, entries[len(entries)-1].Hash)
	return nil
}

// Entries, Verify, and Investigate delegate to the underlying hash-chained log.
func (l *TransparencyLog) Entries() []Entry                      { return l.chain.Entries() }
func (l *TransparencyLog) Verify() error                         { return l.chain.Verify() }
func (l *TransparencyLog) Investigate(id string) (Report, error) { return l.chain.Investigate(id) }

// Size is the number of entries.
func (l *TransparencyLog) Size() int { return len(l.leaves) }

// Root is the current Merkle tree head.
func (l *TransparencyLog) Root() []byte { return Root(l.leaves) }

// PublicKey returns the checkpoint verification key.
func (l *TransparencyLog) PublicKey() ed25519.PublicKey {
	return l.signer.Public().(ed25519.PublicKey)
}

// Checkpoint returns a signed commitment to the current log state.
func (l *TransparencyLog) Checkpoint() SignedCheckpoint {
	cp := SignedCheckpoint{Size: len(l.leaves), Root: Root(l.leaves), KeyID: l.kid}
	cp.Signature = ed25519.Sign(l.signer, checkpointMsg(cp))
	return cp
}

// InclusionProof returns the leaf data and audit path for the entry at index, to verify
// against a checkpoint root with VerifyInclusion.
func (l *TransparencyLog) InclusionProof(index int) (leaf []byte, proof [][]byte, err error) {
	if index < 0 || index >= len(l.leaves) {
		return nil, nil, errors.New("audit: index out of range")
	}
	proof, err = InclusionProof(l.leaves, index)
	return l.leaves[index], proof, err
}

// ConsistencyProof proves the log at oldSize is a prefix of the current log.
func (l *TransparencyLog) ConsistencyProof(oldSize int) ([][]byte, error) {
	return ConsistencyProof(l.leaves, oldSize)
}

// VerifyCheckpoint checks a checkpoint's operator signature.
func VerifyCheckpoint(pub ed25519.PublicKey, cp SignedCheckpoint) bool {
	return ed25519.Verify(pub, checkpointMsg(cp), cp.Signature)
}

func checkpointMsg(cp SignedCheckpoint) []byte {
	b, _ := json.Marshal(struct {
		Size  int    `json:"size"`
		Root  []byte `json:"root"`
		KeyID string `json:"kid"`
	}{cp.Size, cp.Root, cp.KeyID})
	return b
}
