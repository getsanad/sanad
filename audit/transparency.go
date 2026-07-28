package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"

	"github.com/getsanad/sanad/internal/sigctx"
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

	mu     sync.Mutex
	leaves [][]byte // leaf data = each entry's chain hash (a commitment to the entry)
}

// NewTransparencyLog returns a transparency log signing checkpoints with signer.
func NewTransparencyLog(signer ed25519.PrivateKey, kid string, sink Sink) (*TransparencyLog, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: invalid checkpoint signing key")
	}
	return &TransparencyLog{chain: NewHashChainLog(sink), signer: signer, kid: kid}, nil
}

// Append records an entry (chain + sink) and adds its commitment as a Merkle leaf. The
// chain append and the leaf append are one critical section, so leaf i is always the hash
// of entry i: locking the leaves alone would stop the data race but still let two appends
// commit their leaves in the opposite order from the chain, which yields inclusion proofs
// for the wrong entry. Streaming to the sink stays outside the lock, as in HashChainLog.
func (l *TransparencyLog) Append(_ context.Context, e Entry) error {
	l.mu.Lock()
	stored, sink := l.chain.commit(e)
	l.leaves = append(l.leaves, stored.Hash)
	l.mu.Unlock()

	if sink != nil {
		return sink.Write(stored)
	}
	return nil
}

// Entries, Verify, and Investigate delegate to the underlying hash-chained log.
func (l *TransparencyLog) Entries() []Entry                      { return l.chain.Entries() }
func (l *TransparencyLog) Verify() error                         { return l.chain.Verify() }
func (l *TransparencyLog) Investigate(id string) (Report, error) { return l.chain.Investigate(id) }

// Size is the number of entries.
func (l *TransparencyLog) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.leaves)
}

// Root is the current Merkle tree head.
func (l *TransparencyLog) Root() []byte { return Root(l.snapshot()) }

// snapshot copies the leaf list. Every reader works from one snapshot, so it sees a single
// log state (never a size and a root from different ones) and the O(n) Merkle math runs
// without holding the lock against concurrent appends. The leaf hashes are never mutated,
// so sharing the underlying arrays is safe.
func (l *TransparencyLog) snapshot() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][]byte, len(l.leaves))
	copy(out, l.leaves)
	return out
}

// PublicKey returns the checkpoint verification key.
func (l *TransparencyLog) PublicKey() ed25519.PublicKey {
	return l.signer.Public().(ed25519.PublicKey)
}

// Checkpoint returns a signed commitment to the current log state.
func (l *TransparencyLog) Checkpoint() SignedCheckpoint {
	leaves := l.snapshot()
	cp := SignedCheckpoint{Size: len(leaves), Root: Root(leaves), KeyID: l.kid}
	cp.Signature = sigctx.Sign(sigctx.AuditCheckpoint, l.signer, checkpointMsg(cp))
	return cp
}

// InclusionProof returns the leaf data and audit path for the entry at index, to verify
// against a checkpoint root with VerifyInclusion.
func (l *TransparencyLog) InclusionProof(index int) (leaf []byte, proof [][]byte, err error) {
	leaves := l.snapshot()
	if index < 0 || index >= len(leaves) {
		return nil, nil, errors.New("audit: index out of range")
	}
	proof, err = InclusionProof(leaves, index)
	return leaves[index], proof, err
}

// ConsistencyProof proves the log at oldSize is a prefix of the current log.
func (l *TransparencyLog) ConsistencyProof(oldSize int) ([][]byte, error) {
	return ConsistencyProof(l.snapshot(), oldSize)
}

// VerifyCheckpoint checks a checkpoint's operator signature. A witness co-signature over the
// same checkpoint is made under a different context and is rejected here, so co-signatures
// cannot be passed off as the operator's own commitment (and vice versa).
func VerifyCheckpoint(pub ed25519.PublicKey, cp SignedCheckpoint) bool {
	return sigctx.Verify(sigctx.AuditCheckpoint, pub, checkpointMsg(cp), cp.Signature)
}

func checkpointMsg(cp SignedCheckpoint) []byte {
	b, _ := json.Marshal(struct {
		Size  int    `json:"size"`
		Root  []byte `json:"root"`
		KeyID string `json:"kid"`
	}{cp.Size, cp.Root, cp.KeyID})
	return b
}
