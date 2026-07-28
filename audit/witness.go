package audit

import (
	"crypto/ed25519"
	"errors"
	"sync"

	"github.com/getsanad/sanad/internal/sigctx"
)

// A Witness is an independent party that co-signs the operator's log checkpoints (PRD
// FR-25). Crucially, it co-signs a new checkpoint only after confirming — via a
// consistency proof — that it is an append-only extension of the last checkpoint it saw.
// This stops the operator from quietly rewriting or forking history: external verifiers
// trust a checkpoint only if a witness they trust has co-signed it.
type Witness struct {
	priv        ed25519.PrivateKey
	kid         string
	operatorPub ed25519.PublicKey

	mu       sync.Mutex
	lastSize int
	lastRoot []byte
}

// WitnessSignature is a witness's co-signature over a checkpoint.
type WitnessSignature struct {
	KeyID     string `json:"kid"`
	Size      int    `json:"size"`
	Signature []byte `json:"sig"`
}

// NewWitness returns a witness for the given operator's checkpoint key.
func NewWitness(priv ed25519.PrivateKey, kid string, operatorPub ed25519.PublicKey) (*Witness, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("audit: invalid witness key")
	}
	return &Witness{priv: priv, kid: kid, operatorPub: operatorPub}, nil
}

// PublicKey returns the witness's verification key.
func (w *Witness) PublicKey() ed25519.PublicKey { return w.priv.Public().(ed25519.PublicKey) }

// Witness verifies the operator's checkpoint and that it consistently extends the last
// checkpoint this witness co-signed, then co-signs it. consistency is the proof from the
// witness's last size to cp.Size (empty/ignored on the first observation).
func (w *Witness) Witness(cp SignedCheckpoint, consistency [][]byte) (WitnessSignature, error) {
	if !VerifyCheckpoint(w.operatorPub, cp) {
		return WitnessSignature{}, errors.New("audit: operator checkpoint signature invalid")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.lastSize > 0 {
		if cp.Size < w.lastSize {
			return WitnessSignature{}, errors.New("audit: checkpoint size went backwards (possible rewrite)")
		}
		if !VerifyConsistency(w.lastSize, cp.Size, consistency, w.lastRoot, cp.Root) {
			return WitnessSignature{}, errors.New("audit: checkpoint is not a consistent extension (possible rewrite/fork)")
		}
	}

	w.lastSize = cp.Size
	w.lastRoot = cp.Root
	return WitnessSignature{
		KeyID:     w.kid,
		Size:      cp.Size,
		Signature: sigctx.Sign(sigctx.AuditWitness, w.priv, checkpointMsg(cp)),
	}, nil
}

// VerifyWitness checks a witness co-signature over a checkpoint. The co-signature is made
// under its own context, so the operator cannot present its own checkpoint signature as
// independent corroboration — the point of a witness is that someone else signed.
func VerifyWitness(witnessPub ed25519.PublicKey, cp SignedCheckpoint, ws WitnessSignature) bool {
	return ws.Size == cp.Size && sigctx.Verify(sigctx.AuditWitness, witnessPub, checkpointMsg(cp), ws.Signature)
}
