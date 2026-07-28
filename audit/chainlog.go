package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
)

// HashChainLog is an append-only, tamper-evident audit log (PRD FR-21). Each entry's Hash
// covers the previous entry's Hash plus the entry's content, so any silent edit or
// deletion breaks the chain (detectable via Verify). It optionally streams every entry to
// a Sink (FR-23). This in-memory store is the P1 system of record; ADR-003 layers a Merkle
// transparency log and independent witnesses on the same entries in P3-02/P3-03.
type HashChainLog struct {
	sink Sink

	mu      sync.Mutex
	entries []Entry
	last    []byte // hash of the most recent entry
}

// NewHashChainLog returns a log that streams appended entries to sink (sink may be nil).
func NewHashChainLog(sink Sink) *HashChainLog {
	return &HashChainLog{sink: sink}
}

// Append records an entry, chaining it to the previous one, then streams it to the sink.
func (l *HashChainLog) Append(_ context.Context, e Entry) error {
	e, sink := l.commit(e)
	if sink != nil {
		return sink.Write(e)
	}
	return nil
}

// commit chains e onto the log under the lock and returns it exactly as stored (PrevHash
// and Hash filled in) together with the sink it still has to be streamed to. Callers that
// maintain a structure derived from the chain — the Merkle leaves in TransparencyLog — hold
// their own lock across this call so their order is the chain's order, and never have to
// re-read the tail to learn what they just appended. Streaming is left to the caller so it
// keeps happening outside every lock.
func (l *HashChainLog) commit(e Entry) (Entry, Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.PrevHash = l.last
	e.Hash = contentHash(l.last, e)
	l.entries = append(l.entries, e)
	l.last = e.Hash
	return e, l.sink
}

// Entries returns a copy of the recorded entries.
func (l *HashChainLog) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Verify checks the integrity of the whole chain.
func (l *HashChainLog) Verify() error {
	return VerifyChain(l.Entries())
}

// VerifyChain reports an error if the entries do not form an intact hash chain — i.e. if
// any entry was edited, inserted, removed, or reordered.
func VerifyChain(entries []Entry) error {
	var prev []byte
	for i, e := range entries {
		if !bytes.Equal(e.PrevHash, prev) {
			return fmt.Errorf("audit: broken chain at entry %d (prev hash mismatch)", i)
		}
		if !bytes.Equal(e.Hash, contentHash(prev, e)) {
			return fmt.Errorf("audit: tampered entry %d (content hash mismatch)", i)
		}
		prev = e.Hash
	}
	return nil
}

// contentHash = SHA-256(prevHash || canonical(entry content excluding PrevHash/Hash)).
func contentHash(prev []byte, e Entry) []byte {
	h := sha256.New()
	h.Write(prev)
	view := struct {
		At         int64    `json:"at"`
		Action     string   `json:"action"`
		Reason     string   `json:"reason"`
		Server     string   `json:"server"`
		Principal  string   `json:"principal"`
		Agent      string   `json:"agent"`
		PassportID string   `json:"passport_id"`
		Delegation []string `json:"delegation"`
		Effect     string   `json:"effect"`
		DReason    string   `json:"decision_reason"`
		Drift      *Drift   `json:"drift"`
	}{
		At: e.At.UnixNano(), Action: e.Action, Reason: e.Reason, Server: e.Server,
		Principal: e.Principal, Agent: e.Agent, PassportID: e.PassportID, Delegation: e.Delegation,
		Drift: e.Drift,
	}
	if e.Decision != nil {
		view.Effect = string(e.Decision.Effect)
		view.DReason = e.Decision.Reason
	}
	_ = json.NewEncoder(h).Encode(view)
	return h.Sum(nil)
}
