package policy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// Approver resolves a decision the PDP routed for human-in-the-loop review (FR-16).
type Approver interface {
	Decide(ctx context.Context, in Input) (types.Decision, error)
}

// ApproverFunc adapts a function to an Approver.
type ApproverFunc func(ctx context.Context, in Input) (types.Decision, error)

// Decide implements Approver.
func (f ApproverFunc) Decide(ctx context.Context, in Input) (types.Decision, error) {
	return f(ctx, in)
}

// PendingReview is an action waiting for an operator decision.
type PendingReview struct {
	ID    string
	Input Input
}

// ManualApprover queues review requests and blocks each one until an operator approves
// or denies it, the request's context is cancelled, or the timeout elapses (which denies).
// It is an in-memory implementation for P1; durable approval workflows are a later
// refinement and would back this with the control plane (P1-10).
type ManualApprover struct {
	timeout time.Duration

	mu      sync.Mutex
	pending map[string]pendingEntry
}

type pendingEntry struct {
	in Input
	ch chan types.Decision
}

// NewManualApprover returns an approver that denies a review after timeout if no operator
// acts. A non-positive timeout means wait indefinitely (until approve/deny or ctx done).
func NewManualApprover(timeout time.Duration) *ManualApprover {
	return &ManualApprover{timeout: timeout, pending: map[string]pendingEntry{}}
}

// Decide registers a pending review and blocks until it is resolved.
func (m *ManualApprover) Decide(ctx context.Context, in Input) (types.Decision, error) {
	id, err := newID()
	if err != nil {
		return types.Decision{}, err
	}
	ch := make(chan types.Decision, 1)

	m.mu.Lock()
	m.pending[id] = pendingEntry{in: in, ch: ch}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pending, id)
		m.mu.Unlock()
	}()

	var timeout <-chan time.Time
	if m.timeout > 0 {
		t := time.NewTimer(m.timeout)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case d := <-ch:
		return d, nil
	case <-timeout:
		return types.Decision{Effect: types.EffectDeny, Reason: "approval timed out"}, nil
	case <-ctx.Done():
		return types.Decision{}, ctx.Err()
	}
}

// Pending lists the reviews awaiting an operator decision.
func (m *ManualApprover) Pending() []PendingReview {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PendingReview, 0, len(m.pending))
	for id, e := range m.pending {
		out = append(out, PendingReview{ID: id, Input: e.in})
	}
	return out
}

// Approve resolves a pending review as allowed. It reports whether the id was found.
func (m *ManualApprover) Approve(id string) bool {
	return m.resolve(id, types.Decision{Effect: types.EffectAllow, Reason: "approved"})
}

// Deny resolves a pending review as denied with the given reason.
func (m *ManualApprover) Deny(id, reason string) bool {
	return m.resolve(id, types.Decision{Effect: types.EffectDeny, Reason: reason})
}

func (m *ManualApprover) resolve(id string, d types.Decision) bool {
	m.mu.Lock()
	e, ok := m.pending[id]
	m.mu.Unlock()
	if !ok {
		return false
	}
	e.ch <- d
	return true
}

func newID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("policy: id generation failed")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
