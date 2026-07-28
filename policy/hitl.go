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
//
// The queue lives in THIS PROCESS: a pending review is a goroutine parked inside the gateway
// replica that is holding the request, so only that replica can resolve it. With more than one
// replica an operator must therefore reach the one that took the request; a durable, shared
// queue is a later refinement and would back this with the control plane (P1-10).
//
// Every review has exactly one resolver. Approve/Deny and the timeout/cancellation path race
// for the same entry under the lock, and the loser is told so: an operator who is told
// "approved" has approved the decision the requester actually received, never one that had
// already been denied out from under them.
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
//
// Timing out or being cancelled does not simply abandon the entry: it CLAIMS it, so that an
// operator resolving at the same instant either wins (and their decision is the one returned,
// however late) or is told the review is gone. Abandoning it was the bug — the requester was
// denied on the timeout while Approve, holding a reference to the same channel, still reported
// success to the operator.
func (m *ManualApprover) Decide(ctx context.Context, in Input) (types.Decision, error) {
	id, err := newID()
	if err != nil {
		return types.Decision{}, err
	}
	ch := make(chan types.Decision, 1)

	m.mu.Lock()
	m.pending[id] = pendingEntry{in: in, ch: ch}
	m.mu.Unlock()

	var timeout <-chan time.Time
	if m.timeout > 0 {
		t := time.NewTimer(m.timeout)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case d := <-ch:
		// resolve() won: it removed the entry before sending, so nothing else can resolve it.
		return d, nil
	case <-timeout:
		if d, resolved := m.claim(id, ch); resolved {
			return d, nil
		}
		return types.Decision{Effect: types.EffectDeny, Reason: "approval timed out"}, nil
	case <-ctx.Done():
		if d, resolved := m.claim(id, ch); resolved {
			return d, nil
		}
		return types.Decision{}, ctx.Err()
	}
}

// claim takes the review off the queue on behalf of the waiter and reports whether an operator
// got there first. If the entry is still present the waiter is the single winner: no resolve
// can succeed afterwards, so the caller is free to deny. If it is gone, resolve() already
// committed a decision AND has already sent it — the send happens under the same lock this
// call is waiting on — so the receive below cannot block, and returning that decision is what
// keeps the operator's answer and the requester's outcome the same answer.
func (m *ManualApprover) claim(id string, ch <-chan types.Decision) (types.Decision, bool) {
	m.mu.Lock()
	_, stillPending := m.pending[id]
	delete(m.pending, id)
	m.mu.Unlock()

	if stillPending {
		return types.Decision{}, false
	}
	return <-ch, true
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

// Approve resolves a pending review as allowed. It reports whether the review was still
// pending — a false means nobody was told "allow", because the requester had already given up
// (timeout or disconnect) or another operator had already answered.
func (m *ManualApprover) Approve(id string) bool {
	return m.resolve(id, types.Decision{Effect: types.EffectAllow, Reason: "approved"})
}

// Deny resolves a pending review as denied with the given reason. As with Approve, false means
// the review was no longer pending.
func (m *ManualApprover) Deny(id, reason string) bool {
	return m.resolve(id, types.Decision{Effect: types.EffectDeny, Reason: reason})
}

// resolve delivers d to the waiting request, atomically. Removing the entry and sending happen
// under ONE hold of the lock, which is what makes the resolution single-winner: whoever removes
// the entry — this call, or the waiter's claim() on timeout/cancellation — is the only one that
// can commit an outcome, and the other is told it lost. Releasing the lock between the lookup
// and the send (as this used to) let a timeout deny the request while this call still returned
// true, telling an operator they had approved an action that was in fact refused.
//
// The send cannot block: the channel is buffered for one, and only the goroutine that removed
// the entry from the map ever sends on it.
func (m *ManualApprover) resolve(id string, d types.Decision) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.pending[id]
	if !ok {
		return false
	}
	delete(m.pending, id)
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
