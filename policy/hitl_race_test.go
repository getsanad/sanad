package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// TestResolveAndTimeoutAgreeOnOneWinner is the race this fixes.
//
// resolve() used to look the entry up, RELEASE the lock, and only then send on the channel.
// In that window the timeout could fire, deny the request and walk away, while resolve — still
// holding a reference to an abandoned channel — returned true. The operator was told "approved"
// for an action that had already been refused, which is the worst possible disagreement for a
// human-in-the-loop control: the audit log says deny, the person who pressed the button
// believes they let it through, and nobody looks again.
//
// The invariant is one winner per review, and both sides being told which one they are:
//
//	Approve returned true  =>  the requester's decision is allow
//	Approve returned false =>  the requester was denied (timeout), and nobody approved anything
//
// Run with -race -count=20: the timeout is set to fire in the same microseconds as the approval
// so the two paths genuinely collide.
func TestResolveAndTimeoutAgreeOnOneWinner(t *testing.T) {
	// The operator answers a fixed window's worth of review, but at a delay that sweeps from
	// well inside the window to well past it. Early rounds the operator wins outright, late
	// rounds the timeout does, and the ones in between land on the same instant — which is the
	// only interesting case and the one that cannot be produced by asserting on either path
	// alone.
	const (
		rounds = 120
		window = time.Millisecond
		step   = 100 * time.Microsecond
	)

	var approvedButDenied, sawAllow, sawDeny int
	for i := 0; i < rounds; i++ {
		m := NewManualApprover(window)
		delay := time.Duration(i%20) * step

		var (
			wg       sync.WaitGroup
			decision types.Decision
			decErr   error
		)
		done := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, decErr = m.Decide(context.Background(), Input{Server: "s", Method: "tools/call", Tool: "transfer"})
			close(done)
		}()

		// Race the operator against the timeout. Whether the id is even visible in time is
		// itself part of the race: a review that expired before we could read it is one we
		// never approve, which is the honest "false" case.
		var approved bool
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if p := m.Pending(); len(p) > 0 {
					time.Sleep(delay) // answer before, exactly at, or after the expiry
					approved = m.Approve(p[0].ID)
					return
				}
				select {
				case <-done:
					return // the requester has finished; there is nothing left to approve
				default:
				}
			}
		}()
		wg.Wait()

		if decErr != nil {
			t.Fatalf("round %d: decide: %v", i, decErr)
		}
		switch {
		case approved && !decision.Allowed():
			// The bug: an operator told they approved an action the requester saw denied.
			approvedButDenied++
		case approved:
			sawAllow++
		case decision.Allowed():
			// The mirror image: allowed without anyone having successfully approved it.
			t.Fatalf("round %d: request allowed but Approve reported the review was gone", i)
		default:
			sawDeny++
		}

		if p := m.Pending(); len(p) != 0 {
			t.Fatalf("round %d: %d review(s) left pending after resolution", i, len(p))
		}
	}

	if approvedButDenied != 0 {
		t.Fatalf("%d/%d rounds told the operator \"approved\" for a request that was denied", approvedButDenied, rounds)
	}
	// Both outcomes must actually occur, or the test is not exercising the race at all.
	if sawAllow == 0 || sawDeny == 0 {
		t.Fatalf("the race never went both ways (%d approved, %d timed out); the test is not exercising it", sawAllow, sawDeny)
	}
}

// TestResolveAndCancelAgreeOnOneWinner is the same invariant on the other abandonment path: the
// caller disconnects (context cancelled) while an operator is answering.
func TestResolveAndCancelAgreeOnOneWinner(t *testing.T) {
	for i := 0; i < 200; i++ {
		m := NewManualApprover(0) // no timeout: cancellation is the only other way out
		ctx, cancel := context.WithCancel(context.Background())

		var (
			wg       sync.WaitGroup
			decision types.Decision
			decErr   error
			denied   bool
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			decision, decErr = m.Decide(ctx, Input{Server: "s", Method: "tools/call", Tool: "transfer"})
		}()

		id := waitPending(t, m)
		wg.Add(1)
		go func() {
			defer wg.Done()
			denied = m.Deny(id, "not this one")
		}()
		cancel()
		wg.Wait()

		switch {
		case denied && decErr != nil:
			t.Fatalf("round %d: operator told the deny landed, but the request failed with %v instead of carrying it", i, decErr)
		case denied && decision.Allowed():
			t.Fatalf("round %d: operator denied, requester was allowed", i)
		case !denied && decErr == nil:
			t.Fatalf("round %d: nobody resolved the review, yet Decide returned %+v", i, decision)
		}
	}
}

// TestApproveAfterTimeoutIsRefused pins the sequential form of the same rule: once a review has
// timed out and denied, approving it must report false. Silently accepting it would leave an
// operator believing an expired action had been let through.
func TestApproveAfterTimeoutIsRefused(t *testing.T) {
	m := NewManualApprover(10 * time.Millisecond)

	done := make(chan types.Decision, 1)
	go func() {
		d, _ := m.Decide(context.Background(), Input{Server: "s", Tool: "transfer"})
		done <- d
	}()
	id := waitPending(t, m)

	d := <-done
	if d.Allowed() {
		t.Fatal("the review should have timed out and denied")
	}
	if m.Approve(id) || m.Deny(id, "late") {
		t.Fatal("resolving a review the requester has already given up on must report false")
	}
}
