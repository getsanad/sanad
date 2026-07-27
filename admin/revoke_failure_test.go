package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/revoke"
)

// dsnDetail stands in for the kind of internal text a durable store puts in its errors — a
// DSN with a password, a host, a driver code. It must reach the log and never the caller.
const dsnDetail = `dial tcp 10.0.0.5:5432: postgres://passport:hunter2@db.internal/passport`

// flakyKill is a revoke.Store backed by a real MemStore whose writes can be made to fail,
// standing in for an unreachable Postgres kill-switch. applyN > 0 makes it apply that many
// ids before failing — a store that BREAKS the all-or-nothing contract — which is how the
// tests check that the reported outcome comes from the store's actual state rather than
// from the assumption that the write was atomic.
type flakyKill struct {
	*revoke.MemStore
	mu     sync.Mutex
	err    error
	applyN int
}

func newFlakyKill() *flakyKill { return &flakyKill{MemStore: revoke.NewMemStore()} }

func (k *flakyKill) fail(err error, applyN int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.err, k.applyN = err, applyN
}

func (k *flakyKill) Revoke(ids ...string) error { return k.write(k.MemStore.Revoke, ids) }

func (k *flakyKill) Restore(ids ...string) error { return k.write(k.MemStore.Restore, ids) }

func (k *flakyKill) write(op func(...string) error, ids []string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err == nil {
		return op(ids...)
	}
	if n := min(k.applyN, len(ids)); n > 0 {
		_ = op(ids[:n]...)
	}
	return k.err
}

// captureLog redirects the standard logger for the duration of a test so it can assert that
// the internal detail was written where the operator can find it.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return &buf
}

// TestRevokeFailedDurableWriteIs5xxNot200 is the core of the fix: an operator who hits the
// kill-switch must not be told "200 revoked" when the revocation never reached the store
// every gateway reads.
func TestRevokeFailedDurableWriteIs5xxNot200(t *testing.T) {
	kill := newFlakyKill()
	h := NewHandler(NewService(gateway.NewRegistry(), kill), adminToken)
	logs := captureLog(t)

	// While the store is healthy the answer is still a plain 200.
	if rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"agent-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("healthy revoke: got %d (%s), want 200", rec.Code, rec.Body)
	}

	kill.fail(errors.New(dsnDetail), 0)
	rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"agent-2"}`)
	if rec.Code < 500 {
		t.Fatalf("a failed durable write must be 5xx, got %d (%s)", rec.Code, rec.Body)
	}
	if kill.Revoked("agent-2") {
		t.Fatal("agent-2 must not read as revoked after a failed write")
	}

	// The caller is told what did not take effect...
	var body struct {
		Error   string
		Op      string
		Applied []string
		Failed  []string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body, err)
	}
	if body.Op != "revoke" || len(body.Failed) != 1 || body.Failed[0] != "agent-2" {
		t.Fatalf("body must name the id that was not revoked, got %+v", body)
	}
	if len(body.Applied) != 0 {
		t.Fatalf("nothing landed, so applied must be empty, got %v", body.Applied)
	}
	// ...without the internal detail of why.
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "5432") {
		t.Fatalf("response leaks internal store detail: %s", rec.Body)
	}
	// ...which is in the log instead, where the operator can act on it.
	if !strings.Contains(logs.String(), "hunter2") {
		t.Fatalf("the cause must be logged for the operator, got %q", logs.String())
	}
}

// TestRestoreFailedDurableWriteIs5xx: restore is the mirror image and must not lie either —
// an operator told "restored" would expect the agent to be working again.
func TestRestoreFailedDurableWriteIs5xx(t *testing.T) {
	kill := newFlakyKill()
	h := NewHandler(NewService(gateway.NewRegistry(), kill), adminToken)
	captureLog(t)

	if rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"agent-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("healthy revoke: %d", rec.Code)
	}
	kill.fail(errors.New(dsnDetail), 0)

	rec := do(t, h, http.MethodPost, "/admin/restore", adminToken, `{"id":"agent-1"}`)
	if rec.Code < 500 {
		t.Fatalf("a failed restore must be 5xx, got %d (%s)", rec.Code, rec.Body)
	}
	if !kill.Revoked("agent-1") {
		t.Fatal("agent-1 is still revoked; the response must not have claimed otherwise")
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("response leaks internal store detail: %s", rec.Body)
	}
}

// TestCascadeFailureLeavesNothingHalfDone: the cascade is one atomic write, so a failure
// revokes nobody and disables no record — the alternative is a principal reported as cut off
// while some of its agents are still minting passports.
func TestCascadeFailureLeavesNothingHalfDone(t *testing.T) {
	kill := newFlakyKill()
	svc := NewService(gateway.NewRegistry(), kill)
	mustRegister(t, svc, "p1", "a1", "a2")
	kill.fail(errors.New(dsnDetail), 0)

	err := svc.Revoke(context.Background(), "p1")
	var se *StoreError
	if !errors.As(err, &se) {
		t.Fatalf("Revoke() = %v; want a *StoreError", err)
	}
	if got, want := se.IDs, []string{"p1", "a1", "a2"}; !slices.Equal(got, want) {
		t.Fatalf("StoreError.IDs = %v, want the whole cascade %v", got, want)
	}
	if len(se.Applied) != 0 || !slices.Equal(se.Failed(), se.IDs) {
		t.Fatalf("nothing landed: applied=%v failed=%v", se.Applied, se.Failed())
	}
	for _, id := range se.IDs {
		if kill.Revoked(id) {
			t.Fatalf("%s must not be revoked after a failed cascade", id)
		}
	}
	for _, a := range svc.Agents() {
		if a.Disabled {
			t.Fatalf("agent %s was marked disabled although the durable write failed", a.ID)
		}
	}
	for _, p := range svc.Principals() {
		if p.Disabled {
			t.Fatalf("principal %s was marked disabled although the durable write failed", p.ID)
		}
	}
	// The cause is carried for the log, not thrown away.
	if !strings.Contains(se.Error(), "hunter2") {
		t.Fatalf("StoreError must keep the cause for the log, got %q", se.Error())
	}
	if strings.Contains(se.Public(), "hunter2") {
		t.Fatalf("the caller-facing summary must not carry the cause, got %q", se.Public())
	}
}

// TestCascadePartialFailureIsReportedHonestly: the Store contract says a batch is atomic, but
// the report must not simply assume it. Against a store that half-applies the cascade before
// failing, the response says exactly which ids are revoked and which are not.
func TestCascadePartialFailureIsReportedHonestly(t *testing.T) {
	kill := newFlakyKill()
	svc := NewService(gateway.NewRegistry(), kill)
	mustRegister(t, svc, "p1", "a1", "a2")
	h := NewHandler(svc, adminToken)
	captureLog(t)

	kill.fail(errors.New(dsnDetail), 1) // p1 lands; a1 and a2 do not

	rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"p1"}`)
	if rec.Code < 500 {
		t.Fatalf("a partly-applied cascade is still a failure: got %d (%s)", rec.Code, rec.Body)
	}
	var body struct {
		Op              string
		Applied, Failed []string
		Error           string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body, err)
	}
	if !slices.Equal(body.Applied, []string{"p1"}) {
		t.Fatalf("applied = %v, want [p1] (the one id that actually landed)", body.Applied)
	}
	if !slices.Equal(body.Failed, []string{"a1", "a2"}) {
		t.Fatalf("failed = %v, want [a1 a2] (the agents still able to mint)", body.Failed)
	}
	if body.Error == "" {
		t.Fatal("the response must say the operation failed")
	}
}
