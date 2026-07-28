package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/config"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
	"github.com/getsanad/sanad/sts"
)

// reviewPolicy is a policy file that lets an agent look around freely but holds one tool for a
// human — the shape the whole feature exists for.
const reviewPolicy = `{
  "version": 1,
  "policy": {
    "servers": {
      "demo": {
        "note": "transfers need a human",
        "allow":  {"methods": ["initialize", "tools/list", "(none)"], "tools": ["read"]},
        "review": {"tools": ["transfer"]}
      }
    }
  }
}`

// reviewHarness stands up the real vertical: a gateway whose policy stage is driven by a
// policy FILE and whose reviews are resolved over the admin HTTP API. Everything a real
// deployment has between the caller and the upstream is here except principal authentication,
// which is stubbed so the test is about authorization and not about credentials.
type reviewHarness struct {
	gateway  *httptest.Server
	admin    http.Handler
	approver *policy.ManualApprover
	upstream *int // requests that actually reached the protected server
}

func newReviewHarness(t *testing.T, timeout time.Duration) *reviewHarness {
	t.Helper()

	var reached int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(upstream.Close)

	reg := gateway.NewRegistry()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}

	file, err := config.Parse([]byte(reviewPolicy), "policy.json")
	if err != nil {
		t.Fatalf("the policy file must load: %v", err)
	}
	approver := policy.NewManualApprover(timeout)
	signer, err := sts.NewLocalSigner("kid-test")
	if err != nil {
		t.Fatal(err)
	}

	// Principal authentication is stubbed: this test is about what an authenticated caller is
	// authorized to do, not about how it authenticated.
	stubPrincipal := gateway.NewStage("principal", func(_ context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		return nil
	})

	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		stubPrincipal,
		policy.Stage(file.Policy.AllowList(), policy.MCPActions, approver),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}}
	gw := httptest.NewServer(g)
	t.Cleanup(gw.Close)

	return &reviewHarness{
		gateway:  gw,
		admin:    ReviewHandler(approver, adminToken),
		approver: approver,
		upstream: &reached,
	}
}

// call sends a real MCP streamable-HTTP request: the tool is params.name in the POSTed body.
func (h *reviewHarness) call(t *testing.T, tool string) <-chan int {
	t.Helper()
	status := make(chan int, 1)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`
	go func() {
		resp, err := http.Post(h.gateway.URL+"/servers/demo/mcp", "application/json", strings.NewReader(body))
		if err != nil {
			status <- 0
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		status <- resp.StatusCode
	}()
	return status
}

// waitForReview polls the admin listing until the held action shows up, which is exactly what
// an operator's console does.
func (h *reviewHarness) waitForReview(t *testing.T) Review {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec := do(t, h.admin, http.MethodGet, "/admin/reviews", adminToken, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /admin/reviews = %d: %s", rec.Code, rec.Body)
		}
		var out []Review
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode listing: %v (%s)", err, rec.Body)
		}
		if len(out) > 0 {
			return out[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no review appeared in the admin listing")
	return Review{}
}

// TestReviewApprovedOverHTTPReleasesTheRequest is the end-to-end claim of FR-16: an action the
// policy would not let through unsupervised is held, an operator sees it and approves it over
// the admin API, and the ORIGINAL request — still in flight — completes.
func TestReviewApprovedOverHTTPReleasesTheRequest(t *testing.T) {
	h := newReviewHarness(t, 5*time.Second)

	status := h.call(t, "transfer")
	rev := h.waitForReview(t)

	if rev.Server != "demo" || rev.Method != "tools/call" || rev.Tool != "transfer" || rev.Principal != "principal-1" {
		t.Fatalf("the listing must say what is being asked for and by whom, got %+v", rev)
	}

	rec := do(t, h.admin, http.MethodPost, "/admin/reviews/approve", adminToken, `{"id":"`+rev.ID+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", rec.Code, rec.Body)
	}
	if got := <-status; got != http.StatusOK {
		t.Fatalf("the approved request returned %d, want 200", got)
	}
	if *h.upstream != 1 {
		t.Fatalf("upstream reached %d times, want once", *h.upstream)
	}

	// The queue drains, so a second approval of the same id is a 404 rather than a second
	// reassuring 200.
	if rec := do(t, h.admin, http.MethodPost, "/admin/reviews/approve", adminToken, `{"id":"`+rev.ID+`"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("re-approving a resolved review = %d, want 404", rec.Code)
	}
}

// TestReviewDeniedOverHTTPFailsTheRequest: the other half. A denial must fail the request
// closed and never reach the upstream.
func TestReviewDeniedOverHTTPFailsTheRequest(t *testing.T) {
	h := newReviewHarness(t, 5*time.Second)

	status := h.call(t, "transfer")
	rev := h.waitForReview(t)

	rec := do(t, h.admin, http.MethodPost, "/admin/reviews/deny", adminToken, `{"id":"`+rev.ID+`","reason":"not this one"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny = %d: %s", rec.Code, rec.Body)
	}
	if got := <-status; got != http.StatusForbidden {
		t.Fatalf("the denied request returned %d, want 403", got)
	}
	if *h.upstream != 0 {
		t.Fatalf("a denied request reached the upstream %d times", *h.upstream)
	}
}

// TestAllowedAndUnlistedToolsNeedNoReview: the allowlist itself still decides everything it
// can, so only what the policy marked for review ever reaches a human.
func TestAllowedAndUnlistedToolsNeedNoReview(t *testing.T) {
	h := newReviewHarness(t, 5*time.Second)

	if got := <-h.call(t, "read"); got != http.StatusOK {
		t.Fatalf("an allowlisted tool returned %d, want 200", got)
	}
	if got := <-h.call(t, "delete_everything"); got != http.StatusForbidden {
		t.Fatalf("an unlisted tool returned %d, want 403", got)
	}
	if p := h.approver.Pending(); len(p) != 0 {
		t.Fatalf("no human should have been asked: %+v", p)
	}
	if *h.upstream != 1 {
		t.Fatalf("upstream reached %d times, want once (the allowed call only)", *h.upstream)
	}
}

// TestReviewEndpointsRequireTheBearerToken: these endpoints release actions a policy held back
// on purpose, so an unauthenticated caller must not be able to see them, let alone resolve one.
func TestReviewEndpointsRequireTheBearerToken(t *testing.T) {
	h := newReviewHarness(t, 5*time.Second)
	status := h.call(t, "transfer")
	rev := h.waitForReview(t)

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/admin/reviews", ""},
		{http.MethodPost, "/admin/reviews/approve", `{"id":"` + rev.ID + `"}`},
		{http.MethodPost, "/admin/reviews/deny", `{"id":"` + rev.ID + `"}`},
	} {
		if rec := do(t, h.admin, tc.method, tc.path, "", tc.body); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a token = %d, want 401", tc.method, tc.path, rec.Code)
		}
		if rec := do(t, h.admin, tc.method, tc.path, "wrong", tc.body); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a bad token = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}

	// Nothing above resolved it, so the request is still waiting.
	if rec := do(t, h.admin, http.MethodPost, "/admin/reviews/deny", adminToken, `{"id":"`+rev.ID+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("deny = %d: %s", rec.Code, rec.Body)
	}
	if got := <-status; got != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got)
	}
}

// TestReviewErrors covers the 4xx surface: an unknown id is a 404 (already answered, expired,
// or parked on another replica), a missing id is a 400.
func TestReviewErrors(t *testing.T) {
	h := newReviewHarness(t, time.Second)

	rec := do(t, h.admin, http.MethodPost, "/admin/reviews/approve", adminToken, `{"id":"nope"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "another gateway replica") {
		t.Fatalf("the 404 should explain the in-process queue, got %q", rec.Body)
	}
	if rec := do(t, h.admin, http.MethodPost, "/admin/reviews/deny", adminToken, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing id = %d, want 400", rec.Code)
	}
	if rec := do(t, h.admin, http.MethodPost, "/admin/reviews/approve", adminToken, `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body = %d, want 400", rec.Code)
	}
	if rec := do(t, h.admin, http.MethodGet, "/admin/reviews", adminToken, ""); rec.Body.String() != "[]\n" {
		t.Fatalf("an empty queue must list as [], got %q", rec.Body)
	}
}

// TestReviewRoutesAbsentWithoutAQueue: the control-plane handler only grows these routes when
// a queue is wired in, matching how the investigation view is gated.
func TestReviewRoutesAbsentWithoutAQueue(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodGet, "/admin/reviews", adminToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /admin/reviews = %d, want 404 when no queue is configured", rec.Code)
	}
}

// TestServiceReviewMethods covers the control-plane service wrapper an in-process embedding
// would use (WithReviews), including the "no queue configured" answer.
func TestServiceReviewMethods(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), nil)
	if svc.HasReviews() {
		t.Fatal("a service with no queue must not claim one")
	}
	if err := svc.ApproveReview("x"); err == nil {
		t.Fatal("approving without a queue must error")
	}

	m := policy.NewManualApprover(time.Second)
	svc = NewService(gateway.NewRegistry(), nil, WithReviews(m))
	if !svc.HasReviews() {
		t.Fatal("WithReviews must enable the queue")
	}
	if got := svc.PendingReviews(); len(got) != 0 {
		t.Fatalf("pending = %v, want none", got)
	}
	if err := svc.DenyReview("", "x"); err == nil {
		t.Fatal("an empty id must be rejected")
	}
	var nf *NotFoundError
	if err := svc.ApproveReview("missing"); err == nil || !errors.As(err, &nf) {
		t.Fatalf("approving an unknown id must be a NotFoundError, got %v", err)
	}
}
