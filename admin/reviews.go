package admin

import (
	"errors"
	"fmt"
	"sort"

	"github.com/getsanad/sanad/policy"
)

// Reviews is the queue of actions a policy routed to human approval (FR-16).
// *policy.ManualApprover implements it.
//
// The queue is IN-PROCESS, and that shapes where this API can be served from. A pending review
// is a request parked inside the gateway replica that received it; only that replica holds the
// channel that unblocks it. So these endpoints belong to the GATEWAY process (cmd/gateway
// mounts them with admin.ReviewHandler), not to the standalone admin service, and with more
// than one replica an operator must reach the one holding the request — anywhere else the id
// is simply unknown. A shared, durable queue is Phase 3 work; nothing here fakes it.
type Reviews interface {
	Pending() []policy.PendingReview
	Approve(id string) bool
	Deny(id, reason string) bool
}

// Review is the caller-facing projection of a pending approval: what is being asked for and by
// whom, which is what an operator needs to answer it. It is a projection rather than the raw
// policy.Input so the wire shape stays stable as the input grows.
type Review struct {
	ID        string   `json:"id"`
	Server    string   `json:"server"`
	Method    string   `json:"method"`
	Tool      string   `json:"tool,omitempty"`
	Principal string   `json:"principal,omitempty"`
	Agent     string   `json:"agent,omitempty"`
	Scope     []string `json:"delegated_scope,omitempty"` // what the signed chain permits at all
}

// NotFoundError reports that the named resource does not exist. It is a 4xx: the caller asked
// about something that is not there, which for a review means it was already answered, timed
// out, or belongs to another replica — all things the operator needs told apart from success.
type NotFoundError struct {
	Kind string
	ID   string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("admin: no such %s %q (already resolved, expired, or held by another gateway replica)", e.Kind, e.ID)
}

// WithReviews wires the human-approval queue into the control plane, enabling /admin/reviews.
func WithReviews(r Reviews) Option {
	return func(s *Service) { s.reviews = r }
}

// HasReviews reports whether a human-approval queue is available.
func (s *Service) HasReviews() bool { return s.reviews != nil }

// PendingReviews lists the actions waiting for an operator decision.
func (s *Service) PendingReviews() []Review { return pendingReviews(s.reviews) }

// ApproveReview resolves a pending review as allowed, releasing the held request.
func (s *Service) ApproveReview(id string) error { return approveReview(s.reviews, id) }

// DenyReview resolves a pending review as denied, failing the held request closed.
func (s *Service) DenyReview(id, reason string) error { return denyReview(s.reviews, id, reason) }

// pendingReviews projects the queue, sorted by id so listings are stable across calls (the
// underlying store is a map, and an operator comparing two listings should not see churn).
func pendingReviews(r Reviews) []Review {
	if r == nil {
		return []Review{}
	}
	pending := r.Pending()
	out := make([]Review, 0, len(pending))
	for _, p := range pending {
		rev := Review{
			ID:     p.ID,
			Server: p.Input.Server,
			Method: p.Input.Method,
			Tool:   p.Input.Tool,
			Scope:  p.Input.DelegatedScope.Tools,
		}
		if p.Input.Principal != nil {
			rev.Principal = p.Input.Principal.ID
		}
		if p.Input.Agent != nil {
			rev.Agent = p.Input.Agent.ID
		}
		out = append(out, rev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func approveReview(r Reviews, id string) error {
	if err := checkReview(r, id); err != nil {
		return err
	}
	if !r.Approve(id) {
		return &NotFoundError{Kind: "pending review", ID: id}
	}
	return nil
}

// denyReview refuses a pending review. An empty reason gets a default rather than being
// rejected: the reason is carried into the decision the requester and the audit log see, and a
// denial with a thin reason is still better than an operator's denial not going through.
func denyReview(r Reviews, id, reason string) error {
	if err := checkReview(r, id); err != nil {
		return err
	}
	if reason == "" {
		reason = "denied by operator"
	}
	if !r.Deny(id, reason) {
		return &NotFoundError{Kind: "pending review", ID: id}
	}
	return nil
}

func checkReview(r Reviews, id string) error {
	if r == nil {
		return errors.New("admin: no human-approval queue is configured")
	}
	if id == "" {
		return errors.New("admin: review id required")
	}
	return nil
}
