package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/getsanad/sanad/pkg/types"
)

// NewHandler returns the admin control-plane HTTP API. If token is non-empty, every
// request must carry `Authorization: Bearer <token>` (a minimal guard; real deployments
// use the operator IdP + RBAC). All mutating actions should be audited (P1-08) — wired
// where this handler is mounted.
func NewHandler(svc *Service, token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /admin/principals", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Subject, Assurance string }
		if !decode(w, r, &in) {
			return
		}
		p := types.Principal{ID: in.ID, Subject: in.Subject, Assurance: types.AssuranceLevel(in.Assurance)}
		respond(w, http.StatusCreated, svc.RegisterPrincipal(r.Context(), p), p)
	})
	mux.HandleFunc("GET /admin/principals", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Principals())
	})

	mux.HandleFunc("POST /admin/agents", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, PrincipalID, BlueprintID string }
		if !decode(w, r, &in) {
			return
		}
		a := types.Agent{ID: in.ID, PrincipalID: in.PrincipalID, BlueprintID: in.BlueprintID}
		respond(w, http.StatusCreated, svc.RegisterAgent(r.Context(), a), a)
	})
	mux.HandleFunc("GET /admin/agents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Agents())
	})

	mux.HandleFunc("POST /admin/blueprints", func(w http.ResponseWriter, r *http.Request) {
		var bp Blueprint
		if !decode(w, r, &bp) {
			return
		}
		respond(w, http.StatusCreated, svc.RegisterBlueprint(r.Context(), bp), bp)
	})
	mux.HandleFunc("GET /admin/blueprints", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Blueprints())
	})
	mux.HandleFunc("POST /admin/agents/instantiate", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ BlueprintID, AgentID string }
		if !decode(w, r, &in) {
			return
		}
		a, err := svc.InstantiateAgent(r.Context(), in.BlueprintID, in.AgentID)
		respond(w, http.StatusCreated, err, a)
	})

	mux.HandleFunc("POST /admin/servers", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Upstream string }
		if !decode(w, r, &in) {
			return
		}
		respond(w, http.StatusCreated, svc.RegisterServer(in.ID, in.Upstream), in)
	})

	mux.HandleFunc("POST /admin/revoke", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID string }
		if !decode(w, r, &in) {
			return
		}
		respond(w, http.StatusOK, svc.Revoke(r.Context(), in.ID), map[string]string{"revoked": in.ID})
	})
	mux.HandleFunc("POST /admin/restore", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID string }
		if !decode(w, r, &in) {
			return
		}
		respond(w, http.StatusOK, svc.Restore(in.ID), map[string]string{"restored": in.ID})
	})
	mux.HandleFunc("GET /admin/revocations", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Revocations())
	})

	// Investigation view (FR-24), available only when an audit log is wired in.
	if svc.HasAudit() {
		mux.HandleFunc("GET /admin/investigate", func(w http.ResponseWriter, r *http.Request) {
			rep, err := svc.Investigate(r.URL.Query().Get("passport"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, rep)
		})
	}

	// Human-approval queue (FR-16), available only when one is wired in — and only meaningful
	// in a process that actually holds pending reviews (see Reviews).
	if svc.HasReviews() {
		registerReviews(mux, svc.reviews)
	}

	return withAuth(token, mux)
}

// ReviewHandler serves ONLY the human-approval endpoints, for the process that holds the
// queue: the gateway. It is separate from NewHandler because the gateway has no business
// exposing the rest of the control plane (principals, agents, the kill-switch) on its data
// plane, and because the queue is per-process — a review can only be answered where it is
// parked (see Reviews).
//
// token is required by the caller (cmd/gateway refuses to mount this without one): these
// endpoints release actions a policy deliberately held for a human, so an unauthenticated one
// would let the caller whose request is pending approve it themselves.
func ReviewHandler(r Reviews, token string) http.Handler {
	mux := http.NewServeMux()
	registerReviews(mux, r)
	return withAuth(token, mux)
}

// registerReviews mounts the review endpoints on mux:
//
//	GET  /admin/reviews          list what is waiting for a decision
//	POST /admin/reviews/approve  {"id": "…"}                  release the held request
//	POST /admin/reviews/deny     {"id": "…", "reason": "…"}   fail it closed
//
// Resolving is a POST with the id in the body rather than in the path, to match the shape the
// rest of this API already uses (/admin/revoke, /admin/restore). An id that is no longer
// pending is a 404, never a 200: "approved" must mean the request was actually released.
func registerReviews(mux *http.ServeMux, reviews Reviews) {
	mux.HandleFunc("GET /admin/reviews", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, pendingReviews(reviews))
	})
	mux.HandleFunc("POST /admin/reviews/approve", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID string }
		if !decode(w, r, &in) {
			return
		}
		respond(w, http.StatusOK, approveReview(reviews, in.ID), map[string]string{"approved": in.ID})
	})
	mux.HandleFunc("POST /admin/reviews/deny", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ ID, Reason string }
		if !decode(w, r, &in) {
			return
		}
		respond(w, http.StatusOK, denyReview(reviews, in.ID, in.Reason), map[string]string{"denied": in.ID})
	})
}

func withAuth(token string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return false
	}
	return true
}

// respond writes v with code on success, or maps a service error to a status (writeError).
func respond(w http.ResponseWriter, code int, err error, v any) {
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, code, v)
}

// writeError maps a service error to a response. A failure of the durable kill-switch is the
// server's problem, not the caller's: it must never read as success — an operator told "200
// revoked" walks away believing the agent is cut off — and it is not a 400 either, so it
// becomes 503 with an explicit account of which ids did and did not take effect. The cause
// itself stays in the server log; it can carry a DSN, host, or driver detail that must not
// leave the process. A reference to something that does not exist is a 404, separated from the
// 400s because "your request was malformed" and "that review is no longer pending" call for
// different next moves. Everything else is a validation error the caller can act on and keeps
// its message, which this package writes itself.
func writeError(w http.ResponseWriter, err error) {
	var se *StoreError
	if errors.As(err, &se) {
		log.Printf("%v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":   se.Public(),
			"op":      se.Op,
			"applied": se.Applied,
			"failed":  se.Failed(),
		})
		return
	}
	var nf *NotFoundError
	if errors.As(err, &nf) {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
