package admin

import (
	"encoding/json"
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
		svc.Restore(in.ID)
		writeJSON(w, http.StatusOK, map[string]string{"restored": in.ID})
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

	return withAuth(token, mux)
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

// respond writes v with code on success, or maps a service error to 400.
func respond(w http.ResponseWriter, code int, err error, v any) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, code, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
