package gateway

import (
	"net/http"
	"strings"
)

// serverPrefix is the URL namespace under which protected servers are addressed:
// /servers/{id}/<upstream path>.
const serverPrefix = "/servers/"

// AuditFunc receives the outcome of each request for recording. It is an optional seam
// for the audit log (P1-08); the gateway calls it for both allows and denials.
type AuditFunc func(req *Request, allowed bool, reason string)

// Gateway is the enforcement point. It implements http.Handler: it resolves the target
// protected server, runs the decision pipeline, and forwards the request upstream only
// on a clean run that minted a passport. Unknown servers, pipeline errors and a missing
// passport all fail closed (NFR-3).
type Gateway struct {
	Registry *Registry
	Pipeline Pipeline
	Audit    AuditFunc // optional
}

func (g *Gateway) audit(req *Request, allowed bool, reason string) {
	if g.Audit != nil {
		g.Audit(req, allowed, reason)
	}
}

// ServeHTTP routes health/readiness probes and proxies /servers/{id}/... requests.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	case "/readyz":
		if g.Registry == nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
		return
	}

	id, upstreamPath, ok := parseServerPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	srv, found := g.Registry.Lookup(id)
	if !found {
		// Unregistered server: deny, never forward (fail-closed).
		g.audit(&Request{Server: id, HTTP: r}, false, "unknown server")
		http.Error(w, "unknown server", http.StatusNotFound)
		return
	}

	req := &Request{Server: id, Target: srv, HTTP: r}
	if err := g.Pipeline.Run(r.Context(), req); err != nil {
		// Any stage failure fails closed; the upstream is never contacted.
		g.audit(req, false, err.Error())
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if req.Passport == nil {
		// A clean run is not enough: the upstream may only ever be reached with a minted
		// passport (FR-8), so a pipeline that produced none — an empty or misconfigured
		// one included — is a denial rather than a pass-through (NFR-3).
		g.audit(req, false, "no passport minted")
		http.Error(w, "denied", http.StatusForbidden)
		return
	}

	// Strip the /servers/{id} prefix so the upstream sees a clean MCP path.
	r.URL.Path = upstreamPath
	r.URL.RawPath = ""

	g.audit(req, true, "allow")
	srv.proxy.ServeHTTP(w, r)
}

// parseServerPath extracts the server id and the remaining upstream path from a URL of
// the form /servers/{id}/rest...  Returns ok=false if the path is not server-scoped.
func parseServerPath(p string) (id, upstreamPath string, ok bool) {
	rest := strings.TrimPrefix(p, serverPrefix)
	if rest == p || rest == "" {
		return "", "", false
	}
	id, remainder, _ := strings.Cut(rest, "/")
	if id == "" {
		return "", "", false
	}
	return id, "/" + remainder, true
}
