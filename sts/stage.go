package sts

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/getsanad/sanad/gateway"
)

// forwardedHeaders is the allowlist of inbound headers that survive token isolation
// (PRD FR-8). A protected MCP server is only semi-trusted, so the safe default is that it
// learns nothing about the caller it could replay: a denylist forwards every header nobody
// thought to name — the session Cookie, an X-Api-Key, and the agent's own
// X-Agent-Credential / X-Agent-Proof / X-Agent-Delegation, i.e. exactly the material the
// passport exists to withhold. The set below is therefore only what an MCP request needs to
// keep working:
//
//	Accept                MCP streamable HTTP requires "application/json, text/event-stream";
//	                      it is how the client asks for a single JSON reply or an SSE stream.
//	Content-Type          JSON-RPC body framing on POST.
//	Accept-Encoding       without it net/http adds its own "gzip" and transparently
//	                      decompresses, which re-buffers an otherwise byte-transparent SSE
//	                      stream (the reason registry.go sets FlushInterval = -1).
//	User-Agent            not a credential, and the passport already names the principal;
//	                      httputil.ReverseProxy sends none at all when it is absent, which
//	                      upstream logging and WAFs in front of MCP servers dislike.
//	Mcp-Session-Id        MCP session binding — a stateful server answers 400 without it.
//	MCP-Protocol-Version  MCP requires it on every post-initialize request; a server that
//	                      does not see one falls back to assuming protocol 2025-03-26.
//	Last-Event-ID         resumes a dropped SSE stream at the last event received.
//	Connection, Upgrade   httputil.ReverseProxy reads these off the inbound request to detect
//	Te                    a protocol upgrade (and "Te: trailers") before it strips all
//	                      hop-by-hop headers, then re-adds sanitized copies to the outbound
//	                      request — so dropping them here silently kills the upgrade path
//	                      while carrying no caller data of their own.
//
// Content-Length is deliberately absent: net/http regenerates it from Request.ContentLength
// on both HTTP/1.1 and HTTP/2 and ignores the header map's copy, so forwarding the caller's
// is redundant at best. Anything else a specific upstream needs — Origin, tracing context, a
// bespoke tenant selector — is opted into by the operator via WithForwardHeaders.
var forwardedHeaders = []string{
	"Accept",
	"Content-Type",
	"Accept-Encoding",
	"User-Agent",
	"Mcp-Session-Id",
	"MCP-Protocol-Version",
	"Last-Event-ID",
	"Connection",
	"Upgrade",
	"Te",
}

// StageOption configures MintStage.
type StageOption func(*stageOptions)

type stageOptions struct{ forward []string }

// WithForwardHeaders extends the token-isolation allowlist with inbound headers a particular
// upstream legitimately needs (an Origin it validates, W3C tracing context, a tenant
// selector). It can only widen what is forwarded, never what is presented as identity: the
// minted passport is written after filtering, so no configuration puts the caller's own
// Authorization back on the wire.
func WithForwardHeaders(names ...string) StageOption {
	return func(o *stageOptions) { o.forward = append(o.forward, names...) }
}

// MintStage returns a gateway pipeline stage that mints a passport for the verified
// request and enforces token isolation (PRD FR-8): it strips every inbound header that is
// not on the forwardedHeaders allowlist (plus any WithForwardHeaders adds) and forwards
// ONLY the freshly minted passport as a Bearer token. It fails closed if no principal was
// established by an earlier stage.
//
// The requested scope is supplied by the policy decision point in P1-06; until then the
// passport binds identity + audience, which is what enforces SEC-2.
func MintStage(issuer Issuer, opts ...StageOption) gateway.Stage {
	var o stageOptions
	for _, opt := range opts {
		opt(&o)
	}
	allow := make(map[string]bool, len(forwardedHeaders)+len(o.forward))
	for _, name := range slices.Concat(forwardedHeaders, o.forward) {
		if name = strings.TrimSpace(name); name != "" {
			allow[http.CanonicalHeaderKey(name)] = true
		}
	}

	return gateway.NewStage("mint", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("sts: no authenticated principal to mint for")
		}

		audience := req.Server
		if req.Target != nil {
			audience = req.Target.ID
		}

		m, err := issuer.Issue(ctx, IssueRequest{
			Principal:  req.Principal,
			Agent:      req.Agent,
			Audience:   audience,
			Scope:      req.Scope,      // granted by the policy stage (P1-06)
			Delegation: req.Delegation, // verified chain (P2-04), if any
		})
		if err != nil {
			return err
		}
		req.Passport = &m.Passport

		// Token isolation (FR-8): drop everything the caller sent that is not on the
		// allowlist — its credentials, cookies and API keys included — so the upstream sees
		// only the minted passport. Deleting from the map directly (rather than Header.Del)
		// keeps a non-canonical key from surviving the canonicalizing lookup: an unrecognised
		// name is always removed, never forwarded.
		if req.HTTP != nil {
			for name := range req.HTTP.Header {
				if !allow[name] {
					delete(req.HTTP.Header, name)
				}
			}
			req.HTTP.Header.Set("Authorization", "Bearer "+m.Token)
		}
		return nil
	})
}
