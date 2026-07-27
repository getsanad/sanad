package gateway

import (
	"net/http/httputil"
	"net/url"
)

// Transport is the MCP wire protocol a protected server speaks.
type Transport string

const (
	TransportHTTP Transport = "http" // streamable HTTP (default)
	TransportSSE  Transport = "sse"  // server-sent events
)

// AssuranceTier selects how much identity proof a server demands. Higher tiers gate on
// instance mTLS (P2) and code attestation (P3); in P1 all tiers are treated the same.
type AssuranceTier string

const (
	TierStandard AssuranceTier = "standard"
	TierHigh     AssuranceTier = "high"
)

// Server is a protected MCP server the gateway proxies to. No agent reaches it directly.
type Server struct {
	ID        string
	Upstream  *url.URL
	Transport Transport
	Tier      AssuranceTier

	proxy *httputil.ReverseProxy // built by Registry.Register
}
