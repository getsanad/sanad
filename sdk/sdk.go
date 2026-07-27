// Package sdk is the agent-developer client (PRD FR-1, FR-29). An agent calls protected
// MCP servers *through the gateway*; the SDK attaches the principal's short-lived IdP
// credential (no embedded long-lived secret) and the gateway transparently authenticates,
// mints a passport, and forwards. The agent never handles a passport itself.
//
// Registration (binding an agent to a principal) is done via the admin control plane
// (P1-10); the SDK covers the runtime call path.
package sdk

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// TokenSource returns the principal's current bearer credential (e.g. an OIDC token).
// It is called per request so short-lived tokens can refresh without restarting the agent.
type TokenSource func(ctx context.Context) (string, error)

// Client routes an agent's calls through the gateway.
type Client struct {
	gatewayURL string
	tokens     TokenSource
	http       *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New returns a Client targeting the gateway at gatewayURL, using tokens for the
// principal credential.
func New(gatewayURL string, tokens TokenSource, opts ...Option) *Client {
	c := &Client{
		gatewayURL: strings.TrimRight(gatewayURL, "/"),
		tokens:     tokens,
		http:       http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Call sends a request to the given protected MCP server through the gateway. path is the
// upstream path (e.g. "/tools/list"); the SDK prefixes the gateway's /servers/{server}
// namespace and attaches the principal credential. The caller owns closing the response
// body.
func (c *Client) Call(ctx context.Context, server, method, path string, body io.Reader) (*http.Response, error) {
	if c.tokens == nil {
		return nil, fmt.Errorf("sdk: no token source configured")
	}
	tok, err := c.tokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("sdk: token source: %w", err)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("%s/servers/%s%s", c.gatewayURL, server, path)

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return c.http.Do(req)
}
