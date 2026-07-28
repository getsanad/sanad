// Package sdk is the agent-developer client (PRD FR-1, FR-29). An agent calls protected
// MCP servers *through the gateway*; the SDK attaches the principal's short-lived IdP
// credential (no embedded long-lived secret) and the gateway transparently authenticates,
// mints a passport, and forwards. The agent never handles a passport itself.
//
// Registration (binding an agent to a principal) is done via the admin control plane
// (P1-10); the SDK covers the runtime call path.
package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/workload"
)

// TokenSource returns the principal's current bearer credential (e.g. an OIDC token).
// It is called per request so short-lived tokens can refresh without restarting the agent.
type TokenSource func(ctx context.Context) (string, error)

// Client routes an agent's calls through the gateway.
type Client struct {
	gatewayURL string
	tokens     TokenSource
	http       *http.Client

	instanceKey ed25519.PrivateKey // set by WithInstance; nil means principal-only calls
	credHeader  string
	chainHeader string
	cfgErr      error // deferred from an Option, returned by Call
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithInstance gives the client an agent instance identity: it presents cred and, on every
// call, a FRESH proof of possession of key bound to that request — its method, target, body
// and principal token (workload.Proof). Gateways running the instance stage require both.
//
// The proof cannot be precomputed and cached, which is the point: a proof that is the same
// bytes on every request is a bearer token, and anyone who sees one set of headers can be
// this instance until the principal token expires.
func WithInstance(key ed25519.PrivateKey, cred workload.Credential) Option {
	return func(c *Client) {
		// An unusable key is a configuration error surfaced on the first call, not a silent
		// downgrade to sending no proof: the gateway would then deny with "missing instance
		// credential", pointing at the wrong thing.
		if len(key) != ed25519.PrivateKeySize {
			c.cfgErr = fmt.Errorf("sdk: instance key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
			return
		}
		h, err := workload.EncodeCredential(cred)
		if err != nil {
			c.cfgErr = fmt.Errorf("sdk: encoding workload credential: %w", err)
			return
		}
		c.instanceKey, c.credHeader = key, h
	}
}

// WithDelegation attaches a verified delegation chain to every call, the way the `passport
// proxy` sidecar does. Gateways wired with delegation.WithRequireChain reject calls without one.
func WithDelegation(chain delegation.Chain) Option {
	return func(c *Client) {
		h, err := delegation.EncodeChain(chain)
		if err != nil {
			c.cfgErr = fmt.Errorf("sdk: encoding delegation chain: %w", err)
			return
		}
		c.chainHeader = h
	}
}

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
// namespace and attaches the principal credential, plus the instance credential and proof
// when WithInstance was given. The caller owns closing the response body.
//
// With an instance identity configured, body is read into memory before the request is sent:
// the proof commits to a hash of the bytes, so they have to exist before the first one goes
// out. Without one, body is streamed exactly as before.
func (c *Client) Call(ctx context.Context, server, method, path string, body io.Reader) (*http.Response, error) {
	if c.cfgErr != nil {
		return nil, c.cfgErr
	}
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

	var raw []byte
	if c.instanceKey != nil && body != nil {
		if raw, err = io.ReadAll(body); err != nil {
			return nil, fmt.Errorf("sdk: reading request body: %w", err)
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if c.instanceKey != nil {
		proof, err := workload.Proof(c.instanceKey, req.Method, workload.ProofTarget(req.URL), tok, raw)
		if err != nil {
			return nil, fmt.Errorf("sdk: building the instance proof: %w", err)
		}
		req.Header.Set(workload.HeaderCredential, c.credHeader)
		req.Header.Set(workload.HeaderProof, proof)
	}
	if c.chainHeader != "" {
		req.Header.Set(delegation.HeaderDelegation, c.chainHeader)
	}
	return c.http.Do(req)
}
