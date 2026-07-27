package verify

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/getsanad/sanad/jwks"
)

// NewJWKSResolver builds a KeyResolver from a JWK Set document (e.g. fetched from the
// gateway's /.well-known/jwks.json). Multiple keys are supported, so verification keeps
// working across key rotation (the gateway serves new + previous keys).
func NewJWKSResolver(doc []byte) (KeyResolver, error) {
	keys, err := jwks.Parse(doc)
	if err != nil {
		return nil, err
	}
	m := StaticKeys{}
	for _, k := range keys {
		m[k.Kid] = k.Pub
	}
	return m, nil
}

// FetchJWKS retrieves and parses a JWK Set from url. Servers typically fetch once at
// startup and refresh periodically; verification itself stays offline between refreshes.
func FetchJWKS(ctx context.Context, url string) (KeyResolver, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verify: jwks fetch returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return NewJWKSResolver(body)
}
