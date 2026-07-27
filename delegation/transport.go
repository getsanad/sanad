package delegation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/getsanad/sanad/gateway"
)

// HeaderDelegation is the header the agent SDK uses to present a delegation chain.
const HeaderDelegation = "X-Agent-Delegation"

// EncodeChain serializes a chain for transport in a header.
func EncodeChain(c Chain) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeChain parses a chain from its header form.
func DecodeChain(s string) (Chain, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Chain{}, fmt.Errorf("delegation: bad chain encoding: %w", err)
	}
	var c Chain
	if err := json.Unmarshal(b, &c); err != nil {
		return Chain{}, fmt.Errorf("delegation: bad chain: %w", err)
	}
	return c, nil
}

// HeaderExtractor reads a delegation chain from the given request header. Absence of the
// header means no delegation (the principal acts directly).
func HeaderExtractor(header string) ChainExtractor {
	return func(req *gateway.Request) (Chain, bool, error) {
		v := req.HTTP.Header.Get(header)
		if v == "" {
			return Chain{}, false, nil
		}
		c, err := DecodeChain(v)
		if err != nil {
			return Chain{}, false, err
		}
		return c, true, nil
	}
}
