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

// DecodeChain parses a chain from its header form. An over-long chain is refused at the
// transport boundary as well as at Verify: this is the first place the hop count is known,
// and refusing it here keeps a header full of hops from being carried any further into the
// pipeline. The ceiling here is the constant, never a per-stage tightening — DecodeChain has
// no stage — so a stage that tightened it still rejects afterwards.
func DecodeChain(s string) (Chain, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Chain{}, fmt.Errorf("delegation: bad chain encoding: %w", err)
	}
	var c Chain
	if err := json.Unmarshal(b, &c); err != nil {
		return Chain{}, fmt.Errorf("delegation: bad chain: %w", err)
	}
	if len(c.Hops) > MaxDepth {
		return Chain{}, fmt.Errorf("%w: chain has %d hops, the maximum is %d", ErrTooDeep, len(c.Hops), MaxDepth)
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
