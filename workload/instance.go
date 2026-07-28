package workload

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

// Headers the agent SDK sets to present its instance identity.
const (
	HeaderCredential = "X-Agent-Credential" // base64(JSON) workload credential
	HeaderProof      = "X-Agent-Proof"      // base64url(payload).base64url(signature), request-bound
)

// ProofOption tunes the freshness window and replay cache InstanceStage enforces. It is an
// ALIAS of the shared option type so the instance side and the capability side
// (delegation.CapabilityStage) cannot drift into two readings of the same wire format.
type ProofOption = pop.Option

// WithProofWindow sets how old an instance proof may be and how far ahead its iat may sit.
// The defaults (pop.DefaultMaxAge / pop.DefaultSkew) are what deployments should use;
// this exists for tests and for clocks that are genuinely worse than NTP.
func WithProofWindow(maxAge, skew time.Duration) ProofOption { return pop.WithWindow(maxAge, skew) }

// WithProofCacheEntries caps the per-process replay cache. See pop.ReplayCache for how to
// size it and what it does not cover across replicas.
func WithProofCacheEntries(n int) ProofOption { return pop.WithCacheEntries(n) }

// WithProofClock replaces the verifier's clock, for tests.
func WithProofClock(now func() time.Time) ProofOption { return pop.WithClock(now) }

// EncodeCredential serializes a credential for transport in a header.
func EncodeCredential(c Credential) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// DecodeCredential parses a credential from its header form.
func DecodeCredential(s string) (Credential, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Credential{}, fmt.Errorf("workload: bad credential encoding: %w", err)
	}
	var c Credential
	if err := json.Unmarshal(b, &c); err != nil {
		return Credential{}, fmt.Errorf("workload: bad credential: %w", err)
	}
	return c, nil
}

// Proof produces the proof of possession an instance presents for ONE request: a signature,
// with its instance key, over the request's binding — method, target, a hash of the body, a
// hash of the principal bearer token, a creation time and a unique id.
//
// It is the DPoP construction (RFC 9449) in Sanad's signature format; internal/pop documents
// what is adopted, what is not, and why the body is covered here when DPoP leaves it out. The
// previous form signed the bare token, which Ed25519 renders as one fixed value for that
// token's whole lifetime: whoever saw one request's headers was that instance until the token
// expired. body is the request body being sent, nil if there is none.
//
// The signature is domain-separated (sigctx.InstanceProof). It must be: the same instance
// key is registered in the KeyStore and authenticates the delegation hops this agent signs,
// so an untagged signature over caller-supplied bytes is a signing oracle for hops — hand
// it the exact bytes of a hop's canonical encoding and the proof comes back as a valid
// delegation from that agent.
func Proof(instanceKey ed25519.PrivateKey, method, target, principalToken string, body []byte) (string, error) {
	b, err := pop.NewBinding(method, target, principalToken, body, time.Now())
	if err != nil {
		return "", err
	}
	return pop.Sign(sigctx.InstanceProof, instanceKey, b)
}

// ProofTarget is the htu value to sign for a request URL: the origin-form target the gateway
// will see. Callers building requests (the sidecar, the SDK) use it so there is exactly one
// definition of the string both ends compare.
func ProofTarget(u *url.URL) string { return pop.Target(u) }

// InstanceStage authenticates the calling agent instance (PRD FR-5) from a presented
// workload credential plus a proof of possession of the instance private key, bound to THIS
// request. In production this rides on — and would be channel-bound to — mutual TLS; until
// then the binding is what stands in for the channel: the proof commits to the method,
// target, body and principal token in front of the verifier, it must be seconds old, and its
// jti is spent on first use, so a captured header bundle buys a replay of one identical
// request within the freshness window rather than the instance's identity.
//
// The replay cache is per-stage and per-process; see pop.ReplayCache for its bounds and for
// what a second replica behind a load balancer does not know.
//
// On success it sets req.Agent and registers the instance key in store, so delegation
// verification (P2-04) can check hops this agent signs. It fails closed on any problem.
func InstanceStage(caPub ed25519.PublicKey, store *KeyStore, opts ...ProofOption) gateway.Stage {
	verifier := pop.NewVerifier(sigctx.InstanceProof, opts...)
	return gateway.NewStage("instance", func(_ context.Context, req *gateway.Request) error {
		if req.HTTP == nil {
			return errors.New("workload: no request to authenticate")
		}
		raw := req.HTTP.Header.Get(HeaderCredential)
		if raw == "" {
			return errors.New("workload: missing instance credential")
		}
		cred, err := DecodeCredential(raw)
		if err != nil {
			return err
		}
		if err := Verify(caPub, cred, time.Now()); err != nil {
			return err
		}

		token := bearer(req.HTTP)
		if token == "" {
			return errors.New("workload: missing principal token to bind the instance proof")
		}
		// req.Body is what the gateway buffered, and the proof covers exactly that. A request
		// carrying a body the gateway did NOT buffer (it only buffers POST — see mcprpc.HasBody)
		// would be forwarded upstream with bytes no proof committed to, so it is refused rather
		// than authenticated on a binding that covers less than what is being sent.
		if req.Body == nil && req.HTTP.ContentLength != 0 && req.HTTP.Body != nil && req.HTTP.Body != http.NoBody {
			return errors.New("workload: request carries a body the instance proof cannot cover")
		}
		// Exactly one proof header, per RFC 9449 §4.3 step 1. Header.Get would take the first
		// of several silently, which is a parser differential waiting to happen: an
		// intermediary that forwards or reorders duplicates could make the value the gateway
		// checks differ from the one anything in front of it logged or inspected.
		if n := len(req.HTTP.Header.Values(HeaderProof)); n != 1 {
			return fmt.Errorf("workload: expected exactly one %s header, got %d", HeaderProof, n)
		}
		if err := verifier.Check(cred.PublicKey, req.HTTP.Header.Get(HeaderProof), req.HTTP, req.Body, token); err != nil {
			return fmt.Errorf("workload: instance proof of possession failed: %w", err)
		}

		if err := store.Add(cred); err != nil {
			return err
		}
		pid := ""
		if req.Principal != nil {
			pid = req.Principal.ID
		}
		req.Agent = &types.Agent{ID: cred.AgentID, PrincipalID: pid}
		return nil
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}
