package workload

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// Headers the agent SDK sets to present its instance identity.
const (
	HeaderCredential = "X-Agent-Credential" // base64(JSON) workload credential
	HeaderProof      = "X-Agent-Proof"      // base64 signature proving possession of the key
)

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

// Proof produces the proof of possession an instance presents: a signature, with its
// instance key, over the principal bearer token it is using. This binds the instance to
// that specific (short-lived) principal credential.
func Proof(instanceKey ed25519.PrivateKey, principalToken string) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(instanceKey, []byte(principalToken)))
}

// InstanceStage authenticates the calling agent instance (PRD FR-5) from a presented
// workload credential plus a proof of possession of the instance private key. In
// production this rides on — and would be channel-bound to — mutual TLS; here the proof is
// the instance's signature over the principal's bearer token, which ties the instance to
// that specific principal credential and is replay-bounded by the token's short lifetime.
//
// On success it sets req.Agent and registers the instance key in store, so delegation
// verification (P2-04) can check hops this agent signs. It fails closed on any problem.
func InstanceStage(caPub ed25519.PublicKey, store *KeyStore) gateway.Stage {
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
		proof, err := base64.RawURLEncoding.DecodeString(req.HTTP.Header.Get(HeaderProof))
		if err != nil {
			return fmt.Errorf("workload: bad proof encoding: %w", err)
		}
		if !ed25519.Verify(cred.PublicKey, []byte(token), proof) {
			return errors.New("workload: instance proof of possession failed")
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
