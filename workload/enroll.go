package workload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Enrollment is two requests: the agent asks the authority for a single-use nonce, builds
// attestation evidence covering that nonce and its instance public key, then presents both.
// The nonce is what stops a quote being replayed at all; the key binding is what stops a
// captured quote being paired with someone else's key.

// nonceResponse is the wire body of POST /enroll/nonce.
type nonceResponse struct {
	Nonce     string `json:"nonce"`      // base64url challenge the evidence must cover
	ExpiresIn int    `json:"expires_in"` // seconds until the nonce is refused
}

// enrollRequest is the wire body for credential enrollment.
type enrollRequest struct {
	Nonce     string `json:"nonce"`      // base64url nonce from POST /enroll/nonce
	Evidence  string `json:"evidence"`   // base64url attestation evidence over nonce + public_key
	PublicKey string `json:"public_key"` // base64url Ed25519 instance public key
}

// NonceHandler serves the first leg of enrollment: it mints the single-use challenge the
// agent's attestation evidence must cover. Mount at POST /enroll/nonce on the authority.
//
// It is rate limited on the same budget as EnrollHandler (Authority.SetEnrollLimit). This is
// the leg that costs memory — every nonce it hands out sits in the authority's table for
// NonceTTL — so an unlimited nonce endpoint is a way to refuse honest agents a challenge
// without ever attempting an enrollment.
func NonceHandler(a *Authority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if rateLimited(a.limiter, w, r) {
			return
		}
		nonce, err := a.Nonce()
		if err != nil {
			http.Error(w, "cannot issue enrollment nonce", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(nonceResponse{
			Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
			ExpiresIn: int(a.nonceTTL / time.Second),
		})
	})
}

// EnrollHandler serves credential enrollment (PRD FR-1): an agent presents its nonce, its
// attestation evidence and its instance public key, and — if the evidence attests to that
// nonce and that key — receives a signed, short-lived workload credential. Mount at
// POST /enroll on the authority service.
//
// It is unauthenticated by construction (proving who you are is what it is for), so it is rate
// limited: a caller over budget gets 429 with a Retry-After before anything is decoded, and
// cannot grind attestation attempts — with a TokenAttestor each attempt costs one HMAC per
// registered token — or spend the authority's nonces faster than it issues them.
func EnrollHandler(a *Authority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if rateLimited(a.limiter, w, r) {
			return
		}
		var req enrollRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
		if err != nil || len(nonce) == 0 {
			http.Error(w, "bad nonce encoding", http.StatusBadRequest)
			return
		}
		evidence, err := base64.RawURLEncoding.DecodeString(req.Evidence)
		if err != nil {
			http.Error(w, "bad evidence encoding", http.StatusBadRequest)
			return
		}
		pub, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			http.Error(w, "bad public key", http.StatusBadRequest)
			return
		}
		cred, err := a.Issue(evidence, nonce, ed25519.PublicKey(pub))
		if err != nil {
			// Bad nonce or attestation/issue failure: deny (fail closed).
			http.Error(w, "enrollment denied: "+err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cred)
	})
}

// EvidenceFunc builds attestation evidence covering the authority-issued nonce and the
// public key being enrolled — see BootstrapEvidence (dev) and SignQuote (measured).
type EvidenceFunc func(nonce []byte, pub ed25519.PublicKey) ([]byte, error)

// Enroll is the client side of enrollment: fetch a single-use nonce, have evidence build the
// attestation over that nonce and pub, and present both to the authority. Going through this
// function rather than sequencing the two calls by hand is what makes it impossible to
// present evidence that does not cover the key being enrolled. A nil client uses
// http.DefaultClient.
func Enroll(ctx context.Context, client *http.Client, authorityURL string, pub ed25519.PublicKey, evidence EvidenceFunc) (Credential, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Credential{}, fmt.Errorf("enroll: invalid instance public key")
	}
	nonce, err := RequestNonce(ctx, client, authorityURL)
	if err != nil {
		return Credential{}, err
	}
	ev, err := evidence(nonce, pub)
	if err != nil {
		return Credential{}, fmt.Errorf("enroll: building attestation evidence: %w", err)
	}
	body, _ := json.Marshal(enrollRequest{
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		Evidence:  base64.RawURLEncoding.EncodeToString(ev),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	})
	var cred Credential
	if err := post(ctx, client, authorityURL, "/enroll", body, &cred); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// RequestNonce fetches a single-use enrollment nonce from the authority. The evidence built
// against it is only usable for one enrollment, and only within the authority's window.
func RequestNonce(ctx context.Context, client *http.Client, authorityURL string) ([]byte, error) {
	var resp nonceResponse
	if err := post(ctx, client, authorityURL, "/enroll/nonce", []byte("{}"), &resp); err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(resp.Nonce)
	if err != nil || len(nonce) == 0 {
		return nil, fmt.Errorf("enroll: authority returned an unusable nonce")
	}
	return nonce, nil
}

// post sends a JSON body to a path on the authority and decodes a JSON response into out.
func post(ctx context.Context, client *http.Client, authorityURL, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authorityURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("enroll: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
