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
)

// enrollRequest is the wire body for credential enrollment.
type enrollRequest struct {
	Evidence  string `json:"evidence"`   // base64url attestation evidence (bootstrap token or quote)
	PublicKey string `json:"public_key"` // base64url Ed25519 instance public key
}

// EnrollHandler serves credential enrollment (PRD FR-1): an agent presents attestation
// evidence and its instance public key, and — if attestation passes — receives a signed,
// short-lived workload credential. Mount at POST /enroll on the authority service.
func EnrollHandler(a *Authority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req enrollRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
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
		cred, err := a.Issue(evidence, ed25519.PublicKey(pub))
		if err != nil {
			// Attestation/issue failure: deny (fail closed).
			http.Error(w, "enrollment denied: "+err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cred)
	})
}

// Enroll is the client side of EnrollHandler: present evidence + instance public key to the
// authority and receive a credential. A nil client uses http.DefaultClient.
func Enroll(ctx context.Context, client *http.Client, authorityURL string, evidence []byte, pub ed25519.PublicKey) (Credential, error) {
	body, _ := json.Marshal(enrollRequest{
		Evidence:  base64.RawURLEncoding.EncodeToString(evidence),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(authorityURL, "/")+"/enroll", bytes.NewReader(body))
	if err != nil {
		return Credential{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Credential{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Credential{}, fmt.Errorf("enroll: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	var cred Credential
	if err := json.NewDecoder(resp.Body).Decode(&cred); err != nil {
		return Credential{}, err
	}
	return cred, nil
}
