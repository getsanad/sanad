// Package jwks encodes and decodes the gateway's passport signing keys as a JWK Set
// (PRD FR-9, P1-12). Keys are Ed25519 ("OKP"/"Ed25519"). Publishing a JWKS lets MCP
// servers verify passports offline and lets the gateway rotate keys by serving the new
// and previous keys together (P1-12 / ADR-002).
package jwks

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
)

// Key is a named Ed25519 public key.
type Key struct {
	Kid string
	Pub ed25519.PublicKey
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

type set struct {
	Keys []jwk `json:"keys"`
}

// Marshal encodes the keys as a JWK Set document.
func Marshal(keys ...Key) ([]byte, error) {
	var s set
	for _, k := range keys {
		if len(k.Pub) != ed25519.PublicKeySize {
			return nil, errors.New("jwks: invalid Ed25519 public key")
		}
		s.Keys = append(s.Keys, jwk{
			Kty: "OKP", Crv: "Ed25519", Alg: "EdDSA", Use: "sig",
			Kid: k.Kid, X: base64.RawURLEncoding.EncodeToString(k.Pub),
		})
	}
	return json.Marshal(s)
}

// Parse decodes a JWK Set document, returning its Ed25519 keys (others are skipped).
func Parse(b []byte) ([]Key, error) {
	var s set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	var out []Key
	for _, j := range s.Keys {
		if j.Kty != "OKP" || j.Crv != "Ed25519" {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("jwks: bad Ed25519 key length")
		}
		out = append(out, Key{Kid: j.Kid, Pub: ed25519.PublicKey(raw)})
	}
	return out, nil
}

// Handler serves the given keys as a JWK Set (typically at /.well-known/jwks.json).
func Handler(keys ...Key) http.Handler {
	b, err := Marshal(keys...)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err != nil {
			http.Error(w, "jwks error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}
