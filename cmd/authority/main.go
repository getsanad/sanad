// Command authority issues short-lived workload credentials to agents that present valid
// attestation (PRD FR-1). It signs credentials with the workload CA key; publish that key's
// public half as the gateway's PASSPORT_WORKLOAD_CA so the gateway trusts what it issues.
//
// Configuration (env):
//
//	PASSPORT_AUTHORITY_ADDR    listen address (default :8082)
//	PASSPORT_CA_KEY            base64url Ed25519 private key (generated + printed if unset — DEV ONLY)
//	PASSPORT_BOOTSTRAP_TOKENS  "token=agentID,token2=agentID2" — the accepted bootstrap tokens.
//	                           An agentID is a local name: alphanumerics, '.', '_' or '-',
//	                           starting with an alphanumeric (workload.ValidAgentID). Principal
//	                           ids (did:key:..., an OIDC subject) are a separate namespace and
//	                           are refused here.
//	PASSPORT_CREDENTIAL_TTL    credential lifetime, e.g. 1h (default 1h)
//
// This uses bootstrap-token attestation (dev/self-host). A high-assurance deployment swaps
// in workload.MeasuredAttestor (TEE/TPM) — see P3-01.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/getsanad/sanad/workload"
)

func main() {
	caPriv := loadOrGenCAKey()
	caPub := caPriv.Public().(ed25519.PublicKey)

	att := workload.NewTokenAttestor()
	n := 0
	if spec := os.Getenv("PASSPORT_BOOTSTRAP_TOKENS"); spec != "" {
		for entry := range strings.SplitSeq(spec, ",") {
			tok, agentID, ok := strings.Cut(strings.TrimSpace(entry), "=")
			if !ok || tok == "" || agentID == "" {
				log.Fatalf("authority: bad PASSPORT_BOOTSTRAP_TOKENS entry %q (want token=agentID)", entry)
			}
			// Register enforces the agent-id rule (workload.ValidAgentID), so an id shaped like
			// a principal's DID stops the authority at startup instead of minting credentials
			// for an agent that claims a principal's name.
			if err := att.Register(tok, agentID); err != nil {
				log.Fatalf("authority: bad PASSPORT_BOOTSTRAP_TOKENS entry %q: %v", entry, err)
			}
			n++
		}
	}
	if n == 0 {
		log.Print("WARNING: no PASSPORT_BOOTSTRAP_TOKENS set; every enrollment will be denied")
	}

	ttl := time.Hour
	if v := os.Getenv("PASSPORT_CREDENTIAL_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("authority: bad PASSPORT_CREDENTIAL_TTL: %v", err)
		}
		ttl = d
	}

	authority, err := workload.NewAuthority(caPriv, "ca-1", att, ttl)
	if err != nil {
		log.Fatalf("authority: %v", err)
	}

	mux := http.NewServeMux()
	// Enrollment is two legs: the nonce the attestation must answer, then the enrollment.
	mux.Handle("/enroll/nonce", workload.NonceHandler(authority))
	mux.Handle("/enroll", workload.EnrollHandler(authority))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	addr := os.Getenv("PASSPORT_AUTHORITY_ADDR")
	if addr == "" {
		addr = ":8082"
	}
	log.Printf("sanad authority on %s (%d bootstrap tokens, ttl %s)", addr, n, ttl)
	log.Printf("set this on the gateway:  PASSPORT_WORKLOAD_CA=%s", base64.RawURLEncoding.EncodeToString(caPub))
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("authority: %v", err)
	}
}

func loadOrGenCAKey() ed25519.PrivateKey {
	if v := os.Getenv("PASSPORT_CA_KEY"); v != "" {
		raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			log.Fatal("authority: PASSPORT_CA_KEY must be a base64url Ed25519 private key")
		}
		return ed25519.PrivateKey(raw)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("authority: %v", err)
	}
	log.Printf("WARNING: no PASSPORT_CA_KEY set; generated an ephemeral one (DEV ONLY)")
	log.Printf("  persist it with:  PASSPORT_CA_KEY=%s", base64.RawURLEncoding.EncodeToString(priv))
	return priv
}
