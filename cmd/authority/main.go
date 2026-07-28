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
//	PASSPORT_BOOTSTRAP_USES    enrollments each token authorizes (default 1 — single use)
//	PASSPORT_BOOTSTRAP_TTL     how long each token stays usable, from process start (default 15m)
//	PASSPORT_CREDENTIAL_TTL    credential lifetime, e.g. 1h (default 1h)
//
// This uses bootstrap-token attestation (dev/self-host). A high-assurance deployment swaps
// in workload.MeasuredAttestor (TEE/TPM) — see P3-01.
//
// A bootstrap token is spent as it is used and expires; both counters live in THIS PROCESS.
// Restarting the authority re-reads PASSPORT_BOOTSTRAP_TOKENS and hands every token a full
// budget and a fresh window, and a second replica has counters of its own, so N replicas
// honour a single-use token N times. That is the dev/self-host path being honest about what it
// is: run one authority process, and use MeasuredAttestor or SPIFFE for anything else.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getsanad/sanad/workload"
)

func main() {
	caPriv := loadOrGenCAKey()
	caPub := caPriv.Public().(ed25519.PublicKey)

	// The budget every configured token gets. Defaults are strict — one enrollment, a short
	// window — because a bootstrap token that outlives the deploy that used it is the standing
	// shared secret this path is supposed to avoid. A dev stack that re-enrolls all afternoon
	// raises them explicitly (deploy/.env does), which keeps the loose setting visible in the
	// config rather than baked into the binary.
	uses := envInt("PASSPORT_BOOTSTRAP_USES", workload.DefaultTokenUses)
	tokenTTL := envDuration("PASSPORT_BOOTSTRAP_TTL", workload.DefaultTokenTTL)

	att := workload.NewTokenAttestor()
	n := 0
	if spec := os.Getenv("PASSPORT_BOOTSTRAP_TOKENS"); spec != "" {
		for entry := range strings.SplitSeq(spec, ",") {
			tok, agentID, ok := strings.Cut(strings.TrimSpace(entry), "=")
			if !ok || tok == "" || agentID == "" {
				log.Fatalf("authority: bad PASSPORT_BOOTSTRAP_TOKENS entry %q (want token=agentID)", entry)
			}
			// RegisterGrant enforces the agent-id rule (workload.ValidAgentID), so an id shaped
			// like a principal's DID stops the authority at startup instead of minting
			// credentials for an agent that claims a principal's name.
			if err := att.RegisterGrant(tok, workload.TokenGrant{AgentID: agentID, Uses: uses, TTL: tokenTTL}); err != nil {
				log.Fatalf("authority: bad PASSPORT_BOOTSTRAP_TOKENS entry %q: %v", entry, err)
			}
			n++
		}
	}
	if n == 0 {
		log.Print("WARNING: no PASSPORT_BOOTSTRAP_TOKENS set; every enrollment will be denied")
	}

	ttl := envDuration("PASSPORT_CREDENTIAL_TTL", time.Hour)

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
	log.Printf("sanad authority on %s (%d bootstrap tokens, %d enrollment(s) each over %s; credential ttl %s)",
		addr, n, uses, tokenTTL, ttl)
	log.Printf("  bootstrap tokens are spent as they are used and expire; restart this process to reissue them")
	log.Printf("set this on the gateway:  PASSPORT_WORKLOAD_CA=%s", base64.RawURLEncoding.EncodeToString(caPub))
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("authority: %v", err)
	}
}

// envInt reads a positive integer from the environment, or returns def. A value that is not a
// positive integer is a fatal startup error rather than a silent fallback to the default: an
// operator who wrote PASSPORT_BOOTSTRAP_USES=many meant to change the budget, and starting
// anyway would leave them believing they had.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		log.Fatalf("authority: %s must be a positive integer, got %q", name, v)
	}
	return n
}

// envDuration reads a Go duration from the environment, or returns def.
func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		log.Fatalf("authority: %s must be a positive duration (e.g. 15m), got %q", name, v)
	}
	return d
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
