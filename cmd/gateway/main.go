// Command gateway is the Sanad enforcement point (PEP). It wires the decision
// pipeline — principal authentication (P1-03) and passport minting + token isolation
// (P1-04) — in front of the registered protected MCP servers (P1-02).
//
// Configuration (env):
//
//	PASSPORT_GATEWAY_ADDR        listen address (default :8080)
//	PASSPORT_SERVERS             "id=upstreamURL,id2=url2" protected MCP servers
//	PASSPORT_PRINCIPAL_MODE      "oidc" (default) or "vc"
//	PASSPORT_OIDC_ISSUER         IdP issuer URL (oidc mode)
//	PASSPORT_OIDC_CLIENT_ID      expected audience / client id (oidc mode)
//	PASSPORT_VC_TRUSTED_ISSUERS  comma-separated trusted issuer DIDs (vc mode)
//	PASSPORT_WORKLOAD_CA         base64url Ed25519 CA pubkey; enables instance auth + delegation
//	PASSPORT_ISSUER_NAME         `iss` placed on minted passports (default sanad)
//	PASSPORT_SIGNING_KID         signing key id (default gateway-dev)
//	PASSPORT_REVOCATION_DSN      Postgres DSN for a shared kill-switch (empty = in-memory)
//	PASSPORT_REVOCATION_REFRESH  cache refresh interval for the shared kill-switch (default 2s)
//
// With no principal authenticator configured the pipeline is empty; with no registered
// servers every request fails closed. In vc mode, a configured workload CA lets principal
// keys self-provision for delegation. The dev LocalSigner is replaced by KMS/HSM in P1-12.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/getsanad/sanad/audit"
	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/jwks"
	"github.com/getsanad/sanad/metrics"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
	"github.com/getsanad/sanad/principal"
	"github.com/getsanad/sanad/revoke"
	pgrevoke "github.com/getsanad/sanad/revoke/postgres"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/vc"
	"github.com/getsanad/sanad/workload"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
)

func main() {
	reg := gateway.NewRegistry()
	if err := registerServers(reg, os.Getenv("PASSPORT_SERVERS")); err != nil {
		log.Fatalf("gateway: servers: %v", err)
	}

	// Passport signing key. With PASSPORT_SIGNING_KEY (base64url 32-byte seed) the key —
	// and the published JWKS — is stable across restarts and identical across replicas;
	// without it a fresh ephemeral key is generated (dev only). A KMS/HSM-backed
	// sts.RemoteSigner drops in here for production (SEC-4).
	signer, err := loadSigner()
	if err != nil {
		log.Fatalf("gateway: signer: %v", err)
	}

	pipeline, err := buildPipeline(context.Background(), signer)
	if err != nil {
		log.Fatalf("gateway: pipeline: %v", err)
	}

	// Audit every decision to a tamper-evident log, streamed as JSON lines to stdout
	// (stand-in for a SIEM endpoint, P1-08).
	auditLog := audit.NewHashChainLog(audit.NewJSONLinesSink(os.Stdout))

	g := &gateway.Gateway{Registry: reg, Pipeline: pipeline, Audit: audit.GatewayHook(auditLog)}

	// Expose metrics at /metrics and instrument all gateway traffic (P1-11).
	reg2 := metrics.NewRegistry()
	mux := http.NewServeMux()
	mux.Handle("/metrics", reg2.Handler())
	mux.Handle("/.well-known/jwks.json", jwks.Handler(jwks.Key{Kid: signer.KeyID(), Pub: signer.Public()}))
	mux.Handle("/", metrics.Middleware(reg2, g))

	addr := envOr("PASSPORT_GATEWAY_ADDR", ":8080")
	log.Printf("sanad gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("gateway: %v", err)
	}
}

// registerServers parses "id=upstreamURL,id2=url2" into the registry.
func registerServers(reg *gateway.Registry, spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	for entry := range strings.SplitSeq(spec, ",") {
		id, raw, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok {
			return fmt.Errorf("bad server spec %q (want id=url)", entry)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if err := reg.Register(&gateway.Server{ID: id, Upstream: u}); err != nil {
			return err
		}
		log.Printf("registered protected server %q -> %s", id, raw)
	}
	return nil
}

// buildPipeline assembles the decision pipeline from configuration.
func buildPipeline(ctx context.Context, signer sts.Signer) (gateway.Pipeline, error) {
	// One kill-switch enforced at both authentication and mint time (P1-07). Reads are
	// served from a local snapshot (hot path never makes a DB call, FR-20); when a shared
	// Postgres source is configured the snapshot refreshes so revocations propagate across
	// replicas (NFR-2).
	ks, err := buildKillSwitch()
	if err != nil {
		return gateway.Pipeline{}, err
	}

	// Optional workload identity. Its key store also lets the VC principal authenticator
	// self-provision principal keys for delegation.
	var store *workload.KeyStore
	var caPub ed25519.PublicKey
	if caB64 := os.Getenv("PASSPORT_WORKLOAD_CA"); caB64 != "" {
		pub, derr := base64.RawURLEncoding.DecodeString(caB64)
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			return gateway.Pipeline{}, fmt.Errorf("gateway: PASSPORT_WORKLOAD_CA must be a base64url Ed25519 public key: %v", derr)
		}
		caPub = ed25519.PublicKey(pub)
		store = workload.NewKeyStore(caPub)
	}

	auth, err := buildPrincipalAuth(ctx, ks, store)
	if err != nil {
		return gateway.Pipeline{}, err
	}
	if auth == nil {
		log.Print("no principal authenticator configured; running with an empty pipeline")
		return gateway.Pipeline{}, nil
	}

	// Order: principal -> [instance -> delegation] -> revoke -> policy -> mint. Revoke runs
	// after the agent is established so agent revocation is enforced too.
	stages := []gateway.Stage{principal.Stage(auth)}
	if store != nil {
		stages = append(stages,
			workload.InstanceStage(caPub, store),
			delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
		)
		log.Print("instance auth + delegation enabled (PASSPORT_WORKLOAD_CA set)")
	}

	// Deny-by-default (FR-15). PASSPORT_ALLOW_ALL=1 permits everything for development.
	pdp := policy.DenyAll
	if os.Getenv("PASSPORT_ALLOW_ALL") == "1" {
		log.Print("PASSPORT_ALLOW_ALL=1: permitting all actions (development only)")
		pdp = policy.Func(func(context.Context, policy.Input) (types.Decision, error) {
			return types.Decision{Effect: types.EffectAllow, Reason: "allow-all (dev)"}, nil
		})
	}
	mint := sts.MintStage(sts.New(signer, sts.Config{Issuer: envOr("PASSPORT_ISSUER_NAME", "sanad")}))

	stages = append(stages, revoke.Stage(ks), policy.Stage(pdp, nil, nil), mint)
	return gateway.Pipeline{Stages: stages}, nil
}

// buildPrincipalAuth selects the principal authenticator by PASSPORT_PRINCIPAL_MODE
// ("oidc" default, or "vc"). Returns nil when nothing is configured (empty pipeline). In
// VC mode a non-nil key store is wired as the registrar so authenticated principals'
// did:key public keys self-provision for delegation.
func buildPrincipalAuth(ctx context.Context, ks principal.StatusChecker, store *workload.KeyStore) (principal.Authenticator, error) {
	switch os.Getenv("PASSPORT_PRINCIPAL_MODE") {
	case "vc":
		raw := os.Getenv("PASSPORT_VC_TRUSTED_ISSUERS")
		if raw == "" {
			return nil, fmt.Errorf("gateway: PASSPORT_PRINCIPAL_MODE=vc requires PASSPORT_VC_TRUSTED_ISSUERS")
		}
		trust := vc.StaticTrust{}
		for did := range strings.SplitSeq(raw, ",") {
			if did = strings.TrimSpace(did); did != "" {
				trust[did] = true
			}
		}
		var opts []vc.Option
		if store != nil {
			opts = append(opts, vc.WithKeyRegistrar(store))
		}
		log.Print("principal auth: VC mode")
		return vc.NewAuthenticator(trust, opts...), nil

	case "", "oidc":
		issuer := os.Getenv("PASSPORT_OIDC_ISSUER")
		clientID := os.Getenv("PASSPORT_OIDC_CLIENT_ID")
		if issuer == "" || clientID == "" {
			return nil, nil // not configured
		}
		verifier, err := principal.Verifier(ctx, issuer, clientID)
		if err != nil {
			return nil, err
		}
		log.Print("principal auth: OIDC mode")
		return principal.NewOIDC(verifier, principal.WithStatusChecker(ks)), nil

	default:
		return nil, fmt.Errorf("gateway: unknown PASSPORT_PRINCIPAL_MODE %q", os.Getenv("PASSPORT_PRINCIPAL_MODE"))
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadSigner returns the passport signing key. PASSPORT_SIGNING_KEY (base64url 32-byte
// Ed25519 seed) gives a stable key across restarts/replicas; otherwise an ephemeral key is
// generated (dev only). Swap in sts.NewRemoteSigner here for a KMS/HSM in production.
func loadSigner() (*sts.LocalSigner, error) {
	kid := envOr("PASSPORT_SIGNING_KID", "gateway-dev")
	if v := os.Getenv("PASSPORT_SIGNING_KEY"); v != "" {
		seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("PASSPORT_SIGNING_KEY must be base64url: %w", err)
		}
		return sts.LoadSigner(kid, seed)
	}
	log.Print("WARNING: no PASSPORT_SIGNING_KEY set; using an ephemeral signing key (JWKS changes each restart — dev only)")
	return sts.NewLocalSigner(kid)
}

// buildKillSwitch returns the hot-path kill-switch. It is always a CachedStore (a local
// snapshot, so the mint-time decision never makes a network call, FR-20). With
// PASSPORT_REVOCATION_DSN set the snapshot is backed by a shared Postgres source and
// refreshed periodically, so a revocation written by the admin plane or another replica
// propagates to every gateway (NFR-2); without it the source is in-process (single node).
func buildKillSwitch() (*revoke.CachedStore, error) {
	dsn := os.Getenv("PASSPORT_REVOCATION_DSN")
	if dsn == "" {
		log.Print("kill-switch: in-memory (set PASSPORT_REVOCATION_DSN for a shared Postgres kill-switch across replicas)")
		return revoke.NewCachedStore(revoke.NewMemSource(), 0)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("revocation db: %w", err)
	}
	src, err := pgrevoke.New(db)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := src.Migrate(ctx); err != nil {
		return nil, err
	}

	refresh := 2 * time.Second
	if v := os.Getenv("PASSPORT_REVOCATION_REFRESH"); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			return nil, fmt.Errorf("PASSPORT_REVOCATION_REFRESH: %w", perr)
		}
		refresh = d
	}
	log.Printf("kill-switch: shared Postgres source, snapshot refresh every %s", refresh)
	return revoke.NewCachedStore(src, refresh)
}
