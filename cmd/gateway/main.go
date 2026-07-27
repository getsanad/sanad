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
//	PASSPORT_ALLOW_DIRECT_PRINCIPAL  1 = accept requests with no delegation chain (default: reject)
//	PASSPORT_FORWARD_HEADERS     extra inbound headers forwarded upstream, comma-separated
//	PASSPORT_MAX_REQUEST_BODY    bytes of request body buffered for the decision (default 1 MiB)
//	PASSPORT_ISSUER_NAME         `iss` placed on minted passports (default sanad)
//	PASSPORT_SIGNING_KID         signing key id (default gateway-dev)
//	PASSPORT_REVOCATION_DSN      Postgres DSN for a shared kill-switch (empty = in-memory)
//	PASSPORT_REVOCATION_REFRESH  cache refresh interval for the shared kill-switch (default 2s)
//	PASSPORT_REVOCATION_MAX_STALENESS  snapshot age past which revocation checks deny (default 60s)
//	PASSPORT_DEV_NO_AUTH         1 = start without principal auth (development only)
//
// With no principal authenticator configured startup is a fatal error unless
// PASSPORT_DEV_NO_AUTH=1; with no registered servers every request fails closed. Once a
// workload CA enables delegation, a request carrying no chain is rejected unless
// PASSPORT_ALLOW_DIRECT_PRINCIPAL=1. In vc mode, a configured workload CA lets principal
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
	"strconv"
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

	pipeline, killSwitch, err := buildPipeline(context.Background(), signer)
	if err != nil {
		log.Fatalf("gateway: pipeline: %v", err)
	}

	maxBody, err := maxRequestBody()
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}

	// Audit every decision to a tamper-evident log, streamed as JSON lines to stdout
	// (stand-in for a SIEM endpoint, P1-08).
	auditLog := audit.NewHashChainLog(audit.NewJSONLinesSink(os.Stdout))

	// A kill-switch snapshot older than its bound means revocations may not be reaching this
	// replica, so it reports unready and gets pulled from the load balancer — matching the
	// request-path denial in revoke.Stage rather than quietly serving stale decisions (NFR-4).
	g := &gateway.Gateway{
		Registry:       reg,
		Pipeline:       pipeline,
		Audit:          audit.GatewayHook(auditLog),
		Ready:          killSwitch.CheckFresh,
		MaxRequestBody: maxBody,
	}

	// Expose metrics at /metrics and instrument all gateway traffic (P1-11).
	reg2 := metrics.NewRegistry()
	// Snapshot age is the observable form of the revocation window: alert on it approaching
	// the staleness bound and an outage is visible long before it becomes a denial.
	reg2.SetGauge("agentpassport_revocation_snapshot_age_seconds",
		"Seconds since the kill-switch snapshot was last successfully refreshed from its source.",
		func() float64 { return killSwitch.Staleness().Seconds() })
	reg2.SetGauge("agentpassport_revocation_max_staleness_seconds",
		"Snapshot age at which revocation checks start denying (0 = no bound configured).",
		func() float64 { return killSwitch.MaxStaleness().Seconds() })
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

// buildPipeline assembles the decision pipeline from configuration. It also returns the
// kill-switch it wired, so main can surface its snapshot age on /readyz and /metrics.
func buildPipeline(ctx context.Context, signer sts.Signer) (gateway.Pipeline, *revoke.CachedStore, error) {
	// One kill-switch enforced at both authentication and mint time (P1-07). Reads are
	// served from a local snapshot (hot path never makes a DB call, FR-20); when a shared
	// Postgres source is configured the snapshot refreshes so revocations propagate across
	// replicas (NFR-2).
	ks, err := buildKillSwitch()
	if err != nil {
		return gateway.Pipeline{}, nil, err
	}

	// Optional workload identity. Its key store also lets the VC principal authenticator
	// self-provision principal keys for delegation.
	var store *workload.KeyStore
	var caPub ed25519.PublicKey
	if caB64 := os.Getenv("PASSPORT_WORKLOAD_CA"); caB64 != "" {
		pub, derr := base64.RawURLEncoding.DecodeString(caB64)
		if derr != nil || len(pub) != ed25519.PublicKeySize {
			return gateway.Pipeline{}, nil, fmt.Errorf("gateway: PASSPORT_WORKLOAD_CA must be a base64url Ed25519 public key: %v", derr)
		}
		caPub = ed25519.PublicKey(pub)
		store = workload.NewKeyStore(caPub)
	}

	auth, err := buildPrincipalAuth(ctx, ks, store)
	if err != nil {
		return gateway.Pipeline{}, nil, err
	}
	// Never serve unauthenticated by accident. A pipeline with no principal stage mints no
	// passport, so the gateway denies every proxied request (gateway/proxy.go) while looking
	// healthy — and before that check existed it was an open proxy. Fail startup instead;
	// PASSPORT_DEV_NO_AUTH=1 is the explicit opt-in for local development and the demo.
	if auth == nil {
		if os.Getenv("PASSPORT_DEV_NO_AUTH") != "1" {
			need := "PASSPORT_OIDC_ISSUER and PASSPORT_OIDC_CLIENT_ID"
			if os.Getenv("PASSPORT_PRINCIPAL_MODE") == "vc" {
				need = "PASSPORT_VC_TRUSTED_ISSUERS"
			}
			return gateway.Pipeline{}, nil, fmt.Errorf("no principal authenticator configured (PASSPORT_PRINCIPAL_MODE=%s): set %s, or set PASSPORT_DEV_NO_AUTH=1 to start without authentication (development only — every proxied request is then denied)",
				envOr("PASSPORT_PRINCIPAL_MODE", "oidc"), need)
		}
		log.Print("WARNING: PASSPORT_DEV_NO_AUTH=1: no principal authentication configured; every proxied request will be denied (development only)")
		return gateway.Pipeline{}, ks, nil
	}

	// Order: principal -> [instance -> delegation] -> revoke -> policy -> mint. Revoke runs
	// after the agent is established so agent revocation is enforced too.
	stages := []gateway.Stage{principal.Stage(auth)}
	if store != nil {
		// Delegation is REQUIRED once it is enabled. Without that, presenting a chain is
		// opt-in per request: a delegate holding a chain attenuated to ["read"] could omit
		// X-Agent-Delegation, still authenticate as its agent, and be minted a passport with
		// no scope at all — which is unconstrained, i.e. wider than the chain it holds.
		// PASSPORT_ALLOW_DIRECT_PRINCIPAL=1 restores the permissive behaviour for deployments
		// where a principal legitimately calls with no delegation (the sidecar's --delegation
		// flag is optional); the default is the safe one.
		var dopts []delegation.StageOption
		if os.Getenv("PASSPORT_ALLOW_DIRECT_PRINCIPAL") == "1" {
			log.Print("PASSPORT_ALLOW_DIRECT_PRINCIPAL=1: requests with no delegation chain are permitted (the principal acts directly, with no scope narrowing)")
		} else {
			dopts = append(dopts, delegation.WithRequireChain())
		}
		stages = append(stages,
			workload.InstanceStage(caPub, store),
			delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation), dopts...),
		)
		log.Print("instance auth + delegation enabled (PASSPORT_WORKLOAD_CA set)")
	}

	// Deny-by-default (FR-15). PASSPORT_ALLOW_ALL=1 permits everything for development —
	// everything the delegation allows, that is: the policy stage intersects its decision
	// with the verified grant, so even allow-all cannot mint past a signed chain.
	pdp := policy.DenyAll
	if os.Getenv("PASSPORT_ALLOW_ALL") == "1" {
		log.Print("PASSPORT_ALLOW_ALL=1: permitting all actions (development only)")
		pdp = policy.Func(func(context.Context, policy.Input) (types.Decision, error) {
			return types.Decision{Effect: types.EffectAllow, Reason: "allow-all (dev)"}, nil
		})
	}
	// Token isolation (FR-8): the mint stage forwards the minted passport plus a minimal
	// transport allowlist, and drops everything else the caller sent. PASSPORT_FORWARD_HEADERS
	// widens that allowlist for upstreams that legitimately need a header of their own (e.g.
	// "Origin,traceparent"); the default is the safe minimum.
	var mopts []sts.StageOption
	if extra := headerNames(os.Getenv("PASSPORT_FORWARD_HEADERS")); len(extra) > 0 {
		log.Printf("PASSPORT_FORWARD_HEADERS: also forwarding %s upstream", strings.Join(extra, ", "))
		mopts = append(mopts, sts.WithForwardHeaders(extra...))
	}
	mint := sts.MintStage(sts.New(signer, sts.Config{Issuer: envOr("PASSPORT_ISSUER_NAME", "sanad")}), mopts...)

	// policy.MCPTools is the real tool extractor: the gateway buffers the JSON-RPC body and
	// parses it, so the tool a tools/call names reaches the decision (FR-16) instead of the
	// nil extractor's empty tool. Turning it on makes attenuation live — the stage intersects
	// the requested tool with the delegated grant and denies anything outside it — which is
	// why it lands together with the buffering rather than before it.
	stages = append(stages, revoke.Stage(ks), policy.Stage(pdp, policy.MCPTools, nil), mint)
	return gateway.Pipeline{Stages: stages}, ks, nil
}

// buildPrincipalAuth selects the principal authenticator by PASSPORT_PRINCIPAL_MODE
// ("oidc" default, or "vc"). Returns nil when nothing is configured, which buildPipeline
// turns into a fatal startup error unless PASSPORT_DEV_NO_AUTH=1. In
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

// headerNames parses a comma-separated list of header names ("Origin, traceparent"),
// dropping blanks. Canonicalization is the mint stage's job.
func headerNames(spec string) []string {
	var out []string
	for name := range strings.SplitSeq(spec, ",") {
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// maxRequestBody reads the cap on the request body the gateway buffers before deciding
// (PASSPORT_MAX_REQUEST_BODY, in bytes). It returns 0 for "unset", which selects the
// gateway's own default. A non-positive or unparseable value is a startup error rather than
// a silent fallback: an operator who tried to configure the cap and got it wrong should not
// discover at 3am that they are running on the default — and "0 means unlimited" is not on
// offer, since the buffer is filled before the caller is authenticated.
func maxRequestBody() (int64, error) {
	v := strings.TrimSpace(os.Getenv("PASSPORT_MAX_REQUEST_BODY"))
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("PASSPORT_MAX_REQUEST_BODY must be a positive number of bytes, got %q", v)
	}
	log.Printf("buffering at most %d bytes of request body per request", n)
	return n, nil
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
//
// The shared-source snapshot also carries a staleness bound (PASSPORT_REVOCATION_MAX_STALENESS,
// default revoke.DefaultMaxStaleness): once refreshes have been failing for longer than that,
// this replica can no longer promise NFR-4 and starts denying instead of serving a snapshot
// of unbounded age. The in-memory source has nothing to fall out of sync with, so it has no
// bound.
func buildKillSwitch() (*revoke.CachedStore, error) {
	dsn := os.Getenv("PASSPORT_REVOCATION_DSN")
	if dsn == "" {
		log.Print("kill-switch: in-memory (set PASSPORT_REVOCATION_DSN for a shared Postgres kill-switch across replicas)")
		return revoke.NewCachedStore(revoke.NewMemSource(), 0)
	}

	// Validate the timings before dialling: a bad duration should fail immediately, not
	// after a database round-trip.
	refresh, maxStale, err := revocationTiming()
	if err != nil {
		return nil, err
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

	if maxStale <= 0 {
		log.Print("WARNING: PASSPORT_REVOCATION_MAX_STALENESS disables the staleness bound; if the revocation source becomes unreachable this replica will serve its last snapshot indefinitely")
	}
	log.Printf("kill-switch: shared Postgres source, snapshot refresh every %s, denying past %s of staleness", refresh, maxStale)
	return revoke.NewCachedStore(src, refresh, revoke.WithMaxStaleness(maxStale))
}

// revocationTiming reads the shared kill-switch's refresh interval and staleness bound.
// The bound must exceed the refresh interval: at or under it a single missed tick denies
// every request, which is a self-inflicted outage rather than a safety property, so that
// configuration is rejected at startup instead of discovered in production.
func revocationTiming() (refresh, maxStale time.Duration, err error) {
	refresh = 2 * time.Second
	if v := os.Getenv("PASSPORT_REVOCATION_REFRESH"); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			return 0, 0, fmt.Errorf("PASSPORT_REVOCATION_REFRESH: %w", perr)
		}
		refresh = d
	}

	maxStale = revoke.DefaultMaxStaleness
	if v := os.Getenv("PASSPORT_REVOCATION_MAX_STALENESS"); v != "" {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			return 0, 0, fmt.Errorf("PASSPORT_REVOCATION_MAX_STALENESS: %w", perr)
		}
		maxStale = d
	}
	if maxStale > 0 && maxStale <= refresh {
		return 0, 0, fmt.Errorf("PASSPORT_REVOCATION_MAX_STALENESS (%s) must be greater than PASSPORT_REVOCATION_REFRESH (%s)", maxStale, refresh)
	}
	return refresh, maxStale, nil
}
