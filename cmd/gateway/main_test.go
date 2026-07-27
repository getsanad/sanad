package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/revoke"
	"github.com/getsanad/sanad/sts"
)

// clearAuthEnv unsets everything buildPipeline reads, so the test sees a gateway started
// with no configuration at all (the accident this fix guards against).
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PASSPORT_PRINCIPAL_MODE", "PASSPORT_OIDC_ISSUER", "PASSPORT_OIDC_CLIENT_ID",
		"PASSPORT_VC_TRUSTED_ISSUERS", "PASSPORT_WORKLOAD_CA", "PASSPORT_REVOCATION_DSN",
		"PASSPORT_DEV_NO_AUTH", "PASSPORT_ALLOW_DIRECT_PRINCIPAL",
	} {
		t.Setenv(k, "")
	}
}

// TestBuildPipelineRequiresPrincipalAuth locks in fail-closed startup: with no principal
// authenticator the gateway must refuse to start (it would deny every request anyway, and
// looked healthy while doing it), and only PASSPORT_DEV_NO_AUTH=1 opts into that.
func TestBuildPipelineRequiresPrincipalAuth(t *testing.T) {
	signer, err := sts.NewLocalSigner("test")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unconfigured is fatal", func(t *testing.T) {
		clearAuthEnv(t)
		_, _, err := buildPipeline(context.Background(), signer)
		if err == nil {
			t.Fatal("want a startup error with no principal authenticator configured, got nil")
		}
		// The message must be actionable: name the vars to set and the escape hatch.
		for _, want := range []string{"PASSPORT_OIDC_ISSUER", "PASSPORT_OIDC_CLIENT_ID", "PASSPORT_DEV_NO_AUTH"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %s", err, want)
			}
		}
	})

	t.Run("vc mode names the vc var", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_PRINCIPAL_MODE", "vc")
		_, _, err := buildPipeline(context.Background(), signer)
		if err == nil || !strings.Contains(err.Error(), "PASSPORT_VC_TRUSTED_ISSUERS") {
			t.Fatalf("want an error naming PASSPORT_VC_TRUSTED_ISSUERS, got %v", err)
		}
	})

	t.Run("dev escape hatch", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_DEV_NO_AUTH", "1")
		p, _, err := buildPipeline(context.Background(), signer)
		if err != nil {
			t.Fatalf("PASSPORT_DEV_NO_AUTH=1: %v", err)
		}
		if len(p.Stages) != 0 {
			t.Fatalf("want an empty pipeline, got %d stages", len(p.Stages))
		}
	})
}

// TestBuildPipelineRequiresDelegationChain locks in the wiring: once a workload CA enables
// delegation, omitting X-Agent-Delegation must be denied rather than minted an unscoped
// (i.e. unconstrained) passport. PASSPORT_ALLOW_DIRECT_PRINCIPAL=1 is the explicit opt-out.
func TestBuildPipelineRequiresDelegationChain(t *testing.T) {
	signer, err := sts.NewLocalSigner("test")
	if err != nil {
		t.Fatal(err)
	}
	caPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Configure a gateway that has delegation enabled (VC principal auth + workload CA).
	configure := func(t *testing.T) {
		t.Helper()
		clearAuthEnv(t)
		t.Setenv("PASSPORT_PRINCIPAL_MODE", "vc")
		t.Setenv("PASSPORT_VC_TRUSTED_ISSUERS", "did:key:z6MkTrustedIssuer")
		t.Setenv("PASSPORT_WORKLOAD_CA", base64.RawURLEncoding.EncodeToString(caPub))
	}

	// delegationStage builds the configured pipeline and returns its delegation stage.
	delegationStage := func(t *testing.T) gateway.Stage {
		t.Helper()
		p, _, err := buildPipeline(context.Background(), signer)
		if err != nil {
			t.Fatalf("buildPipeline: %v", err)
		}
		for _, s := range p.Stages {
			if s.Name() == "delegation" {
				return s
			}
		}
		t.Fatal("configured pipeline has no delegation stage")
		return nil
	}

	// An authenticated request that presents no delegation chain at all.
	noChain := func() *gateway.Request {
		return &gateway.Request{
			HTTP:      httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil),
			Principal: &types.Principal{ID: "principal-1"},
		}
	}

	t.Run("missing chain denied by default", func(t *testing.T) {
		configure(t)
		if err := delegationStage(t).Handle(context.Background(), noChain()); err == nil {
			t.Fatal("a request with no delegation chain must be denied")
		}
	})

	t.Run("opt-out permits acting directly", func(t *testing.T) {
		configure(t)
		t.Setenv("PASSPORT_ALLOW_DIRECT_PRINCIPAL", "1")
		if err := delegationStage(t).Handle(context.Background(), noChain()); err != nil {
			t.Fatalf("PASSPORT_ALLOW_DIRECT_PRINCIPAL=1: %v", err)
		}
	})
}

// TestRevocationTiming covers the shared kill-switch's staleness configuration: the NFR-4
// bound is the default, and a bound that would deny on a single missed refresh is rejected
// at startup rather than silently turning the gateway into a coin flip.
func TestRevocationTiming(t *testing.T) {
	cases := []struct {
		name             string
		refresh, maxStal string
		wantRefresh      time.Duration
		wantMax          time.Duration
		wantErr          string
	}{
		{name: "defaults", wantRefresh: 2 * time.Second, wantMax: revoke.DefaultMaxStaleness},
		{name: "explicit", refresh: "5s", maxStal: "30s", wantRefresh: 5 * time.Second, wantMax: 30 * time.Second},
		{name: "bound at refresh interval", refresh: "10s", maxStal: "10s", wantErr: "must be greater than"},
		{name: "bound under refresh interval", refresh: "10s", maxStal: "1s", wantErr: "must be greater than"},
		{name: "bound disabled explicitly", maxStal: "0s", wantRefresh: 2 * time.Second, wantMax: 0},
		{name: "unparseable bound", maxStal: "soon", wantErr: "PASSPORT_REVOCATION_MAX_STALENESS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PASSPORT_REVOCATION_REFRESH", tc.refresh)
			t.Setenv("PASSPORT_REVOCATION_MAX_STALENESS", tc.maxStal)

			refresh, maxStale, err := revocationTiming()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if refresh != tc.wantRefresh || maxStale != tc.wantMax {
				t.Fatalf("got refresh=%s maxStale=%s, want %s / %s", refresh, maxStale, tc.wantRefresh, tc.wantMax)
			}
		})
	}
}

// TestBuildPipelineReturnsKillSwitchForProbes: main wires the returned store into /readyz
// and the snapshot-age gauge, so buildPipeline must hand one back on every path — including
// the dev no-auth path, where it would otherwise be nil-dereferenced at startup.
func TestBuildPipelineReturnsKillSwitchForProbes(t *testing.T) {
	signer, err := sts.NewLocalSigner("test")
	if err != nil {
		t.Fatal(err)
	}
	for _, devNoAuth := range []string{"1", ""} {
		clearAuthEnv(t)
		if devNoAuth == "" {
			t.Setenv("PASSPORT_PRINCIPAL_MODE", "vc")
			t.Setenv("PASSPORT_VC_TRUSTED_ISSUERS", "did:key:z6MkTrustedIssuer")
		} else {
			t.Setenv("PASSPORT_DEV_NO_AUTH", devNoAuth)
		}
		_, ks, err := buildPipeline(context.Background(), signer)
		if err != nil {
			t.Fatalf("PASSPORT_DEV_NO_AUTH=%q: %v", devNoAuth, err)
		}
		if ks == nil {
			t.Fatalf("PASSPORT_DEV_NO_AUTH=%q: no kill-switch returned for /readyz to check", devNoAuth)
		}
		// The in-memory dev source has no background refresh, so it must never go stale.
		if err := ks.CheckFresh(); err != nil {
			t.Fatalf("freshly built kill-switch reports stale: %v", err)
		}
	}
}
