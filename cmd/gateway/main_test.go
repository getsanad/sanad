package main

import (
	"context"
	"strings"
	"testing"

	"github.com/getsanad/sanad/sts"
)

// clearAuthEnv unsets everything buildPipeline reads, so the test sees a gateway started
// with no configuration at all (the accident this fix guards against).
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PASSPORT_PRINCIPAL_MODE", "PASSPORT_OIDC_ISSUER", "PASSPORT_OIDC_CLIENT_ID",
		"PASSPORT_VC_TRUSTED_ISSUERS", "PASSPORT_WORKLOAD_CA", "PASSPORT_REVOCATION_DSN",
		"PASSPORT_DEV_NO_AUTH",
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
		_, err := buildPipeline(context.Background(), signer)
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
		_, err := buildPipeline(context.Background(), signer)
		if err == nil || !strings.Contains(err.Error(), "PASSPORT_VC_TRUSTED_ISSUERS") {
			t.Fatalf("want an error naming PASSPORT_VC_TRUSTED_ISSUERS, got %v", err)
		}
	})

	t.Run("dev escape hatch", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_DEV_NO_AUTH", "1")
		p, err := buildPipeline(context.Background(), signer)
		if err != nil {
			t.Fatalf("PASSPORT_DEV_NO_AUTH=1: %v", err)
		}
		if len(p.Stages) != 0 {
			t.Fatalf("want an empty pipeline, got %d stages", len(p.Stages))
		}
	})
}
