package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
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
		"PASSPORT_POLICY_FILE", "PASSPORT_ALLOW_ALL", "PASSPORT_APPROVAL_TIMEOUT",
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
		_, _, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
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
		_, _, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
		if err == nil || !strings.Contains(err.Error(), "PASSPORT_VC_TRUSTED_ISSUERS") {
			t.Fatalf("want an error naming PASSPORT_VC_TRUSTED_ISSUERS, got %v", err)
		}
	})

	t.Run("dev escape hatch", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_DEV_NO_AUTH", "1")
		p, _, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
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
		p, _, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
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

// TestBuildPipelineWiresTheToolExtractor: the shipped gateway used to pass a nil extractor,
// so every request reached the PDP with an empty tool and every passport shipped an empty
// scope — per-tool authorization (FR-16) was unreachable. With policy.MCPActions wired, the
// tool inside the MCP JSON-RPC body reaches the decision, and the attenuation floor the
// policy stage enforces becomes live: a tool the delegation gave up is denied even under
// PASSPORT_ALLOW_ALL, which is exactly what a nil extractor could not do.
func TestBuildPipelineWiresTheToolExtractor(t *testing.T) {
	signer, err := sts.NewLocalSigner("test")
	if err != nil {
		t.Fatal(err)
	}
	clearAuthEnv(t)
	t.Setenv("PASSPORT_PRINCIPAL_MODE", "vc")
	t.Setenv("PASSPORT_VC_TRUSTED_ISSUERS", "did:key:z6MkTrustedIssuer")
	t.Setenv("PASSPORT_ALLOW_ALL", "1") // the PDP permits everything: only attenuation can deny

	p, _, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
	if err != nil {
		t.Fatalf("buildPipeline: %v", err)
	}
	var stage gateway.Stage
	for _, s := range p.Stages {
		if s.Name() == "policy" {
			stage = s
		}
	}
	if stage == nil {
		t.Fatal("configured pipeline has no policy stage")
	}

	// A request already narrowed to [read] by delegation, asking for admin_delete in its body.
	call := func(tool string) *gateway.Request {
		return &gateway.Request{
			Server:    "demo",
			HTTP:      httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil),
			Principal: &types.Principal{ID: "principal-1"},
			Scope:     types.Scope{Tools: []string{"read"}},
			Calls:     []gateway.RPCCall{{Method: "tools/call", Tool: tool}},
		}
	}
	if err := stage.Handle(context.Background(), call("admin_delete")); err == nil {
		t.Fatal("a tool outside the delegated scope must be denied; the extractor is not wired")
	}

	granted := call("read")
	if err := stage.Handle(context.Background(), granted); err != nil {
		t.Fatalf("a tool inside the delegated scope should pass: %v", err)
	}
	if len(granted.Scope.Tools) != 1 || granted.Scope.Tools[0] != "read" {
		t.Fatalf("granted scope = %v, want [read]", granted.Scope.Tools)
	}
}

// TestMaxRequestBody covers the buffered-body cap: unset means the gateway's own default, and
// a value an operator got wrong is a startup error rather than a silent fallback to it.
func TestMaxRequestBody(t *testing.T) {
	cases := []struct {
		env     string
		want    int64
		wantErr bool
	}{
		{env: "", want: 0}, // 0 = "unset": gateway.DefaultMaxRequestBody applies
		{env: "4194304", want: 4 << 20},
		{env: " 2048 ", want: 2048},
		{env: "0", wantErr: true}, // not an "unlimited" switch
		{env: "-1", wantErr: true},
		{env: "1MiB", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("PASSPORT_MAX_REQUEST_BODY="+tc.env, func(t *testing.T) {
			t.Setenv("PASSPORT_MAX_REQUEST_BODY", tc.env)
			got, err := maxRequestBody()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}

	// Unset must land on the documented default once the gateway applies it.
	if (&gateway.Gateway{MaxRequestBody: 0}).MaxRequestBody != 0 || gateway.DefaultMaxRequestBody != 1<<20 {
		t.Fatalf("default request-body cap changed: %d", gateway.DefaultMaxRequestBody)
	}
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
		_, ks, _, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
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

// --- authorization configuration (FR-16) ---------------------------------------------

// policyFile writes a policy config and points PASSPORT_POLICY_FILE at it.
func policyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSPORT_POLICY_FILE", path)
	return path
}

// decide runs a PDP the way the policy stage does.
func decide(t *testing.T, pdp policy.PDP, method, tool string) types.Decision {
	t.Helper()
	d, err := pdp.Evaluate(context.Background(), policy.Input{Server: "demo", Method: method, Tool: tool})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return d
}

// TestBuildPDPFromPolicyFile is the fix for the gap this item names: an operator can configure
// authorization without writing Go. Before it, the only reachable PDPs were "deny everything"
// and the dev "allow everything".
func TestBuildPDPFromPolicyFile(t *testing.T) {
	clearAuthEnv(t)
	policyFile(t, `{
	  "version": 1,
	  "policy": {"servers": {"demo": {
	    "allow":  {"methods": ["initialize", "tools/list"], "tools": ["read"]},
	    "review": {"tools": ["transfer"]}
	  }}}
	}`)

	pdp, err := buildPDP(gateway.NewRegistry())
	if err != nil {
		t.Fatalf("buildPDP: %v", err)
	}
	cases := []struct {
		name         string
		method, tool string
		want         types.Effect
	}{
		{"listed tool", "tools/call", "read", types.EffectAllow},
		{"unlisted tool", "tools/call", "admin_delete", types.EffectDeny},
		{"listed method", "tools/list", "", types.EffectAllow},
		{"unlisted method", "resources/read", "", types.EffectDeny},
		{"reviewed tool", "tools/call", "transfer", types.EffectReview},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decide(t, pdp, tc.method, tc.tool).Effect; got != tc.want {
				t.Fatalf("effect = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestBuildPDPDefaults: with nothing configured the gateway denies, and the dev switch still
// works. Deny-by-default is the posture that must survive every wiring change (FR-15).
func TestBuildPDPDefaults(t *testing.T) {
	t.Run("no file denies everything", func(t *testing.T) {
		clearAuthEnv(t)
		pdp, err := buildPDP(gateway.NewRegistry())
		if err != nil {
			t.Fatalf("buildPDP: %v", err)
		}
		if d := decide(t, pdp, "tools/call", "read"); d.Allowed() {
			t.Fatalf("want deny-by-default, got %+v", d)
		}
	})

	t.Run("allow-all still works for dev", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_ALLOW_ALL", "1")
		pdp, err := buildPDP(gateway.NewRegistry())
		if err != nil {
			t.Fatalf("buildPDP: %v", err)
		}
		if d := decide(t, pdp, "tools/call", "anything"); !d.Allowed() {
			t.Fatalf("PASSPORT_ALLOW_ALL=1 must allow, got %+v", d)
		}
	})
}

// TestBuildPDPRejectsAllowAllWithAPolicyFile: whichever won, the other would be a setting the
// operator believes is in force and is not — and with allow-all winning, a carefully written
// policy file would be silently ignored.
func TestBuildPDPRejectsAllowAllWithAPolicyFile(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("PASSPORT_ALLOW_ALL", "1")
	path := policyFile(t, `{"version":1,"policy":{"servers":{"demo":{"allow":{"tools":["read"]}}}}}`)

	_, err := buildPDP(gateway.NewRegistry())
	if err == nil {
		t.Fatal("setting both must be a startup error")
	}
	for _, want := range []string{"PASSPORT_ALLOW_ALL", "PASSPORT_POLICY_FILE", path} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

// TestBuildPDPBrokenFileFailsStartup: a policy that cannot be read as written must stop the
// gateway, naming what to fix. Starting on a half-understood policy is how an outage or an
// open door gets shipped.
func TestBuildPDPBrokenFileFailsStartup(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"malformed json", "{\n  \"version\": 1,\n  \"policy\": {\n}\n", []string{"line "}},
		{"misspelled key", `{"version":1,"policy":{"servers":{"demo":{"allow":{"tool":["read"]}}}}}`, []string{`unknown field "tool"`}},
		{"empty entry", `{"version":1,"policy":{"servers":{"demo":{"allow":{"tools":["read",""]}}}}}`, []string{`server "demo"`, "allow.tools[1]"}},
		{"no servers", `{"version":1,"policy":{"servers":{}}}`, []string{"no servers configured"}},
		{"unsupported version", `{"version":7,"policy":{"servers":{"demo":{"allow":{"tools":["read"]}}}}}`, []string{"version 7 is not supported"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAuthEnv(t)
			path := policyFile(t, tc.content)
			_, err := buildPDP(gateway.NewRegistry())
			if err == nil {
				t.Fatal("a broken policy file must fail startup")
			}
			if !strings.Contains(err.Error(), path) {
				t.Errorf("error %q does not name the file", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		clearAuthEnv(t)
		t.Setenv("PASSPORT_POLICY_FILE", filepath.Join(t.TempDir(), "absent.json"))
		if _, err := buildPDP(gateway.NewRegistry()); err == nil {
			t.Fatal("a missing policy file must fail startup, not degrade to no policy")
		}
	})
}

// TestBuildPipelineWiresTheApprover: the gateway used to pass a nil approver, so every
// EffectReview became "requires approval but no approver is configured" — an immediate deny,
// with human-in-the-loop unreachable in the shipped binary. The stage must now hold the
// request until an operator answers.
func TestBuildPipelineWiresTheApprover(t *testing.T) {
	signer, err := sts.NewLocalSigner("test")
	if err != nil {
		t.Fatal(err)
	}
	clearAuthEnv(t)
	t.Setenv("PASSPORT_PRINCIPAL_MODE", "vc")
	t.Setenv("PASSPORT_VC_TRUSTED_ISSUERS", "did:key:z6MkTrustedIssuer")
	policyFile(t, `{"version":1,"policy":{"servers":{"demo":{"review":{"tools":["transfer"]}}}}}`)

	p, _, approver, err := buildPipeline(context.Background(), signer, gateway.NewRegistry())
	if err != nil {
		t.Fatalf("buildPipeline: %v", err)
	}
	if approver == nil {
		t.Fatal("no approver returned; the review API would have nothing to serve")
	}
	var stage gateway.Stage
	for _, s := range p.Stages {
		if s.Name() == "policy" {
			stage = s
		}
	}

	req := &gateway.Request{
		Server:    "demo",
		HTTP:      httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil),
		Principal: &types.Principal{ID: "principal-1"},
		Calls:     []gateway.RPCCall{{Method: "tools/call", Tool: "transfer"}},
	}
	done := make(chan error, 1)
	go func() { done <- stage.Handle(context.Background(), req) }()

	deadline := time.Now().Add(2 * time.Second)
	for len(approver.Pending()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the action was not held for review")
		}
		time.Sleep(time.Millisecond)
	}
	if !approver.Approve(approver.Pending()[0].ID) {
		t.Fatal("approve reported the review was gone")
	}
	if err := <-done; err != nil {
		t.Fatalf("an approved action must proceed: %v", err)
	}
}

// TestApprovalTimeout: the window an operator has is configurable, and a value they got wrong
// is a startup error rather than a silent fallback to the default.
func TestApprovalTimeout(t *testing.T) {
	cases := []struct {
		env     string
		want    time.Duration
		wantErr bool
	}{
		{env: "", want: 2 * time.Minute},
		{env: "90s", want: 90 * time.Second},
		{env: " 5m ", want: 5 * time.Minute},
		{env: "0", want: 0}, // wait indefinitely
		{env: "-1s", wantErr: true},
		{env: "soon", wantErr: true},
	}
	for _, tc := range cases {
		t.Run("PASSPORT_APPROVAL_TIMEOUT="+tc.env, func(t *testing.T) {
			t.Setenv("PASSPORT_APPROVAL_TIMEOUT", tc.env)
			got, err := approvalTimeout()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %s", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
