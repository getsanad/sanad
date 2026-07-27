package sts

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

func fixedNow() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

// --- TTL normalization ---------------------------------------------------------------

func TestNewTTLNormalization(t *testing.T) {
	signer, err := NewLocalSigner("kid-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cases := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"zero -> DefaultTTL", 0, DefaultTTL},
		{"negative -> DefaultTTL", -5 * time.Minute, DefaultTTL},
		{"tiny negative -> DefaultTTL", -time.Nanosecond, DefaultTTL},
		{"positive kept", 30 * time.Second, 30 * time.Second},
		{"large positive kept", time.Hour, time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iss := New(signer, Config{Issuer: "sanad", TTL: tc.ttl})
			if iss.cfg.TTL != tc.want {
				t.Fatalf("TTL = %s, want %s", iss.cfg.TTL, tc.want)
			}
		})
	}
}

func TestIssueExpiryReflectsTTL(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	for _, ttl := range []time.Duration{0, -time.Hour, 30 * time.Second, time.Hour} {
		iss := New(signer, Config{Issuer: "sanad", TTL: ttl})
		iss.now = fixedNow
		m, err := iss.Issue(context.Background(), IssueRequest{
			Principal: &types.Principal{ID: "p"},
			Audience:  "server-a",
		})
		if err != nil {
			t.Fatalf("issue (ttl=%s): %v", ttl, err)
		}
		want := iss.cfg.TTL // already normalized by New
		if got := m.Passport.ExpiresAt.Sub(m.Passport.IssuedAt); got != want {
			t.Fatalf("ttl=%s: lifetime %s, want %s", ttl, got, want)
		}
	}
}

// --- Missing / empty inputs ----------------------------------------------------------

func TestIssueRejectsEmptyPrincipalID(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})

	cases := []struct {
		name string
		req  IssueRequest
	}{
		{"nil principal", IssueRequest{Audience: "server-a"}},
		{"empty-string principal ID", IssueRequest{Principal: &types.Principal{ID: ""}, Audience: "server-a"}},
		{"missing audience", IssueRequest{Principal: &types.Principal{ID: "p"}}},
		{"empty audience string", IssueRequest{Principal: &types.Principal{ID: "p"}, Audience: ""}},
		{"both missing", IssueRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := iss.Issue(context.Background(), tc.req); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

// --- nil vs set Agent ----------------------------------------------------------------

func TestIssueNilAgentYieldsEmptyAgentID(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	iss.now = fixedNow

	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "p"},
		Audience:  "server-a",
		// Agent intentionally nil
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if m.Passport.AgentID != "" {
		t.Fatalf("AgentID = %q, want empty for nil agent", m.Passport.AgentID)
	}
	claims, err := passport.Verify(signer.Public(), m.Token, "server-a", fixedNow())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Agent != "" {
		t.Fatalf("token agent = %q, want empty", claims.Agent)
	}
}

func TestIssueSetAgentPropagates(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	iss.now = fixedNow

	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "p"},
		Agent:     &types.Agent{ID: "agent-42"},
		Audience:  "server-a",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if m.Passport.AgentID != "agent-42" {
		t.Fatalf("AgentID = %q, want agent-42", m.Passport.AgentID)
	}
	claims, _ := passport.Verify(signer.Public(), m.Token, "server-a", fixedNow())
	if claims.Agent != "agent-42" {
		t.Fatalf("token agent = %q, want agent-42", claims.Agent)
	}
}

// --- Scope + delegation passthrough --------------------------------------------------

func TestIssueScopePropagatesIntoPassport(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	iss.now = fixedNow

	scope := types.Scope{Tools: []string{"read", "write"}, Budget: &types.Budget{Limit: 5, Unit: "calls"}}
	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "p"},
		Audience:  "server-a",
		Scope:     scope,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The structured Passport carries the full scope (including Budget).
	if len(m.Passport.Scope.Tools) != 2 || m.Passport.Scope.Tools[0] != "read" {
		t.Fatalf("passport tools = %v", m.Passport.Scope.Tools)
	}
	if m.Passport.Scope.Budget == nil || m.Passport.Scope.Budget.Limit != 5 {
		t.Fatalf("passport budget not propagated: %+v", m.Passport.Scope.Budget)
	}

	// The signed token now carries both tools and the budget.
	claims, _ := passport.Verify(signer.Public(), m.Token, "server-a", fixedNow())
	if len(claims.Tools) != 2 || claims.Tools[1] != "write" {
		t.Fatalf("token scope = %v, want [read write]", claims.Tools)
	}
	if claims.Budget == nil || claims.Budget.Limit != 5 || claims.Budget.Unit != "calls" {
		t.Fatalf("token budget = %+v, want {5 calls}", claims.Budget)
	}
}

func TestIssueDelegationPropagatesIntoPassport(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	iss.now = fixedNow

	chain := &types.DelegationChain{Hops: []types.DelegationHop{
		{Delegator: "p", Delegate: "agent-1", Scope: types.Scope{Tools: []string{"read"}}},
	}}
	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal:  &types.Principal{ID: "p"},
		Audience:   "server-a",
		Delegation: chain,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if m.Passport.Delegation == nil || len(m.Passport.Delegation.Hops) != 1 {
		t.Fatalf("delegation not propagated into structured passport: %+v", m.Passport.Delegation)
	}
	if m.Passport.Delegation.Hops[0].Delegate != "agent-1" {
		t.Fatalf("delegate = %q, want agent-1", m.Passport.Delegation.Hops[0].Delegate)
	}
}

// --- jti uniqueness ------------------------------------------------------------------

func TestIssueJTIUnique(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	iss.now = fixedNow // fixed clock => uniqueness must come from randomness, not time

	const n = 2000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		m, err := iss.Issue(context.Background(), IssueRequest{
			Principal: &types.Principal{ID: "p"},
			Audience:  "server-a",
		})
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if m.Passport.ID == "" {
			t.Fatal("empty jti")
		}
		if _, dup := seen[m.Passport.ID]; dup {
			t.Fatalf("duplicate jti at iteration %d: %q", i, m.Passport.ID)
		}
		seen[m.Passport.ID] = struct{}{}
	}
}

func TestIssueJTIUniqueConcurrent(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})

	const goroutines = 16
	const perG = 200
	var (
		mu   sync.Mutex
		seen = make(map[string]struct{}, goroutines*perG)
		wg   sync.WaitGroup
	)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				m, err := iss.Issue(context.Background(), IssueRequest{
					Principal: &types.Principal{ID: "p"},
					Audience:  "server-a",
				})
				if err != nil {
					t.Errorf("issue: %v", err)
					return
				}
				mu.Lock()
				if _, dup := seen[m.Passport.ID]; dup {
					t.Errorf("duplicate jti under concurrency: %q", m.Passport.ID)
				}
				seen[m.Passport.ID] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != goroutines*perG {
		t.Fatalf("got %d unique jti, want %d", len(seen), goroutines*perG)
	}
}

// --- Injected clock & end-to-end verification ---------------------------------------

func TestIssueUsesInjectedClock(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad", TTL: time.Minute})
	frozen := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	iss.now = func() time.Time { return frozen }

	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "p"},
		Audience:  "server-a",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !m.Passport.IssuedAt.Equal(frozen) {
		t.Fatalf("IssuedAt = %v, want %v", m.Passport.IssuedAt, frozen)
	}
	if !m.Passport.ExpiresAt.Equal(frozen.Add(time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want %v", m.Passport.ExpiresAt, frozen.Add(time.Minute))
	}

	// Minted token verifies via pkg/passport at a time within the window, and is rejected
	// before issuance and at/after expiry.
	if _, err := passport.Verify(signer.Public(), m.Token, "server-a", frozen.Add(30*time.Second)); err != nil {
		t.Fatalf("verify within window: %v", err)
	}
	if _, err := passport.Verify(signer.Public(), m.Token, "server-a", frozen.Add(time.Minute)); err == nil {
		t.Fatal("verify at expiry must fail")
	}
}

func TestMintedTokenIssuerClaim(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "my-issuer"})
	iss.now = fixedNow
	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "p"},
		Audience:  "server-a",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := passport.Verify(signer.Public(), m.Token, "server-a", fixedNow())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Issuer != "my-issuer" {
		t.Fatalf("issuer = %q, want my-issuer", claims.Issuer)
	}
	if claims.ID != m.Passport.ID {
		t.Fatalf("token jti %q != passport jti %q", claims.ID, m.Passport.ID)
	}
}

// --- LocalSigner ---------------------------------------------------------------------

func TestLocalSignerKeyIDAndKeyPair(t *testing.T) {
	signer, err := NewLocalSigner("kid-abc")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if signer.KeyID() != "kid-abc" {
		t.Fatalf("KeyID = %q, want kid-abc", signer.KeyID())
	}
	// Sign a claim set and confirm the public key verifies it (key pair is consistent).
	now := fixedNow()
	c := passport.Claims{
		ID: "j", Issuer: "iss", Principal: "p", Audience: "server-a",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
	}
	tok, err := signer.Sign(c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := passport.Verify(signer.Public(), tok, "server-a", now); err != nil {
		t.Fatalf("public key did not verify signer's own token: %v", err)
	}
	// Independent signers must produce distinct keys.
	other, _ := NewLocalSigner("kid-abc")
	if signer.Public().Equal(other.Public()) {
		t.Fatal("two NewLocalSigner calls produced the same key")
	}
}
