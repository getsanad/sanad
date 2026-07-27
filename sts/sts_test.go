package sts

import (
	"context"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

func newIssuer(t *testing.T, ttl time.Duration) (*EdDSAIssuer, *LocalSigner) {
	t.Helper()
	signer, err := NewLocalSigner("kid-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return New(signer, Config{Issuer: "sanad", TTL: ttl}), signer
}

func TestIssueAndVerify(t *testing.T) {
	iss, signer := newIssuer(t, 2*time.Minute)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	iss.now = func() time.Time { return now }

	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "principal-1"},
		Agent:     &types.Agent{ID: "agent-1"},
		Audience:  "server-a",
		Scope:     types.Scope{Tools: []string{"read"}},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if m.Passport.ExpiresAt.Sub(m.Passport.IssuedAt) != 2*time.Minute {
		t.Fatalf("TTL mismatch: %s", m.Passport.ExpiresAt.Sub(m.Passport.IssuedAt))
	}

	claims, err := passport.Verify(signer.Public(), m.Token, "server-a", now)
	if err != nil {
		t.Fatalf("verify minted token: %v", err)
	}
	if claims.Principal != "principal-1" || claims.Agent != "agent-1" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if claims.Issuer != "sanad" {
		t.Fatalf("issuer = %q, want sanad", claims.Issuer)
	}
}

func TestIssueRejectsMissingInputs(t *testing.T) {
	iss, _ := newIssuer(t, 0) // 0 → DefaultTTL

	if _, err := iss.Issue(context.Background(), IssueRequest{Audience: "server-a"}); err == nil {
		t.Fatal("missing principal must error")
	}
	if _, err := iss.Issue(context.Background(), IssueRequest{Principal: &types.Principal{ID: "p"}}); err == nil {
		t.Fatal("missing audience must error")
	}
}

func TestDefaultTTLApplied(t *testing.T) {
	iss, _ := newIssuer(t, 0)
	if iss.cfg.TTL != DefaultTTL {
		t.Fatalf("default TTL = %s, want %s", iss.cfg.TTL, DefaultTTL)
	}
}

func TestIssuedPassportAudienceBinding(t *testing.T) {
	iss, signer := newIssuer(t, time.Minute)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	iss.now = func() time.Time { return now }

	m, err := iss.Issue(context.Background(), IssueRequest{
		Principal: &types.Principal{ID: "principal-1"},
		Audience:  "server-a",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := passport.Verify(signer.Public(), m.Token, "server-b", now); err == nil {
		t.Fatal("minted passport for server-a must not verify at server-b")
	}
}
