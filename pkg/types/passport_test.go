package types

import (
	"testing"
	"time"
)

func TestPassportExpired(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	p := Passport{ExpiresAt: now.Add(time.Minute)}

	if p.Expired(now) {
		t.Fatal("passport should be valid before expiry")
	}
	if !p.Expired(now.Add(2 * time.Minute)) {
		t.Fatal("passport should be expired after expiry")
	}
	if !p.Expired(p.ExpiresAt) {
		t.Fatal("passport should be expired exactly at expiry (deny-on-boundary)")
	}
}

func TestDecisionAllowed(t *testing.T) {
	if (Decision{Effect: EffectAllow}).Allowed() != true {
		t.Fatal("allow decision must be allowed")
	}
	for _, e := range []Effect{EffectDeny, EffectReview, ""} {
		if (Decision{Effect: e}).Allowed() {
			t.Fatalf("non-allow effect %q must not be allowed (deny-by-default)", e)
		}
	}
}
