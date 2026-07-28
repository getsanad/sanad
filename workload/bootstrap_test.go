package workload

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The flaw these pin: a bootstrap token used to be a permanent, unlimited enrollment right.
// One leaked token — out of a config file, a CI log, a `ps` listing — enrolled unlimited
// instances under that agent id, forever, and nothing rate limited the attempts.

func TestBootstrapTokenIsSingleUseByDefault(t *testing.T) {
	_, caPriv := newCA(t)
	att := NewTokenAttestor()
	if err := att.Register("boot", "agent-1"); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	first, _ := instanceKey(t)
	if _, err := enroll(t, authority, "boot", first); err != nil {
		t.Fatalf("the honest first enrollment must work: %v", err)
	}

	// The second instance holds the same token and a key of its own — the attacker's position
	// after a token leaks, and the whole point of the old design being wrong.
	second, _ := instanceKey(t)
	if _, err := enroll(t, authority, "boot", second); err == nil {
		t.Fatal("REGRESSION: a single-use bootstrap token enrolled a second instance")
	} else if !strings.Contains(err.Error(), "spent") {
		t.Fatalf("the refusal should say the token is spent, got %v", err)
	}
	if n := att.Remaining("boot"); n != 0 {
		t.Fatalf("a spent token should have no budget left, got %d", n)
	}
}

func TestBootstrapTokenBudgetIsBounded(t *testing.T) {
	_, caPriv := newCA(t)
	att := NewTokenAttestor()
	if err := att.RegisterGrant("boot", TokenGrant{AgentID: "agent-1", Uses: 3, TTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		pub, _ := instanceKey(t)
		if _, err := enroll(t, authority, "boot", pub); err != nil {
			t.Fatalf("enrollment %d of a 3-use token: %v", i+1, err)
		}
		if got, want := att.Remaining("boot"), 2-i; got != want {
			t.Fatalf("after enrollment %d, %d uses left, want %d", i+1, got, want)
		}
	}
	pub, _ := instanceKey(t)
	if _, err := enroll(t, authority, "boot", pub); err == nil {
		t.Fatal("a 3-use token must not authorize a 4th enrollment")
	}
}

func TestBootstrapTokenExpires(t *testing.T) {
	_, caPriv := newCA(t)
	att := NewTokenAttestor()
	base := time.Now()
	att.now = func() time.Time { return base }
	// Generous budget, so only the window can refuse the second enrollment.
	if err := att.RegisterGrant("boot", TokenGrant{AgentID: "agent-1", Uses: 10, TTL: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := instanceKey(t)
	if _, err := enroll(t, authority, "boot", pub); err != nil {
		t.Fatalf("inside the window the token must work: %v", err)
	}

	att.now = func() time.Time { return base.Add(10*time.Minute + time.Second) }
	if n := att.Remaining("boot"); n != 0 {
		t.Fatalf("an expired token should report no budget, got %d", n)
	}
	other, _ := instanceKey(t)
	if _, err := enroll(t, authority, "boot", other); err == nil {
		t.Fatal("an expired bootstrap token must be refused")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the refusal should say the token expired, got %v", err)
	}
}

// TestBootstrapTokenDefaults pins that leaving a field zero buys the strict default rather
// than "unlimited" — the failure mode the old map had by construction.
func TestBootstrapTokenDefaults(t *testing.T) {
	att := NewTokenAttestor()
	base := time.Now()
	att.now = func() time.Time { return base }
	if err := att.RegisterGrant("boot", TokenGrant{AgentID: "agent-1"}); err != nil {
		t.Fatal(err)
	}
	if got := att.Remaining("boot"); got != DefaultTokenUses {
		t.Fatalf("zero Uses = %d enrollments, want the default %d", got, DefaultTokenUses)
	}
	att.now = func() time.Time { return base.Add(DefaultTokenTTL + time.Second) }
	if got := att.Remaining("boot"); got != 0 {
		t.Fatalf("zero TTL should default to %s, but the token still has %d uses after it", DefaultTokenTTL, got)
	}

	// Re-registering refreshes the grant: that is how an operator reissues one.
	if err := att.Register("boot", "agent-1"); err != nil {
		t.Fatal(err)
	}
	if got := att.Remaining("boot"); got != DefaultTokenUses {
		t.Fatalf("re-registering should reset the budget, got %d", got)
	}
	if err := att.Register("", "agent-1"); err == nil {
		t.Fatal("an empty bootstrap token must be refused")
	}
}

// TestBootstrapTokenSpentConcurrently pins the budget under the race detector: N goroutines
// racing on a 1-use token must produce exactly one credential, not N.
func TestBootstrapTokenSpentConcurrently(t *testing.T) {
	_, caPriv := newCA(t)
	att := NewTokenAttestor()
	if err := att.Register("boot", "agent-1"); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const racers = 16
	results := make(chan error, racers)
	for range racers {
		pub, _ := instanceKey(t)
		go func() {
			nonce, nerr := authority.Nonce()
			if nerr != nil {
				results <- nerr
				return
			}
			_, ierr := authority.Issue(BootstrapEvidence("boot", nonce, pub), nonce, pub)
			results <- ierr
		}()
	}
	issued := 0
	for range racers {
		if <-results == nil {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("a single-use token issued %d credentials under concurrency, want 1", issued)
	}
}

// --- rate limiting ---------------------------------------------------------------

func TestEnrollHandlerRateLimits(t *testing.T) {
	srv, _, authority := enrollSetup(t)
	defer srv.Close()
	// A budget small enough to trip deterministically, with a refill slow enough that the test
	// cannot outrun it.
	authority.SetEnrollLimit(EnrollLimit{ClientBurst: 3, ClientPerMin: 1, GlobalBurst: 100, GlobalPerMin: 1})

	nonce200, limited := 0, 0
	for range 10 {
		resp, err := srv.Client().Post(srv.URL+"/enroll/nonce", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
			nonce200++
		case http.StatusTooManyRequests:
			limited++
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("a 429 must carry Retry-After")
			}
		default:
			t.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
	if nonce200 != 3 {
		t.Fatalf("burst of 3 allowed %d requests", nonce200)
	}
	if limited != 7 {
		t.Fatalf("%d requests limited, want 7", limited)
	}

	// The two legs share one budget, so the exhausted client cannot switch to /enroll and keep
	// grinding attestations.
	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if code, _ := postEnroll(t, srv, []byte("n"), []byte("e"), instPub); code != http.StatusTooManyRequests {
		t.Fatalf("POST /enroll after the shared budget is spent = %d, want 429", code)
	}
}

// TestEnrollRateLimitAllowsHonestEnrollment is the other half: the limiter must not stand
// between an agent and its one enrollment.
func TestEnrollRateLimitAllowsHonestEnrollment(t *testing.T) {
	srv, caPub, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cred, err := Enroll(context.Background(), srv.Client(), srv.URL, instPub, bootstrapEvidenceFor("boot-token"))
	if err != nil {
		t.Fatalf("the honest enrollment must not be rate limited: %v", err)
	}
	if err := Verify(caPub, cred, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestLimiterMemoryIsBounded is the property that makes the limiter safe to put in front of an
// unauthenticated endpoint: a client-keyed map would be a second unbounded table for the same
// attacker to fill. A million distinct clients must cost exactly what one costs.
func TestLimiterMemoryIsBounded(t *testing.T) {
	l := NewLimiter(EnrollLimit{ClientBurst: 1, ClientPerMin: 1, GlobalBurst: 1 << 30, GlobalPerMin: 1 << 30})
	before := len(l.buckets)
	now := time.Now()
	for i := range 1_000_000 {
		l.Allow(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), now)
	}
	if got := len(l.buckets); got != before || got != limiterBuckets {
		t.Fatalf("the bucket table grew from %d to %d (fixed size is %d)", before, got, limiterBuckets)
	}
}

// TestLimiterRefills pins that the budget comes back, so a throttled client is delayed and not
// locked out, and that the global bucket bounds everyone together.
func TestLimiterRefills(t *testing.T) {
	base := time.Now()
	l := NewLimiter(EnrollLimit{ClientBurst: 2, ClientPerMin: 60, GlobalBurst: 1000, GlobalPerMin: 6000})
	for i := range 2 {
		if !l.Allow("1.2.3.4", base) {
			t.Fatalf("request %d should be inside the burst", i+1)
		}
	}
	if l.Allow("1.2.3.4", base) {
		t.Fatal("the third request should exceed a burst of 2")
	}
	// 60/min is one token a second.
	if !l.Allow("1.2.3.4", base.Add(time.Second)) {
		t.Fatal("a token should have refilled after a second")
	}
	// A different client has its own bucket (barring a hash collision, which this pair is
	// chosen to avoid).
	if !l.Allow("5.6.7.8", base) {
		t.Fatal("one client's flood must not refuse another")
	}

	// The global bucket refuses everyone once it is empty, whatever bucket they hash to.
	g := NewLimiter(EnrollLimit{ClientBurst: 1000, ClientPerMin: 6000, GlobalBurst: 5, GlobalPerMin: 1})
	allowed := 0
	for i := range 50 {
		if g.Allow(fmt.Sprintf("10.0.0.%d", i), base) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("a global burst of 5 allowed %d requests across 50 clients", allowed)
	}
}

// TestLimiterIgnoresForwardedHeaders: the limiter keys on the peer address only. A client that
// could pick its own bucket by setting a header would not be limited at all.
func TestLimiterIgnoresForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/enroll", nil)
	r.RemoteAddr = "192.0.2.7:54321"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Real-IP", "203.0.113.9")
	if got := clientKey(r); got != "192.0.2.7" {
		t.Fatalf("clientKey = %q, want the peer address 192.0.2.7", got)
	}
	// A RemoteAddr with no port (some transports) is still a usable key rather than an error.
	r.RemoteAddr = "@"
	if got := clientKey(r); got != "@" {
		t.Fatalf("clientKey = %q, want the raw address", got)
	}
}
