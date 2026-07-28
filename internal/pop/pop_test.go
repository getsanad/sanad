package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

const testCtx = sigctx.InstanceProof

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// proofFor signs a proof bound to r at time now.
func proofFor(t *testing.T, priv ed25519.PrivateKey, r *http.Request, body []byte, token string, now time.Time) string {
	t.Helper()
	b, err := NewBinding(r.Method, Target(r.URL), token, body, now)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := Sign(testCtx, priv, b)
	if err != nil {
		t.Fatal(err)
	}
	return hdr
}

const testToken = "principal-bearer-token"

func TestTargetIsTheOriginFormRequestTarget(t *testing.T) {
	cases := []struct{ url, want string }{
		{"/servers/demo/mcp", "/servers/demo/mcp"},
		{"/servers/demo/mcp?cursor=abc", "/servers/demo/mcp?cursor=abc"},
		// The escaped path is used verbatim, so a percent-encoded separator is not silently
		// decoded into a real one — both ends compare the same bytes the client sent.
		{"/servers/demo/a%2Fb", "/servers/demo/a%2Fb"},
		// The authority is deliberately absent: see Target's doc comment.
		{"http://gw.example.com/servers/demo/mcp", "/servers/demo/mcp"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, c.url, nil)
		if got := Target(r.URL); got != c.want {
			t.Errorf("Target(%s) = %q, want %q", c.url, got, c.want)
		}
	}
	if got := Target(nil); got != "" {
		t.Errorf("Target(nil) = %q, want empty", got)
	}
}

// The honest path: a proof made for a request verifies against that request.
func TestCheckAcceptsAProofForItsOwnRequest(t *testing.T) {
	pub, priv := testKey(t)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read"}}`)
	r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil)

	v := NewVerifier(testCtx)
	if err := v.Check(pub, proofFor(t, priv, r, body, testToken, time.Now()), r, body, testToken); err != nil {
		t.Fatalf("an honest proof must verify: %v", err)
	}
}

// The whole point: a proof captured from one request is worthless on a different one. Each
// case changes exactly one covered input.
func TestCheckRejectsAProofCapturedFromADifferentRequest(t *testing.T) {
	pub, priv := testKey(t)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read"}}`)
	captured := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil)
	hdr := proofFor(t, priv, captured, body, testToken, time.Now())

	evil := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete"}}`)
	cases := []struct {
		name string
		r    *http.Request
		body []byte
		tok  string
	}{
		{"different method", httptest.NewRequest(http.MethodGet, "/servers/demo/mcp", nil), body, testToken},
		{"different path", httptest.NewRequest(http.MethodPost, "/servers/other/mcp", nil), body, testToken},
		{"different query", httptest.NewRequest(http.MethodPost, "/servers/demo/mcp?x=1", nil), body, testToken},
		{"different body", httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil), evil, testToken},
		{"body added to a bodyless request", httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil), nil, testToken},
		{"different principal token", httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil), body, "another-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A fresh verifier each time, so the rejection is the binding and not the cache.
			if err := NewVerifier(testCtx).Check(pub, hdr, c.r, c.body, c.tok); err == nil {
				t.Fatal("a proof from a different request must be rejected")
			}
		})
	}
}

// The same request, replayed verbatim: the binding still matches, so only the replay cache
// stands between the attacker and a second execution.
func TestCheckRejectsTheSameRequestTwice(t *testing.T) {
	pub, priv := testKey(t)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read"}}`)
	r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil)
	hdr := proofFor(t, priv, r, body, testToken, time.Now())

	v := NewVerifier(testCtx)
	if err := v.Check(pub, hdr, r, body, testToken); err != nil {
		t.Fatalf("first presentation must be accepted: %v", err)
	}
	err := v.Check(pub, hdr, r, body, testToken)
	if !errors.Is(err, ErrReplayed) {
		t.Fatalf("second presentation = %v, want ErrReplayed", err)
	}
}

func TestCheckEnforcesTheFreshnessWindow(t *testing.T) {
	pub, priv := testKey(t)
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	now := time.Now()

	cases := []struct {
		name    string
		iat     time.Time
		wantErr bool
	}{
		{"now", now, false},
		{"just inside the max age", now.Add(-DefaultMaxAge + time.Second), false},
		{"just past the max age", now.Add(-DefaultMaxAge - time.Second), true},
		{"long expired", now.Add(-time.Hour), true},
		{"slightly ahead, inside the skew", now.Add(DefaultSkew - time.Second), false},
		{"further ahead than the skew allows", now.Add(DefaultSkew + time.Second), true},
		{"far in the future", now.Add(time.Hour), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := NewVerifier(testCtx, WithClock(func() time.Time { return now }))
			err := v.Check(pub, proofFor(t, priv, r, nil, testToken, c.iat), r, nil, testToken)
			if c.wantErr && !errors.Is(err, ErrStale) {
				t.Fatalf("err = %v, want ErrStale", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("a proof inside the window must be accepted: %v", err)
			}
		})
	}
}

// A proof that never said when it was made is stale, not epoch-fresh.
func TestCheckRejectsAProofWithNoIAT(t *testing.T) {
	pub, priv := testKey(t)
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	b := Binding{ATH: Hash([]byte(testToken)), BH: Hash(nil), HTM: r.Method, HTU: Target(r.URL), JTI: "no-iat"}
	hdr, err := Sign(testCtx, priv, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewVerifier(testCtx).Check(pub, hdr, r, nil, testToken); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
}

// A signature made under any other context must not pass, and must not reach the cache.
func TestCheckRejectsAnotherContextsSignature(t *testing.T) {
	pub, priv := testKey(t)
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	b, err := NewBinding(r.Method, Target(r.URL), testToken, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range sigctx.All {
		if other == testCtx {
			continue
		}
		hdr, err := Sign(other, priv, b)
		if err != nil {
			t.Fatal(err)
		}
		if err := NewVerifier(testCtx).Check(pub, hdr, r, nil, testToken); err == nil {
			t.Fatalf("a %s signature was accepted as %s", other, testCtx)
		}
	}
}

// The cache is the one piece of per-request state here, so nothing an unauthenticated caller
// sends may enter it. Everything that fails before or at the signature check must leave it
// empty, or a flood of junk becomes a denial of service against real agents.
func TestCheckDoesNotPopulateTheCacheBeforeAuthenticating(t *testing.T) {
	pub, priv := testKey(t)
	_, attacker := testKey(t)
	r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", nil)
	body := []byte(`{"jsonrpc":"2.0","method":"tools/list"}`)

	v := NewVerifier(testCtx)
	junk := []string{
		"",
		"not-a-proof",
		"only-one-part",
		"!!!." + base64.RawURLEncoding.EncodeToString([]byte("sig")),
		base64.RawURLEncoding.EncodeToString([]byte("{}")) + ".!!!",
		base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
		// Correctly shaped, correctly bound — signed by the wrong key.
		proofFor(t, attacker, r, body, testToken, time.Now()),
	}
	for _, hdr := range junk {
		if err := v.Check(pub, hdr, r, body, testToken); err == nil {
			t.Fatalf("%q must not be accepted", hdr)
		}
	}
	if n := v.Cache().Len(); n != 0 {
		t.Fatalf("unauthenticated input put %d entries in the replay cache, want 0", n)
	}

	// And a proof that authenticates but fails a later check is likewise not spent, so the
	// cache only ever holds jtis from requests that were actually served.
	stale := proofFor(t, priv, r, body, testToken, time.Now().Add(-time.Hour))
	if err := v.Check(pub, stale, r, body, testToken); !errors.Is(err, ErrStale) {
		t.Fatalf("err = %v, want ErrStale", err)
	}
	if n := v.Cache().Len(); n != 0 {
		t.Fatalf("a rejected proof was recorded: cache has %d entries", n)
	}
}

// A jti is a map key held for a whole window, so its length has to be bounded or the memory
// bound is "entries times whatever the caller sent".
func TestCheckRejectsAnOversizedJTI(t *testing.T) {
	pub, priv := testKey(t)
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	for _, jti := range []string{"", strings.Repeat("a", MaxJTI+1)} {
		b := Binding{
			ATH: Hash([]byte(testToken)), BH: Hash(nil),
			HTM: r.Method, HTU: Target(r.URL), IAT: time.Now().Unix(), JTI: jti,
		}
		hdr, err := Sign(testCtx, priv, b)
		if err != nil {
			t.Fatal(err)
		}
		v := NewVerifier(testCtx)
		if err := v.Check(pub, hdr, r, nil, testToken); err == nil {
			t.Fatalf("a %d-byte jti must be rejected", len(jti))
		}
		if n := v.Cache().Len(); n != 0 {
			t.Fatalf("an unusable jti was stored: cache has %d entries", n)
		}
	}
}

// --- replay cache -----------------------------------------------------------------------

func TestReplayCacheSpendsOnce(t *testing.T) {
	c := NewReplayCache(time.Minute, 10)
	now := time.Now()
	if err := c.Use("a", now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := c.Use("a", now); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second use = %v, want ErrReplayed", err)
	}
	if err := c.Use("b", now); err != nil {
		t.Fatalf("a different jti must be accepted: %v", err)
	}
}

// An entry has to outlive every proof it could cover: it is still refused a full window after
// it was recorded, and only forgotten once no proof carrying it could still be fresh.
func TestReplayCacheRetainsForAtLeastOneWindow(t *testing.T) {
	const window = time.Minute
	c := NewReplayCache(window, 100)
	start := time.Now()
	if err := c.Use("a", start); err != nil {
		t.Fatal(err)
	}
	if err := c.Use("a", start.Add(window)); !errors.Is(err, ErrReplayed) {
		t.Fatalf("an entry must survive one window: %v", err)
	}
	if err := c.Use("a", start.Add(2*window+time.Second)); err != nil {
		t.Fatalf("past two windows the entry may be forgotten: %v", err)
	}
}

// The memory bound: sustained traffic does not grow the cache without limit, because whole
// generations age out. Without rotation this would hold every jti ever seen.
func TestReplayCacheDoesNotGrowUnboundedly(t *testing.T) {
	const window = time.Second
	const max = 100000 // far above what this test inserts, so the cap is not what bounds it
	c := NewReplayCache(window, max)

	now := time.Now()
	const rounds, perRound = 20, 500
	for i := 0; i < rounds; i++ {
		for j := 0; j < perRound; j++ {
			if err := c.Use(fmt.Sprintf("jti-%d-%d", i, j), now); err != nil {
				t.Fatalf("round %d: %v", i, err)
			}
		}
		now = now.Add(window)
	}

	// 10,000 proofs went through; at most two generations may be held, so at most two rounds'
	// worth may remain. A cache that never forgot would be at 10,000 here.
	if n := c.Len(); n > 2*perRound {
		t.Fatalf("cache holds %d entries after %d, want at most %d", n, rounds*perRound, 2*perRound)
	}
	if n := c.Len(); n == 0 {
		t.Fatal("the cache forgot everything: recent proofs would be replayable")
	}
}

// Past the cap the cache refuses rather than evicting: evicting would silently re-open replay
// for exactly the entries an attacker is flooding to push out (NFR-3, fail closed).
func TestReplayCacheFailsClosedWhenFull(t *testing.T) {
	const max = 8
	c := NewReplayCache(time.Minute, max)
	now := time.Now()
	for i := 0; i < max; i++ {
		if err := c.Use(fmt.Sprintf("jti-%d", i), now); err != nil {
			t.Fatalf("filling: %v", err)
		}
	}
	if err := c.Use("one-too-many", now); !errors.Is(err, ErrCacheFull) {
		t.Fatalf("err = %v, want ErrCacheFull", err)
	}
	if n := c.Len(); n != max {
		t.Fatalf("cache grew past its cap: %d entries, max %d", n, max)
	}
	// It recovers on its own once the window has passed, without an operator touching it.
	if err := c.Use("later", now.Add(2*time.Minute+time.Second)); err != nil {
		t.Fatalf("the cache must drain and accept again: %v", err)
	}
}

// The verifier is shared by every request on a replica, so the cache has to be safe under
// concurrency — and exactly one of N racing presentations of one jti may win.
func TestReplayCacheIsConcurrencySafe(t *testing.T) {
	c := NewReplayCache(time.Minute, 1000)
	now := time.Now()
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Use("contended", now); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("%d concurrent presentations of one jti were accepted, want 1", accepted)
	}
}
