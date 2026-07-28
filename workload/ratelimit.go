package workload

import (
	"hash/fnv"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Enrollment rate limits. /enroll/nonce and /enroll are the only unauthenticated endpoints the
// authority exposes, and both do work for whoever asks: the first grows the outstanding-nonce
// table, the second runs an HMAC per registered bootstrap token. Unbounded, that is a free way
// to fill the nonce table until honest agents are refused, and a free way to grind attestation
// attempts. These are the default budgets.
//
// The two legs share one budget, because they are one operation: an honest enrollment is a
// nonce fetch followed by an enroll, so a per-client burst of 20 is ten enrollments back to
// back. Limiting them separately would leave the nonce leg — the one that costs memory — with
// a budget of its own to spend.
const (
	// DefaultClientBurst and DefaultClientPerMin bound one client. An instance enrolls once at
	// startup; the burst is for a deploy that restarts a handful of replicas at once.
	DefaultClientBurst  = 20
	DefaultClientPerMin = 20

	// DefaultGlobalBurst and DefaultGlobalPerMin bound everyone together, which is the bound
	// that actually protects the nonce table: at 200/min a caller can hold at most 200/min ×
	// NonceTTL = 400 outstanding nonces, comfortably under maxOutstandingNonces (4096), so an
	// unauthenticated flood can no longer starve an honest agent of a challenge.
	DefaultGlobalBurst  = 200
	DefaultGlobalPerMin = 200

	// limiterBuckets is the fixed number of per-client buckets. Clients are hashed into it, so
	// the limiter's memory is decided here and never again: ~32 KiB, whether it is serving one
	// agent or a botnet. That is the point — a limiter keyed by a map of client addresses is a
	// second unbounded table for the same attacker to fill, which is how limiters become the
	// exhaustion they were added to prevent. The cost of a fixed table is collisions: two
	// clients sharing a bucket share a budget. Under a flood that is the behaviour we want
	// (the flooder's neighbours are throttled with it, and the global bucket is what holds),
	// and at honest volumes 1024 buckets make it rare.
	limiterBuckets = 1024
)

// EnrollLimit is the enrollment rate-limit budget: a sustained rate per minute and a burst,
// per client and overall. A non-positive field selects its default.
type EnrollLimit struct {
	ClientBurst  int
	ClientPerMin int
	GlobalBurst  int
	GlobalPerMin int
}

// DefaultEnrollLimit is the budget NewAuthority installs.
func DefaultEnrollLimit() EnrollLimit {
	return EnrollLimit{
		ClientBurst:  DefaultClientBurst,
		ClientPerMin: DefaultClientPerMin,
		GlobalBurst:  DefaultGlobalBurst,
		GlobalPerMin: DefaultGlobalPerMin,
	}
}

// bucket is one token bucket: tokens available, and when they were last topped up.
type bucket struct {
	tokens float64
	last   time.Time
}

// take refills the bucket at rate tokens/sec (capped at burst) and reports whether it holds a
// whole token, without spending it — Limiter.Allow checks both its buckets before spending
// either, so a request refused by one does not silently cost a token in the other.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	switch {
	case b.last.IsZero():
		b.tokens, b.last = burst, now
	case now.After(b.last):
		b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
		b.last = now
	}
	return b.tokens >= 1
}

// Limiter is a token-bucket rate limiter with a fixed memory footprint: a per-client bucket
// (clients hashed into a fixed table) and a global bucket, both refilled continuously. It is
// safe for concurrent use.
//
// Like every other counter in this package it is PROCESS-LOCAL: N authority replicas behind a
// load balancer allow N times the budget. The global bound is therefore a per-replica bound,
// which is the right shape anyway — it is protecting that replica's nonce table.
type Limiter struct {
	mu      sync.Mutex
	buckets []bucket
	global  bucket

	clientRate, clientBurst float64 // tokens per second, cap
	globalRate, globalBurst float64
	retryAfter              time.Duration
}

// NewLimiter returns a Limiter with the given budget. The bucket table is allocated once here
// and never grows.
func NewLimiter(l EnrollLimit) *Limiter {
	lim := &Limiter{buckets: make([]bucket, limiterBuckets)}
	lim.SetLimit(l)
	return lim
}

// SetLimit replaces the budget and empties the buckets. It takes the limiter's own lock rather
// than being a pointer swap on the Authority, so an operator may retune a limiter that is
// already serving without racing the handlers reading it.
func (l *Limiter) SetLimit(el EnrollLimit) {
	d := DefaultEnrollLimit()
	if el.ClientBurst <= 0 {
		el.ClientBurst = d.ClientBurst
	}
	if el.ClientPerMin <= 0 {
		el.ClientPerMin = d.ClientPerMin
	}
	if el.GlobalBurst <= 0 {
		el.GlobalBurst = d.GlobalBurst
	}
	if el.GlobalPerMin <= 0 {
		el.GlobalPerMin = d.GlobalPerMin
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clientRate, l.clientBurst = float64(el.ClientPerMin)/60, float64(el.ClientBurst)
	l.globalRate, l.globalBurst = float64(el.GlobalPerMin)/60, float64(el.GlobalBurst)
	// How long until the slower of the two buckets has a token again, rounded up to a whole
	// second because that is all Retry-After can carry (RFC 9110 §10.2.3).
	l.retryAfter = time.Duration(math.Ceil(60/math.Min(float64(el.ClientPerMin), float64(el.GlobalPerMin)))) * time.Second
	clear(l.buckets)
	l.global = bucket{}
}

// Allow reports whether client may make a request at time now, spending a token from its
// bucket and from the global bucket if so.
func (l *Limiter) Allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := &l.buckets[bucketIndex(client, len(l.buckets))]
	// Both refill on every call, so a bucket the request is about to be refused by is still
	// aged forward and cannot be left holding a stale timestamp.
	okClient := b.take(now, l.clientRate, l.clientBurst)
	okGlobal := l.global.take(now, l.globalRate, l.globalBurst)
	if !okClient || !okGlobal {
		return false
	}
	b.tokens--
	l.global.tokens--
	return true
}

// RetryAfter is how long a refused client should wait, for the Retry-After header.
func (l *Limiter) RetryAfter() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.retryAfter
}

// bucketIndex hashes a client key into the fixed bucket table.
func bucketIndex(client string, n int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(client))
	return int(h.Sum32() % uint32(n))
}

// clientKey identifies the caller for rate limiting: the peer address of the TCP connection,
// without the ephemeral port.
//
// It deliberately ignores X-Forwarded-For and friends. A client-settable header is a limiter
// the client can switch off — every request carrying a different forged value lands in a
// different bucket — and the limiter would be worse than none, since it would report that
// enrollment was rate limited. Behind a load balancer this means every caller shares the
// proxy's address and therefore one client bucket; that degrades per-client fairness to the
// global bound, which is the bound that protects the nonce table. A deployment that wants
// per-agent limits at the edge should set them at the edge, where the peer address is real.
func clientKey(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// rateLimited answers a request that has exhausted its budget and reports whether it did. The
// authority's handlers call it first, before decoding anything, so a flood costs a hash and a
// mutex rather than a JSON parse and an HMAC per registered token.
func rateLimited(l *Limiter, w http.ResponseWriter, r *http.Request) bool {
	if l == nil || l.Allow(clientKey(r), time.Now()) {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(l.RetryAfter()/time.Second)))
	http.Error(w, "enrollment rate limit exceeded", http.StatusTooManyRequests)
	return true
}
