package metrics

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHistogramBoundaryValues(t *testing.T) {
	// le bucket counts are cumulative and inclusive of the boundary (v <= b).
	h := newHistogram([]float64{0.001, 0.01, 0.1})
	h.observe(0.001) // exactly the first boundary -> counts in all three
	h.observe(0.01)  // exactly the second boundary -> counts in buckets 1 and 2
	h.observe(0.1)   // exactly the third boundary -> counts only in bucket 2

	wantCounts := []uint64{1, 2, 3}
	for i, want := range wantCounts {
		if h.counts[i] != want {
			t.Fatalf("counts[%d] (le=%g) = %d, want %d", i, h.buckets[i], h.counts[i], want)
		}
	}
	if h.count != 3 {
		t.Fatalf("count = %d, want 3", h.count)
	}
}

func TestHistogramValueAboveAllBuckets(t *testing.T) {
	h := newHistogram([]float64{0.001, 0.01})
	h.observe(5.0) // exceeds every bucket
	for i := range h.counts {
		if h.counts[i] != 0 {
			t.Fatalf("counts[%d] = %d, want 0 (value above all buckets)", i, h.counts[i])
		}
	}
	if h.count != 1 {
		t.Fatalf("count = %d, want 1 (still counted toward +Inf/total)", h.count)
	}
	if h.sum != 5.0 {
		t.Fatalf("sum = %g, want 5", h.sum)
	}
}

func TestHistogramSumAccumulates(t *testing.T) {
	h := newHistogram(defaultBuckets)
	h.observe(0.002)
	h.observe(0.003)
	if h.count != 2 {
		t.Fatalf("count = %d, want 2", h.count)
	}
	// Float sum; compare with a tolerance.
	if diff := h.sum - 0.005; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("sum = %g, want ~0.005", h.sum)
	}
}

func TestExpositionFormatLines(t *testing.T) {
	reg := NewRegistry()
	reg.Observe("demo", "200", 600*time.Microsecond) // 0.0006s -> > 0.0005, <= 0.001
	reg.Observe("other", "500", 2*time.Second)       // above all buckets

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q, want text/plain...", ct)
	}

	wantLines := []string{
		"# HELP agentpassport_requests_total Total gateway requests by server and status code.",
		"# TYPE agentpassport_requests_total counter",
		`agentpassport_requests_total{server="demo",code="200"} 1`,
		`agentpassport_requests_total{server="other",code="500"} 1`,
		"# HELP agentpassport_request_duration_seconds Gateway request latency.",
		"# TYPE agentpassport_request_duration_seconds histogram",
		`agentpassport_request_duration_seconds_bucket{le="0.0005"} 0`, // 0.0006 not counted here
		`agentpassport_request_duration_seconds_bucket{le="0.001"} 1`,  // 0.0006 counted
		`agentpassport_request_duration_seconds_bucket{le="+Inf"} 2`,   // total
		"agentpassport_request_duration_seconds_count 2",
	}
	for _, want := range wantLines {
		if !strings.Contains(body, want) {
			t.Fatalf("exposition output missing line %q\n---\n%s", want, body)
		}
	}
}

func TestExpositionBucketsSortedAndCumulative(t *testing.T) {
	// Every bucket line must be present once and counts must be monotonically non-decreasing
	// up to +Inf (cumulative histogram invariant).
	reg := NewRegistry()
	for _, d := range []time.Duration{
		300 * time.Microsecond, 700 * time.Microsecond, 3 * time.Millisecond,
		40 * time.Millisecond, 800 * time.Millisecond, 5 * time.Second,
	} {
		reg.Observe("s", "200", d)
	}
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	var last uint64
	for _, b := range defaultBuckets {
		line := bucketLine(strconv.FormatFloat(b, 'g', -1, 64))
		n := bucketCount(t, rec.Body.String(), line)
		if n < last {
			t.Fatalf("bucket le=%v count %d < previous %d (not cumulative)", b, n, last)
		}
		last = n
	}
	inf := bucketCount(t, rec.Body.String(), `agentpassport_request_duration_seconds_bucket{le="+Inf"}`)
	if inf != 6 {
		t.Fatalf("+Inf bucket = %d, want 6", inf)
	}
	if inf < last {
		t.Fatalf("+Inf %d < last finite bucket %d", inf, last)
	}
}

func TestObserveEmptyServerBecomesDash(t *testing.T) {
	reg := NewRegistry()
	reg.Observe("", "200", time.Millisecond)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `agentpassport_requests_total{server="-",code="200"} 1`) {
		t.Fatalf("empty server should be recorded as \"-\":\n%s", rec.Body.String())
	}
}

func TestMiddlewareImplicitOK(t *testing.T) {
	// A handler that only Writes (never calls WriteHeader) implies a 200.
	reg := NewRegistry()
	h := Middleware(reg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("body without explicit status"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil))

	if !metricsContain(t, reg, `agentpassport_requests_total{server="demo",code="200"} 1`) {
		t.Fatal("implicit write must record code 200")
	}
}

func TestMiddlewareExplicitCode(t *testing.T) {
	reg := NewRegistry()
	h := Middleware(reg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil))
	if !metricsContain(t, reg, `agentpassport_requests_total{server="demo",code="418"} 1`) {
		t.Fatal("explicit WriteHeader code must be recorded")
	}
}

func TestMiddlewareFirstWriteHeaderWins(t *testing.T) {
	// statusWriter only captures the first WriteHeader; a later one (which net/http would
	// reject anyway) must not change the recorded status.
	reg := NewRegistry()
	h := Middleware(reg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.WriteHeader(http.StatusOK) // ignored by the wrapper's status tracking
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil))
	if !metricsContain(t, reg, `agentpassport_requests_total{server="demo",code="403"} 1`) {
		t.Fatal("first WriteHeader code must win")
	}
}

func TestMiddlewareNoWriteAtAllIsOK(t *testing.T) {
	// A handler that writes nothing still leaves the default status 200.
	reg := NewRegistry()
	h := Middleware(reg, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil))
	if !metricsContain(t, reg, `agentpassport_requests_total{server="demo",code="200"} 1`) {
		t.Fatal("no write should default to code 200")
	}
}

func TestServerFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/servers/demo/tools/list", "demo"},
		{"/servers/demo", "demo"},  // no trailing path
		{"/servers/demo/", "demo"}, // trailing slash
		{"/servers/x/y", "x"},      // first segment only
		{"/servers/", "-"},         // empty id
		{"/servers", "-"},          // prefix without trailing slash -> not /servers/
		{"/", "-"},                 // root
		{"", "-"},                  // empty
		{"/metrics", "-"},          // unrelated path
		{"/servers//double", "-"},  // empty id before //
	}
	for _, tc := range cases {
		if got := serverFromPath(tc.path); got != tc.want {
			t.Errorf("serverFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestConcurrentObserve hammers Observe and Handler concurrently (run with -race) and
// asserts the final total equals the number of observations.
func TestConcurrentObserve(t *testing.T) {
	reg := NewRegistry()
	const workers = 8
	const iters = 1000

	var wg sync.WaitGroup
	wg.Add(workers + 1)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				reg.Observe("demo", "200", time.Duration(i)*time.Microsecond)
			}
		}()
	}
	// A concurrent scraper to exercise write() under the same lock.
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			rec := httptest.NewRecorder()
			reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}
	}()
	wg.Wait()

	total := workers * iters
	want := bucketLineTotal(total)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, want) {
		t.Fatalf("expected total count line %q after concurrent observes\n%s", want, body[len(body)-200:])
	}
}

// --- helpers ---

func metricsContain(t *testing.T, reg *Registry, want string) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return strings.Contains(rec.Body.String(), want)
}

func bucketLine(le string) string {
	return `agentpassport_request_duration_seconds_bucket{le="` + le + `"}`
}

func bucketLineTotal(n int) string {
	return "agentpassport_request_duration_seconds_count " + itoa(n)
}

func itoa(n int) string { return strconv.Itoa(n) }

// bucketCount finds the line beginning with prefix and parses its trailing integer.
func bucketCount(t *testing.T, body, prefix string) uint64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix+" ") {
			fields := strings.Fields(line)
			n, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
			if err != nil {
				t.Fatalf("parse count in %q: %v", line, err)
			}
			return n
		}
	}
	t.Fatalf("no line with prefix %q in:\n%s", prefix, body)
	return 0
}
