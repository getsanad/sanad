package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObserveAndExposition(t *testing.T) {
	reg := NewRegistry()
	reg.Observe("demo", "200", 2*time.Millisecond)
	reg.Observe("demo", "200", 8*time.Millisecond)
	reg.Observe("demo", "403", 1*time.Millisecond)

	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`agentpassport_requests_total{server="demo",code="200"} 2`,
		`agentpassport_requests_total{server="demo",code="403"} 1`,
		`agentpassport_request_duration_seconds_count 3`,
		`agentpassport_request_duration_seconds_bucket{le="+Inf"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q\n---\n%s", want, body)
		}
	}
}

func TestMiddlewareRecords(t *testing.T) {
	reg := NewRegistry()
	h := Middleware(reg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))

	rec2 := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec2.Body.String(), `agentpassport_requests_total{server="demo",code="403"} 1`) {
		t.Fatalf("middleware did not record server/status:\n%s", rec2.Body.String())
	}
}

func TestHistogramCumulative(t *testing.T) {
	h := newHistogram([]float64{0.001, 0.01})
	h.observe(0.0005) // <= both buckets
	h.observe(0.005)  // <= 0.01 only
	h.observe(0.5)    // <= neither bucket, but counts toward total

	if h.counts[0] != 1 {
		t.Fatalf("le=0.001 bucket = %d, want 1", h.counts[0])
	}
	if h.counts[1] != 2 {
		t.Fatalf("le=0.01 bucket = %d, want 2", h.counts[1])
	}
	if h.count != 3 {
		t.Fatalf("total count = %d, want 3", h.count)
	}
}

// TestGaugeSampledAtScrape: a gauge reads its value when scraped, not when registered, so
// a live quantity like the kill-switch snapshot age (NFR-4) is always current.
func TestGaugeSampledAtScrape(t *testing.T) {
	reg := NewRegistry()
	age := 0.0
	reg.SetGauge("agentpassport_revocation_snapshot_age_seconds", "Snapshot age.", func() float64 { return age })

	scrape := func() string {
		rec := httptest.NewRecorder()
		reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}

	body := scrape()
	for _, want := range []string{
		"# TYPE agentpassport_revocation_snapshot_age_seconds gauge",
		"agentpassport_revocation_snapshot_age_seconds 0",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}

	age = 87.5
	if !strings.Contains(scrape(), "agentpassport_revocation_snapshot_age_seconds 87.5") {
		t.Fatalf("gauge not re-sampled at scrape time:\n%s", scrape())
	}

	reg.SetGauge("agentpassport_revocation_snapshot_age_seconds", "", nil)
	if strings.Contains(scrape(), "agentpassport_revocation_snapshot_age_seconds") {
		t.Fatalf("a nil value function should unregister the gauge:\n%s", scrape())
	}
}
