// Package metrics provides lightweight, dependency-free observability for the gateway
// (PRD FR-28): request volume by server and status, and a request-latency histogram to
// track the NFR-1 budget (p95 added latency ≤ ~50ms common path). Output is in the
// Prometheus text exposition format, so it scrapes with standard tooling.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// defaultBuckets are cumulative latency upper bounds in seconds, spanning the
// microsecond compute path up to slow network calls.
var defaultBuckets = []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1}

type reqKey struct {
	server string
	code   string
}

// Registry holds the gateway's metrics. It is safe for concurrent use.
type Registry struct {
	mu       sync.Mutex
	requests map[reqKey]uint64
	hist     histogram
}

// NewRegistry returns an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		requests: map[reqKey]uint64{},
		hist:     newHistogram(defaultBuckets),
	}
}

// Observe records one served request: its target server, HTTP status, and duration.
func (r *Registry) Observe(server, code string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if server == "" {
		server = "-"
	}
	r.requests[reqKey{server, code}]++
	r.hist.observe(d.Seconds())
}

// Handler serves the metrics in Prometheus text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.write(w)
	})
}

func (r *Registry) write(w http.ResponseWriter) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintln(w, "# HELP agentpassport_requests_total Total gateway requests by server and status code.")
	fmt.Fprintln(w, "# TYPE agentpassport_requests_total counter")
	keys := make([]reqKey, 0, len(r.requests))
	for k := range r.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].server != keys[j].server {
			return keys[i].server < keys[j].server
		}
		return keys[i].code < keys[j].code
	})
	for _, k := range keys {
		fmt.Fprintf(w, "agentpassport_requests_total{server=%q,code=%q} %d\n", k.server, k.code, r.requests[k])
	}

	fmt.Fprintln(w, "# HELP agentpassport_request_duration_seconds Gateway request latency.")
	fmt.Fprintln(w, "# TYPE agentpassport_request_duration_seconds histogram")
	for i, b := range r.hist.buckets {
		fmt.Fprintf(w, "agentpassport_request_duration_seconds_bucket{le=%q} %d\n",
			strconv.FormatFloat(b, 'g', -1, 64), r.hist.counts[i])
	}
	fmt.Fprintf(w, "agentpassport_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", r.hist.count)
	fmt.Fprintf(w, "agentpassport_request_duration_seconds_sum %g\n", r.hist.sum)
	fmt.Fprintf(w, "agentpassport_request_duration_seconds_count %d\n", r.hist.count)
}

// histogram tracks cumulative bucket counts plus sum/count.
type histogram struct {
	buckets []float64
	counts  []uint64 // counts[i] = observations <= buckets[i]
	sum     float64
	count   uint64
}

func newHistogram(buckets []float64) histogram {
	return histogram{buckets: buckets, counts: make([]uint64, len(buckets))}
}

func (h *histogram) observe(v float64) {
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
	h.sum += v
	h.count++
}
