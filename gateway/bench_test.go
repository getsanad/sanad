package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// BenchmarkProxyPassthrough isolates the gateway's routing + reverse-proxy overhead with
// a minimal (mint-only) pipeline and a local upstream.
func BenchmarkProxyPassthrough(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	reg := NewRegistry()
	u, _ := url.Parse(upstream.URL)
	_ = reg.Register(&Server{ID: "demo", Upstream: u})
	g := &Gateway{Registry: reg, Pipeline: Pipeline{Stages: []Stage{stubMint()}}}

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}
