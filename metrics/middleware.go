package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Middleware wraps a handler to record each request's target server, status code, and
// latency into the registry. It is transport-only and decoupled from the gateway's
// internals, so it composes with any http.Handler.
func Middleware(reg *Registry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		reg.Observe(serverFromPath(r.URL.Path), strconv.Itoa(sw.status), time.Since(start))
	})
}

// serverFromPath extracts the protected-server id from /servers/{id}/... ("-" otherwise).
func serverFromPath(p string) string {
	rest := strings.TrimPrefix(p, "/servers/")
	if rest == p {
		return "-"
	}
	id, _, _ := strings.Cut(rest, "/")
	if id == "" {
		return "-"
	}
	return id
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true // an implicit 200 if WriteHeader was never called
	return s.ResponseWriter.Write(b)
}

// Flush propagates flushes so streaming (SSE) still works through the wrapper.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
