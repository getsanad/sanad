package gateway

import (
	"errors"
	"net/http/httputil"
	"sync"
)

// Registry holds the protected MCP servers the gateway will proxy to. Lookups are
// concurrency-safe so the registry can be updated by the control plane while serving.
type Registry struct {
	mu      sync.RWMutex
	servers map[string]*Server
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{servers: make(map[string]*Server)}
}

// Register validates and stores a server, building its reverse proxy. It applies
// defaults (standard tier, streamable HTTP) and returns an error for invalid input.
func (r *Registry) Register(s *Server) error {
	if s == nil || s.ID == "" {
		return errors.New("gateway: server must have an ID")
	}
	if s.Upstream == nil {
		return errors.New("gateway: server " + s.ID + " has no upstream URL")
	}
	if s.Transport == "" {
		s.Transport = TransportHTTP
	}
	if s.Tier == "" {
		s.Tier = TierStandard
	}

	p := httputil.NewSingleHostReverseProxy(s.Upstream)
	// Flush immediately so SSE / streamable-HTTP responses are not buffered.
	p.FlushInterval = -1
	s.proxy = p

	r.mu.Lock()
	defer r.mu.Unlock()
	r.servers[s.ID] = s
	return nil
}

// Lookup returns the registered server for id, if any.
func (r *Registry) Lookup(id string) (*Server, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.servers[id]
	return s, ok
}
