package workload

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// KeyStore caches verified subject public keys so delegation verification (P2-04) can
// resolve the key of each delegating party. Agent keys are added from their workload
// credentials (Add); the root principal's key is added directly (AddKey), pending
// VC-based principal credentials (P2-08). Entries expire with the credential, and an
// expired key is treated as unknown. KeyStore satisfies delegation.KeyRegistry.
type KeyStore struct {
	caPub ed25519.PublicKey
	now   func() time.Time

	mu   sync.RWMutex
	keys map[string]keyEntry
}

type keyEntry struct {
	pub      ed25519.PublicKey
	notAfter time.Time // zero = no expiry (e.g. a directly-added principal key)
}

// NewKeyStore returns a store that verifies added credentials against caPub.
func NewKeyStore(caPub ed25519.PublicKey) *KeyStore {
	return &KeyStore{caPub: caPub, now: time.Now, keys: map[string]keyEntry{}}
}

// Add verifies a workload credential against the CA and caches the agent's key until the
// credential expires. A credential that fails verification is not cached.
func (s *KeyStore) Add(c Credential) error {
	if err := Verify(s.caPub, c, s.now().UTC()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[c.AgentID] = keyEntry{pub: c.PublicKey, notAfter: c.NotAfter}
	return nil
}

// AddKey registers a key for a subject directly (e.g. the root principal). A zero notAfter
// means it does not expire.
func (s *KeyStore) AddKey(id string, pub ed25519.PublicKey, notAfter time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = keyEntry{pub: pub, notAfter: notAfter}
}

// PublicKey implements delegation.KeyRegistry, returning the key only if it has not expired.
func (s *KeyStore) PublicKey(id string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.keys[id]
	if !ok {
		return nil, false
	}
	if !e.notAfter.IsZero() && !s.now().Before(e.notAfter) {
		return nil, false // expired
	}
	return e.pub, true
}
