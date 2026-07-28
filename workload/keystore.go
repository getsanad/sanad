package workload

import (
	"crypto/ed25519"
	"sync"
	"time"
)

// KeyStore caches verified subject public keys so delegation verification (P2-04) can
// resolve the key of each delegating party. It holds TWO SEPARATE NAMESPACES: agent keys,
// which only ever arrive on a CA-verified workload credential (Add), and principal keys,
// which the principal authenticator registers directly from a VC's did:key
// (AddPrincipalKey). Each is read back by its own method — AgentKey, PrincipalKey — so a
// caller has to say which kind of subject it means, and there is no lookup that will answer
// from whichever namespace happens to hold the id.
//
// They are separate maps rather than one map with tagged keys because the two id spaces are
// unrelated and neither is trusted to stay out of the other's way: agent ids are chosen by
// whoever configures the authority, principal ids come from an IdP or a DID document. Sharing
// one flat map made the last writer win, and InstanceStage adds a credential on EVERY
// request — so a credential issued to an agent named after a principal's DID silently
// replaced that principal's root signing key, after which any chain rooted at that principal
// verified against the attacker's key. Split, no agent id can name a principal entry at all,
// whatever it is called. ValidAgentID keeps the two apart to the eye as well.
//
// Entries expire with the credential, and an expired key is treated as unknown. KeyStore
// satisfies delegation.KeyRegistry.
type KeyStore struct {
	caPub ed25519.PublicKey
	now   func() time.Time

	mu         sync.RWMutex
	agents     map[string]keyEntry
	principals map[string]keyEntry
}

type keyEntry struct {
	pub      ed25519.PublicKey
	notAfter time.Time // zero = no expiry (e.g. a directly-added principal key)
}

// NewKeyStore returns a store that verifies added credentials against caPub.
func NewKeyStore(caPub ed25519.PublicKey) *KeyStore {
	return &KeyStore{
		caPub: caPub, now: time.Now,
		agents: map[string]keyEntry{}, principals: map[string]keyEntry{},
	}
}

// Add verifies a workload credential against the CA and caches the agent's key — in the
// AGENT namespace, where it can never be read back as a principal — until the credential
// expires. A credential that fails verification is not cached; Verify also rejects one whose
// agent id is empty or shaped like a principal id, so neither can reach the map.
func (s *KeyStore) Add(c Credential) error {
	if err := Verify(s.caPub, c, s.now().UTC()); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[c.AgentID] = keyEntry{pub: c.PublicKey, notAfter: c.NotAfter}
	return nil
}

// AddPrincipalKey registers a key for a principal directly (the root of a delegation chain),
// in the PRINCIPAL namespace. A zero notAfter means it does not expire. An empty id is
// ignored: nothing may be registered under a key that an unset id would also look up.
func (s *KeyStore) AddPrincipalKey(id string, pub ed25519.PublicKey, notAfter time.Time) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[id] = keyEntry{pub: pub, notAfter: notAfter}
}

// AgentKey implements delegation.KeyRegistry, resolving an agent id against the agent
// namespace only. It returns the key only if it has not expired.
func (s *KeyStore) AgentKey(id string) (ed25519.PublicKey, bool) {
	return s.lookup(s.agents, id)
}

// PrincipalKey implements delegation.KeyRegistry, resolving a principal id against the
// principal namespace only. It returns the key only if it has not expired.
func (s *KeyStore) PrincipalKey(id string) (ed25519.PublicKey, bool) {
	return s.lookup(s.principals, id)
}

// lookup reads one namespace. It never falls back to the other: a miss is a miss, because an
// id resolved in the wrong namespace is exactly the confusion the split exists to prevent.
func (s *KeyStore) lookup(m map[string]keyEntry, id string) (ed25519.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := m[id]
	if !ok {
		return nil, false
	}
	if !e.notAfter.IsZero() && !s.now().Before(e.notAfter) {
		return nil, false // expired
	}
	return e.pub, true
}
