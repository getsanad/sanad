package revoke

import "slices"

// SyncStore adapts a durable Source (error-returning, e.g. Postgres) to the Store interface
// used by the admin control plane. It is NOT for the gateway hot path — each call hits the
// Source directly — so it belongs to admin operations (revoke/restore/list a handful of
// times), not to per-request decisions, which use a CachedStore.
//
// Store's methods cannot return an error, so a Source failure is reported through OnError
// instead of being silently dropped. On a kill-switch a failed revoke MUST be visible:
// callers should set OnError to log loudly and/or alert. A failed List returns nil (empty),
// which is the safe direction for the admin's read-back — it never invents revocations.
type SyncStore struct {
	src     Source
	OnError func(op, id string, err error)
}

// Compile-time check: SyncStore is a control-plane Store.
var _ Store = (*SyncStore)(nil)

// NewSyncStore adapts src to the Store interface. onError may be nil (errors are then
// dropped — only acceptable in tests); production callers should pass a logging hook.
func NewSyncStore(src Source, onError func(op, id string, err error)) *SyncStore {
	return &SyncStore{src: src, OnError: onError}
}

func (s *SyncStore) report(op, id string, err error) {
	if err != nil && s.OnError != nil {
		s.OnError(op, id, err)
	}
}

// Revoke writes through to the Source, reporting any error via OnError.
func (s *SyncStore) Revoke(id string) { s.report("revoke", id, s.src.Revoke(id)) }

// Restore writes through to the Source, reporting any error via OnError.
func (s *SyncStore) Restore(id string) { s.report("restore", id, s.src.Restore(id)) }

// List returns the revoked ids from the Source, or nil on error (reported via OnError).
func (s *SyncStore) List() []string {
	ids, err := s.src.List()
	if err != nil {
		s.report("list", "", err)
		return nil
	}
	return ids
}

// Revoked reports whether id is on the deny list. It reads through the Source (List), so it
// is for control-plane use only, not the hot path.
func (s *SyncStore) Revoked(id string) bool {
	return slices.Contains(s.List(), id)
}
