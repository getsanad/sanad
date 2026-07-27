package revoke

import (
	"slices"
	"strings"
)

// SyncStore adapts a durable Source (error-returning, e.g. Postgres) to the Store interface
// used by the admin control plane. It is NOT for the gateway hot path — each call hits the
// Source directly — so it belongs to admin operations (revoke/restore/list a handful of
// times), not to per-request decisions, which use a CachedStore.
//
// A write failure is returned to the caller, so the operator who flipped the kill-switch
// learns that it did not take effect, and is *additionally* reported through OnError, which
// is the alerting hook and the only channel for List — whose signature cannot carry an
// error. A failed List returns nil (empty), which is the safe direction for the admin's
// read-back: it never invents revocations.
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

// report passes err to the alerting hook (if any) and hands it back, so the write methods
// can both alert and return in one line.
func (s *SyncStore) report(op, id string, err error) error {
	if err != nil && s.OnError != nil {
		s.OnError(op, id, err)
	}
	return err
}

// Revoke writes ids through to the Source atomically, returning any error to the caller and
// reporting it via OnError.
func (s *SyncStore) Revoke(ids ...string) error {
	return s.report("revoke", strings.Join(ids, ","), s.src.Revoke(ids...))
}

// Restore writes ids through to the Source atomically, returning any error to the caller and
// reporting it via OnError.
func (s *SyncStore) Restore(ids ...string) error {
	return s.report("restore", strings.Join(ids, ","), s.src.Restore(ids...))
}

// List returns the revoked ids from the Source, or nil on error (reported via OnError).
func (s *SyncStore) List() []string {
	ids, err := s.src.List()
	if err != nil {
		_ = s.report("list", "", err)
		return nil
	}
	return ids
}

// Revoked reports whether id is on the deny list. It reads through the Source (List), so it
// is for control-plane use only, not the hot path.
func (s *SyncStore) Revoked(id string) bool {
	return slices.Contains(s.List(), id)
}
