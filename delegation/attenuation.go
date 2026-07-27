package delegation

import (
	"errors"
	"fmt"
)

// attenuates reports an error if child grants more authority than parent — the
// attenuation-only rule (PRD FR-11, issue P2-05). A hop may only narrow:
//   - tools/servers: a concrete parent set may only be replaced by a subset; a hop may
//     not widen a concrete set back to the wildcard (empty) or add un-granted entries.
//   - expiry: may only move earlier (a bounded parent may not be made unbounded/later).
//   - budget: a bounded parent may only be kept or lowered, same unit.
func attenuates(parent, child Grant) error {
	if err := subset("tools", parent.Tools, child.Tools); err != nil {
		return err
	}
	if err := subset("servers", parent.Servers, child.Servers); err != nil {
		return err
	}
	if !parent.NotAfter.IsZero() {
		if child.NotAfter.IsZero() || child.NotAfter.After(parent.NotAfter) {
			return errors.New("expiry not narrowed")
		}
	}
	if parent.Budget != nil {
		if child.Budget == nil {
			return errors.New("budget constraint removed")
		}
		if child.Budget.Unit != parent.Budget.Unit {
			return fmt.Errorf("budget unit changed %q -> %q", parent.Budget.Unit, child.Budget.Unit)
		}
		if child.Budget.Limit > parent.Budget.Limit {
			return fmt.Errorf("budget raised %d -> %d", parent.Budget.Limit, child.Budget.Limit)
		}
	}
	return nil
}

// subset enforces narrowing for a string set. An empty parent is a wildcard (any child is
// fine). A concrete parent requires a non-empty child whose entries are all in parent.
func subset(name string, parent, child []string) error {
	if len(parent) == 0 {
		return nil
	}
	if len(child) == 0 {
		return fmt.Errorf("%s widened to wildcard", name)
	}
	allowed := make(map[string]struct{}, len(parent))
	for _, p := range parent {
		allowed[p] = struct{}{}
	}
	for _, c := range child {
		if _, ok := allowed[c]; !ok {
			return fmt.Errorf("%s %q not granted by the parent hop", name, c)
		}
	}
	return nil
}
