package tooldefs

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Mode is what the gateway does when a pinned server's tool definitions drift.
type Mode string

const (
	// ModeDeny refuses the drifted tools/list response and quarantines the server. It is the
	// default; see Config for why, and for when it is the wrong choice.
	ModeDeny Mode = "deny"
	// ModeWarn records and alerts but forwards everything. It is for the period between
	// noticing that a server changes legitimately and getting its releases under control.
	ModeWarn Mode = "warn"
)

// DefaultMode is what a pinned server with no explicit on_drift gets.
const DefaultMode = ModeDeny

// Config is the "tooldefs" section of the Sanad configuration document (see the config
// package, which owns the document and its decoding). It pins the tool surface each protected
// server is approved to advertise, which is the defence against tool-definition drift — a
// server that gets approved with a benign tool and later rewrites that tool's description or
// schema into an instruction to the model (PRD SEC-3).
//
//	"tooldefs": {
//	  "note": "pins reviewed with each vendor release; see runbook/mcp-pins.md",
//	  "servers": {
//	    "github": {
//	      "note": "approved 2026-07-01 by @security (github-mcp v1.4.2)",
//	      "fingerprint": "sha256:9f2b…"
//	    },
//	    "internal-wiki": {
//	      "note": "ships continuously; alert only until releases are cut properly",
//	      "on_drift": "warn"
//	    }
//	  }
//	}
//
// A server absent from this section is not inspected at all — no response is buffered, nothing
// is compared. Pinning is opt-in per server, and so the whole feature is inert until an
// operator opts in, which is why an absent section is legal where an absent "policy" section is
// an error: an unpinned server is a server whose tools nobody has approved yet, not a server
// nobody may reach.
//
// FAILURE MODE. The default is "deny", and it is deliberately a different judgement from the
// deny-by-default everywhere else in the system. Elsewhere the default applies to something
// nobody configured; here it applies only to a server an operator went out of their way to pin,
// having decided that this tool surface and no other is approved. Honouring that literally is
// the only reading that makes the pin worth writing — a pin that merely logs is a pin an
// attacker can ignore. The cost is real and is bounded on purpose: a false positive (a
// legitimate vendor release that adds a tool) takes out ONE server, the quarantine still lets
// initialize/tools/list through so a rolled-back server heals itself on the next list, and
// "on_drift": "warn" is one line, settable for the whole section or for a single server.
type Config struct {
	// Note is free-form prose. JSON has no comments, and a fingerprint is the single most
	// opaque thing an operator will ever write into a config file — 64 hex characters that say
	// nothing about which release they were taken from — so the place to record that is here.
	Note string `json:"note,omitempty"`
	// OnDrift is the section-wide default, overridable per server. Empty means DefaultMode.
	OnDrift Mode                 `json:"on_drift,omitempty"`
	Servers map[string]ServerPin `json:"servers"`
}

// ServerPin is one protected server's approved tool surface.
type ServerPin struct {
	Note string `json:"note,omitempty"`
	// Fingerprint is the approved digest, "sha256:<hex>", of the server's canonical tool
	// definitions (see Canonical). EMPTY is legal and means "watch but do not enforce": the
	// gateway fingerprints what the server advertises and reports it, so an operator can copy
	// the value into this field. That is how a pin is obtained in the first place — the
	// alternative is asking an operator to compute a digest over a canonicalization only this
	// package implements.
	Fingerprint string `json:"fingerprint,omitempty"`
	// OnDrift overrides the section default for this server.
	OnDrift Mode `json:"on_drift,omitempty"`
}

// Validate reports the first problem that would make this section mean something other than
// what it reads as. Like the policy section, a broken one stops startup: a gateway running on
// a pin nobody wrote is worse than one that did not start.
func (c *Config) Validate() error {
	if c == nil {
		return nil // an absent section is the feature being off, which is legal
	}
	if len(c.Servers) == 0 {
		return errors.New(`tooldefs: no servers configured: "tooldefs.servers" is empty, so nothing would be pinned; ` +
			`list the servers whose tool definitions you have approved (or remove the section)`)
	}
	if err := c.OnDrift.validate("tooldefs.on_drift"); err != nil {
		return err
	}
	for _, id := range c.ServerIDs() {
		p := c.Servers[id]
		switch {
		case strings.TrimSpace(id) == "":
			return errors.New(`tooldefs: servers: a server id is empty; keys under "servers" must match a registered server id`)
		case strings.TrimSpace(id) != id:
			return fmt.Errorf("tooldefs: server %q: server ids must not have leading or trailing whitespace (it would never match a registered server)", id)
		}
		if err := p.OnDrift.validate(fmt.Sprintf("tooldefs: server %q: on_drift", id)); err != nil {
			return err
		}
		if p.Fingerprint != "" {
			if _, err := ParseFingerprint(p.Fingerprint); err != nil {
				return fmt.Errorf("tooldefs: server %q: %w", id, err)
			}
		}
	}
	return nil
}

func (m Mode) validate(field string) error {
	switch m {
	case "", ModeDeny, ModeWarn:
		return nil
	default:
		return fmt.Errorf("%s = %q: must be %q or %q", field, m, ModeDeny, ModeWarn)
	}
}

// Warnings are configurations that load and run but are probably not what the operator meant.
func (c *Config) Warnings() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, id := range c.ServerIDs() {
		p := c.Servers[id]
		if p.Fingerprint != "" {
			continue
		}
		out = append(out, fmt.Sprintf("server %q has no \"fingerprint\": its tool definitions are watched and reported "+
			"but NOT enforced. The gateway logs the fingerprint it observes on the next tools/list; paste that value in to pin it", id))
		if p.OnDrift != "" {
			out = append(out, fmt.Sprintf("server %q sets on_drift=%q but has no \"fingerprint\", so nothing can drift and the setting has no effect", id, p.OnDrift))
		}
	}
	return out
}

// ServerIDs returns the configured server ids in a stable order, so a caller can cross-check
// them against the servers actually registered and log deterministically.
func (c *Config) ServerIDs() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Servers))
	for id := range c.Servers {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Mode returns the effective failure mode for a server: its own override, else the section
// default, else DefaultMode.
func (c *Config) Mode(server string) Mode {
	p, ok := c.Servers[server]
	switch {
	case ok && p.OnDrift != "":
		return p.OnDrift
	case c.OnDrift != "":
		return c.OnDrift
	default:
		return DefaultMode
	}
}

// Guard compiles the section into the runtime check the gateway runs. Validate first: this
// re-checks the fingerprints (it has to parse them) but nothing else.
func (c *Config) Guard() (*Guard, error) {
	if c == nil {
		return nil, nil // the feature is off
	}
	g := newGuard()
	for id, p := range c.Servers {
		w := watch{mode: c.Mode(id)}
		if p.Fingerprint != "" {
			f, err := ParseFingerprint(p.Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("tooldefs: server %q: %w", id, err)
			}
			g.approved.Pin(id, f)
			w.pinned = true
		}
		g.watched[id] = w
	}
	return g, nil
}
