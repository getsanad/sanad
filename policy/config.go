package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Config is the "policy" section of the Sanad configuration document (see the config
// package, which owns the document and its decoding). It is the operator-facing form of an
// AllowList: deny-by-default, per server, with the two namespaces AllowList matches in —
// tools and JSON-RPC methods — named separately so both are expressible.
//
//	"policy": {
//	  "servers": {
//	    "github": {
//	      "note": "read-only research bot",
//	      "allow":  {"methods": ["initialize", "notifications/initialized", "tools/list", "(none)"],
//	                 "tools":   ["search_issues", "get_file"]},
//	      "review": {"tools": ["create_issue"]}
//	    }
//	  }
//	}
//
// Rules are grouped by EFFECT first (allow / review) because that is the question an operator
// is answering — what may this agent do here, and what needs a human — and within an effect by
// what the entry matches on. "*" in either list is the wildcard for that namespace only, so a
// tool wildcard cannot accidentally authorize the protocol traffic around it, or vice versa.
//
// The section is deliberately self-contained: it names nothing outside itself, so it drops
// unchanged into a broader sanad.yaml alongside sections for servers, principal mode, TTLs
// and storage.
type Config struct {
	// Note is free-form prose. JSON has no comments, so every object an operator would want
	// to annotate carries one; it is validated as a string, logged at startup, and otherwise
	// ignored. Unknown fields are rejected (see config.Parse), so this is the place for prose
	// and a misspelled key is an error rather than a silently dropped rule.
	Note    string                 `json:"note,omitempty"`
	Servers map[string]ServerRules `json:"servers"`
}

// ServerRules is one protected server's policy. A server absent from the map is denied
// entirely, as is any action not listed here.
type ServerRules struct {
	Note   string `json:"note,omitempty"`
	Allow  Rules  `json:"allow,omitempty"`
	Review Rules  `json:"review,omitempty"`
}

// Rules are the entries of one effect, split by the namespace they match in. Methods are
// matched against the JSON-RPC method of any message that names no tool (plus "(none)" for a
// request carrying no JSON-RPC call at all); Tools are matched against the params.name of a
// tools/call.
type Rules struct {
	Methods []string `json:"methods,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

func (r Rules) empty() bool { return len(r.Methods) == 0 && len(r.Tools) == 0 }

// Validate reports the first problem that would make this policy mean something other than
// what it reads as. Every message names the offending entry: a policy file is edited by hand
// under time pressure, and the failure mode of a silently misread one is an outage or an open
// door, so a broken file must stop startup rather than start a gateway on a policy nobody wrote.
func (c *Config) Validate() error {
	if c == nil || len(c.Servers) == 0 {
		return errors.New(`policy: no servers configured: "policy.servers" is empty, so every request would be denied; ` +
			`list the servers you mean to authorize (or unset the config file to run deny-by-default deliberately)`)
	}

	for _, id := range sortedIDs(c.Servers) {
		s := c.Servers[id]
		if strings.TrimSpace(id) == "" {
			return errors.New(`policy: servers: a server id is empty; keys under "servers" must match a registered server id`)
		}
		if strings.TrimSpace(id) != id {
			return fmt.Errorf("policy: server %q: server ids must not have leading or trailing whitespace (it would never match a registered server)", id)
		}
		if s.Allow.empty() && s.Review.empty() {
			return fmt.Errorf("policy: server %q: no rules: give it at least one allow or review entry, or remove it "+
				"(as written it denies everything, which is already the default for a server that is absent)", id)
		}

		for _, list := range s.lists() {
			if err := list.validate(id); err != nil {
				return err
			}
		}
		if err := bothSides(id, "tools", s.Allow.Tools, s.Review.Tools); err != nil {
			return err
		}
		if err := bothSides(id, "methods", s.Allow.Methods, s.Review.Methods); err != nil {
			return err
		}
	}
	return nil
}

// namedList is one of the four entry lists of a server, carrying the path an operator would
// have to look at ("allow.tools") so an error can point straight at it.
type namedList struct {
	field   string
	entries []string
}

func (s ServerRules) lists() []namedList {
	return []namedList{
		{"allow.methods", s.Allow.Methods}, {"allow.tools", s.Allow.Tools},
		{"review.methods", s.Review.Methods}, {"review.tools", s.Review.Tools},
	}
}

func (l namedList) validate(server string) error {
	seen := map[string]struct{}{}
	for i, e := range l.entries {
		switch {
		case e == "":
			return fmt.Errorf("policy: server %q: %s[%d] is empty; every entry must name something (or %q for any)",
				server, l.field, i, Wildcard)
		case strings.TrimSpace(e) != e:
			return fmt.Errorf("policy: server %q: %s[%d] = %q has leading or trailing whitespace; it would never match",
				server, l.field, i, e)
		}
		if _, dup := seen[e]; dup {
			return fmt.Errorf("policy: server %q: %s lists %q twice; remove the duplicate", server, l.field, e)
		}
		seen[e] = struct{}{}
	}
	return nil
}

// bothSides rejects a name listed as both allowed and needing review. AllowList resolves it
// (review wins), but silently: the operator wrote two rules and only one of them means
// anything, and which one is not obvious from the file.
func bothSides(server, namespace string, allow, review []string) error {
	inReview := make(map[string]struct{}, len(review))
	for _, r := range review {
		inReview[r] = struct{}{}
	}
	for _, a := range allow {
		if _, ok := inReview[a]; ok {
			return fmt.Errorf("policy: server %q: %q is in both allow.%s and review.%s; keep it in exactly one "+
				"(review would win, which is probably not what the allow entry was meant to say)", server, a, namespace, namespace)
		}
	}
	return nil
}

// Warnings are configurations that are legal, and load, but are very likely not what the
// operator meant. They are reported rather than rejected because each has a legitimate
// reading — the gateway may front something that is not an MCP server at all.
func (c *Config) Warnings() []string {
	if c == nil {
		return nil
	}
	var out []string
	for _, id := range sortedIDs(c.Servers) {
		s := c.Servers[id]
		hasMethods := len(s.Allow.Methods)+len(s.Review.Methods) > 0
		hasTools := len(s.Allow.Tools)+len(s.Review.Tools) > 0
		if hasTools && !hasMethods {
			out = append(out, fmt.Sprintf(`server %q lists tools but no methods: an MCP client POSTs "initialize" `+
				`and "tools/list" before it can call anything, and opens its event stream with a bodyless GET — all `+
				`decided as methods — so every session to it will be denied. Add e.g. `+
				`"methods": ["initialize", "notifications/initialized", "tools/list", %q]`, id, MethodNone))
		}
	}
	return out
}

// AllowList compiles the section into the PDP the gateway runs. Validate first: this does no
// checking of its own, so an unvalidated config compiles to an allowlist that quietly means
// something else.
func (c *Config) AllowList() *AllowList {
	al := NewAllowList()
	if c == nil {
		return al
	}
	for id, s := range c.Servers {
		al.Allow(id, s.Allow.Tools...)
		al.AllowMethods(id, s.Allow.Methods...)
		al.Review(id, s.Review.Tools...)
		al.ReviewMethods(id, s.Review.Methods...)
	}
	return al
}

// ServerIDs returns the configured server ids in a stable order, so a caller can cross-check
// them against the servers actually registered and log deterministically.
func (c *Config) ServerIDs() []string {
	if c == nil {
		return nil
	}
	return sortedIDs(c.Servers)
}

func sortedIDs(m map[string]ServerRules) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
