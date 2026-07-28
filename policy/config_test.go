package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/getsanad/sanad/pkg/types"
)

// cfg is a small helper for building a policy section in tests.
func cfg(servers map[string]ServerRules) *Config { return &Config{Servers: servers} }

// TestConfigCompilesToAWorkingAllowList is the property the whole file exists for: what an
// operator writes decides what the gateway permits, without anyone recompiling Go.
func TestConfigCompilesToAWorkingAllowList(t *testing.T) {
	c := cfg(map[string]ServerRules{
		"github": {
			Note:   "read-only research bot",
			Allow:  Rules{Methods: []string{"initialize", "tools/list"}, Tools: []string{"search_issues"}},
			Review: Rules{Tools: []string{"create_issue"}},
		},
		"payments": {
			Allow:  Rules{Methods: []string{Wildcard}},
			Review: Rules{Tools: []string{Wildcard}},
		},
	})
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	al := c.AllowList()

	cases := []struct {
		name           string
		server         string
		method, tool   string
		want           types.Effect
		wantReasonPart string
	}{
		{"listed tool allowed", "github", "tools/call", "search_issues", types.EffectAllow, `tool "search_issues"`},
		{"unlisted tool denied", "github", "tools/call", "delete_repo", types.EffectDeny, "not allowlisted"},
		{"listed method allowed", "github", "tools/list", "", types.EffectAllow, `method "tools/list"`},
		{"unlisted method denied", "github", "resources/read", "", types.EffectDeny, "not allowlisted"},
		{"reviewed tool held", "github", "tools/call", "create_issue", types.EffectReview, "requires approval"},
		{"unknown server denied", "gitlab", "tools/list", "", types.EffectDeny, "no policy for server"},
		{"method wildcard", "payments", "initialize", "", types.EffectAllow, "wildcard"},
		{"tool wildcard under review", "payments", "tools/call", "transfer", types.EffectReview, "wildcard"},
		// The namespaces do not leak into each other: payments' method wildcard permits the
		// protocol traffic and NOT the calls, which is the whole point of splitting them.
		{"tool not covered by the method wildcard", "github", "tools/call", "anything", types.EffectDeny, "not allowlisted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := al.Evaluate(context.Background(), Input{Server: tc.server, Method: tc.method, Tool: tc.tool})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if d.Effect != tc.want {
				t.Fatalf("effect = %s, want %s (reason %q)", d.Effect, tc.want, d.Reason)
			}
			if !strings.Contains(d.Reason, tc.wantReasonPart) {
				t.Fatalf("reason %q does not mention %q", d.Reason, tc.wantReasonPart)
			}
		})
	}
}

// TestConfigMethodGatingSeparatesListFromCall is the case that could not be expressed while
// the PDP saw only the tool: let an agent SEE the tools, let a human decide before it runs one.
func TestConfigMethodGatingSeparatesListFromCall(t *testing.T) {
	c := cfg(map[string]ServerRules{"github": {
		Allow: Rules{Methods: []string{"initialize", "tools/list", MethodNone}},
	}})
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	al := c.AllowList()
	ctx := context.Background()

	if d, _ := al.Evaluate(ctx, Input{Server: "github", Method: "tools/list"}); !d.Allowed() {
		t.Fatalf("tools/list must be allowed: %+v", d)
	}
	if d, _ := al.Evaluate(ctx, Input{Server: "github", Method: MethodNone}); !d.Allowed() {
		t.Fatalf("a request with no JSON-RPC call must be allowed by its %q entry: %+v", MethodNone, d)
	}
	if d, _ := al.Evaluate(ctx, Input{Server: "github", Method: "tools/call", Tool: "search_issues"}); d.Allowed() {
		t.Fatal("no tool is allowlisted, so every tools/call must be denied")
	}
}

// TestConfigValidateNamesTheOffendingEntry: a policy file is edited by hand, so a broken one
// must fail startup with a message that points at the line to fix — not at "invalid config".
func TestConfigValidateNamesTheOffendingEntry(t *testing.T) {
	cases := []struct {
		name string
		c    *Config
		want []string // fragments the message must contain
	}{
		{
			name: "no servers",
			c:    cfg(nil),
			want: []string{"no servers configured"},
		},
		{
			name: "server with no rules",
			c:    cfg(map[string]ServerRules{"github": {Note: "todo"}}),
			want: []string{`server "github"`, "no rules"},
		},
		{
			name: "empty entry",
			c:    cfg(map[string]ServerRules{"github": {Allow: Rules{Tools: []string{"read", ""}}}}),
			want: []string{`server "github"`, "allow.tools[1]", "empty"},
		},
		{
			name: "padded entry never matches",
			c:    cfg(map[string]ServerRules{"github": {Allow: Rules{Methods: []string{" tools/list"}}}}),
			want: []string{`server "github"`, "allow.methods[0]", "whitespace"},
		},
		{
			name: "duplicate entry",
			c:    cfg(map[string]ServerRules{"github": {Allow: Rules{Tools: []string{"read", "read"}}}}),
			want: []string{`server "github"`, "allow.tools", `"read" twice`},
		},
		{
			name: "allowed and reviewed at once",
			c: cfg(map[string]ServerRules{"github": {
				Allow:  Rules{Tools: []string{"transfer"}},
				Review: Rules{Tools: []string{"transfer"}},
			}}),
			want: []string{`server "github"`, `"transfer"`, "allow.tools", "review.tools"},
		},
		{
			name: "padded server id",
			c:    cfg(map[string]ServerRules{" github": {Allow: Rules{Tools: []string{"read"}}}}),
			want: []string{`" github"`, "whitespace"},
		},
		{
			name: "empty server id",
			c:    cfg(map[string]ServerRules{"": {Allow: Rules{Tools: []string{"read"}}}}),
			want: []string{"server id is empty"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if err == nil {
				t.Fatal("want a validation error, got nil")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}

	// A nil section is the same failure as an empty one, not a panic.
	if err := (*Config)(nil).Validate(); err == nil {
		t.Fatal("a nil policy section must not validate")
	}
}

// TestConfigWarnsAboutToolsWithoutMethods: a policy that lists only tools is legal but breaks
// every MCP session, because the handshake around the call is decided too. That is a footgun
// worth naming at startup rather than debugging from a 403.
func TestConfigWarnsAboutToolsWithoutMethods(t *testing.T) {
	c := cfg(map[string]ServerRules{"github": {Allow: Rules{Tools: []string{"read"}}}})
	if err := c.Validate(); err != nil {
		t.Fatalf("this configuration is legal: %v", err)
	}
	w := c.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], `server "github"`) || !strings.Contains(w[0], "initialize") {
		t.Fatalf("warnings = %v, want one naming the server and the methods to add", w)
	}

	// Once the methods are there, silence.
	c.Servers["github"] = ServerRules{Allow: Rules{Methods: []string{"initialize"}, Tools: []string{"read"}}}
	if w := c.Warnings(); len(w) != 0 {
		t.Fatalf("warnings = %v, want none", w)
	}
}

func TestConfigServerIDsAreSorted(t *testing.T) {
	c := cfg(map[string]ServerRules{
		"zulu":  {Allow: Rules{Tools: []string{"read"}}},
		"alpha": {Allow: Rules{Tools: []string{"read"}}},
	})
	got := c.ServerIDs()
	if len(got) != 2 || got[0] != "alpha" || got[1] != "zulu" {
		t.Fatalf("ServerIDs = %v, want [alpha zulu]", got)
	}
}

// TestAllowListPrecedence pins the resolution order: the most specific entry wins, and a tie
// goes to the safer effect. An operator writing "allow *, review transfer" means exactly that.
func TestAllowListPrecedence(t *testing.T) {
	al := NewAllowList().
		Allow("s", Wildcard, "read").
		Review("s", "transfer").
		AllowMethods("s", "tools/list").
		ReviewMethods("s", Wildcard)
	ctx := context.Background()

	cases := []struct {
		method, tool string
		want         types.Effect
	}{
		{"tools/call", "read", types.EffectAllow},      // exact allow
		{"tools/call", "transfer", types.EffectReview}, // exact review beats the allow wildcard
		{"tools/call", "other", types.EffectAllow},     // allow wildcard
		{"tools/list", "", types.EffectAllow},          // exact allow beats the review wildcard
		{"initialize", "", types.EffectReview},         // review wildcard
	}
	for _, tc := range cases {
		d, _ := al.Evaluate(ctx, Input{Server: "s", Method: tc.method, Tool: tc.tool})
		if d.Effect != tc.want {
			t.Errorf("{%s %s} = %s, want %s (%s)", tc.method, tc.tool, d.Effect, tc.want, d.Reason)
		}
	}
}
