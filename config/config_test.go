package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
	"github.com/getsanad/sanad/tooldefs"
)

// A realistic policy file, comments and all — "note" being where the comments go, since JSON
// has none and a rule nobody can explain is a rule nobody dares delete.
const example = `{
  "version": 1,
  "note": "production policy, owned by #security",
  "policy": {
    "servers": {
      "github": {
        "note": "read-only research bot; issue creation needs a human",
        "allow":  {"methods": ["initialize", "notifications/initialized", "tools/list", "(none)"],
                   "tools":   ["search_issues", "get_file"]},
        "review": {"tools": ["create_issue"]}
      }
    }
  }
}`

// TestLoadProducesAWorkingAllowList: a file on disk becomes the PDP the gateway runs, which is
// the entire point — before this, configuring authorization meant editing Go and recompiling.
func TestLoadProducesAWorkingAllowList(t *testing.T) {
	path := write(t, "policy.json", example)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if file.Note == "" || file.Policy.Servers["github"].Note == "" {
		t.Fatal("notes are parsed, not dropped: they are how a JSON policy file carries comments")
	}

	al := file.Policy.AllowList()
	ctx := context.Background()
	cases := []struct {
		name         string
		method, tool string
		want         types.Effect
	}{
		{"listed tool", "tools/call", "search_issues", types.EffectAllow},
		{"unlisted tool", "tools/call", "delete_repo", types.EffectDeny},
		{"listed method", "tools/list", "", types.EffectAllow},
		{"unlisted method", "resources/read", "", types.EffectDeny},
		{"reviewed tool", "tools/call", "create_issue", types.EffectReview},
		{"no json-rpc call at all", policy.MethodNone, "", types.EffectAllow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := al.Evaluate(ctx, policy.Input{Server: "github", Method: tc.method, Tool: tc.tool})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if d.Effect != tc.want {
				t.Fatalf("effect = %s, want %s (%s)", d.Effect, tc.want, d.Reason)
			}
		})
	}
}

// TestParseRejectsBrokenDocuments: every one of these must stop startup, and say enough that an
// operator can fix the file without reading the source.
func TestParseRejectsBrokenDocuments(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{
			name: "malformed json names the line",
			doc:  "{\n  \"version\": 1,\n  \"policy\": {\n}\n",
			want: []string{"line "},
		},
		{
			name: "unknown field names the field",
			doc:  `{"version":1,"policy":{"servers":{"github":{"allow":{"tool":["read"]}}}}}`,
			want: []string{`unknown field "tool"`},
		},
		{
			name: "unknown top-level section",
			doc:  `{"version":1,"policy":{"servers":{"a":{"allow":{"tools":["read"]}}}},"policies":{}}`,
			want: []string{`unknown field "policies"`},
		},
		{
			name: "wrong type names the field and the line",
			doc:  "{\n\"version\": 1,\n\"policy\": {\"servers\": {\"github\": {\"allow\": {\"tools\": \"read\"}}}}\n}",
			want: []string{"line ", "allow.tools", "must be a"},
		},
		{
			name: "missing version",
			doc:  `{"policy":{"servers":{"a":{"allow":{"tools":["read"]}}}}}`,
			want: []string{`missing "version"`},
		},
		{
			name: "future version",
			doc:  `{"version":99,"policy":{"servers":{"a":{"allow":{"tools":["read"]}}}}}`,
			want: []string{"version 99 is not supported", "version 1"},
		},
		{
			name: "no policy section",
			doc:  `{"version":1}`,
			want: []string{`no "policy" section`},
		},
		{
			name: "policy validation errors surface with the file name",
			doc:  `{"version":1,"policy":{"servers":{"github":{"allow":{"tools":["read",""]}}}}}`,
			want: []string{"config test.json", `server "github"`, "allow.tools[1]"},
		},
		{
			name: "trailing content",
			doc:  `{"version":1,"policy":{"servers":{"a":{"allow":{"tools":["read"]}}}}} {"version":1}`,
			want: []string{"trailing content"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc), "test.json")
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestLoadMissingFileIsAStartupError: pointing PASSPORT_POLICY_FILE at nothing must not
// degrade to "no policy" — that would silently swap the operator's rules for a deny-all (or,
// read the other way, leave them wondering why nothing works).
func TestLoadMissingFileIsAStartupError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing policy file must be an error")
	}
	if !strings.Contains(err.Error(), "absent.json") {
		t.Fatalf("error %q does not name the missing file", err)
	}
}

// TestParseSurfacesWarningsWithoutFailing: a legal-but-suspicious policy loads, so the gateway
// starts, and says what is likely wrong.
func TestParseSurfacesWarningsWithoutFailing(t *testing.T) {
	file, err := Parse([]byte(`{"version":1,"policy":{"servers":{"github":{"allow":{"tools":["read"]}}}}}`), "test.json")
	if err != nil {
		t.Fatalf("this file is legal and must load: %v", err)
	}
	if w := file.Policy.Warnings(); len(w) != 1 {
		t.Fatalf("warnings = %v, want one about the missing methods", w)
	}
}

// --- the tooldefs section (SEC-3) -----------------------------------------------------

// TestToolDefsSectionLoads: pins arrive through the SAME versioned, sectioned document as the
// policy rules, decoded by the same strict decoder — not through a second configuration
// mechanism an operator has to learn and a deployment has to mount separately.
func TestToolDefsSectionLoads(t *testing.T) {
	path := write(t, "config.json", `{
	  "version": 1,
	  "policy": {"servers": {"github": {"allow": {"methods": ["tools/list"], "tools": ["read"]}}}},
	  "tooldefs": {
	    "note": "pins reviewed with each vendor release",
	    "servers": {
	      "github":  {"note": "approved 2026-07-01 by @security", "fingerprint": "sha256:`+strings.Repeat("ab", 32)+`"},
	      "staging": {"on_drift": "warn", "fingerprint": "sha256:`+strings.Repeat("cd", 32)+`"}
	    }
	  }
	}`)

	file, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if file.Tooldefs == nil {
		t.Fatal("the tooldefs section was dropped")
	}
	if file.Tooldefs.Note == "" || file.Tooldefs.Servers["github"].Note == "" {
		t.Fatal("notes are parsed, not dropped: a bare 64-hex pin is the least self-explanatory thing in the file")
	}
	if got := file.Tooldefs.Mode("github"); got != tooldefs.ModeDeny {
		t.Fatalf("github on_drift = %q, want the deny default", got)
	}
	if got := file.Tooldefs.Mode("staging"); got != tooldefs.ModeWarn {
		t.Fatalf("staging on_drift = %q, want the per-server override", got)
	}

	guard, err := file.Tooldefs.Guard()
	if err != nil || guard == nil {
		t.Fatalf("the section must compile into the runtime check: %v", err)
	}
	if !guard.Watches("github") || guard.Watches("elsewhere") {
		t.Fatal("the guard watches exactly the servers the file names")
	}
}

// TestToolDefsSectionIsOptional: absent means the check is off, which is a legal deployment —
// unlike an absent policy section, which is a mistake.
func TestToolDefsSectionIsOptional(t *testing.T) {
	file, err := Parse([]byte(example), "test.json")
	if err != nil {
		t.Fatalf("a document with no tooldefs section must load: %v", err)
	}
	if file.Tooldefs != nil {
		t.Fatal("an absent section must stay absent, not become an empty one")
	}
	guard, err := file.Tooldefs.Guard()
	if err != nil || guard != nil {
		t.Fatalf("no section, no guard: %v (%v)", guard, err)
	}
}

// TestToolDefsSectionValidatesWithTheFileName: a pin an operator mistyped must stop startup
// pointing at the file and the entry, exactly like a broken policy rule.
func TestToolDefsSectionValidatesWithTheFileName(t *testing.T) {
	policySection := `"policy":{"servers":{"github":{"allow":{"tools":["read"]}}}}`
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{
			name: "mistyped fingerprint",
			doc:  `{"version":1,` + policySection + `,"tooldefs":{"servers":{"github":{"fingerprint":"sha256:oops"}}}}`,
			want: []string{"config test.json", `server "github"`, "hex"},
		},
		{
			name: "truncated fingerprint",
			doc:  `{"version":1,` + policySection + `,"tooldefs":{"servers":{"github":{"fingerprint":"sha256:abcdef"}}}}`,
			want: []string{"config test.json", `server "github"`, "64 hex characters"},
		},
		{
			name: "unknown failure mode",
			doc:  `{"version":1,` + policySection + `,"tooldefs":{"servers":{"github":{"on_drift":"page-me"}}}}`,
			want: []string{"config test.json", "on_drift", `"deny"`},
		},
		{
			name: "present but empty",
			doc:  `{"version":1,` + policySection + `,"tooldefs":{"servers":{}}}`,
			want: []string{"no servers configured"},
		},
		{
			name: "misspelled key inside the section",
			doc:  `{"version":1,` + policySection + `,"tooldefs":{"servers":{"github":{"fingerprints":"sha256:x"}}}}`,
			want: []string{`unknown field "fingerprints"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc), "test.json")
			if err == nil {
				t.Fatal("want an error, got nil")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
