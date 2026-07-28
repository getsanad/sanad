package tooldefs

import (
	"strings"
	"testing"
)

// TestConfigRejectsWhatItCannotMean: a pin an operator got wrong must stop startup, naming the
// offending entry. The failure mode of a silently misread pin is either an outage (a good
// server quarantined) or an open door (a bad one never checked), and neither should be
// discovered at 3am.
func TestConfigRejectsWhatItCannotMean(t *testing.T) {
	good := pinTo(t, approvedResult)
	cases := []struct {
		name string
		cfg  *Config
		want []string
	}{
		{
			name: "empty section",
			cfg:  &Config{Servers: map[string]ServerPin{}},
			want: []string{"no servers configured"},
		},
		{
			name: "unknown section mode",
			cfg:  &Config{OnDrift: "alert", Servers: map[string]ServerPin{"demo": {Fingerprint: good}}},
			want: []string{"tooldefs.on_drift", `"deny"`, `"warn"`},
		},
		{
			name: "unknown per-server mode",
			cfg:  &Config{Servers: map[string]ServerPin{"demo": {Fingerprint: good, OnDrift: "ignore"}}},
			want: []string{`server "demo"`, "on_drift"},
		},
		{
			name: "fingerprint with no algorithm",
			cfg:  &Config{Servers: map[string]ServerPin{"demo": {Fingerprint: strings.Repeat("ab", 32)}}},
			want: []string{`server "demo"`, "sha256:"},
		},
		{
			name: "truncated fingerprint",
			cfg:  &Config{Servers: map[string]ServerPin{"demo": {Fingerprint: "sha256:abcd"}}},
			want: []string{`server "demo"`, "64 hex characters"},
		},
		{
			name: "server id with whitespace",
			cfg:  &Config{Servers: map[string]ServerPin{" demo": {Fingerprint: good}}},
			want: []string{"whitespace"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
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

// TestAbsentSectionIsTheFeatureBeingOff: unlike the policy section, no tooldefs section is a
// legal, meaningful configuration — pinning is opt-in, and requiring it would make adding the
// feature an outage for every server nobody has approved yet.
func TestAbsentSectionIsTheFeatureBeingOff(t *testing.T) {
	var cfg *Config
	if err := cfg.Validate(); err != nil {
		t.Fatalf("an absent section must be legal: %v", err)
	}
	g, err := cfg.Guard()
	if err != nil || g != nil {
		t.Fatalf("an absent section must compile to no guard, got %v (%v)", g, err)
	}
	if cfg.ServerIDs() != nil || cfg.Warnings() != nil {
		t.Fatal("an absent section reports nothing")
	}
}

// TestWarningsPointAtPinsThatDoNothing: both of these load and run, and both are almost
// certainly not what the operator meant.
func TestWarningsPointAtPinsThatDoNothing(t *testing.T) {
	cfg := &Config{Servers: map[string]ServerPin{
		"pinned":   {Fingerprint: pinTo(t, approvedResult)},
		"watching": {},
		"confused": {OnDrift: ModeDeny},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("this configuration is legal and must load: %v", err)
	}
	warnings := strings.Join(cfg.Warnings(), "\n")
	for _, want := range []string{`server "watching" has no "fingerprint"`, `server "confused" sets on_drift`} {
		if !strings.Contains(warnings, want) {
			t.Errorf("warnings %q do not mention %q", warnings, want)
		}
	}
	if strings.Contains(warnings, `"pinned"`) {
		t.Errorf("a correctly pinned server must not be warned about: %q", warnings)
	}
}

// TestGuardCompilesThePins: the section becomes the runtime check, with the pins in place and
// the modes resolved.
func TestGuardCompilesThePins(t *testing.T) {
	cfg := &Config{OnDrift: ModeWarn, Servers: map[string]ServerPin{
		"pinned":   {Fingerprint: pinTo(t, approvedResult)},
		"strict":   {Fingerprint: pinTo(t, approvedResult), OnDrift: ModeDeny},
		"watching": {},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := cfg.Guard()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pinned", "strict", "watching"} {
		if !g.Watches(id) {
			t.Errorf("server %q is configured but not watched", id)
		}
	}
	if g.Watches("elsewhere") {
		t.Error("a server absent from the section must not be watched")
	}
	if got := g.approved.Check("pinned", canonical(t, approvedResult).Bytes()); got != OK {
		t.Errorf("the pin did not compile into the baseline: %v", got)
	}
	if got := g.approved.Check("watching", canonical(t, approvedResult).Bytes()); got != Unknown {
		t.Errorf("an unpinned server must have no baseline, got %v", got)
	}
	if got := g.watched["strict"].mode; got != ModeDeny {
		t.Errorf("strict mode = %q, want the per-server override", got)
	}
	if got := g.watched["pinned"].mode; got != ModeWarn {
		t.Errorf("pinned mode = %q, want the section default", got)
	}
	if ids := strings.Join(cfg.ServerIDs(), ","); ids != "pinned,strict,watching" {
		t.Errorf("ServerIDs = %q, want them sorted for deterministic logging", ids)
	}
}
