package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/tooldefs"
)

// TestToolDefsHookRecordsAnInvestigableEvent: a drift alert that says only "server X drifted"
// leaves an investigator with nowhere to go. The entry has to carry both fingerprints, the
// tools that were actually advertised, whether anything was blocked, and who was asking.
func TestToolDefsHookRecordsAnInvestigableEvent(t *testing.T) {
	log := NewHashChainLog(nil)
	ToolDefsHook(log)(tooldefs.Event{
		At: time.Now().UTC(), Server: "github", Status: tooldefs.Drifted, Mode: tooldefs.ModeDeny,
		Blocked:   true,
		Approved:  "sha256:" + strings.Repeat("ab", 32),
		Observed:  "sha256:" + strings.Repeat("cd", 32),
		Tools:     []string{"exfiltrate", "read_file", "search"},
		Reason:    "TOOL-DEFINITION DRIFT: server \"github\" advertised …",
		Principal: "did:key:z6MkPrincipal", Agent: "agent-1", PassportID: "jti-1",
		Delegation: []string{"did:key:z6MkPrincipal", "agent-1"},
	})

	entries := log.Entries()
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "drift" {
		t.Fatalf("action = %q: drift is its own event, not a deny — it is true of the SERVER, for every caller after this one", e.Action)
	}
	if e.Server != "github" || e.Principal != "did:key:z6MkPrincipal" || e.Agent != "agent-1" || e.PassportID != "jti-1" {
		t.Fatalf("the entry is unattributed: %+v", e)
	}
	if e.Drift == nil {
		t.Fatal("no drift detail: the alert is not investigable")
	}
	switch {
	case e.Drift.Status != "drifted" || e.Drift.Mode != "deny" || !e.Drift.Blocked:
		t.Fatalf("drift detail = %+v", e.Drift)
	case e.Drift.Approved == e.Drift.Observed || e.Drift.Approved == "" || e.Drift.Observed == "":
		t.Fatalf("both fingerprints must be recorded and must differ: %+v", e.Drift)
	case strings.Join(e.Drift.Tools, ",") != "exfiltrate,read_file,search":
		t.Fatalf("tools = %v, want the names the upstream advertised", e.Drift.Tools)
	}

	// It reaches a SIEM with the detail intact, and it is covered by the chain hash, so the
	// record of what was seen cannot be quietly edited afterwards.
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"status":"drifted"`, `"observed":"sha256:cdcd`, `"exfiltrate"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("streamed entry %s does not contain %s", raw, want)
		}
	}

	tampered := e
	tampered.Drift = &Drift{Status: "ok"}
	if err := VerifyChain([]Entry{tampered}); err == nil {
		t.Fatal("the drift detail must be inside the tamper-evident hash, or an attacker edits the finding away")
	}
}

// TestToolDefsHookRecordsNonDriftEvents: an unpinned server reporting its fingerprint, or a
// quarantine lifting, are audit events too — under their own action, so a SIEM rule that pages
// on "drift" is not woken by them.
func TestToolDefsHookRecordsNonDriftEvents(t *testing.T) {
	log := NewHashChainLog(nil)
	hook := ToolDefsHook(log)
	hook(tooldefs.Event{Server: "staging", Status: tooldefs.Unknown, Reason: "watched but not pinned"})
	hook(tooldefs.Event{Server: "github", Status: tooldefs.OK, Reason: "the quarantine is lifted"})

	for i, e := range log.Entries() {
		if e.Action != "tooldefs" {
			t.Errorf("entry %d action = %q, want %q", i, e.Action, "tooldefs")
		}
		if e.At.IsZero() {
			t.Errorf("entry %d has no timestamp; an event with no time is not a record", i)
		}
	}
	if err := log.Verify(); err != nil {
		t.Fatalf("chain: %v", err)
	}
}
