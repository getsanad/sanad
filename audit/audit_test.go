package audit

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func appendN(t *testing.T, l *HashChainLog, n int) {
	t.Helper()
	for range n {
		if err := l.Append(context.Background(), Entry{Action: "allow", Principal: "p1", Server: "demo"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
}

func TestHashChainAppendAndVerify(t *testing.T) {
	l := NewHashChainLog(nil)
	appendN(t, l, 3)

	entries := l.Entries()
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if len(entries[0].PrevHash) != 0 {
		t.Fatal("first entry should have empty prev hash")
	}
	if !bytes.Equal(entries[1].PrevHash, entries[0].Hash) {
		t.Fatal("entry 1 must chain to entry 0")
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("intact chain must verify: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	l := NewHashChainLog(nil)
	appendN(t, l, 3)

	entries := l.Entries()
	entries[1].Principal = "attacker" // silently edit a recorded entry
	if err := VerifyChain(entries); err == nil {
		t.Fatal("editing an entry must break the chain")
	}

	// Deleting an entry must also be detected.
	if err := VerifyChain([]Entry{entries[0], entries[2]}); err == nil {
		t.Fatal("removing an entry must break the chain")
	}
}

func TestSinkStreaming(t *testing.T) {
	var buf bytes.Buffer
	l := NewHashChainLog(NewJSONLinesSink(&buf))
	appendN(t, l, 2)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d streamed lines, want 2", len(lines))
	}
	if !strings.Contains(lines[0], `"Principal":"p1"`) {
		t.Fatalf("streamed line missing attribution: %s", lines[0])
	}
}

func TestGatewayHookRecordsDecision(t *testing.T) {
	l := NewHashChainLog(nil)
	hook := GatewayHook(l)

	req := &gateway.Request{
		Server:    "demo",
		Principal: &types.Principal{ID: "p1"},
		Agent:     &types.Agent{ID: "a1"},
		Decision:  &types.Decision{Effect: types.EffectAllow, Reason: "allowlisted"},
	}
	hook(req, true, "allow")

	entries := l.Entries()
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Principal != "p1" || e.Agent != "a1" || e.Server != "demo" || e.Action != "allow" {
		t.Fatalf("attribution mismatch: %+v", e)
	}
}

// TestGatewayIntegration wires the hook into the gateway and confirms a denied request
// (unknown server) is recorded with an intact chain.
func TestGatewayIntegration(t *testing.T) {
	l := NewHashChainLog(nil)
	g := &gateway.Gateway{Registry: gateway.NewRegistry(), Audit: GatewayHook(l)}

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/ghost/x", nil))

	entries := l.Entries()
	if len(entries) != 1 || entries[0].Action != "deny" || entries[0].Server != "ghost" {
		t.Fatalf("expected one deny entry for unknown server, got %+v", entries)
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("chain must verify: %v", err)
	}
}
