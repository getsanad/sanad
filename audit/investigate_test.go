package audit

import (
	"context"
	"testing"
)

func TestInvestigate(t *testing.T) {
	l := NewHashChainLog(nil)
	ctx := context.Background()

	_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1", Server: "other"})
	_ = l.Append(ctx, Entry{
		Action: "allow", Principal: "p1", Agent: "a2", Server: "payments",
		PassportID: "pp-42", Delegation: []string{"p1", "a1", "a2"},
	})

	rep, err := l.Investigate("pp-42")
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if rep.Principal != "p1" || rep.Agent != "a2" || rep.Server != "payments" {
		t.Fatalf("report attribution wrong: %+v", rep)
	}
	if len(rep.DelegationPath) != 3 || rep.DelegationPath[0] != "p1" || rep.DelegationPath[2] != "a2" {
		t.Fatalf("delegation path wrong: %v", rep.DelegationPath)
	}
	if !rep.IntegrityOK {
		t.Fatal("intact log should report IntegrityOK=true")
	}
}

func TestInvestigateNotFound(t *testing.T) {
	l := NewHashChainLog(nil)
	if _, err := l.Investigate("missing"); err == nil {
		t.Fatal("unknown passport id must error")
	}
}

func TestByPrincipal(t *testing.T) {
	l := NewHashChainLog(nil)
	ctx := context.Background()
	_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1", PassportID: "a"})
	_ = l.Append(ctx, Entry{Action: "deny", Principal: "p2", PassportID: "b"})
	_ = l.Append(ctx, Entry{Action: "allow", Principal: "p1", PassportID: "c"})

	if got := l.ByPrincipal("p1"); len(got) != 2 {
		t.Fatalf("ByPrincipal(p1) = %d entries, want 2", len(got))
	}
}
