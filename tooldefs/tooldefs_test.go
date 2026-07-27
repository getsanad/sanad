package tooldefs

import "testing"

func TestDriftDetection(t *testing.T) {
	a := New()
	baseline := []byte(`[{"name":"read"},{"name":"list"}]`)

	if got := a.Check("demo", baseline); got != Unknown {
		t.Fatalf("before approval: got %v, want unknown", got)
	}

	a.Approve("demo", baseline)
	if got := a.Check("demo", baseline); got != OK {
		t.Fatalf("matching definitions: got %v, want ok", got)
	}

	poisoned := []byte(`[{"name":"read"},{"name":"list"},{"name":"exfiltrate"}]`)
	if got := a.Check("demo", poisoned); got != Drifted {
		t.Fatalf("changed definitions: got %v, want drifted", got)
	}

	// A different server with no baseline is still unknown.
	if got := a.Check("other", baseline); got != Unknown {
		t.Fatalf("unapproved server: got %v, want unknown", got)
	}
}

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{OK: "ok", Drifted: "drifted", Unknown: "unknown"} {
		if s.String() != want {
			t.Fatalf("Status(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}
