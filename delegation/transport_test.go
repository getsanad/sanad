package delegation

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
)

func TestEncodeDecodeChainRoundTrip(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})

	enc, err := EncodeChain(chain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeChain(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The decoded chain must still verify (signatures survive the round-trip).
	if _, _, err := Verify(got, registry(principal, a1), principal.id, time.Now()); err != nil {
		t.Fatalf("round-tripped chain failed to verify: %v", err)
	}
}

func TestDecodeChainBadInput(t *testing.T) {
	if _, err := DecodeChain("!!!not-base64"); err == nil {
		t.Fatal("non-base64 must error")
	}
	if _, err := DecodeChain("Zm9v"); err == nil { // "foo", not JSON
		t.Fatal("non-JSON must error")
	}
}

func TestHeaderExtractor(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	enc, _ := EncodeChain(chain)

	extract := HeaderExtractor(HeaderDelegation)

	// Absent header -> not present, no error.
	bare := &gateway.Request{HTTP: httptest.NewRequest(http.MethodGet, "/x", nil)}
	if _, present, err := extract(bare); present || err != nil {
		t.Fatalf("absent header: present=%v err=%v", present, err)
	}

	// Present header -> decoded chain.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(HeaderDelegation, enc)
	c, present, err := extract(&gateway.Request{HTTP: r})
	if err != nil || !present || len(c.Hops) != 1 {
		t.Fatalf("present header: present=%v err=%v hops=%d", present, err, len(c.Hops))
	}

	// Malformed header -> error.
	bad := httptest.NewRequest(http.MethodGet, "/x", nil)
	bad.Header.Set(HeaderDelegation, "!!!")
	if _, _, err := extract(&gateway.Request{HTTP: bad}); err == nil {
		t.Fatal("malformed header must error")
	}
}
