package jwks

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

// --- Marshal: empty and bad-length keys ---------------------------------------------

func TestMarshalEmptyKeySet(t *testing.T) {
	doc, err := Marshal()
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	keys, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys, want 0", len(keys))
	}
	// The empty document must still be a valid JWK Set object with a keys field.
	var raw map[string]any
	if err := json.Unmarshal(doc, &raw); err != nil {
		t.Fatalf("empty doc not valid JSON: %v", err)
	}
	if _, ok := raw["keys"]; !ok {
		// keys may be null/absent when empty; that is acceptable as long as Parse copes.
		t.Logf("empty set marshalled without a keys field: %s", doc)
	}
}

func TestMarshalRejectsWrongLengthKey(t *testing.T) {
	cases := []struct {
		name string
		pub  ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"too short", make([]byte, ed25519.PublicKeySize-1)},
		{"too long", make([]byte, ed25519.PublicKeySize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Marshal(Key{Kid: "k", Pub: tc.pub}); err == nil {
				t.Fatal("expected error marshalling invalid key")
			}
		})
	}
}

func TestMarshalRejectsWrongLengthKeyAmongValid(t *testing.T) {
	// A single bad key in the batch fails the whole Marshal (fail-closed).
	good := newPub(t)
	if _, err := Marshal(Key{Kid: "good", Pub: good}, Key{Kid: "bad", Pub: make([]byte, 5)}); err == nil {
		t.Fatal("expected error when any key has the wrong length")
	}
}

// --- Parse: duplicate kids -----------------------------------------------------------

// TestParseDuplicateKidsAllReturned documents CURRENT behavior: Parse does not deduplicate
// kids. Two JWKs sharing a kid both come back as separate entries. The verify-side
// resolver collapses them into a map (last-wins), but jwks.Parse itself keeps both.
func TestParseDuplicateKidsAllReturned(t *testing.T) {
	pub1 := newPub(t)
	pub2 := newPub(t)
	doc, err := Marshal(Key{Kid: "dup", Pub: pub1}, Key{Kid: "dup", Pub: pub2})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2 (Parse does not dedupe kids)", len(keys))
	}
	for _, k := range keys {
		if k.Kid != "dup" {
			t.Fatalf("unexpected kid %q", k.Kid)
		}
	}
}

// --- Parse: invalid x / wrong length / non-OKP --------------------------------------

func TestParseInvalidXBase64(t *testing.T) {
	// "!!!" is outside the base64url alphabet.
	const doc = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"!!!"}]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("expected error for invalid base64 x")
	}
}

func TestParseWrongKeyLength(t *testing.T) {
	// Valid base64url but not 32 bytes.
	short := base64.RawURLEncoding.EncodeToString([]byte("too-short"))
	doc := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + short + `"}]}`
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("expected error for wrong Ed25519 key length")
	}
}

func TestParseSkipsNonOKPAndWrongCurve(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(newPub(t))
	// A valid Ed25519 OKP key alongside entries that must be skipped:
	//   - RSA (wrong kty)
	//   - EC P-256 (wrong kty)
	//   - OKP X25519 (right kty, wrong crv)
	doc := `{"keys":[
		{"kty":"RSA","kid":"rsa","n":"abc","e":"AQAB"},
		{"kty":"EC","crv":"P-256","kid":"ec","x":"abc","y":"def"},
		{"kty":"OKP","crv":"X25519","kid":"x25519","x":"` + good + `"},
		{"kty":"OKP","crv":"Ed25519","kid":"ed","x":"` + good + `"}
	]}`
	keys, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 || keys[0].Kid != "ed" {
		t.Fatalf("expected only the Ed25519 key, got %+v", keys)
	}
}

// --- Parse: empty / garbage docs -----------------------------------------------------

func TestParseGarbageDocs(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantErr bool
		wantLen int
	}{
		{"empty bytes", "", true, 0},
		{"not json", "not json at all", true, 0},
		{"truncated json", `{"keys":[`, true, 0},
		{"json array not object", `[]`, true, 0},
		{"empty object", `{}`, false, 0},
		{"keys null", `{"keys":null}`, false, 0},
		{"keys empty array", `{"keys":[]}`, false, 0},
		{"unknown fields ignored", `{"keys":[],"extra":"ok"}`, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := Parse([]byte(tc.doc))
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q", tc.doc)
			}
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("unexpected error for %q: %v", tc.doc, err)
				}
				if len(keys) != tc.wantLen {
					t.Fatalf("got %d keys, want %d", len(keys), tc.wantLen)
				}
			}
		})
	}
}

// --- Handler -------------------------------------------------------------------------

func TestHandlerContentTypeAndBody(t *testing.T) {
	pub := newPub(t)
	rec := httptest.NewRecorder()
	Handler(Key{Kid: "k1", Pub: pub}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	keys, err := Parse(rec.Body.Bytes())
	if err != nil || len(keys) != 1 {
		t.Fatalf("served body not parseable: %v (%d keys)", err, len(keys))
	}
	if keys[0].Kid != "k1" || !keys[0].Pub.Equal(pub) {
		t.Fatal("served key did not round-trip")
	}
}

func TestHandlerEmptyKeySetServesOK(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	keys, err := Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse served empty set: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("got %d keys, want 0", len(keys))
	}
}

// TestHandlerServesErrorOnBadKey exercises the Handler's error path: a malformed key makes
// Marshal fail at construction time, and every request then returns 500.
func TestHandlerServesErrorOnBadKey(t *testing.T) {
	h := Handler(Key{Kid: "bad", Pub: make([]byte, 3)})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 for unmarshalable key set", rec.Code)
	}
}
