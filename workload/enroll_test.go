package workload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// authorityServer mounts both legs of enrollment, as cmd/authority does.
func authorityServer(a *Authority) *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("/enroll/nonce", NonceHandler(a))
	mux.Handle("/enroll", EnrollHandler(a))
	return httptest.NewServer(mux)
}

func enrollSetup(t *testing.T) (*httptest.Server, ed25519.PublicKey, *Authority) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := NewTokenAttestor()
	att.Register("boot-token", "agent-1")
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return authorityServer(authority), caPub, authority
}

// bootstrapEvidenceFor is the EvidenceFunc a dev agent enrolls with.
func bootstrapEvidenceFor(token string) EvidenceFunc {
	return func(nonce []byte, pub ed25519.PublicKey) ([]byte, error) {
		return BootstrapEvidence(token, nonce, pub), nil
	}
}

// postEnroll submits a hand-built enrollment, which is how an attacker replays one. It
// returns the status code and the body so a test can assert on the denial.
func postEnroll(t *testing.T, srv *httptest.Server, nonce, evidence []byte, pub ed25519.PublicKey) (int, string) {
	t.Helper()
	body, _ := json.Marshal(enrollRequest{
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		Evidence:  base64.RawURLEncoding.EncodeToString(evidence),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
	})
	resp, err := srv.Client().Post(srv.URL+"/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func TestEnrollRoundTrip(t *testing.T) {
	srv, caPub, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cred, err := Enroll(context.Background(), srv.Client(), srv.URL, instPub, bootstrapEvidenceFor("boot-token"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if cred.AgentID != "agent-1" || !cred.PublicKey.Equal(instPub) {
		t.Fatalf("credential mismatch: %+v", cred)
	}
	if err := Verify(caPub, cred, time.Now()); err != nil {
		t.Fatalf("issued credential should verify against the CA: %v", err)
	}
}

func TestEnrollRejectsBadAttestation(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, instPub, bootstrapEvidenceFor("not-a-real-token")); err == nil {
		t.Fatal("enrollment with unrecognized attestation must be denied")
	}
}

// TestEnrollReplayedQuoteWithAttackerKeyDenied is the proof of concept that motivated this
// contract, run against the live enrollment endpoints with the high-assurance attestor.
//
// It used to pass: Attest saw only the evidence, so anyone who captured one quote — off the
// network, out of a log, out of a CI artifact, from another container on the host — could
// post it with THEIR public key and be handed a CA-signed credential for that agent id. That
// credential authenticates at InstanceStage, registers the attacker's key in the KeyStore,
// and signs delegation hops as the agent.
//
// Every replay below must now be refused: the quote answers one nonce and names one key.
func TestEnrollReplayedQuoteWithAttackerKeyDenied(t *testing.T) {
	attPub, attPriv, _ := ed25519.GenerateKey(rand.Reader)
	att, err := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := authorityServer(authority)
	defer srv.Close()

	honestPub, _, _ := ed25519.GenerateKey(rand.Reader)
	attackerPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// 1. The PoC at its sharpest. The attacker holds a quote for agent-1 captured in flight
	//    and a nonce that is live, unissued-to-anyone-else and completely unspent — so the
	//    freshness check has nothing to say. Only the cnf binding refuses this.
	live, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	inFlight, err := SignQuote(attPriv, "agent-1", "build-v1", live, honestPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := postEnroll(t, srv, live, inFlight, attackerPub); code == http.StatusOK {
		t.Fatal("REGRESSION: a quote for agent-1 minted a credential for the attacker's key")
	} else if code != http.StatusForbidden {
		t.Fatalf("the replay should be denied 403, got %d (%s)", code, body)
	}

	// 2. The honest path still works end to end, and its quote leaks afterwards.
	var capturedNonce, capturedQuote []byte
	cred, err := Enroll(context.Background(), srv.Client(), srv.URL, honestPub,
		func(nonce []byte, pub ed25519.PublicKey) ([]byte, error) {
			q, qerr := SignQuote(attPriv, "agent-1", "build-v1", nonce, pub, time.Now())
			capturedNonce, capturedQuote = nonce, q
			return q, qerr
		})
	if err != nil {
		t.Fatalf("honest enrollment must still work: %v", err)
	}
	if cred.AgentID != "agent-1" || !cred.PublicKey.Equal(honestPub) {
		t.Fatalf("honest credential mismatch: %+v", cred)
	}

	// 3. That captured quote, replayed against its own now-spent nonce.
	if code, _ := postEnroll(t, srv, capturedNonce, capturedQuote, attackerPub); code == http.StatusOK {
		t.Fatal("REGRESSION: a captured quote replayed with an attacker's key was accepted")
	}

	// 4. And against a nonce the attacker legitimately obtains — even for the honest key, so
	//    a quote is never good for a second credential either.
	for _, pub := range []ed25519.PublicKey{attackerPub, honestPub} {
		fresh, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := postEnroll(t, srv, fresh, capturedQuote, pub); code == http.StatusOK {
			t.Fatal("REGRESSION: a captured quote was replayable under a fresh nonce")
		}
	}

	// And nothing above minted anything: the attacker's key holds no credential for agent-1.
	ks := NewKeyStore(caPub)
	if err := ks.Add(Credential{AgentID: "agent-1", PublicKey: attackerPub}); err == nil {
		t.Fatal("an unsigned credential for the attacker key must not verify")
	}
}

// TestEnrollBootstrapEvidenceIsKeyBound pins the same property for the dev/bootstrap
// attestor: capturing an enrollment does not let the captor enroll a different key, because
// the token itself never crosses the wire.
func TestEnrollBootstrapEvidenceIsKeyBound(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	honestPub, _, _ := ed25519.GenerateKey(rand.Reader)
	attackerPub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Evidence for the honest key, against a live and entirely unspent nonce: the key
	// binding is the only thing that can refuse it.
	live, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postEnroll(t, srv, live, BootstrapEvidence("boot-token", live, honestPub), attackerPub); code == http.StatusOK {
		t.Fatal("captured bootstrap evidence must not enroll a different key")
	}

	// The honest agent enrolls; its evidence leaks and is replayed under a fresh nonce.
	var capturedEvidence []byte
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, honestPub,
		func(nonce []byte, pub ed25519.PublicKey) ([]byte, error) {
			capturedEvidence = BootstrapEvidence("boot-token", nonce, pub)
			return capturedEvidence, nil
		}); err != nil {
		t.Fatalf("honest enrollment: %v", err)
	}
	fresh, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postEnroll(t, srv, fresh, capturedEvidence, attackerPub); code == http.StatusOK {
		t.Fatal("captured bootstrap evidence must not enroll a different key under a fresh nonce")
	}
}

func TestEnrollNonceIsSingleUse(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	nonce, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	evidence := BootstrapEvidence("boot-token", nonce, instPub)

	if code, body := postEnroll(t, srv, nonce, evidence, instPub); code != http.StatusOK {
		t.Fatalf("first use of a nonce should succeed, got %d (%s)", code, body)
	}
	if code, _ := postEnroll(t, srv, nonce, evidence, instPub); code == http.StatusOK {
		t.Fatal("a nonce must not be usable twice")
	}
}

func TestEnrollRejectsUnknownNonce(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	unknown := make([]byte, nonceSize)
	if _, err := rand.Read(unknown); err != nil {
		t.Fatal(err)
	}
	// Evidence perfectly formed over a nonce this authority never issued.
	if code, _ := postEnroll(t, srv, unknown, BootstrapEvidence("boot-token", unknown, instPub), instPub); code == http.StatusOK {
		t.Fatal("a nonce the authority never issued must be rejected")
	}
	if code, _ := postEnroll(t, srv, nil, nil, instPub); code != http.StatusBadRequest {
		t.Fatalf("an empty nonce should be a bad request, got %d", code)
	}
}

func TestEnrollRejectsExpiredNonce(t *testing.T) {
	srv, _, authority := enrollSetup(t)
	defer srv.Close()

	// Inject a clock so we can cross the nonce window deterministically.
	base := time.Now()
	authority.now = func() time.Time { return base }

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	nonce, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	authority.now = func() time.Time { return base.Add(NonceTTL + time.Second) }

	if code, _ := postEnroll(t, srv, nonce, BootstrapEvidence("boot-token", nonce, instPub), instPub); code == http.StatusOK {
		t.Fatal("an expired nonce must be rejected")
	}
}

// TestEnrollNonceSpentOnFailure pins that a failed attestation burns its challenge, so an
// attacker cannot grind attempts against one nonce.
func TestEnrollNonceSpentOnFailure(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	nonce, err := RequestNonce(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postEnroll(t, srv, nonce, BootstrapEvidence("wrong-token", nonce, instPub), instPub); code == http.StatusOK {
		t.Fatal("bad evidence must be denied")
	}
	if code, _ := postEnroll(t, srv, nonce, BootstrapEvidence("boot-token", nonce, instPub), instPub); code == http.StatusOK {
		t.Fatal("a nonce spent on a failed attempt must not be retryable")
	}
}

func TestNonceHandlerRejectsGET(t *testing.T) {
	srv, _, _ := enrollSetup(t)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/enroll/nonce")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /enroll/nonce = %d, want 405", resp.StatusCode)
	}
}

func TestNonceIsFreshAndBounded(t *testing.T) {
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	authority, _ := NewAuthority(caPriv, "ca-1", NewTokenAttestor(), time.Hour)

	seen := map[string]bool{}
	for range 64 {
		n, err := authority.Nonce()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != nonceSize {
			t.Fatalf("nonce length = %d, want %d", len(n), nonceSize)
		}
		if seen[string(n)] {
			t.Fatal("the authority must never issue the same nonce twice")
		}
		seen[string(n)] = true
	}

	// Expired nonces are swept rather than accumulating forever.
	base := time.Now()
	authority.now = func() time.Time { return base.Add(2 * NonceTTL) }
	if _, err := authority.Nonce(); err != nil {
		t.Fatal(err)
	}
	if got := len(authority.nonces); got != 1 {
		t.Fatalf("expired nonces should be swept, %d left", got)
	}
}
