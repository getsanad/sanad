// Command demo runs the whole Sanad flow end-to-end in one process and narrates
// each step, so you can SEE the system work without any external setup.
//
//	go run ./cmd/demo
//
// It sets up a VC principal, a workload-attested agent instance, and a delegation chain;
// stands a fake MCP server behind the gateway; sends an allowed request (showing the
// minted passport and that the caller's credential is NOT forwarded), then a denied one
// after revocation; and finally prints the tamper-evident audit log and an investigation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/getsanad/sanad/audit"
	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
	"github.com/getsanad/sanad/principal"
	"github.com/getsanad/sanad/revoke"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/vc"
	"github.com/getsanad/sanad/workload"
)

func genKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func section(s string) { fmt.Printf("\n\033[1m== %s ==\033[0m\n", s) }

func main() {
	// --- identities ---------------------------------------------------------------
	issuerPub, issuerPriv := genKey()
	issuerDID := vc.EncodeDIDKey(issuerPub)
	principalPub, principalPriv := genKey()
	principalDID := vc.EncodeDIDKey(principalPub)
	caPub, caPriv := genKey()
	a1Pub, a1Priv := genKey()

	section("Identities")
	fmt.Printf("Credential issuer : %s\n", issuerDID)
	fmt.Printf("Principal (human) : %s\n", principalDID)
	fmt.Printf("Agent instance    : agent-1 (workload-attested)\n")

	// --- principal VC, agent credential, delegation chain -------------------------
	cred, _ := vc.Issue(issuerDID, issuerPriv, vc.Subject{ID: principalDID, Assurance: types.AssuranceOrg}, time.Hour, time.Now())
	vcJSON, _ := json.Marshal(cred)
	bearer := base64.RawURLEncoding.EncodeToString(vcJSON)

	att := workload.NewTokenAttestor()
	att.Register("boot-token", "agent-1")
	authority, _ := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	agentCred, _ := authority.Issue([]byte("boot-token"), a1Pub)
	credHdr, _ := workload.EncodeCredential(agentCred)

	chain, _ := delegation.NewRoot(principalPriv, principalDID, "agent-1", delegation.Grant{Tools: []string{"read"}})
	chainHdr, _ := delegation.EncodeChain(chain)

	section("Setup")
	fmt.Println("- Issued a Verifiable Credential for the principal (did:key)")
	fmt.Println("- Issued a short-lived workload credential for agent-1 (via attestation)")
	fmt.Println("- Built delegation chain: principal -> agent-1, scope=[read]")

	// --- gateway + a fake protected MCP server ------------------------------------
	store := workload.NewKeyStore(caPub)
	vcAuth := vc.NewAuthenticator(vc.StaticTrust{issuerDID: true}, vc.WithKeyRegistrar(store))
	signer, _ := sts.NewLocalSigner("kid-gw")
	auditLog := audit.NewHashChainLog(nil)
	ks := revoke.NewMemStore()
	allowAll := policy.Func(func(_ context.Context, _ policy.Input) (types.Decision, error) {
		return types.Decision{Effect: types.EffectAllow, Reason: "demo allow-all"}, nil
	})

	var forwardedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"tools":["read"]}`)
	}))
	defer upstream.Close()

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	_ = reg.Register(&gateway.Server{ID: "demo", Upstream: u})

	g := &gateway.Gateway{
		Registry: reg,
		Audit:    audit.GatewayHook(auditLog),
		Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
			principal.Stage(vcAuth),
			workload.InstanceStage(caPub, store),
			delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
			revoke.Stage(ks),
			policy.Stage(allowAll, nil, nil),
			sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
		}},
	}
	gw := httptest.NewServer(g)
	defer gw.Close()

	send := func() (*http.Response, error) {
		req, _ := http.NewRequest(http.MethodGet, gw.URL+"/servers/demo/tools/list", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set(workload.HeaderCredential, credHdr)
		req.Header.Set(workload.HeaderProof, workload.Proof(a1Priv, bearer))
		req.Header.Set(delegation.HeaderDelegation, chainHdr)
		return http.DefaultClient.Do(req)
	}

	// --- request 1: allowed -------------------------------------------------------
	section("Request 1: agent-1 calls the protected MCP server")
	resp, err := send()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("Gateway -> %d; upstream replied: %s\n", resp.StatusCode, body)

	tok := forwardedAuth[len("Bearer "):]
	claims, _ := passport.Verify(signer.Public(), tok, "demo", time.Now())
	fmt.Println("\nThe upstream received a freshly-minted PASSPORT (not the principal's VC):")
	fmt.Printf("  principal : %s\n  agent     : %s\n  audience  : %s\n  scope     : %v\n  expires   : %s (in %s)\n",
		claims.Principal, claims.Agent, claims.Audience, claims.Tools,
		time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339), time.Until(time.Unix(claims.ExpiresAt, 0)).Round(time.Second))
	if bearer != tok {
		fmt.Println("  (the caller's VC was stripped and never forwarded — token isolation, FR-8)")
	}

	// --- request 2: denied after revocation ---------------------------------------
	section("Request 2: revoke the principal, then call again")
	_ = ks.Revoke(principalDID) // in-process store: cannot fail
	resp2, _ := send()
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	fmt.Printf("Gateway -> %d (%s) — revoked principal is cut off, fails closed (NFR-3)\n",
		resp2.StatusCode, trim(body2))

	// --- audit trail --------------------------------------------------------------
	section("Tamper-evident audit log")
	for i, e := range auditLog.Entries() {
		fmt.Printf("  [%d] %-5s principal=%s agent=%s server=%s reason=%q\n",
			i, e.Action, short(e.Principal), e.Agent, e.Server, e.Reason)
	}
	if err := auditLog.Verify(); err == nil {
		fmt.Println("  chain integrity: OK (any edit/delete would break it)")
	}
	if rep, err := auditLog.Investigate(claims.ID); err == nil {
		section("Investigation: who is accountable for the allowed action?")
		fmt.Printf("  passport %s -> principal %s, agent %s, delegation path %v, record intact=%v\n",
			short(rep.PassportID), short(rep.Principal), rep.Agent, rep.DelegationPath, rep.IntegrityOK)
	}

	fmt.Println("\nDone. Everything above ran through the real gateway + packages.")
}

func trim(b []byte) string {
	s := string(b)
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s
}

func short(s string) string {
	if len(s) > 24 {
		return s[:21] + "..."
	}
	return s
}
