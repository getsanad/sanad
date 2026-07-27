# Sanad — Review Findings & Improvement Plan

Result of a full review of the codebase against `README.md` and `Sanad-PRD.md`, including a
live end-to-end run of the real binaries. Every finding marked **[verified]** was reproduced
by running the code, not inferred from reading it.

This document is written to be *built from*. Work items carry file:line anchors and
acceptance criteria. Phases are ordered by risk, not by convenience.

---

## Part 1 — Does it work as described?

**Yes, the happy path is real.** This is not a demo with stubs behind it. Verified directly:

- `make check` — builds clean, `go vet` clean, **313 tests across 19 packages pass**; `go test -race` also passes.
- `make demo` — the narrated flow runs: VC principal → attested agent instance → delegation
  chain → minted passport (`scope:[read]`, 120s TTL) → principal revoked → next request
  denied → audit chain verifies.
- **Live multi-process run** (not just the in-process demo): real `authority` + `gateway` +
  `echomcp` binaries plus the `passport` sidecar. Enrollment issued a CA-signed credential;
  a request through the sidecar arrived upstream carrying a genuine EdDSA passport JWT
  (`aud:demo`, `scope:["read"]`), with the principal's own credential stripped.
- With no policy configured the gateway correctly denied with `deny-by-default`.

**The cryptographic core is genuinely good** and should not be regressed:

- `audit/merkle.go` is a faithful RFC 6962 implementation — leaf/node domain separation,
  correct split, strict proof-length check. It was verified against Certificate Transparency
  known-answer vectors for sizes 1..8, including negative cases.
- `pkg/passport` pins EdDSA structurally rather than reading `alg` from the token, and
  enforces `typ`. Algorithm confusion and `alg:none` are impossible by construction.
- `delegation/attenuation.go` implements correct subset/expiry/budget narrowing, including
  the wildcard-widening case. Hop chaining via `prevSig` genuinely prevents reordering and splicing.
- `principal/` OIDC is real `go-oidc` with signature, issuer, audience and expiry checks.
  There is no `SkipClientIDCheck`/`InsecureSkipSignatureCheck` anywhere in the repo.

**But three claims in the README/PRD are not true as written**, and the gap between "correct
library code" and "enforcement that actually runs" is the defining problem of this codebase.

### The three false claims

1. **"Strips the caller's credential"** — only `Authorization` and `Proxy-Authorization` are
   removed (`sts/stage.go:42-46`). `Cookie`, `X-Api-Key`, and the agent's own
   `X-Agent-Credential` / `X-Agent-Proof` / `X-Agent-Delegation` are forwarded verbatim to
   the upstream MCP server — precisely the material the passport exists to withhold from it.

2. **"A signed chain from the accountable human through every hop to the action"** — the
   passport does not carry the delegation chain. `ToClaims` drops it
   (`pkg/passport/passport.go:156-166`); there is even a test asserting this
   (`pkg/passport/edges_test.go:448 TestToClaimsToPassportDropsDelegation`). The MCP server
   sees `sub` and `agent` and cannot verify who delegated what. Only the gateway's own audit
   log has the path.

3. **"Instance credential over mutual TLS" (FR-5)** — there is no mTLS. `grep` for
   `ListenAndServeTLS|tls.Config|x509|ClientAuth` returns **zero matches** repo-wide. Every
   service is plain `http.ListenAndServe`. The substitute is a signature over the bearer
   token, which the code comments concede is interim.

Additionally `pip install sanad-sdk` (README.md:136) **does not work** — the package is not
on PyPI (404; the npm half is real and published).

### The two critical fail-open paths [verified]

**C1 — An unconfigured gateway is an open proxy that leaks the caller's token.**
`cmd/gateway/main.go:144-146` logs `"no principal authenticator configured; running with an
empty pipeline"` and *keeps serving*. `Pipeline.Run` over zero stages returns `nil`, and
`gateway/proxy.go:63-75` treats `nil` as allow without ever checking that identity was
established. Reproduced against the real binary:

```
$ PASSPORT_SERVERS=demo=http://localhost:9090 go run ./cmd/gateway
  no principal authenticator configured; running with an empty pipeline

$ curl localhost:18080/servers/demo/tools/list
  {"received_passport":"(none)","tools":["read","list"]}          # HTTP 200, no credentials

$ curl -H "Authorization: Bearer CALLER-SECRET-IDP-TOKEN" ...
  {"received_passport":"CALLER-SECRET-IDP-TOKEN"}                 # caller's token forwarded
```

This is reachable by ordinary misconfiguration — an unset env var in OIDC mode (the default).
The gateway becomes an unauthenticated reverse proxy that also hands every protected MCP
server the caller's raw IdP token: the exact inverse of NFR-3 and FR-8.

**C2 — Delegation is opt-in; dropping one header discards all attenuation.**
`delegation/stage.go:34-36` is `if !present { return nil }`. A sub-agent holding a chain
narrowed to `["read"]` simply omits `X-Agent-Delegation` and is minted a passport with **no
scope at all**, while still authenticating as the agent. Reproduced end-to-end against the
running gateway:

```
WITH    X-Agent-Delegation -> HTTP 200, {"scope":["read"], "agent":"agent-1", "aud":"demo"}
WITHOUT X-Agent-Delegation -> HTTP 200, {"scope":null,     "agent":"agent-1", "aud":"demo"}
```

Nothing downstream compensates: `verify.Middleware` (`verify/verify.go:81-95`) checks
signature, audience and expiry and never inspects scope. An empty scope is strictly more
permissive than a narrow one at every enforcement point in the codebase.

### The systemic problem: written but not wired

A large fraction of the security value exists as correct, tested library code that no binary
ever calls. This is the highest-leverage thing to fix — the code is already paid for.

| Component | Status |
|---|---|
| `audit.TransparencyLog` + `Witness` (Merkle proofs, checkpoints) | Not used by any binary. `cmd/gateway` uses the plain hash chain. |
| `delegation.CapabilityStage` (offline attenuation mode) | Dead code — referenced only by its own definition. |
| `delegation.ExchangeAuthority` (centralized mode) | No HTTP endpoint, no stage, no binary. |
| `policy.NewAllowList` (FR-16 tool allowlist) | Constructed nowhere outside tests. |
| `policy.ManualApprover` (HITL) | No operator surface; gateway passes `nil` approver, so any `EffectReview` is an immediate **deny** (`policy/stage.go:38-40`). |
| `tooldefs.Check` (tool-definition drift, SEC-3) | Called by nothing. |
| `Server.Tier` / `Server.Transport` | Defaulted then read by nothing — one global pipeline for all servers. |

So the shipped product is: identity authentication + an all-or-nothing policy
(`DenyAll` or dev `PASSPORT_ALLOW_ALL=1`) + a hash chain streamed to stdout. P2's offline and
centralized delegation modes and P3's transparency log are, in the deployed binary, absent.

### Signed constraints that are never enforced

Constraints are cryptographically signed, transported, attenuation-checked — and then discarded:

- **`Grant.Servers` is never compared to the target server.** `delegation/stage.go:46` does
  `req.Scope = grant.Scope()` and `Scope()` projects only `Tools` and `Budget`. A chain
  signed as "agent-1 may call `readonly-reports` only" authorizes `payments` equally well.
- **`Grant.Budget` is never enforced** anywhere; it only flows into a passport claim.
- **`Scope.Tools` is never enforced** — not by the gateway (no tool extraction) and not by
  `verify/` (ships no scope-checking helper). "Task-scoped" is decorative at the point of use.
- **The policy stage overwrites rather than intersects** (`policy/stage.go:50-52`):
  `req.Scope = types.Scope{Tools: []string{tool}}`. Dormant only because `main.go:171` passes
  a `nil` extractor — wiring the documented FR-16 allowlist would *break* attenuation.

### Architectural gap: the gateway is not MCP-aware

This one is product-level, not a bug. `policy.ToolExtractor` must derive the tool name from
`req.HTTP`, but in MCP streamable HTTP the tool lives in a **JSON-RPC body POSTed to a single
endpoint**. The gateway never buffers the body — `gateway/proxy.go` hands the request straight
to the reverse proxy — so any extractor that reads `req.HTTP.Body` consumes the one-shot
reader and forwards an empty body upstream. Per-tool authorization is therefore *architecturally
unreachable* without modifying the gateway, which is why `nil` is passed and every shipped
passport carries an empty scope. MCP also permits JSON-RPC batching, so one decision per HTTP
request cannot cover a batch.

Related: `gateway/proxy.go:71-72` sets `r.URL.Path` and clears `RawPath`, so percent-encoded
slashes collapse into real separators. Verified: `/servers/demo/resource%2Fwith%2Fslashes`
reaches the upstream as `/resource/with/slashes`. That corrupts any MCP resource URI containing
an encoded slash, and on upstreams that normalize before routing (nginx, Express, Spring) it is
a path-traversal primitive out of the registered prefix.

### Identity binding weaknesses

- **Attestation evidence is not bound to the enrolled key** (`workload/workload.go:25-27,99-117`).
  `Attest(evidence) (agentID, error)` never receives the public key being enrolled, so no
  implementation *can* bind them. A captured quote replayed with an attacker's own key yields a
  valid CA-signed credential for that agent ID. This is the load-bearing flaw in the workload-identity story.
- **No domain separation.** `Proof()` (`workload/instance.go:49-51`) makes the instance key a raw
  signing oracle over a caller-supplied string; the same key verifies delegation hops signed over
  canonical JSON. With no context tag, a proof-of-possession signature can serve as a valid hop signature.
- **Proofs are static, not request-bound.** `sign(key, principalToken)` covers no method, path,
  body, timestamp or nonce; Ed25519 is deterministic so the value is byte-identical every request.
  There is no nonce/challenge anywhere in the repo. Anyone who observes one request's headers can
  replay the whole bundle for the token's lifetime.
- **`KeyStore` is one flat namespace** (`workload/keystore.go:34-50`) shared by principals and
  agents, last-write-wins. Since agent IDs come from operator config with no format validation, a
  credential whose `AgentID` equals a principal's DID silently replaces that principal's root key.
- **VC principal credentials have no holder binding** (`vc/authenticator.go:51-72`) — no
  Verifiable Presentation, no challenge. The VC is a pure bearer blob; whoever copies the JSON is
  the principal. `Verify` also never checks `type` or `@context`, and `ExpirationDate` is optional
  (a no-expiry VC installs a never-expiring principal key).
- **VC signing is struct-marshal, not JSON-LD canonicalization**, while declaring
  `Ed25519Signature2020` (`vc/vc.go:134-137`). Unknown JSON keys are dropped by `json.Unmarshal`,
  so unsigned properties survive verification invisibly, and any spec-conformant verifier will
  disagree with this one about what was signed.
- **Bootstrap tokens are long-lived shared secrets**, contradicting `workload/workload.go:1-4`
  ("There is no long-lived shared secret"). They never expire, never rotate, are not rate-limited,
  and are passed as a CLI argument.
- `MeasuredAttestor` freshness is one-sided (`workload/attestation.go:65-67`): `now.Sub(IssuedAt) > maxAge`
  is negative for future dates, so a quote dated arbitrarily far ahead never goes stale.

### Durability: nothing survives a restart

The "tamper-evident system of record" is a Go slice. `audit/chainlog.go:17-23` holds
`entries []Entry` in memory; the only externalization is a JSON-lines sink pointed at
**stdout** (`cmd/gateway/main.go:76`). Merkle leaves and witness anti-rollback state are
likewise in-memory, so a restarted witness will co-sign a rewritten history. Audit failures
also never block forwarding (`audit/hook.go:44-46` logs and continues), so a SIEM write
failure loses the only external copy while the action proceeds.

The same pattern repeats: the admin control plane is process-local maps, and
`cmd/admin/main.go:37` builds its service over a **fresh registry no gateway reads** — so
`POST /admin/servers` has no effect on any running gateway. `KeyStore` is per-process, so
behind a load balancer a multi-hop chain that verifies on replica A fails on replica B. Only
the kill-switch genuinely crosses process boundaries (Postgres), and it **fails open silently
and unboundedly**: `revoke/cached.go:90` is `_ = c.Refresh()`, so if Postgres becomes
unreachable every replica serves its last snapshot forever with no log, metric, or staleness
bound. The ≤60s revocation target silently becomes infinite.

**Confirmed data race:** `audit/transparency.go:40-47` appends to `l.leaves` with no lock and
re-reads the chain tail after releasing the chain's lock. 50 concurrent appends produced 46
leaves with one duplicated 29 times. Any HTTP-served deployment is concurrent, so the Merkle
tree is corrupt by construction the moment it is wired.

### Production readiness

No TLS anywhere; no server timeouts (`http.ListenAndServe` with a zero-value `http.Server`
— trivially Slowloris-able); no rate limiting. Unbounded memory growth on the request path in
three places: the audit log, the `KeyStore`, and metrics labels keyed on an
**attacker-controlled path segment** (`metrics/middleware.go:23-32` — unregistered server IDs
are 404'd *and still counted*). Without `PASSPORT_SIGNING_KEY` the gateway generates an
ephemeral key and keeps serving, so N replicas publish N different `kid`s behind one load
balancer; JWKS serves exactly one key, so the documented rotation strategy has no
implementation. Passport TTL is pinned to 2 minutes with no env knob despite `Config.TTL`
existing. `verify` performs no `iss` check, no `nbf`/`iat` check, no clock-skew leeway, and no
`jti` replay cache. WebSocket upgrades return **502** in the shipped wiring because
`metrics.statusWriter` implements neither `http.Hijacker` nor `Unwrap` — it works in package
tests and fails in production. Long-lived SSE streams are authorized once at open and then run
indefinitely, outliving both the 2-minute TTL and the kill-switch.

---

## Part 2 — Improvement plan

Six phases. **Phase 0 and 1 are the ones that matter most**: Phase 0 removes ways the system
silently stops protecting anything, and Phase 1 turns already-written code into enforcement.
Together they are a small fraction of the total effort for most of the security value.

A note on sequencing: do **not** start with Phase 4 (TLS/mTLS) even though it is the most
visible gap. A gateway that fails open over TLS is still an open gateway.

### Phase 0 — Fail closed by construction (do first)

The theme: safety currently depends on wiring order and on optional stages being present.
Make it structural instead, so a future misconfiguration cannot reopen these holes.

1. **Refuse to forward without a minted passport.** In `gateway/proxy.go`, after
   `Pipeline.Run` succeeds, require `req.Passport != nil` before calling `srv.proxy.ServeHTTP`.
   This single check kills C1 at the root regardless of pipeline contents.
   *Acceptance:* a gateway with an empty pipeline returns 403 for every proxied request.

2. **Fatal on an unauthenticated pipeline.** `cmd/gateway/main.go:144-146` must
   `log.Fatal` rather than log-and-serve. Add an explicit `PASSPORT_DEV_NO_AUTH=1` escape
   hatch for the demo path so the safe behavior is the default and the unsafe one is opt-in.
   *Acceptance:* starting the gateway with no principal auth configured exits non-zero.

3. **Make delegation mandatory when configured.** Add a `RequireChain` mode to
   `delegation.Stage`; when a workload CA is configured, a missing `X-Agent-Delegation`
   must fail closed rather than return `nil` (`delegation/stage.go:34-36`). Same fix for
   `delegation/capability.go:162-164`.
   *Acceptance:* the reproducer above returns 403 for the header-less request instead of a
   `scope:null` passport.

4. **Replace header stripping with a forwarding allowlist.** `sts/stage.go:42-46` must clear
   all inbound headers except an explicit allowlist (plus the minted `Authorization`), so
   `Cookie`, `X-Api-Key` and every `X-Agent-*` header stop reaching upstreams.
   *Acceptance:* a request carrying `Cookie`/`X-Api-Key`/`X-Agent-*` reaches the upstream with
   none of them present.

5. **Bound revocation-cache staleness and fail closed past it.** `revoke/cached.go:90` must
   record refresh failures, expose `last_successful_refresh` as a metric and on `/readyz`, and
   after a configurable `MaxStaleness` (default ~60s, matching NFR-4) start **denying** rather
   than serving an unbounded-age snapshot.
   *Acceptance:* with Postgres stopped, the gateway denies after `MaxStaleness` and reports unready.

6. **Fix the transparency-log race.** Guard `leaves` with a mutex and have `Append` use the
   entry it just wrote rather than re-reading the tail (`audit/transparency.go:40-47`). Add a
   concurrent-append test asserting `Size() == N` and that all inclusion proofs verify.
   *Acceptance:* `go test -race` passes a 1000-goroutine concurrent append test.

7. **Report revocation failures honestly.** `revoke.Store.Revoke` cannot return an error, so
   `admin/http.go:73` answers `200 {"revoked":...}` even when the durable write failed.
   Give it an error return and propagate; make cascade atomic or explicitly report partial failure.
   *Acceptance:* with the store failing, `POST /admin/revoke` returns 5xx, not 200.

### Phase 1 — Enforce what is already signed (highest leverage)

8. **Enforce `Grant.Servers`** against `req.Server` in `delegation/stage.go`.
   *Acceptance:* a chain granting only `reports` is denied at `payments`.

9. **Intersect scope, never assign.** `policy/stage.go:50-52` must intersect the requested tool
   with any delegation-derived scope and preserve `Budget`. Add `Delegation` to `policy.Input`
   so the PDP can see the grant it is deciding against.
   *Acceptance:* a request for `admin_delete` under a `["read"]` chain is denied, not re-scoped.

10. **Make the gateway MCP-aware — the key architectural fix.** Buffer the request body once in
    the gateway (with a size cap), parse JSON-RPC to extract method/tool, expose it on
    `gateway.Request`, and re-supply the body to the reverse proxy. Handle JSON-RPC **batches**
    by requiring a decision per element and denying the batch if any element is denied. This
    unblocks FR-16, per-tool audit, and `tooldefs` drift checking simultaneously.
    *Acceptance:* an allowlist permitting `tools/list` but not `tools/call` enforces correctly
    on real MCP streamable-HTTP traffic, including a batched POST.

11. **Wire the allowlist and HITL.** Construct `policy.AllowList` from config in `cmd/gateway`,
    pass a real `Approver`, and add admin endpoints for `Pending`/`Approve`/`Deny`. Move pending
    approvals into shared storage so any replica can resolve them, and fix the resolve race in
    `policy/hitl.go:111-120` where an operator can be told "approved" for a request that was denied.
    *Acceptance:* an operator approves a held request from a different admin process and the
    original request proceeds.

12. **Enforce scope at the resource server.** Put the delegation chain into the passport claims
    (`pkg/passport/passport.go` — delete `TestToClaimsToPassportDropsDelegation` and invert it),
    and ship `verify.RequireScope(tool)` so MCP owners can enforce in one line. Without this,
    "task-scoped" remains decorative and README claim #2 stays false.
    *Acceptance:* an MCP server rejects a passport whose scope omits the invoked tool.

13. **Wire `tooldefs`** into the pipeline so tool-definition drift is actually detected (SEC-3).

### Phase 2 — Fix identity binding

14. **Bind attestation to the enrolled key.** Change the `Attestor` interface to
    `Attest(evidence []byte, pubKey ed25519.PublicKey, nonce []byte)` so the quote covers the
    key being enrolled (RATS `eat_nonce` shape). Add a server-issued, single-use enrollment
    nonce. This is the single most important crypto fix.
    *Acceptance:* a replayed quote paired with a different public key is rejected.

15. **Add domain separation to every signature.** Distinct context prefixes for PoP proofs,
    delegation hops, capability blocks, VC proofs and checkpoints, so a signature from one
    context can never validate in another.
    *Acceptance:* a PoP signature is rejected as a delegation hop signature.

16. **Make proofs request-bound.** Cover method, path, a body hash, and a timestamp or
    server-issued nonce; add a small replay cache. Adopt the DPoP shape rather than inventing one.
    *Acceptance:* a captured header bundle replayed on a different path/method is rejected.

17. **Namespace the `KeyStore`** (`principal:` / `agent:` prefixes) and validate agent-ID format
    at the authority so an agent credential can never overwrite a principal's root key.

18. **Add VC holder binding** — a Verifiable Presentation with a challenge/domain and
    `proofPurpose: authentication`. Enforce `type`/`@context`, require `ExpirationDate`, and wire
    the kill-switch into VC mode as it already is for OIDC. Either adopt real JSON-LD
    canonicalization or stop claiming `Ed25519Signature2020` and document the profile honestly.

19. **Make bootstrap tokens single-use and expiring**, rate-limit `EnrollHandler`, and accept
    them from a file/stdin rather than a CLI argument.

20. **Fix `MeasuredAttestor` freshness** to reject future-dated quotes (`workload/attestation.go:65-67`).

21. **Cap chain and capability length** (`delegation/verify.go:25`, `capability.go:88`) and add
    cycle detection — 4001 hops in one header costs ~113ms of pre-authorization CPU. Chain
    `prevSig` into `blockMsg` so capability truncation is structurally impossible rather than
    prevented only by the caller remembering to use `VerifyHolder`.

### Phase 3 — Durability and horizontal scale

22. **Persist the audit log.** Implement the Postgres (or ClickHouse per ADR-004) sink so the
    chain, Merkle leaves, and witness anti-rollback state survive a restart. Make audit
    write-ahead: a failed audit write must deny the request, not log and continue
    (`audit/hook.go:44-46`).
23. **Wire the transparency log and witnesses** into `cmd/gateway`, and serve
    `/checkpoint`, `/proof/inclusion`, `/proof/consistency` over HTTP. Give `Witness` a network
    transport — an in-process object co-signing whatever it is handed is not an independent witness.
    Add a timestamp to `checkpointMsg` so freshness is provable.
24. **Share the `KeyStore`** across replicas (Postgres/Redis) with TTL eviction, or derive agent
    keys from the credential on each request instead of a registration side effect.
25. **Persist the control plane** and make `POST /admin/servers` actually reconfigure running
    gateways (push or poll), so the admin API stops being inert.
26. **Multi-key JWKS + rotation**: publish current + previous keys, refresh `verify.FetchJWKS`
    periodically, and refuse to start in production mode without `PASSPORT_SIGNING_KEY`.

### Phase 4 — Production hardening

27. TLS everywhere; mTLS for instance auth (FR-5) with the PoP proof as the fallback profile —
    and update the PRD if mTLS is deliberately deferred, rather than leaving the claim standing.
28. `http.Server` timeouts (`ReadHeaderTimeout`, `IdleTimeout`, `WriteTimeout`), upstream
    transport timeouts, a `ReverseProxy.ErrorHandler`, and rate limiting ahead of signature verification.
29. Bound all request-path memory: cap/rotate the in-memory audit slice, evict `KeyStore`
    entries, and **stop keying metrics on unvalidated path segments** (`metrics/middleware.go:23-32`).
30. Fix path handling (`gateway/proxy.go:71-72`) — preserve `RawPath`/`EscapedPath` so encoded
    slashes survive, and reject dot-segments before forwarding.
31. Fix WebSocket upgrades: give `metrics.statusWriter` an `Unwrap() http.ResponseWriter` (and
    `Hijack`), plus a test that asserts 101 through the *production* mux wiring, not just the
    gateway package.
32. Re-authorize long-lived streams periodically (or bound SSE lifetime to the passport TTL) so
    the kill-switch reaches streaming connections — otherwise NFR-4 holds only for request/response.
33. Validate `iss`, add `nbf`/`iat` and clock-skew leeway, add a `jti` replay cache, and make
    passport TTL configurable (`sts.Config.TTL` already exists and is unused).
34. Return **401 + `WWW-Authenticate`** for authentication failures instead of a blanket 403, so
    MCP clients following the OAuth flow know to refresh (`gateway/proxy.go:63-67`, `verify/verify.go`).
35. Record method, path and tool in audit entries (`audit/hook.go:21-27`), and audit the upstream
    *outcome* rather than logging "allow" before the call is made. Audit admin mutations, which
    currently leave no trail at all.

### Phase 5 — Truth in advertising and developer experience

36. **Publish the Python SDK or fix the README.** `pip install sanad-sdk` currently 404s.
37. **Bring the Go SDK to parity** — it sends only the principal bearer, so it cannot
    authenticate against any gateway with a workload CA configured, while the TS and Python SDKs
    can. Today `README.md:134` is wrong for the flagship stack.
38. **Correct the README**: token isolation is partial; the passport does not carry the chain;
    `cmd/sts` is a skeleton; mTLS is not implemented; the admin console is API-only.
39. **Run SDK tests in CI** and add a publish workflow — the TS/Python interop tests never run in
    CI today, and `dist/` is gitignored with no `prepublishOnly`, so a fresh clone can publish an empty package.
40. **Add an end-to-end wiring test** that exercises the real `cmd/gateway` pipeline (not
    hand-built test pipelines) and asserts the fail-closed invariants from Phase 0. Most of the
    findings here survived 313 passing tests precisely because the tests exercise packages in
    isolation rather than the shipped binary's configuration.

---

## Suggested order

Phase 0 → Phase 1 → Phase 2, then 3–5 as deployment demands. Items 1, 2, 3, 4 and 10 deliver
the most security per unit of effort. Item 40 is what keeps these from regressing: the gap
between "package tests pass" and "the shipped binary is safe" is where nearly every finding in
this document lives.

---

# Part 3 — Adoption: making Sanad easy to start using

PRD R6 names adoption friction as a top risk and mitigates it with "thin adapters, drop-in
proxy, clear migration path." The drop-in proxy exists and works. The friction is everywhere
around it.

## The friction, measured

**An operator must configure 20 environment variables** (`grep -rhoE 'PASSPORT_[A-Z_]+' cmd/`)
across **six binaries** — `gateway`, `authority`, `admin`, `sts`, `devsecrets`, `echomcp` —
and **there is no config file of any kind**: no YAML, no TOML, no config loader anywhere in
the tree. Getting to a first authenticated request today means: install Go, clone the repo,
`devsecrets`, edit compose, `docker compose up --build`, `passport enroll`, `passport proxy`,
then point a client at `127.0.0.1:7070`. That is seven steps and a Go toolchain before
anything works.

**There is no way to configure policy at all.** `policy.AllowList` exists and is tested but is
constructed nowhere outside tests, so an operator's only options are `DenyAll` (nothing works)
or `PASSPORT_ALLOW_ALL=1` (everything works). Configuring real authorization currently
requires writing Go and recompiling. This is the same gap as Phase 1 item 11, reached from the
adoption side — which is why the config file and the allowlist should be built together.

**The naming is inconsistent.** The product is Sanad, the module is `github.com/getsanad/sanad`,
and the CLI an agent developer installs is called `passport`. There is no `sanad` command.

**Sanad does not speak the MCP authorization spec.** The gateway serves exactly one
well-known endpoint, `/.well-known/jwks.json`. There is no
`/.well-known/oauth-protected-resource`, no authorization-server metadata, and no dynamic
client registration anywhere in the repo. Meanwhile the MCP spec has, since November 2025,
mandated OAuth 2.1 + PKCE and RFC 9728 protected-resource metadata for remote HTTP servers,
and mainstream clients implement it: point Claude Code, Cursor, or VS Code at a remote MCP URL
and they discover the auth server and run the flow themselves. PRD §11 says Sanad aligns with
that spec and NG4 says it complements it; today it does neither on the client-facing side.

Competing open-source MCP gateways ship a single `docker run` and are usable in a minute.

## The strategic unlock: let the client do the auth

**This is the highest-value DX item in the document.** If the gateway serves
`/.well-known/oauth-protected-resource` and returns `401` with a `WWW-Authenticate` challenge
pointing at an authorization server, then for interactive agents there is **no install, no
enrollment, no sidecar, and no bootstrap token**. The user pastes a URL into their MCP client
and the client runs OAuth. Onboarding collapses from seven steps to one.

This composes with the security work rather than competing with it:

- It requires the **401 + `WWW-Authenticate`** fix already listed as Phase 4 item 34 — that
  item is not cosmetic, it is the entry point to the entire discovery flow.
- **Dynamic Client Registration** (RFC 7591) lets agents self-register instead of being handed
  a long-lived bootstrap token, which directly resolves Phase 2 item 19.
- The sidecar does not go away. It remains the right answer for headless workload agents that
  have no browser and no human — which is where the workload-credential and attestation story
  actually belongs. The two paths stop competing and start covering different cases.

Sequence it after Phase 0/1 (do not put an OAuth front door on a gateway that fails open), but
treat it as the flagship adoption feature.

## Tiered onboarding

Design for three distinct people. Today all three are handed the same seven steps.

**Tier 1 — the evaluator (target: 60 seconds, no Go, no clone).**

```
docker run -p 8080:8080 ghcr.io/getsanad/sanad up --demo
# or:  brew install sanad && sanad up --demo
```

`sanad up` runs gateway + authority + admin in **one process** with an embedded store
(SQLite/bbolt), auto-generated dev keys, a bundled demo upstream, and dev policy — then prints
a ready-to-paste MCP client config block and a working `curl`. No `devsecrets`, no compose
edit, no key handling. The existing `cmd/demo` narration is a good model for what it should
print; this is that demo turned into a real, reachable server.

**Tier 2 — the operator protecting a real server (target: one command).**

```
sanad protect https://my-mcp-server.internal --id payments --require-scope tools/list
sanad config check          # validate before restart
sanad doctor                # diagnose a live gateway
```

`protect` registers an upstream and prints the client-facing URL and the policy stanza it
generated. This depends on making `POST /admin/servers` actually reconfigure a running gateway
(Phase 3 item 25) — today that endpoint writes to a registry no gateway reads.

**Tier 3 — production.** Keep compose, add a Helm chart, real IdP, Postgres, KMS. Already
documented in `docs/DEPLOYMENT.md`; leave it alone until Tiers 1–2 exist.

## Work items

41. **Ship one `sanad` binary with subcommands**, replacing six inconsistently-named ones:
    `sanad up`, `protect`, `enroll`, `proxy`, `revoke`, `doctor`, `config check`, `verify`.
    Keep `passport` as a deprecated alias so the existing skill and docs keep working. Fold
    `devsecrets` into `sanad up --demo` and `echomcp` into `--demo` so neither ships as a
    separate production artifact.
    *Acceptance:* `sanad up --demo` on a clean machine with no Go toolchain serves an
    authenticated request end-to-end.

42. **Add a single `sanad.yaml`** covering servers, principal mode, policy allowlist, HITL
    rules, TTLs, and storage — with env vars kept as overrides for container deployments.
    Build this together with Phase 1 item 11; the allowlist is unreachable without it.
    *Acceptance:* an operator configures per-server tool allowlists and a HITL rule without
    writing Go, and `sanad config check` rejects a malformed file with a line number.

43. **Serve MCP OAuth 2.1 metadata**: `/.well-known/oauth-protected-resource` plus a `401`
    with `WWW-Authenticate` on unauthenticated requests, so unmodified MCP clients discover
    and complete auth with no sidecar. Add Dynamic Client Registration for agent
    self-enrollment.
    *Acceptance:* Claude Code (or any spec-compliant client) connects to a Sanad-protected
    server given only its URL, with nothing installed locally.

44. **`sanad doctor` — make fail-closed debuggable.** The gateway denies correctly and often,
    but every denial returns the same opaque `403 denied` body while the real reason goes to
    the gateway's stdout. `doctor` should probe a live gateway and report which stage would
    reject and why: clock skew, expired credential, key/credential mismatch, revoked
    principal, unknown server id, missing scope. The skill's troubleshooting table
    (`skills/sanad/SKILL.md:89-98`) is the spec — make it executable.
    *Acceptance:* each documented failure mode produces a distinct, actionable diagnosis.
    (Pair with returning a machine-readable error code in the denial body — without leaking
    to unauthenticated callers *why* they failed.)

45. **Print the client config, don't describe it.** After `up` or `protect`, emit the exact
    JSON block for the user's MCP client and a copy-paste `curl`. Add
    `sanad client-config --format claude-code|cursor|vscode|json`.

46. **Rewrite the skills around the new flow, and add an operator skill.** The current
    `skills/sanad` is agent-side only and opens by requiring five things from an operator
    (gateway URL, authority URL, bootstrap token, principal token, server id). After item 43
    the interactive path needs none of them. Split into: `sanad-operator` (protect a server,
    write policy, revoke, investigate) and `sanad-agent` (connect, with the sidecar as the
    headless fallback). Fix the `pip install sanad-sdk` line — it is currently wrong in the
    skill as well as the README.

47. **Distribution:** publish a `ghcr.io/getsanad/sanad` image, a Homebrew tap, and
    `curl -fsSL get.sanad.dev | sh`. Today the only install path is cloning and building with
    Go 1.25+, which excludes most of the Python and TypeScript agent developers the SDKs target.

48. **A 60-second README quickstart.** The current README opens with a 30-second `make demo`
    that requires a clone and a Go toolchain, then explains repository layout. Lead instead
    with the one-command trial and the pasteable client config, and move layout below.

## Suggested order for Part 3

Items 41, 42, 44, 45 are self-contained and can land alongside Phase 0/1 — 42 in particular
should be built *with* Phase 1 item 11, since neither is useful alone. Item 43 is the
strategic one; schedule it once the fail-closed invariants are in place, because it puts a
standards-compliant front door on the gateway and the front door should not open onto an open
proxy. Items 46–48 follow whatever 41–45 settle on.
