# Sanad — Concepts in Plain English

This explains the ideas behind the project without assuming a security background.
If a term in the code or notes confuses you, it's probably defined here.

## The one-sentence idea

> AI agents are starting to *do real things* (move money, change code, read customer
> data). Sanad is a **security checkpoint** that checks *who is really behind
> an agent* and *what it's allowed to do* before letting it through — and gives it a
> short-lived **pass** instead of a permanent key.

Think of an **airport**:
- The **agent** is a traveler.
- The **MCP server** is the destination country (the system the agent wants to use).
- The **gateway** is passport control at the border.
- The **passport** we issue is like a single-trip visa: valid for one country, for a
  short time, for a specific purpose.

## The cast of characters

| Term | Plain meaning | Airport analogy |
|---|---|---|
| **Agent** | An AI program that takes actions on someone's behalf | A traveler |
| **MCP server** | A tool/system the agent wants to use (code, payments, data). "MCP" is just the common protocol agents use to talk to tools. | The destination country |
| **Principal** | The accountable human or organization behind the agent — *who we blame if it goes wrong* | The person the visa is actually about |
| **Gateway** | Our checkpoint that every agent must pass through | Passport control |
| **Passport** | The short-lived pass we issue after checks pass | A single-trip visa |

## Why the old way is risky

Today most agents carry a **long-lived API key** — basically a password that never
expires. Problems:
- It doesn't say *which human/company* is behind the agent.
- If it leaks, an attacker has access until someone notices and rotates it.
- It can't express "you may only do X, for the next 5 minutes, on this one system."
- It leaves a weak paper trail.

A permanent master key for everything is the thing we're replacing.

## How Sanad works (the four checks)

When an agent tries to reach a protected system, the gateway runs a short pipeline.
If **any** step fails, the request is **denied** ("fail closed" — when unsure, say no):

1. **Who's behind this?** (`principal auth`) — The agent presents a login token from the
   company's existing identity system. We verify it's genuine.
2. **Is anyone cut off?** (`kill-switch`) — If this principal/agent has been revoked, stop.
3. **Are they allowed to do this?** (`policy`) — Check the action against the rules. Default
   answer is **no** unless a rule explicitly says yes ("deny by default").
4. **Issue a pass** (`mint passport`) — Create a short-lived, single-purpose pass and
   forward the request. The agent's original login token is **thrown away, not passed on**.

The destination system only ever sees the **passport**, never the agent's real credentials.

## The key ideas, one at a time

### Passport = short-lived, single-purpose pass
Instead of a permanent key, the gateway issues a pass that:
- **expires in minutes** (so a stolen pass is useless almost immediately),
- works for **one destination only** ("audience-bound" — a pass for system A is rejected
  at system B),
- is scoped to **specific actions**.

This is the opposite of a master key, and it's why revocation is easy: we just *stop
issuing new passes* and existing ones expire on their own.

### Token isolation
The agent's real login credential **never reaches** the destination system. We strip it
and replace it with the passport. So even a compromised destination can't steal the
agent's real identity.

### Delegation chain + attenuation ("power of attorney")
Sometimes an agent hands work to a sub-agent, which hands it to another. A **delegation
chain** is the signed record of "X authorized Y authorized Z."

The crucial rule is **attenuation** — *each handoff can only give away the same or fewer
powers, never more.* Like a power of attorney: if you can spend up to $100, anyone you
delegate to can spend $100 or less — never more. We check the whole chain and reject it if
any link tries to widen its powers, or if any signature is faked.

### Revocation + kill-switch
**Revoking** = cutting off access. Because passports are short-lived, the main lever is
simply "stop issuing." The **kill-switch** is an instant deny-list the gateway checks: put
a principal or agent on it and they're blocked immediately. Revoking a principal
**cascades** to all of its agents (this is the P2-09 work).

### Audit log + tamper-evidence
Every decision is written to an **audit log** — a permanent record of who did what.
We make it **tamper-evident** with a **hash chain**: each entry carries a fingerprint of
the entry before it, so if anyone edits or deletes a past record, the chain breaks and we
can detect it. (Like a ledger where you can't tear out a page without it being obvious.)

The **investigation view** answers: "given this action, who is the responsible human, and
is the record intact?"

## The cryptography bits, demystified

You don't need the math — just the intuition.

### Public/private keys (and "Ed25519")
A **key pair** is two matched keys:
- a **private key** you keep secret and use to **sign** things,
- a **public key** you share so anyone can **check** your signature.

Only the holder of the private key can produce a valid signature, but *anyone* with the
public key can verify it. **Ed25519** is just the specific, modern, fast algorithm we use
(the same kind a modern SSH key uses). When we say "the passport is signed," we mean the
gateway used its private key, and systems use the gateway's public key to confirm it's real.

### "Signing" vs "encrypting"
We **sign** (prove authenticity + that nothing was altered), we don't encrypt the passport
contents. Anyone can read a passport; nobody can forge one without the private key.

### OIDC (how we check the human's login)
**OIDC** (OpenID Connect) is the standard most companies already use to log people in
(the tech behind "Sign in with..."). The agent presents a login token from the company's
identity provider; we verify it the same way any app would. We don't run our own password
system.

### JWKS (sharing public keys)
**JWKS** is just a small file the gateway publishes listing its **public keys**, so the
destination systems can fetch them and verify passports **offline** — without calling back
to us on every request (which keeps things fast). When we rotate to a new signing key, we
publish both old and new for a while so nothing breaks.

### Why not blockchain?
A common question. We need a tamper-evident, append-only record — but a blockchain is
slow, costs money per write, and can't honor "delete my data" laws. A hash-chained log
(plus optional independent witnesses later) gives the same tamper-evidence without those
downsides. See `docs/adr/ADR-003-audit-store.md`.

## How the code maps to these ideas

Each folder is one responsibility:

| Folder | Plain meaning |
|---|---|
| `gateway/` | The checkpoint that routes requests and runs the checks |
| `principal/` | Verifying the human/org behind the agent (OIDC) |
| `policy/` | The rules engine: "is this allowed?" (deny by default) |
| `revoke/` | The kill-switch / instant deny-list |
| `sts/` | Mints (creates and signs) the short-lived passports |
| `verify/` | A small library destination systems use to check a passport |
| `delegation/` | Signed handoff chains + the "can only narrow" rule |
| `audit/` | The tamper-evident record of every decision |
| `metrics/` | Health/speed numbers for operators |
| `jwks/` | Publishes the gateway's public keys |
| `sdk/` | A helper for agent developers to call through the gateway |
| `admin/` | The control panel: register/disable/revoke |

## Glossary (quick reference)

- **Agent** — an AI program taking actions.
- **Principal** — the accountable human/org behind the agent.
- **MCP server** — a tool/system the agent uses.
- **Gateway** — our checkpoint; nothing reaches a protected system without passing it.
- **Passport** — short-lived, single-destination, single-purpose pass.
- **Audience-bound** — a pass valid for exactly one destination.
- **Token isolation** — the agent's real credential is never forwarded.
- **Delegation chain** — signed record of who authorized whom.
- **Attenuation** — each handoff may only keep or reduce powers, never add.
- **Revocation / kill-switch** — cutting off access; instant deny-list.
- **Audit log** — permanent record of decisions.
- **Tamper-evident / hash chain** — edits to the past are detectable.
- **Fail closed** — when unsure, deny.
- **Key pair / Ed25519** — secret signing key + shareable checking key.
- **OIDC** — the standard company-login system we verify against.
- **JWKS** — published list of the gateway's public keys for offline checks.
