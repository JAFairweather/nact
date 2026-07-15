# Nact — design

## The four roles

```
  PROPOSER  →  APPROVAL BROKER  →  SOVEREIGN SIGNER  →  BROADCASTER
```

`nact` owns the middle-to-right: given a proposed action, route it to a human,
and on approval sign + broadcast. The **proposer** (drafting: LLM, signals,
voice) is your application's job — `nact` takes the finished unsigned event.

## Core (`src/nact.mjs`)

- `new Nact({ identities, relays, approval })` — resolves each identity into a
  **signer** (see below); holds an in-memory map of pending proposals.
- `propose({ identity, event, context, replyTo })` — stamps an id, stores the
  draft, and hands it to the approval adapter's `send()`.
- `handleCallback(raw)` / `enact({ id, verb, approver })` — verify the human,
  then ask the identity's signer to sign and publish to the relays.

The signing gate is the point of the whole thing: **the key only signs a
discrete, human-approved event** — no standing "post whenever" authority — and,
with the NIP-46 signer, the key never touches this process at all.

## Signers (`src/signers/*`)

An identity config resolves to a signer, so *where the key lives* is pluggable
and independent of *how the human is asked*:

| config | signer | key lives | when |
| --- | --- | --- | --- |
| `{ nsec }` | `custodial` | in this process (ideally SOPS-encrypted at rest) | a role key you've explicitly decided a server may hold |
| `{ bunker, clientSecret? }` | `nip46` | on your device, behind a bunker | your sovereign identity — the key must never touch a server |
| `{ signer }` | your own | anywhere | any object with `publicKey()` / `sign()` / `close()` |

A signer implements `async publicKey()`, `async sign(unsigned)`, and
`async close()`. The NIP-46 signer resolves lazily — the bunker isn't contacted
until an identity is first used — and a bunker declining to sign is treated as a
legitimate **second veto** (approver taps enact, bunker still refuses), reported
back through the same ack channel, not a crash.

## Adapter contract

An approval adapter implements:

- `send({ id, identity, npub, draft, context, fingerprint, report }) → boolean`
  — deliver the Approve/Reject prompt to the human; return whether it was
  delivered. `fingerprint` is the event id of the frozen bytes (re-checked before
  signing); `report` is the WYSIWYS inspection (`kindLabel`, `risk`, `tags`,
  `warnings`) — render it so the human sees the *actual* action. See
  `docs/threat-model.md`.
- `parseDecision(raw) → { id, verb, approver } | null` — turn the channel's
  callback payload into a decision.
- `isApprover(approver) → boolean` — is this the authorized human?
- `ack({ id, result }) → void` — reflect the outcome back to the human.

`send`, `parseDecision`, `isApprover`, and `ack` may each be sync or async —
`nact` awaits them — so an adapter that unwraps encrypted DMs fits the same
shape. Two adapters ship:

- **`src/adapters/telegram.mjs`** — an Approve/Reject card in a dedicated
  Telegram bot; the card edits in place to show the outcome.
- **`src/adapters/nostr-dm.mjs`** — the native path (below).

### Nostr-DM adapter (NIP-59 / NIP-17)

`nostrDmApproval({ channelNsec, approver, relays })` delivers each proposal as a
gift-wrapped (NIP-59) NIP-17 chat message to the approver's npub. The approver
reads it in any NIP-17 client and replies `ok <id>` / `no <id>`; that reply is
itself a signed, gift-wrapped DM, so the approval is authenticated by *their*
key — no bot account, no platform, entirely inside nostr.

- `channelNsec` is a **low-value carrier key** whose only job is to send/receive
  approval traffic; it can't enact anything — authority is the approver's
  signature (and, paired with the NIP-46 signer, their bunker).
- `listen(onWrap)` subscribes for the approver's wrapped replies and feeds each
  raw wrap to `nact.handleCallback`. A `since` floor skips history so restarts
  don't re-fire old DMs.
- The verb+id matcher requires the id right after the verb, scoping a decision
  to exactly one proposal and avoiding stray 8-char-word false matches.

## Extension points (designed, not yet built)

- **Persisted pending store.** The in-memory map drops unresolved proposals on
  restart; back it with a file/db for durability across deploys.
- **Multi-approver / quorum.** `isApprover` generalizes to a set or an
  m-of-n rule.

## Relationship to the ecosystem

- **Nvoy** governs the agent's *inputs* (scoped, revocable data grants).
- **Nact** governs the agent's *outputs* (signature-gated actions).
- Together: **scoped autonomy** — an agent bounded on both what it may perceive
  and what it may do.

## Three expressions of one thing

Nact is the enactment **protocol** (propose → approve → sign → broadcast), and it
shows up in three forms under one name — unlike Nscope→Nvoy, where the app is one
of many on the protocol. Here the app *is* the protocol made usable, so it keeps
the Nact name:

- **the pattern** — the four roles and the trust model (this doc).
- **the library** (`nact` on npm) — the runtime that runs the pipeline; what an
  agent or app imports.
- **the app** (nact.nave.pub) — the human **control plane**: construct and
  manage approval channels, and grant or revoke an agent's authority to act. The
  mirror of Nvoy on the perceive side. It reaches the runtime not through an HTTP
  API but by granting it the config as scoped data — see
  [`docs/architecture.md`](docs/architecture.md).

### What the app manages

An **approval channel is itself a scoped grant** — of *approval authority*, not
data. So the app is a grant manager, built (like Nvoy) on the same NIP-DA
primitive:

- **Identities** the agent may act as (custodial or NIP-46).
- **Channels** — Telegram, NIP-59 nostr-DM, later Signal / Matrix / web-push —
  bound to identities.
- **Scoped authority** — which identities, which event kinds, rate limits,
  per-proposal TTL, m-of-n quorum, time windows.
- **Queue + history** — what's pending, what was enacted or rejected, an audit
  trail.
- **Revoke in one move** — rotate the channel key or the identity's authority and
  the agent instantly loses the right to propose. Nvoy's *un-see it* becomes
  *un-authorize it*.

The library is the runtime; the app is the control plane that configures it —
the same idea seen from two sides, under one name.

### Nactor — the runtime

Deployed on a box with its own keypair and an actuator, the library runs as
**Nactor** — the on-box *actor* that receives config/proposals (as scoped data)
and enacts. Its actuator is pluggable: **publish to relays** for Nact, **exec on
the box** for [Nops](docs/nops.md). Same actor, different enactment. See
[`nactor/`](nactor) and [`docs/architecture.md`](docs/architecture.md).

## Two directions the primitive wants to grow

These aren't built yet — they're the design's natural next moves, recorded so we
build toward them deliberately.

### Credentials as scopes — nvoy carries more than data

The NIP-DA mechanism (an encrypted **scope**, a gift-wrapped **grant**, live
dereference, revocation-by-key-rotation) isn't limited to documents. The same
wire can carry a **credential** — an OAuth token, an API key, a session — into
an agent flow:

- A **broker** authenticates to an OAuth provider, obtains a token, and delivers
  it to the agent *as a scoped grant*: end-to-end encrypted to the agent's key,
  so the broker's server holds the data no longer than it takes to hand it over.
- It's **live** — the broker refreshes the token in place; the agent always
  dereferences the current one, never a stale copy pasted into its prompt.
- It's **severable** — rotate the grant's key and the agent's use of the
  credential dies instantly. That's a delegatee-level revocation OAuth itself
  doesn't give you.
- It's **scoped** — the grant carries exactly the one credential the flow needs.

A credential is higher-value than ordinary data, so this pairs naturally with
Nact's approval gate (a human *enacts* the granting of a credential) and short
TTLs. Net effect: an agent gets **use** of a credential for a bounded flow
without that credential entering its long-term storage, its logs, or its model
context.

### Requests that are grants and enacts at once — the loop closes

So far the roles are fixed: grants flow human→agent (perceive), actions flow
agent→(human enacts)→world (act). But an agent can **initiate** a scoped-data
request from a *named provider*, and that single request is two things at once:

1. a **scoped grant** — the agent grants the provider scoped, revocable access
   to the request itself (the query, the context the provider needs), and
2. an **enact request** — it asks the provider to *act*: assemble the data,
   decide whether to approve, and return it.

The provider, on approval, assembles the result and returns it as **another
scope** — a grant back to the agent:

```
  agent    → [ request = grant(params) + enact-request ] → provider
  provider → [ approve + assemble ]                      → agent
  provider → [ response = grant(data) ]                  → agent
```

This is where **nvoy and Nact turn out to be one primitive seen from two
sides**: a *data request is an action* (nact-shaped — proposed, approved,
fulfilled), and *fulfilling it produces a grant* (nvoy-shaped — scoped, live,
revocable). The provider's "approval" is exactly an **enact** — a signature
authorizing the assembly-and-return. And because the reply is a scope, the
provider keeps revocation power over what it returned: rotate the response
grant's key and the agent's copy stops opening.

What it buys:

- **Providers become first-class** — named and discoverable over NIP-05, able to
  publish which scopes they'll fulfill and on what terms.
- **Composition** — an agent chains: request from provider A, then use A's
  returned scope as a param-grant in a request to provider B, with revocation
  propagating along the chain.
- **Symmetry** — the same event shapes serve human→agent and agent→provider;
  only the roles rotate. Perceive and act stop being separate systems and become
  two directions of the same signed, scoped exchange.
