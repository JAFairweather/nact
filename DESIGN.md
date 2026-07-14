# nact — design

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

- `send({ id, identity, npub, draft, context }) → boolean` — deliver the
  Approve/Reject prompt to the human; return whether it was delivered.
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

- **nvoy** governs the agent's *inputs* (scoped, revocable data grants).
- **nact** governs the agent's *outputs* (signature-gated actions).
- Together: **scoped autonomy** — an agent bounded on both what it may perceive
  and what it may do.
