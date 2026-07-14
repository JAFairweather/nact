# nact — design

## The four roles

```
  PROPOSER  →  APPROVAL BROKER  →  SOVEREIGN SIGNER  →  BROADCASTER
```

`nact` owns the middle-to-right: given a proposed action, route it to a human,
and on approval sign + broadcast. The **proposer** (drafting: LLM, signals,
voice) is your application's job — `nact` takes the finished unsigned event.

## Core (`src/nact.mjs`)

- `new Nact({ identities, relays, approval })` — resolves role keys into
  `{ sk, pk, npub }`; holds an in-memory map of pending proposals.
- `propose({ identity, event, context, replyTo })` — stamps an id, stores the
  draft, and hands it to the approval adapter's `send()`.
- `handleCallback(raw)` / `enact({ id, verb, approver })` — verify the human,
  then `finalizeEvent` with the identity's key and publish to the relays.

The signer is the point of the whole thing: **the key never leaves this
process's custody surface, and it only signs a discrete, human-approved
event.** No standing "post whenever" authority.

## Adapter contract

An approval adapter implements:

- `send({ id, identity, npub, draft, context }) → boolean` — deliver the
  Approve/Reject prompt to the human; return whether it was delivered.
- `parseDecision(raw) → { id, verb, approver } | null` — turn the channel's
  callback payload into a decision.
- `isApprover(approver) → boolean` — is this the authorized human?
- `ack({ id, result }) → void` — reflect the outcome back to the human.

`src/adapters/telegram.mjs` is the reference. Any channel that can show a
prompt and report a tap fits the same four methods.

## Extension points (designed, not yet built)

- **nostr-DM adapter (NIP-59 gift-wrap).** Deliver the proposal as an
  encrypted DM to the approver's own npub; they approve in any nostr client.
  Fully nostr-native — no third-party messenger, no extra trust surface.
- **NIP-46 signer mode.** Instead of a custodial role key in this process,
  request the signature from the human's remote signer (their phone). The
  key never touches a server at all. `Nact` would swap `finalizeEvent(...)`
  for a NIP-46 sign request keyed by `identity`.
- **Persisted pending store.** The in-memory map drops unresolved proposals on
  restart; back it with a file/db for durability across deploys.
- **Multi-approver / quorum.** `isApprover` generalizes to a set or an
  m-of-n rule.

## Relationship to the ecosystem

- **nvoy** governs the agent's *inputs* (scoped, revocable data grants).
- **nact** governs the agent's *outputs* (signature-gated actions).
- Together: **scoped autonomy** — an agent bounded on both what it may perceive
  and what it may do.
