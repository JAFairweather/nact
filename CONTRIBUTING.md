# Contributing to Nact

Thanks for looking. Nact is small on purpose — a clean pipeline (propose →
enact → broadcast) with pluggable **approval adapters** and **signers**. Most
contributions slot into one of those two seams without touching the core.

## The shape

```
your proposer → Nact.propose() → approval adapter → you enact → signer → relays
```

- **Core** (`src/nact.mjs`) — the pending-proposal store and the enact pipeline.
  Keep it dependency-light and boring; it's the trust-critical part.
- **Adapters** (`src/adapters/`) — how a human is asked and how they answer.
  Implement `send`, `parseDecision`, `isApprover`, `ack` (each may be async).
  See `telegram.mjs` and `nostr-dm.mjs` for the two references.
- **Signers** (`src/signers/`) — where the authorizing key lives. Implement
  `publicKey()`, `sign(unsigned)`, `close()`. See `custodial.mjs` and
  `nip46.mjs`.

## Good first contributions

- **New approval adapter** — Signal, Matrix, a web-push endpoint, a
  Discord DM. Match the four-method contract; add an `examples/` wiring.
- **Persisted pending store** — the in-memory `Map` drops proposals on restart.
  A small file/SQLite backing behind the same interface.
- **Multi-approver / quorum** — generalize `isApprover` to an m-of-n rule.
- **A real proposer example** — show the pattern in a domain (release notes,
  moderation actions, zap-splits) we haven't demoed.

## Ground rules

- **Never** commit a key, token, or `.env`. Secrets live only in the deployer's
  environment. The whole point of Nact is that keys don't move — the codebase
  must model that.
- Keep the core's trust surface obvious. If a change touches signing or approver
  verification, explain the threat model in the PR.
- Match the surrounding style — no build step, plain ESM, comments that explain
  *why*.
- Add a focused check. The repo's smoke test wires an in-memory approval stub
  and asserts the enact path (sign → broadcast → ack), reject, and unauthorized
  cases; extend it for your seam.

## Running the checks

```bash
npm install
node examples/basic.mjs          # Telegram wiring (needs env)
node examples/nostr-native.mjs   # NIP-59 + NIP-46 wiring (needs env)
```

## Reporting

Security-relevant issues (a way to enact without the approver's signature, a key
leak path): email **help@nave.pub** rather than opening a public issue first.
Everything else: open an issue with what you tried and what happened.
