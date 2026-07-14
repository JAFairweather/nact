# nact

**Give an AI agent the ability to act on nostr — it drafts the action, you
enact it with a signature, your keys never move.**

`nact` is the missing safety layer for agentic nostr. An agent (Claude or
anything else) can *propose* any nostr action — a note, a reaction, a follow,
a zap, a profile edit, a NIP-DA grant — but nothing happens until a human
**enacts** it by signing. The agent never holds the identity key. Human-in-
the-loop isn't a setting you can forget to enable; it's the architecture.

> The agent proposes. You enact it by signing.

## Why

Almost every "AI posts to social" integration hands the bot the credentials —
which is why nobody sane points one at their real account. `nact` inverts
that: the **authorization is your signature**, and the key that produces it
stays with you. The agent can compose, schedule, and publish on your behalf,
but every outbound action passes through a human tap.

It's the action-out half of **scoped autonomy**:

| | governs | direction |
|---|---|---|
| [nvoy](https://github.com/JAFairweather/nvoy) | what the agent may **perceive** (scoped data grants) | in |
| **nact** | what the agent may **do** (signature-gated actions) | out |

An agent that operates inside a data boundary *and* an action boundary.

## The four roles

```
  PROPOSER  →  APPROVAL BROKER  →  SOVEREIGN SIGNER  →  BROADCASTER
  your app     (routes to human)   (human's key signs)   (publishes)
```

- **Proposer** — *your* code. Drafts an unsigned event (kind + content +
  tags) and hands it to `nact`. This is where the LLM / signals / voice live.
  `nact` doesn't prescribe it.
- **Approval broker** — routes the proposal to the human and collects the
  decision. Ships with two adapters: **Telegram**, and a **nostr gift-wrap
  DM** adapter (NIP-59 / NIP-17) that delivers the proposal to your own npub
  so you approve in any nostr client — fully nostr-native, no third party.
- **Sovereign signer** — turns approval into a signature. Two signers:
  **custodial role-key** (encrypted on your box — easy) or **NIP-46**
  (your key stays in your phone signer — maximal sovereignty). `nact` never
  puts your *personal* key on a server; role identities are your call.
- **Broadcaster** — publishes the finished, signed event to relays.

## Quickstart

```js
import { Nact } from 'nact'
import { telegramApproval } from 'nact/adapters/telegram'

const nact = new Nact({
  // role identities the agent may act as (custodial nsecs, or NIP-46 signers)
  identities: {
    nave: { nsec: process.env.NAVE_NSEC },
    luke: { nsec: process.env.LUKE_NSEC },
  },
  relays: ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'],
  approval: telegramApproval({
    botToken:  process.env.TELEGRAM_BOT_TOKEN,
    approverId: process.env.TELEGRAM_APPROVER_ID, // only this human may enact
    webhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET,
  }),
})

// your proposer drafts an action and asks for it to be enacted:
await nact.propose({
  identity: 'nave',
  event: { kind: 1, content: 'nave.pub now serves NIP-05 for luke@ and nave@.' },
  context: 'shipping note — verified handles are live',   // shown to the human, not published
})
// → the human gets an Approve/Reject card. On approve, nact signs with the
//   nave role key and broadcasts. On reject, nothing happens.
```

Wire the approval broker's callback (e.g. the Telegram webhook) to
`nact.enact(decision)` and you're done.

### Fully nostr-native (no Telegram, key stays on your phone)

Deliver approvals as encrypted DMs to your own npub, and sign with your
NIP-46 bunker — nothing custodial, no third-party messenger:

```js
import { Nact } from 'nact'
import { nostrDmApproval } from 'nact/adapters/nostr-dm'

const approval = nostrDmApproval({
  channelNsec: process.env.NACT_CHANNEL_NSEC, // low-value carrier key; can't enact
  approver:    process.env.MY_NPUB,           // only this npub may enact
  relays,
})

const nact = new Nact({
  identities: { me: { bunker: process.env.MY_BUNKER_URI } }, // key lives on your phone
  relays,
  approval,
})

approval.listen(wrap => nact.handleCallback(wrap))  // receive your replies

// proposals now arrive as a DM; reply "ok <id>" in any NIP-17 client to enact.
await nact.propose({ identity: 'me', event: { kind: 1, content: 'hello, sovereignly.' } })
```

Two independent gates now stand between the agent and a post: you tap **enact**
in your DM client, and your **bunker** signs. Neither the agent nor the carrier
key can produce a valid event.

## Safety model

- **Keys never leave the human's custody surface.** Role keys are custodial
  by *your* explicit choice (encrypt them — e.g. with SOPS); your sovereign
  identity should use NIP-46 and never touch a server.
- **Only the configured human may enact.** Approvals are checked against a
  single identity (Telegram id, or an npub in the nostr-DM adapter).
- **Every action is discrete and reviewed.** The human sees the exact event
  and a rationale before signing. No standing "post whenever" authority.

## Relationship to NIP-46

`nact` composes with [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)
rather than replacing it. NIP-46 answers "how does a remote signer approve a
signature?"; `nact` adds the layer above it: **an agent that drafts the event
in the first place, and an asynchronous, messaging-based approval flow** fit
for an agent that proposes on a schedule and a human who enacts whenever.
Use the NIP-46 signer mode and your key never leaves your phone.

## Status

Extracted from the Nave ecosystem's Luke agent, where the custodial signer +
Telegram adapter run the live twice-daily posting loop. The **NIP-46 signer**
and the **NIP-59 nostr-DM adapter** are now built (see `DESIGN.md` and
`examples/`) — the nostr-native path is here, not just designed. Next: a
persisted pending store and multi-approver quorum.

## Contributing & community

nact is small on purpose — most contributions slot into an **approval adapter**
or a **signer** without touching the trust-critical core. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the seams and ground rules, and
[`COMMUNITY.md`](COMMUNITY.md) for where nact is headed in the nostr ecosystem
and how to help it get there.

---

Part of the [Nave](https://nave.pub) ecosystem · a nave.pub project
