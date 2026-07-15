# Nact architecture — how the app talks to the runtime

**This doc describes the target** — config delivered to the runtime as scoped
data over Nvoy. A **pragmatic V1 of the same shape is built and live** (see
`../nactor/`): identical endpoints and app, but the transport is HTTP + NIP-98
and the config lives in a local file instead of a grant. The two reconcile at
the end of this doc; the migration is contained (swap the config store's
read/write, keep everything else). Every primitive the target stands on already
runs in the ecosystem today: NIP-DA scoped grants (via Nvoy's MCP server),
NIP-59 DMs, SOPS on the box, and NIP-07/NIP-46 signing in the browser.

## The short version

The app does **not** call a server API. It writes your Nact config as an
**encrypted, scoped grant addressed to the runtime's npub** (a Nvoy / NIP-DA
grant); the runtime **decrypts it with its nsec** and reconciles the box to it.
Status flows back the same way. The "server" is a **nostr peer**, not an HTTP
endpoint — so there's no `/api`, no CORS, no session cookie, and no NIP-98 gate.
Authorization is carried by the grant itself: only you can sign a scope under
your key, and the runtime trusts config only from your npub.

```
   YOU (jaf@)                              THE BOX
   nsec on your device                     ┌──────────────────────────────┐
      │                                     │  Nactor                      │
      │ 1. publish config scope +           │   nsec (SOPS) ─ decrypts ─┐    │
      │    grant → runtime npub             │   npub  ◄─────────────────┘    │
      ▼          (Nvoy / NIP-DA)            │        reconciles box to it:   │
  [ relays ] ── encrypted scope ─────────►  │    • gen role keys (SOPS)      │
      ▲                                     │    • register webhooks         │
      │ 4. read queue / status              │    • apply routing + tiers     │
      │    grant ← runtime npub             │   role nsecs (SOPS) sign ──────┼─► relays
   the app (static files + relays,          └──────────────────────────────┘
   signs scopes with NIP-07/46)
```

## Three keypairs, three jobs

A NIP-DA grant is a scope **encrypted to the recipient's pubkey** — only the
holder of the matching **nsec** can open it. That's why each actor needs its own
keypair, and it's what keeps your sovereign key off the box:

| keypair | lives | job | verb |
| --- | --- | --- | --- |
| **you** — jaf@ | your device (never on the box) | sign the config/credential scopes | **grant** (authorization) |
| **the runtime** | on the box, SOPS-sealed | decrypt what you grant it | **receive** |
| **the roles** — luke@, nave@ | on the box, SOPS-sealed | sign the actual broadcasts | **act** |

Grant → receive → act. Your key authorizes; the runtime's key reads; the role
keys do. Your sovereign nsec never touches the box.

## Config is desired state, delivered as a grant

You publish the Nact config — identities, channels, routing, risk tiers — as an
**encrypted scope** and **grant it to the runtime's npub**. It's *desired state*,
not a command stream: "these identities exist, these channels exist, this is the
routing." The runtime dereferences it **live** and **reconciles reality to it**.

- Change the config in the app → publish a new version of the scope → the
  runtime reads the current one and converges.
- **Rotate the key → the runtime loses its config → revoked.** Same guarantee as
  any Nvoy data.

It's GitOps, but the "git" is a nostr scoped grant under your key.

### How the grant actually reaches the runtime: Nvoy's MCP server

Nvoy doesn't serve data over HTTP — it **mounts as an MCP server**. So the
runtime never speaks NIP-DA itself; it reads its config the way *any* agent reads
delegated data — an MCP tool call:

```
you (master) ── grant config-scope ──► runtime's npub          (NIP-DA, over relays)
Nvoy (holds the runtime's nsec) ── dereferences + decrypts the scope, live
   └── exposes it as an MCP tool:  get_config → { identities, channels, routing, tiers }
Nactor ── calls the MCP tool ── "zero nostr knowledge"
```

Nvoy handles the decrypt, the live-dereference, and revocation; the runtime just
gets current config JSON. The bot-token **credential-scope** arrives the same way
(another MCP-served scope). Rotate the grant → the MCP tool returns nothing → the
runtime is deconfigured.

### The reconcile loop (what the runtime does)

Idempotent, runs on every config change:

```
read the config grant (decrypt with runtime nsec)
for each declared identity:
    if custodial and no key on box → generate nsec on box, SOPS-seal, publish kind-0
    if NIP-46 → record the bunker pointer
for each declared channel:
    if it has a delivered credential-scope → decrypt token, register webhook
for routing + tiers:
    apply to the poster's live state
```

You pass **intent** ("want a custodial identity `scout@`"), never a key — the
runtime makes it real on the box. Your key is never involved in key-gen.

## Secrets ride as credential-scopes

Some config carries a secret the runtime must obtain — a Telegram **bot token**,
a channel **nsec**. These are delivered as **credential-scopes**: the exact
"credentials as scopes" mechanism in
[`nvoy/ROADMAP.md`](https://github.com/JAFairweather/nvoy/blob/main/ROADMAP.md) —
E2E-encrypted to the runtime's npub, live, revocable. The runtime decrypts, uses,
and **SOPS-seals at rest** (defense in depth). The secret never sits in a
database and is never echoed back to the browser.

## The reverse channel: status as a grant back to you

The app also needs to *read* — the pending queue, a new identity's npub, whether
a webhook registered. That's runtime→you, so the runtime publishes its
**status/queue as a scope granted to your npub**. The app reads the queue by
dereferencing a grant *from* the runtime.

Bidirectional grants — which is precisely the "a request is a grant *and* an
enact" symmetry recorded in
[`nostr-scoped-data-grants/FUTURE.md`](https://github.com/JAFairweather/nostr-scoped-data-grants/blob/main/FUTURE.md).
Perceive and act, both directions, all grants.

## What this collapses

- **No HTTP API surface.** The app is static files plus a relay connection; the
  runtime is a headless nostr peer. Nothing to attack but relays holding
  ciphertext.
- **No separate auth gate.** The signature on the scope *is* the authorization —
  the runtime accepts config only from your npub, so there's no NIP-98 session to
  mint or CORS to configure.
- **The browser signs with NIP-07 or NIP-46** — your master key stays in your
  extension or bunker; the app only ever emits signed scopes.

## Authorization model

The runtime is configured **once** with its master npub (at deploy — one
constant in SOPS/env). From then on it accepts config and credential grants only
from that npub. That single trust anchor replaces per-request authentication.

## Honest caveats

- **One bootstrap constant** — the runtime must be told its master npub once.
  That anchor is the whole trust root; guard it like any deploy secret.
- **Relay latency** — relay round-trips instead of a direct call. Fine for config
  (seconds); the approval queue is already nostr-native via the NIP-59 DM
  adapter, so it fits the same transport.
- **Secrets at rest** — credential-scopes are decrypted in memory and re-sealed
  with SOPS on the box; the master key never touches the box.
- **Versioning** — the config scope is replaceable / newest-wins, which is clean
  for a single master. Multi-admin would need an explicit merge rule.
- **Relay availability** — the runtime caches the last-known config and keeps
  running if relays are briefly unreachable; it converges when they return.

## V1 (built) vs the target

The V1 runtime proves the *pipeline* (propose → WYSIWYS enact → broadcast) with
real keys and a real gate. Only the config store's read/write differs from the
target; the endpoints and the app are identical, so the swap is contained.

| | V1 (built + live) | target (this doc) |
| --- | --- | --- |
| runtime identity | reads role keys from env | its own **nsec/npub** |
| config **read** | local `nact-config.json` | **Nvoy MCP `get_config`** — a scope granted to it |
| config **write** | HTTP `PUT /api/config` | publish a new scope version |
| auth | NIP-98 per request | the signature on the scope *is* the auth |
| secrets | env / SOPS | credential-scopes via Nvoy MCP |
| provisioning | identities = env keys | the reconcile loop (on-box key-gen, webhook register) |

The migration: point the runtime's config-read at Nvoy's MCP server instead of a
file, publish config as a scope from the app instead of `PUT`, and turn on the
reconcile loop. The NIP-98 HTTP path can stay as a fallback/local transport.

## How it relates to the rest

- [`threat-model.md`](threat-model.md) — WYSIWYS on the *act* side (what you
  sign). This doc is the *config / transport* side (how the runtime is told what
  to do).
- [`scoped-action-approvals.md`](scoped-action-approvals.md) — the optional
  approval-handshake NIP; orthogonal to config transport.
- **Nvoy ROADMAP** — credentials-as-scopes and the request-is-a-grant-and-enact
  symmetry; this doc is those ideas applied to Nact's *own* control plane.
- [`../DESIGN.md`](../DESIGN.md) "Three expressions" — the app is one expression
  of Nact; this is how that expression reaches the runtime.

The whole ecosystem folds in on itself: **Nvoy feeds the agent-runtime its
config the same way it feeds any agent its data.**
