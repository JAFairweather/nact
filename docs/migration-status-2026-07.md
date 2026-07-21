# Credential-grant migration — design spec + status review (2026-07-17)

Written after a night of drift. The build spree (engine upgrade, calendar, email,
morning brief) added real capability but parked four new secrets in box-local
env files and, at one point, proposed exactly the env-cache intermediate that
[`migration.md`](migration.md) principle 2 names a dead end. This doc restates
the target so it can't blur again, reviews where every credential actually sits
today, and stages the path back — with the acceptance criterion the Director set
tonight:

> **A secret is migrated when its only durable home is a Director-signed scoped
> grant (NIP-44-encrypted to Nactor's npub, revocable, on relays), its runtime
> home is Nactor RAM, and every env copy is deleted.**

## 1. The target, restated (normative)

Per [`architecture.md`](architecture.md) — grant → receive → act:

- **Delivery.** A Director, from their device, encrypts each credential to
  Nactor's npub and publishes it as a scoped grant (NIP-DA / Nvoy). The
  Director's key never touches the box. Revocation = key/grant rotation,
  propagating on next read.
- **Custody.** Nactor decrypts and holds values **in RAM only**. Nothing
  services-facing on disk. The only sanctioned box-resident secrets are the two
  bootstrap keys: the `age` key and `NACTOR_NSEC`.
- **Consumption.** Consumers never hold provider credentials. Our code brokers
  through `/api/broker` (NIP-98 as an activated identity); third-party engines
  use the dummy-token egress proxy; protocol clients (IMAP) will use verb-scoped
  protocol adapters ([`imap-adapter.md`](imap-adapter.md)).
- **Transports.** V1 delivery = `PUT /api/credential` (NIP-98 Director-signed,
  NIP-44 ciphertext — **built, unused**). Target delivery = scopes served over
  Nvoy's MCP, same as config. The HTTP path remains a local fallback.
- **SOPS' place.** `secrets.enc.env` is the *legacy being drained*, kept only as
  Phase-1/2 bootstrap. It is not the destination and new secrets should not
  settle there on their way to a grant — that's motion, not migration.

## 2. Status by phase (honest)

| Phase | Definition | Status |
| --- | --- | --- |
| 0 · inventory | classify env via `migrate-env.mjs` | **STALE** — predates tonight's four new secrets; re-run needed |
| 1 · grantee + activations | Nactor nsec/npub; Director activates role identities | **DONE** — luke, nave, brain activated; bootstrap Director anchored |
| 2a · consumption (broker) | consumers reach providers only through Nactor | **LIVE and carrying real traffic** — see table below |
| 2b · delivery (grants) | credentials arrive as Director-signed scopes, env keys retired | **LIVE, CARRYING ALL 7 (verified 2026-07-21)** — grants were issued 2026-07-18 (ahead of this doc — see §3 correction); the reader loads every credential from relay scopes each sweep. Env fallback lines remain only for `anthropic` + approvals `telegram` — delete on verify closes M4 |
| 3 · whole-box | every service brokered; env → bootstrap stub | not started |
| v2/v3 · agent residency | role keys to enclave/NIP-46; agent protocol-resident | design only |

The asymmetry is the finding: **2a raced ahead (five providers brokered), 2b
never started.** The broker made env custody *feel* solved because consumers
stopped seeing secrets — but the secrets themselves still live and die with the
box.

## 3. Credential inventory — where every secret actually is tonight

Tier key: **G** = grant-delivered (target) · **S** = SOPS root (`secrets.enc.env`)
· **B** = box-local plaintext env (gitignored) · **D** = on-disk file read by
consumers · **E** = engine SecretRef store.

> **2026-07-21 correction — the box moved ahead of this table on 2026-07-18.**
> The Nvoy Ledger + a runtime probe (container env names + reader logs) show:
> every provider credential below now arrives as a Director-signed scope
> (`credential:{telegram-luke, gworkspace, anthropic, telegram,
> telegram-nactjaf, telegram-brain, telegram-nave}` — the last two are
> beyond-plan per-agent comms bots), the reader loads all of them each sweep,
> and the env copies for `TELEGRAM_LUKE_BOT_TOKEN` and `GOOGLE_OAUTH_*` are
> already deleted. Still bootstrap-env on the box: `ANTHROPIC_API_KEY` and
> approvals `TELEGRAM_BOT_TOKEN` (both now redundant fallbacks — grant-sourced
> values override them; delete on verify). `GEMINI_API_KEY` is gone from the
> env with no `google` grant issued — the `google` broker credential currently
> exists nowhere; re-grant it or retire the provider entry. Rows below are as
> written 2026-07-17 — read them with this correction.

| credential | class | today | brokered use | target | gap |
| --- | --- | --- | --- | --- | --- |
| `ANTHROPIC_API_KEY` | B | **S** → luke.env → RAM; *duplicated* in openclaw.env for the engine | ✓ anthropic (brain drafts) | G; engine via egress proxy | grant; unwire engine copy |
| `TELEGRAM_BOT_TOKEN` (approvals) | B | **S** → luke.env → RAM | ✓ telegram (poster + cards) | G | grant; retire env key |
| `TELEGRAM_LUKE_BOT_TOKEN` | B | **B** (nactor.env, bridged tonight from a pre-vault backup) + **E** (engine's own copy — legitimate: it runs the bot) | ✓ telegram-luke (morning brief) | G for Nactor's copy | first grant pilot (M2) |
| `GOOGLE_OAUTH_*` (gworkspace) | B | **B** (nactor.env) | ✓ gcal + gmail (OAuth mint in RAM) | G | grant; retire env |
| `GMAIL_APP_PASSWORD` | B | **B** (luke-mail.env) **+ D** (`mail/app-passwd` read by himalaya in two containers) — worst tier in the system | ✗ (protocol, not HTTP) | G + Nmail verb-scoped adapter | build #36; delete disk file; grant |
| `OPENCLAW_GATEWAY_PASSWORD` | C | **B** (openclaw.env, minted tonight) | n/a (engine-internal) | C-class: scope or stay bootstrap (never remotely rotated) | decide in M6 |
| `LUKE_NSEC` / `NAVE_NSEC` | A | **S** (intentional per Phase 1 — durability for one-tap signing) | activations ✓ | v2: enclave / NIP-46 | unchanged, correct |
| `BRAIN_NSEC` | A | **S** → brain.env | signs NIP-98 to broker ✓ | v2 | unchanged, correct |
| `NACTOR_NSEC`, box `age` key | bootstrap | **B** by design — the two sanctioned box secrets | — | unchanged | none |
| `TELEGRAM_WEBHOOK_SECRET`, `PROPOSE_TOKEN` | C | **S** | — | scope or retire (PROPOSE_TOKEN superseded by NIP-98) | retire dead keys in M1 |

Also on the box, outside this table's scope: the engine's own SecretRef store
(its telegram token, properly encrypted — the engine is a legitimate
credential-holder for the channel it runs), and `luke-brain-deploy.key` (backup
repo deploy key, class C).

## 4. Drift log — what actually happened tonight (so it's never mystery-meat)

1. Four secrets entered at tier **B/D** (`GOOGLE_OAUTH_*`, `GMAIL_APP_PASSWORD`
   + disk file, `OPENCLAW_GATEWAY_PASSWORD`, `TELEGRAM_LUKE_BOT_TOKEN`) —
   expedient, off-design.
2. A "consolidation to SOPS" apparatus was built — the exact env-cache
   intermediate migration.md warns against. Superseded by this doc; the script
   stays only as a disaster-recovery sweep, not a migration step.
3. Three misdirected sends went out via the approvals bot while wiring the
   brief; fixed structurally (wrong voice now impossible — Luke's bot or
   silence).
4. Root cause: building against memory of the design instead of re-reading it.
   The docs were right; the drift was operational.
5. **2026-07-18 — a second drift, same root cause.** Reached for a bespoke
   `grant.html` + HTTP `PUT /api/credential`→RAM as "the delivery half," when
   Nvoy is the grant tool and credentials are relay-resident scopes Nactor reads
   on boot. Retracted `grant.html`; §5 rewritten to the actual target. The
   HTTP-PUT path (and `issue-credential.mjs`) stay only as a labelled fallback.

## 5. The path back — corrected 2026-07-18 to the relay-resident target

**The correction (Director's, 2026-07-18):** the delivery transport is NOT an
HTTP `PUT /api/credential` into RAM. That endpoint (and its CLI twin
`issue-credential.mjs`, and the retracted `grant.html`) is the V1 *fallback* and
recreates the ephemerality the protocol exists to solve. The **target — and the
plan — is what architecture.md already says**:

- **Nvoy is the grant tool.** Credentials are issued as **NIP-DA credential-
  scopes** from Nvoy's console (`nvoy.nave.pub`, `console/nvoygrant.mjs`) — the
  token rides as the scope's data, gift-wrapped and granted to Nactor's npub,
  with terms. The Director's key signs via NIP-07 and never touches the box.
  *This side is already built and deployed.*
- **Nactor reads its grants from the relays.** On boot and on a timer, Nactor
  dereferences the credential-scopes granted to its npub **with its own nsec**,
  decrypts, and loads the values into RAM. **There is no restart problem and no
  cache** — a restart just re-reads from the relays. **Revocation = the Director
  rotates the scope key in Nvoy** → Nactor's next read fails to decrypt → the
  credential is gone. Same guarantee as any Nvoy data. *This is the one missing
  piece — on the Nactor side only.*

Restated acceptance criterion: **a credential is migrated when it exists only as
a Nvoy-issued scope on the relays, Nactor loads it by reading that scope, and no
env copy remains.** RAM is the runtime home; the *relays* are the durable home.

- **M1 · Re-inventory — DONE (2026-07-18).** `migrate-env.mjs` classifies all 25
  live keys with zero unknowns; the agent-era secrets are now in its rules.
- **M2 · Nactor credential-scope reader (the real delivery) — DONE (2026-07-21,
  nact#1).** The NIP-DA read path, live on boot + a 5-minute timer
  (`nactor/grant-reader.mjs`, offline-tested against the in-memory relay;
  self-contained — no dependency on Nvoy's MCP for V1). What shipped, beyond the
  original recipe:
  - **Two readers, per credential-sovereignty.md.** `syncCredentialGrants` reads
    *Nactor's own* grants and loads values into `CREDS` (the broker's supply);
    `syncIdentityEntitlements` reads *each runtime identity's* grants with that
    identity's key and derives the entitlement map the broker gates on
    (enforcement stays off by default). Identities imported at runtime are swept
    without a restart. The A2 end state — credential *ciphertext* re-addressed to
    the owning identity — is decided per-credential from M3 on.
  - **Director-only trust.** A grant is honored only if its publisher is in the
    live Director set — a spoofed scope gift-wrapped to Nactor's npub by anyone
    else is counted and ignored, never loaded.
  - **Revocation semantics, tested.** Scope-key rotation drops the credential on
    the next sweep; revoking an identity's *last* grant clears its entitlement
    (a successful read of zero grants is authoritative); a transient relay
    failure never strips anything — asymmetric by design.
  - **Env fallback flagged.** The set of credentials still bootstrap-env-sourced
    is logged at boot and on change, and `/api/state.credentials[].source` shows
    per-credential provenance (`grant` / `bootstrap-env` / `director-put`) —
    names only, never values. The honest measure of migration remaining.
  - **Runtime audit (AD-1).** Every observation transition — grant-load /
    grant-update / grant-drop, entitlement-gain / entitlement-loss — lands as a
    timestamped event in `/api/state.history` and the Nact History tab. The
    issuance-side lifecycle stays in Nvoy's Ledger.
  - **Tolerant payload keys.** `.value` is canonical (what Nvoy's console
    issues); `.secret`/`.key`/`.api_key`/bare-string are honored on read so one
    issuance feeds every reader (warm.contact's Swift reader accepts
    `key`/`api_key`/`value`).
- **M3 · Issue the pilot from Nvoy: `telegram-luke` — DONE (issued 2026-07-18,
  verified 2026-07-21, nact#2).** The scope was created from `nvoy.nave.pub`
  via the request→Issue loop (the Ledger's purpose line is
  `request-credential.mjs`'s default), granted to Nactor's npub, and the env
  line is deleted — the runtime probe shows `TELEGRAM_LUKE_BOT_TOKEN` absent
  and the reader logging `credential-grants: loaded [telegram-luke, …]` every
  sweep. **Rollback path:** re-add the env line to `nactor.env` from the
  Bitwarden note and restart — the bootstrap-env loader stays wired and a
  grant-sourced value simply overrides it again once the relays are readable.
  (Same rollback shape applies to every migrated credential.)
- **M4 · Migrate the rest as scopes — ISSUED (2026-07-18); two env retirements
  remain.** `gworkspace`, `anthropic`, approvals `telegram` (+ beyond-plan
  per-agent comms bots `telegram-brain`, `telegram-nave`) are all issued from
  Nvoy and read by Nactor each sweep. `GOOGLE_OAUTH_*` env is retired.
  Outstanding: delete `ANTHROPIC_API_KEY` and `TELEGRAM_BOT_TOKEN` from the
  box env after verify — the latter completes the approvals-bot flip to
  `@navenactorbot` (the granted `telegram-nactjaf` re-issue carries the new
  token; the env line still holds the old bot's), so verify approvals arrive
  from the new bot before deleting. Note: `GEMINI_API_KEY` left the env with
  no `google` grant issued — decide re-grant vs retire the provider.
- **M5 · Nmail adapter (#36).** Verb-scoped IMAP proxy; the Gmail app password
  becomes a credential-scope + RAM-only; `mail/app-passwd` deleted.
- **M6 · Engine egress.** Engine model calls → `/api/proxy` (dummy-token); drop
  `ANTHROPIC_API_KEY` from openclaw.env.
- **M7 · Nvoy MCP transport (the fuller target).** Nvoy's MCP holds Nactor's
  nsec and serves config + credential scopes as MCP tools; Nactor reads with
  "zero nostr knowledge." Completes Phase 2b→3, opens v2 (enclave role keys).

Each milestone ends with: *verify consumer works → delete the env copy → note it
here.* No milestone leaves two live sources of truth, and no milestone reaches
for a local cache — the relays are the store.

## 6. Standing rules (so tonight doesn't repeat)

1. **New secret? It gets a grant plan before it gets a home.** If the grant
   flow isn't ready, it may sit in `secrets.enc.env` (bootstrap tier) with an
   entry in §3 — never in an untracked box-local env.
2. **No consumer reads a secret from disk.** Broker it, proxy it, or adapter
   it. (Current violation: himalaya's app-passwd file — closes in M5.)
3. **Wrong identity is worse than no message.** Voice-bearing credentials
   (bots, signing keys) never substitute for each other; senders fail silent.
4. **Re-read the design doc before touching custody.** It exists; it was right.
