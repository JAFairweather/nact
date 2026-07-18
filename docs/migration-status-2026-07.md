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
| 2b · delivery (grants) | credentials arrive as Director-signed scopes, env keys retired | **BUILT, NEVER USED** — every credential still arrives bootstrap-env; zero grants issued; zero env keys retired |
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

## 5. The path back — staged, small, reversible

- **M1 · Re-inventory (Phase 0 refresh).** Run `migrate-env.mjs` over the real
  current envs (luke.env + nactor.env + brain.env + openclaw.env + luke-mail.env);
  commit the names-only manifest; retire dead keys (`PROPOSE_TOKEN`,
  `OPENCLAW_GATEWAY_TOKEN`-legacy) while there.
- **M2 · First grant (pilot): `telegram-luke`.** Director-side flow — Nact app
  (or a 20-line CLI on the Director's device): NIP-44-encrypt the token to
  Nactor's npub, NIP-98-sign `PUT /api/credential`. Nactor RAM-imports (path
  already proven by smoke test). Verify the morning brief still sends, then
  **delete the line from nactor.env**. First credential to meet the acceptance
  criterion; the pattern is then mechanical.
- **M3 · `gworkspace` + `anthropic` + approvals `telegram` as grants.** Same
  flow; retire each env key on verify. `secrets.enc.env` shrinks to classes A +
  D/E remnants.
- **M4 · Restart-resilience decision.** Grants are re-fetchable; choose per
  migration.md principle 2: re-import on restart (from relays / Director
  re-issue) vs Nactor's *private* optional SOPS cache. Default: re-fetch;
  cache only if relay availability bites.
- **M5 · Nmail adapter (#36).** Verb-scoped IMAP proxy in Nactor; app password
  becomes RAM-only, `mail/app-passwd` and the config-mounted secret path are
  deleted; then the password itself arrives as a grant.
- **M6 · Engine egress.** Point the engine's model calls at `/api/proxy`
  (dummy-token) and drop `ANTHROPIC_API_KEY` from openclaw.env; decide
  `OPENCLAW_GATEWAY_PASSWORD`'s tier (likely stays bootstrap-C).
- **M7 · Config over Nvoy MCP.** The architecture.md transport swap: config +
  credential scopes read via `get_config`-style MCP tools; HTTP stays fallback.
  This completes Phase 2b→3 and opens v2 (enclave role keys).

Each milestone ends with: *verify consumer works → delete the env copy → note
it here.* No milestone leaves two live sources of truth.

## 6. Standing rules (so tonight doesn't repeat)

1. **New secret? It gets a grant plan before it gets a home.** If the grant
   flow isn't ready, it may sit in `secrets.enc.env` (bootstrap tier) with an
   entry in §3 — never in an untracked box-local env.
2. **No consumer reads a secret from disk.** Broker it, proxy it, or adapter
   it. (Current violation: himalaya's app-passwd file — closes in M5.)
3. **Wrong identity is worse than no message.** Voice-bearing credentials
   (bots, signing keys) never substitute for each other; senders fail silent.
4. **Re-read the design doc before touching custody.** It exists; it was right.
