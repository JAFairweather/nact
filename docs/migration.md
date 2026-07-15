# Migrating the box off `secrets.env` — onto Nact + Nactor

**Goal.** Today the whole environment is a flat, human-maintained SOPS file
(`secrets.enc.env`) baked onto the box, read directly by each service. The target
is the model in [`architecture.md`](architecture.md): the box's environment is
**reconstructed from Director-issued scoped grants** that Nactor reconciles —
config as a grant, secrets as credential-scopes, identities materialized on the
box. `secrets.env` stops being the source of truth; it becomes (at most) an on-box
cache Nactor writes.

This doc classifies what's in the env today, maps each piece to its Nact/Nactor
home, states the migration principles, and stages the build.

## What's in the env today (classification)

Every key currently in the platform's env, by *what it is* — because each class
migrates differently:

| class | keys | migrates to |
| --- | --- | --- |
| **A · role signing keys** | `LUKE_NSEC`, `NAVE_NSEC`, `NOIR_DIRECTOR_NSEC`, `NACT_CHANNEL_NSEC` | **identities** in config; the existing nsec is *imported once* as a credential-scope (never rotated — see below), Nactor SOPS-seals it |
| **B · provider credentials** | `ANTHROPIC_API_KEY`, `REPLICATE_API_TOKEN`, `TELEGRAM_BOT_TOKEN` | **credential-scopes** — E2E to Nactor's npub, live, revocable; SOPS-sealed at rest |
| **C · infra secrets** | `TELEGRAM_WEBHOOK_SECRET`, `PROPOSE_TOKEN`, `GATE_SECRET`, `OPENCLAW_GATEWAY_TOKEN` | credential-scopes (or stay SOPS-only if never rotated remotely) |
| **D · identities / addresses (public)** | `LUKE_MASTER_NPUB` / `NACT_DIRECTOR_NPUB`, `MY_NPUB`, `MASTER_NIP05`, `TELEGRAM_APPROVER_ID`, `MY_BUNKER_URI` | **config** — `directors[]`, channel `approver`, identity metadata (npubs are public; the bunker URI is a pointer, not a secret) |
| **E · operational config** | relays (`*_RELAYS`), models (`*_MODEL`), guardrails (`NOIR_RATE_LIMIT`, `NOIR_DAILY_CAP`, `NOIR_ALLOWED_ORIGINS`, `MAX_POSTS`, `SINCE_HOURS`), feeds (`SUBSTACK_FEED`, `NAVE_REPOS`, `PROPOSE_URL`), labels (`LUKE_MANDATE`, `LUKE_NAME`), TTLs, `ACME_EMAIL` | **config** — plain desired-state fields, per service |
| **F · pure runtime** | ports (`*_PORT`), `WS_NO_*` flags, `NACT_CONFIG` path | stay as deploy-time env — they're about *where the process runs*, not *what it does*; never secrets, never grants |

The ingest tool below applies exactly this table to a real dotenv.

## Migration principles

1. **Never rotate a live identity.** `luke@`, `nave@`, and the Noir Director npub
   are already published (NIP-05) and are the addresses existing nvoy grants point
   at. Their nsecs are **imported** (preserved), not regenerated. Only genuinely
   new identities are born on the box.
2. **SOPS stays as the at-rest floor.** The target doesn't delete SOPS — it moves
   the *source of truth* from "a file a human edits in git" to "scopes the Director
   grants." Nactor decrypts a credential-scope in memory and **re-seals it with
   SOPS on the box** (defense in depth, per `architecture.md`). The age key and the
   Nactor nsec are the two bootstrap secrets that stay box-local.
3. **One class at a time, reversibly.** Migrate a class, verify the box still
   serves, keep the old env path as a fallback until the grant path is proven —
   the same V1-vs-target discipline already in `architecture.md`.
4. **The Director's key never touches the box.** Migration is the Director signing
   config + credential scopes from their device; the box only ever *receives*.

## The one scope decision

How far does Nactor's reach extend?

- **Option 1 — Nact domain only (recommended first).** Nactor owns the
  approval-and-identity layer: role keys (A), the approval channels + their secrets
  (B/C for Telegram), directors (D), routing, and tiers. Noir's GM and Luke's brain
  keep their *app-specific* config (models, caps, feeds) in their own env. Clean
  boundary; already half-built (config + directors + identities exist).
- **Option 2 — whole-box config plane.** Nactor becomes the single source of truth
  for **every** service: each gets its config + secrets as grants Nactor reconciles
  onto the box, and `secrets.env` disappears entirely. This needs Nactor to grow a
  *provisioning actuator* (write each service's effective env/secret, register
  webhooks, restart) — which is [Nops](nops.md) territory (the `exec` actuator).

**Recommendation: stage it.** Do Option 1 first (it's the natural trust boundary
and mostly built), then extend Nactor's actuator toward Option 2 once the grant
path is proven. The classification and ingest tool below are identical either way —
only what Nactor *does* with the result differs.

## Staged plan

- **Phase 0 — inventory (this doc + the ingest tool).** Deterministically classify
  the real env into a config document + a secrets manifest. No secrets leave the
  box; the tool emits key *names* and classes, config *values*.
- **Phase 1 — Nactor as grantee.** Nactor gets its own nsec/npub (SOPS on box).
  Import the role nsecs (A) as one-time credential-scopes; publish identities.
  Move D + the Nact-domain slice of E into the config grant. Prove: the app
  configures identities/channels/directors/routing, Nactor reconciles, approvals
  flow — with the old env still present as fallback.
- **Phase 2 — credentials as scopes.** Move B/C to credential-scopes over Nvoy MCP;
  Nactor decrypts + SOPS-seals + registers the Telegram webhook from the granted
  token. Drop those keys from `secrets.env`.
- **Phase 3 — whole-box (optional, Option 2).** Nactor's provisioning actuator
  writes each service's effective config/secrets from grants and reconciles the
  running services. `secrets.env` retires to a bootstrap stub (age key + Nactor
  nsec only).

Each phase leaves the box working and is independently reversible.

## The ingest tool

[`nactor/migrate-env.mjs`](../nactor/migrate-env.mjs) reads a dotenv file and applies
the classification table above, emitting:

- a **config document** (classes D + E) with values — the desired-state seed for
  the Nact config grant;
- a **secrets manifest** (classes A + B + C) — key *names* and their class/target
  only, never values — the list of credential-scopes to issue;
- an **unknown** list — anything not in the rules, so the table stays honest as the
  env grows.

```
node nactor/migrate-env.mjs path/to/secrets.env > plan.json
```

It never prints a secret value, so its output is safe to inspect and commit as a
migration plan. It is the mechanical first step of Phase 0.
