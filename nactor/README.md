# Nactor — the Nact runtime

The on-box **actor** that receives config/proposals and enacts: a NIP-98-gated
HTTP control-plane over the Nact library. The control-plane app (`app.html`)
talks to this; only a configured **Director** may read the queue, enact, or edit
config. The Director is the human decision-maker — **not** Noir's AI "Director".
Directors live in the config (`directors[]`), seeded by a bootstrap env anchor
that can't be locked out, so co-Directors are added from the app without a
redeploy. Role signing keys come from the environment (SOPS-decrypted on the box)
and never leave it.

The app and the runtime are **decoupled**: the config carries the Nactor's own
address (`nactorAddress`), and the app just points at it — the runtime can be
this box or a remote one.

Its actuator is pluggable — *publish to relays* for Nact, *exec on the box* for
Nops (`../docs/nops.md`). Same actor, different enactment.

This is the **pragmatic V1 transport** — HTTP + NIP-98, the same gate Luke's
cockpit uses. The config-as-grant-over-Nvoy model in
[`../docs/architecture.md`](../docs/architecture.md) is what it migrates to; the
endpoints stay the same.

## Run

```bash
NACT_DIRECTOR_NPUB=npub1…    # bootstrap Director anchor (legacy: NACT_MASTER_NPUB / LUKE_MASTER_NPUB)
NACTOR_NSEC=nsec1…           # Nactor's OWN key — the grantee credential-scopes encrypt to (SOPS on box)
LUKE_NSEC=…  NAVE_NSEC=…      # bootstrap FALLBACK role keys; the migration imports these as credential-scopes instead
LUKE_RELAYS=wss://relay.damus.io,wss://nos.lol
NACT_CONFIG=/data/nact-config.json   # directors / channels / tiers / metadata (persisted)
NACT_ADDRESS=https://nact.nave.pub/api   # optional — the address the app points at (informational)
NACT_PORT=8791
node nactor/nactor.mjs
```

Directors and the Nactor address live in the **config**, not just env — the
bootstrap npub above only seeds an empty config and stays permanently authorized;
everything else (add a co-Director, repoint the address) is edited from the app.

### Credential-scopes (the migration path — see `../docs/migration.md`)

`NACTOR_NSEC` gives Nactor its own keypair. A Director then **NIP-44-encrypts a
secret to Nactor's npub** and imports it; Nactor decrypts with its nsec and holds
it **only in memory** — never on disk, never returned by the API. A `role-key`
scope becomes an in-memory signing identity (replacing the `<NAME>_NSEC` env), so
the box's role keys stop living in a file. Issue from the Director's machine:

```bash
# import Luke's role key as an in-memory identity on the live Nactor:
DIRECTOR_NSEC=nsec1… node nactor/issue-credential.mjs \
  --name luke --type role-key --secret-file ./luke.nsec --url https://nact.nave.pub/api
# revoke: --name luke --revoke --url …
```

Directors and the Nactor address live in the **config**, not just env — the
bootstrap npub above only seeds an empty config and stays permanently authorized;
everything else (add a co-Director, repoint the address) is edited from the app.

## Endpoints (all `/api/*` require NIP-98 from a Director, except health)

| method | path | does |
| --- | --- | --- |
| GET | `/api/health` | liveness; identity names, `directorsConfigured`, **`nactorNpub`** (the grantee address); **no secrets, no auth** |
| GET | `/api/state` | `directors`, `nactorAddress`, `nactorNpub`, identities (npub/signer/status/**source**), **credentials** (names/types only), channels, tiers, queue, history |
| POST | `/api/propose` | `{identity, event:{kind,content,tags}, context}` → queue |
| POST | `/api/enact` | `{id, verb}` → sign the frozen bytes + broadcast, or reject |
| PUT | `/api/config` | `{directors?, nactorAddress?, channels?, tiers?, identitiesMeta?}` → persist (refuses to remove the last Director) |
| PUT | `/api/credential` | `{name, type, enc}` (NIP-44 ciphertext to `nactorNpub`) → decrypt in memory; a `role-key` becomes a signing identity. `{name, revoke:true}` to forget. **Values never touch disk or any response.** |

Auth: `Authorization: Nostr <base64 kind-27235 event>` signed by a **Director's**
key, pinning the method + URL path (+ sha256 of the body). The effective Director
set is the bootstrap anchor ∪ `config.directors`. See `nip98.mjs`.

## Deploy (on the Nave platform)

- Built as the `nactor` service (see `nactor/Dockerfile`), env from
  `luke.env` (reuses `LUKE_NSEC` / `NAVE_NSEC`; the bootstrap Director from
  `LUKE_MASTER_NPUB` / `NACT_DIRECTOR_NPUB`).
- Caddy routes `nact.nave.pub/api/*` → `nactor:8791`; everything else is
  the static app off disk.

## What V1 does and doesn't

- **Does:** live queue, enact (with the WYSIWYS fingerprint re-check), reject,
  edit routing/tiers, and manage **Directors + the Nactor address** in config —
  all as a Director over the NIP-98 gate.
- **Doesn't yet:** provision a *new* custodial identity (on-box key-gen) or
  register a channel's webhook. Those are the reconcile steps; identities today
  come from env keys. The app's create-forms stay local until then.
