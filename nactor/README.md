# Nactor — the Nact runtime

The on-box **actor** that receives config/proposals and enacts: a NIP-98-gated
HTTP control-plane over the Nact library. The control-plane app (`app.html`)
talks to this; only the master's key may read the queue, enact, or edit config.
Role signing keys come from the environment (SOPS-decrypted on the box) and never
leave it.

Its actuator is pluggable — *publish to relays* for Nact, *exec on the box* for
Nops (`../docs/nops.md`). Same actor, different enactment.

This is the **pragmatic V1 transport** — HTTP + NIP-98, the same gate Luke's
cockpit uses. The config-as-grant-over-Nvoy model in
[`../docs/architecture.md`](../docs/architecture.md) is what it migrates to; the
endpoints stay the same.

## Run

```bash
NACT_MASTER_NPUB=npub1…      # or LUKE_MASTER_NPUB — the only key that may act
LUKE_NSEC=…  NAVE_NSEC=…      # each <NAME>_NSEC becomes identity <name>
LUKE_RELAYS=wss://relay.damus.io,wss://nos.lol
NACT_CONFIG=/data/nact-config.json   # channels / tiers / metadata (persisted)
NACT_PORT=8791
node nactor/nactor.mjs
```

## Endpoints (all `/api/*` require NIP-98 from the master, except health)

| method | path | does |
| --- | --- | --- |
| GET | `/api/health` | liveness; lists identity names; **no secrets, no auth** |
| GET | `/api/state` | identities (npub/signer/status), channels, tiers, queue, history |
| POST | `/api/propose` | `{identity, event:{kind,content,tags}, context}` → queue |
| POST | `/api/enact` | `{id, verb}` → sign the frozen bytes + broadcast, or reject |
| PUT | `/api/config` | `{channels?, tiers?, identitiesMeta?}` → persist |

Auth: `Authorization: Nostr <base64 kind-27235 event>` signed by the master key,
pinning the method + URL path (+ sha256 of the body). See `nip98.mjs`.

## Deploy (on the Nave platform)

- Built as the `nactor` service (see `nactor/Dockerfile`), env from
  `luke.env` (reuses `LUKE_NSEC` / `NAVE_NSEC` / `LUKE_MASTER_NPUB`).
- Caddy routes `nact.nave.pub/api/*` → `nactor:8791`; everything else is
  the static app off disk.

## What V1 does and doesn't

- **Does:** live queue, enact (with the WYSIWYS fingerprint re-check), reject,
  and edit routing/tiers — all as the master over the NIP-98 gate.
- **Doesn't yet:** provision a *new* custodial identity (on-box key-gen) or
  register a channel's webhook. Those are the reconcile steps; identities today
  come from env keys. The app's create-forms stay local until then.
