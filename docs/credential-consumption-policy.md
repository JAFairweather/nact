# Nave credential consumption policy — broker vs grant-to-app

**One-line policy:** *A credential is consumed either by the **broker** (Nactor
holds the key and makes the call) or **grant-to-app** (the owning identity holds
and uses the credential itself). Both are sovereign — authority is always a
Director-signed grant. Which mode you use is decided by **two tests**, not taste.*

Read `credential-sovereignty.md` first (the identity/grant model). This doc is the
**decision rule** for how a granted credential is actually used.

---

## The two tests (apply in order)

For a given **credential × consumer**, ask:

1. **Is the request content sensitive to Nave?** — Would the *content* of the
   provider call (a prompt, a query body) expose something that must not transit
   shared Nave infrastructure? (e.g. an AI prompt carrying private contact data.)
2. **Is the consumer off-box?** — Does it run somewhere that can't reach the
   private `nactor:8791` on the `nave` network? (e.g. a native macOS app.)

**If either is YES → grant-to-app.** The identity decrypts its own grant and
calls the provider directly; Nactor is not in the path, and never sees the
content. **If both are NO → broker.** Nactor holds the key in RAM and makes the
call, so the key is never at rest in the agent.

That's the whole policy. It's "hybrid by sensitivity" — sovereign where it
matters, tight custody where it's free.

```
            request content         consumer
            sensitive to Nave?      off-box?
                  │                    │
             yes ─┼─ no          yes ─┼─ no
                  │   └────────────────┼── (both no) ──▶  BROKER  (Nactor holds key)
                  └──────── either yes ─┘             ──▶  GRANT-TO-APP (identity holds key)
```

## Why both are sovereign

Sovereignty is not "who holds the bytes" — it's *"who authorized this, and can
they revoke it."* In **both** modes the authority is a Director-signed grant
addressed to the owning identity, revocable by one signed event. The broker is
not a policy authority; it's a custody convenience for the on-box, non-sensitive
case. So choosing broker does **not** surrender sovereignty — it only changes
*where the key sits at rest*.

| | **Broker** (Phase A) | **Grant-to-app** (Phase B) |
|---|---|---|
| Key at rest in the agent | no (RAM in Nactor) | yes (a scoped, revocable grant) |
| Nave sees call content | yes (it proxies) | no (call never touches Nave) |
| Works off-box | no | yes |
| Revoke | rotate at the broker | one signed revocation event |
| Sovereign? | yes (grant is the authority) | yes (grant is the authority) |

## Current mapping (who uses which, and why)

| Consumer | Credential | Content sensitive to Nave? | Off-box? | **Mode** |
|---|---|---|---|---|
| Luke / Brain (on-box) | `anthropic` (public-post drafting) | no — drafts are bound for public posts | no | **broker** |
| Luke (on-box) | `telegram-luke`, `gcal`, `gworkspace` | no | no | **broker** |
| Nact_jaf (on-box) | `telegram-nactjaf` (approvals) | no | no | **broker** |
| warm.contact instances (off-box) | `anthropic` (prompt carries contact data) | **yes** | **yes** | **grant-to-app** |
| warm.contact instances (off-box) | `gmail` / `imap` (history) | (off-box alone triggers it) | **yes** | **grant-to-app** |

Note the mode is per **(credential × consumer)**, not per credential: the *same*
`anthropic` credential is brokered for Luke (on-box, public content) and
grant-to-app for warm.contact (off-box, private content). The tests decide, every
time.

## Who may broker: the entitlement gate (A1/A2, shipped with M2)

The two tests decide *where the key sits*. A second, orthogonal question is *who
may ask the broker to use it* — and the answer is the same substance as
everything else here: **a Director-signed grant, verified on-box, never a
box-local ACL.**

- Nactor derives an **entitlement map** by reading each runtime identity's own
  `credential:*` grants with that identity's key (`nactor/grant-reader.mjs`,
  boot + timer). Holding a live, decryptable, Director-published grant for a
  credential *is* the entitlement; revocation is the same scope-key rotation as
  everywhere else and flows through on the next sweep.
- Only grants **published by a Director** count — for the entitlement map and
  for the CREDS delivery path both. Anyone can gift-wrap a scope to a runtime
  npub; only the Director's are honored.
- **Enforcement is graduated and off by default**
  (`NACT_ENFORCE_CREDENTIAL_OWNERSHIP`): when on, a credential is gated only
  once *some* identity holds a grant for it — so an unmigrated credential stays
  on blanket trust and nothing breaks mid-cutover.
- Scope names are **namespaced strings** (AD-8: `profile:* · credential:* ·
  data:* · capability:*`), not enums. This reader consumes `credential:*` only;
  other namespaces pass through inert. The decrypt core
  (`receiveGrants`/`latestGrants`/`fetchScope`) is namespace-agnostic, so a
  future `capability:*` resolver (the Scoped-Action-Approvals management layer,
  warm.contact's interim local policy object) rides the same path.
- Provenance is visible, values never are: the env-fallback set is flagged in
  logs at boot and on change, `/api/state.credentials[].source` says
  `grant`/`bootstrap-env`/`director-put` per credential, and every grant or
  entitlement transition lands in the runtime audit (AD-1).

## Consequences to design for

- **Grant-to-app = more copies at rest.** Mitigate on the *credential*, not the
  pattern: issue per-instance least-privilege credentials where the provider
  allows it, short TTLs, revoke-on-compromise (one signed event). See the
  warm.contact review §2.
- **Broker = a central hold.** Acceptable precisely because the content isn't
  sensitive to Nave and the agent is on-box; if either changes, the credential
  graduates to grant-to-app. Migrating a credential broker→grant-to-app is just
  re-addressing the grant to the consuming identity — no secret re-entered.
- **Default for new Nhosted apps:** off-box by definition ⇒ grant-to-app. Nactor
  stays the broker for the on-box Nave agents (Luke, Brain, Nact_jaf).

*The rule never asks "who's in charge" — the grant already answers that. It only
asks "where is it safe for the key to sit."*
