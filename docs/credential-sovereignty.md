# Credential sovereignty — credentials follow the *identity*, not the box

**Status:** decision record. Refines [`architecture.md`](architecture.md) and
[`migration.md`](migration.md). Supersedes their assumption that credential-scopes
are encrypted to *Nactor's* npub.

**Decision in one line:** **config is granted to the *runtime*; credentials are
granted to the *identity*.** Today both are encrypted to the Nave Nactor's npub —
that conflation is the bug this doc corrects.

---

## What went wrong

Nactor was built as a per-box credential *broker*: the Director NIP-44-encrypts
each provider secret to **Nactor's npub**, Nactor decrypts it with `NACTOR_NSEC`
and holds it in RAM, and **any activated identity may invoke any credential**
(`nactor.mjs`: `if (!isDirector(pub) && !activatedPubs().has(pub)) return 403`).

Two problems, one root cause:

1. **Blanket trust.** The Nave Nactor became the owner-of-record of *every*
   identity's keys, and every activated identity got reach into *every* credential
   — Nave-hub and Noir silently held rights to Luke's Telegram, calendar, and
   Anthropic they never needed. The broker is a single juicy target holding the
   keys to the whole kingdom.
2. **Box-locked.** A credential grant encrypted to the Nave Nactor's npub can be
   decrypted **only** by `NACTOR_NSEC`. Move Luke to another box with a *different*
   Nactor (a different nsec) and his credentials are **unreadable**. This isn't a
   policy gap — it's cryptographic. Today's design **cannot** let an identity
   operate elsewhere and keep its credentials.

The root cause is that the credential was addressed to **the machine that happens
to execute it**, not to **the identity that owns it**.

## Two constraints that turn out to be the same constraint

The owner asked for two things:

- *"I don't want an ACL. An ACL defeats identity sovereignty."*
- *"I want these agents to operate on other boxes through a different Nactor, and
  still reach their credentials via scope grants."*

An **ACL is per-box policy** — the box decides who may do what. **Cross-box
operation** means an identity shows up on a box that has never heard of it and
still works. Those are contradictory **unless authority stops living in the box.**
Both collapse to one rule:

> **Authority lives in the grant, carried by the identity — never in the broker.**

A box-maintained `{credential: [pubkeys]}` table is an ACL and it is exactly what
makes cross-box impossible (per-box config can't travel). A **master-signed grant,
addressed to the identity,** is a capability: it travels with the holder, any box
can *verify* it (check the Director's signature), and no box needs prior knowledge
of the identity. Capability, not ACL — the box verifies, it does not decide.

## The corrected keypair model

`architecture.md`'s table stands, with credentials re-homed:

| grant | encrypted to | why |
| --- | --- | --- |
| **box config** (Directors, routing, tiers, channels) | **the runtime** (Nactor's npub) | config *is* box-specific — it configures *this* runtime |
| **an identity's credentials** (provider secrets) | **the identity** (e.g. `luke@`'s npub) | credentials belong to the identity and must follow it across boxes |
| **an authorization** ("Luke may invoke credential X") | Director-signed capability | the *authority*, portable and verifiable, that replaces the blanket `activatedPubs()` check |

The Nave Nactor keeps *receiving* config for the box it runs. It stops being the
*recipient* of anyone's credentials.

## The Nactor's demoted role: an execution service, not a keyholder

A per-box Nactor still earns its keep — an identity often *wants* the box to do
egress on its behalf: keep the raw token out of the agent's heap, scope the
outbound call ("Telegram to the approver only"), centralize rate-limit + audit.
But it does so as a **service the identity lends a capability to, per session** —
derived from a grant the *identity* unwrapped — not as a standing keyholder:

- holds **no credential durably** (nothing on disk, nothing surviving the session);
- keeps **no authority table** (no ACL); every action is gated by verifying a
  **Director-signed, identity-scoped grant at call time**;
- needs **zero per-identity config** — any box's Nactor works for any identity,
  because it only ever *verifies a signature*, never *knows the identity in
  advance*.

**Blast radius = your own identity.** Each identity only ever unwraps *its own*
credentials, so a compromised agent leaks its own keys and nothing else — not
another identity's, not the box's. Strictly better than a broker holding
everyone's plaintext, and strictly better than a box holding everyone's policy.

## Migration — A then B, each step reversible and non-breaking

The live infrastructure (Luke's Telegram, the 7:20am calendar beat) must not
break, so authority migrates before the credential locus does.

**Phase A1 — authority to the master-grant (kills blanket trust; no ACL).**
Replace the broker's `activatedPubs()` check with: *this credential requires a
Director-signed grant naming the calling identity.* The credential ciphertext
still decrypts to Nactor for now (egress path untouched), but the **decision** is
already a portable, master-signed capability the box merely verifies. Blanket
trust is gone; revocation = the Director revokes the naming-grant. Nave-hub and
Noir lose their accidental reach into Luke's credentials the moment this lands.

**Phase A2 — credential ciphertext to the identity (unlocks cross-box).**
Re-issue each credential scope encrypted to the **owning identity's** npub instead
of Nactor's. Each identity runs its **own** grant-reader (its own nsec unwraps its
own credentials). The co-resident Nave Nactor still executes egress — but now on a
capability the identity **lends** it per session, not one it holds standing. A
*different* Nactor on another box now works with **zero re-issuance**.

**Phase B — full sovereignty.** Identities relocate freely; a box's Nactor is a
stateless execution surface; `nave.env` shrinks to the box's own bootstrap (the
`age` key + the Nave Nactor's nsec + pure infra) because identities carry their
own keys and credentials with them.

Each phase leaves the box working and is independently reversible. At no point is
authority stored as a box-local list.

## How a new app plugs in (e.g. `warm.contact`)

An app that wants an IMAP app-password (or any secret) on this box does **not**
hand it to a shared broker keyed to the box. It:

1. is an **identity** (`warm@nave.pub` or its own sovereign npub);
2. receives its secret as a **credential scope the Director encrypts to *its* npub**;
3. reads and unwraps that scope with **its own nsec** (its own grant-reader);
4. optionally **lends the co-resident Nave Nactor a capability** to do IMAP egress
   on its behalf — scoped, per-session, nothing held.

The app is portable by construction: move it to another box with another Nactor
and its credentials follow, because they were never addressed to *this* box. The
box's deploy contract (Caddy, compose, the deploy pipeline) is the companion
integration spec; this doc is the **identity + credential** half of that contract.

---

*Terminology: "Nactor" is a **role** — a per-box credential/execution runtime.
This box runs **the Nave Nactor**; other boxes run their own. There is no such
thing as "the" Nactor.*
