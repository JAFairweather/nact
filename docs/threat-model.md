# Nact threat model & response plan — WYSIWYS

The hardest guarantee Nact must make: **the human approves the *actual* action.**
Borrowed from hardware wallets, the property is **WYSIWYS — "what you see is
what you sign."** This document records the threats and the layered response.

## The core threat: displayed ≠ signed

The description on the approval screen can diverge from the bytes that get
broadcast, in four places:

1. **Two representations.** The proposer supplies a payload *and* a friendly
   "description"; the card shows the description while the pipeline signs the
   payload. They drift or are gamed. *(Architecture flaw, not a bug.)*
2. **Mutation between show and sign.** The draft shown at propose-time is altered
   before enact-time.
3. **The content/tags lie at render time.** The human sees "post: hello" but
   doesn't see it's **kind 3** (overwrites the whole contact list), or that it
   carries a `p` mention, an `e` reply, a `q` quote, or zero-width / bidi-override
   characters that make the *displayed* text differ from the *actual* bytes.
4. **Compromised runtime.** The Nact process shows X and signs Y.

## The response — layered, cheapest first

### Rule 0 — render the action, never a *description* of it
The card is a deterministic render of the **exact template that will be signed**:
kind + content + *every* tag. The proposer's rationale is shown separately,
permanently labelled *"context — not published,"* and is never the thing
approved. This kills threat #1 at the architecture level.

### 1 — freeze the bytes, bind approval to the hash
A nostr event id already **is** the sha256 of `[0, pubkey, created_at, kind,
tags, content]` (NIP-01). So stamp `created_at` at **propose** time (not enact),
making the whole event — and its id — determined up front. Show the id's short
fingerprint on the card. At enact, **re-derive the id from the exact bytes about
to be signed and refuse if it differs.** Threat #2 becomes impossible: any
mutation changes the hash and the sign aborts.

### 2 — a faithful render that can't lie
- Human-label the kind; **loudly flag high-impact kinds** (⚠ 0 profile, ⚠ 3
  contact-list replace, ⚠ 5 deletion, ⚠ 10002 relay list, ⚠ 30000-series lists).
- Show **every tag** (p/e/q and anything with side effects).
- Show content **length**; **detect and flag zero-width & bidi-control
  characters**; never silently truncate what's signed.

### 3 — sign-on-device for critical items (the strong guarantee)
This is where NIP-46 earns its keep *beyond* key custody. With a bunker (Amber,
nsec.app), the human approves **on the signing device, which displays the exact
event it will sign.** Display and signer become the *same* device, so "show X,
sign Y" is impossible for the party that matters. The convenience channel
(Telegram) degrades to a notification; the **authoritative** approval is the
bunker's own confirmation. See "Open in bunker" below.

### 4 — public verifiability
Because the approval response references the proposal id, the broadcast event can
carry `["approval", <id>, <approver>]`, so a *third party* can re-derive the
render from the template and confirm the approver approved the exact bytes that
shipped. See `scoped-action-approvals.md`. Human-in-the-loop stops being "trust
Nact" and becomes checkable on-protocol.

## Risk tiering

Not every action deserves the same friction. Tier by kind (and value):

| tier | examples | required path |
| --- | --- | --- |
| **low** | note (1), reaction (7), repost (6) | one-tap approve (custodial, or background bunker prompt) |
| **elevated** | replies/mentions, zaps under a threshold, follows | approve **after** the full tag list + fingerprint are shown |
| **critical** | profile (0), contact list (3), deletion (5), relay list (10002), large zaps, first post as a new identity | **sign-on-device required** — no one-tap custodial path offered |

The control-plane app (see `DESIGN.md` → "the app") is where a human sets these
tiers per identity/kind. Until then they live as library defaults.

## "Open in bunker" — the two questions

> *Is a link to open in the bunker for critical items the right idea?*

**Yes.** It's step-up authentication: escalate critical actions to the path where
the **bunker is the authoritative WYSIWYS screen**. Nuance worth stating:

- For an identity that already uses a **NIP-46 signer**, the bunker prompt fires
  on its own at enact — the button just makes it *explicit and immediate* (and
  lets a normally-custodial identity **step up** to on-device signing for a
  critical item).
- The guarantee is the **bunker's** display, not Nact's. Any Nact-hosted preview
  is still Nact-hosted; the last line of defence is the screen on the device that
  holds the key. Bunkers vary in how much they show — the guarantee is only as
  good as that screen, and that's worth saying out loud to users.

> *Can that be embedded in Telegram as a button?*

**Yes — via a `web_app` (Mini App) button, not a raw `url` button.**

- A raw `url` button to a signer scheme (`nostrsigner:` / `bunker:`) is
  **unreliable**: Telegram restricts inline `url` buttons to http/https/tg, so
  custom app schemes are typically blocked or dead.
- A **`web_app` button** opens a Nact-hosted Mini App (e.g.
  `https://nact.nave.pub/sign?p=<proposalId>`) inside Telegram. There it:
  1. loads the exact unsigned event by id and renders the faithful WYSIWYS
     preview (kind, content, all tags, fingerprint, flags);
  2. runs a **NIP-46 client handshake** to the user's bunker over a relay (or, on
     Android, hands off to Amber via `nostrsigner:` from inside the webview);
  3. the **bunker shows and signs** the identical bytes;
  4. the Mini App returns the signed event to Nact's backend, which broadcasts.
- Note: NIP-07 (browser extension) is **not** available inside Telegram's
  in-app webview, so the Mini App path relies on NIP-46 (relay) or an Amber
  hand-off, not an extension.

So: low-risk items keep the one-tap `callback_data` button; **critical items
replace it with a `web_app` "Sign in your bunker" button** that routes the exact
event to the signing device.

## The second threat: unbound approvers — who is really approving?

WYSIWYS (above) protects **what** is signed. A separate guarantee protects
**who** approves: that an approval attributed to a Director was actually produced
by the holder of that Director's key, over a channel that key-holder consented to.

### The threat: a config entry is not consent

Adding a Director is two independent acts — **authorizing** an npub (an allowlist
entry: "honor a valid signature from this key") and **routing** a channel to them
(a delivery path). A naïve entry is just `(npub, channel)` — **two identifiers
with no cryptographic relationship.** "npub1luke…" and "Telegram chat 12345" are
strings the *configurer* typed; nothing about the channel id is derivable from, or
provable against, the key. So:

- **You cannot know an out-of-band channel reaches the key-holder.** Delivery to a
  channel proves nothing about who is on the other end; possession of a key proves
  nothing about which channels reach them. They are independent until someone
  staples them together — and only the key-holder can do that honestly.
- **A channel-tap can be mis-attributed to a key that never signed.** A Telegram
  "Approve" is authenticated by *Telegram delivery*, not by the Director's nostr
  key — and the configurer holds the bot token. So a callback saying "Luke
  approved" is only as trustworthy as a bot the configurer controls. That is not
  cryptography binding Luke; it is the system mis-attributing a tap to a key.

The principle: **a Director's authority must be anchored in their key, never in a
channel someone else controls.** An npub in config is *inert until they sign* —
which means it cannot be used to forge their approval, but it also means an
out-of-band channel bound to it must be *proven*, not asserted.

### The free case: the channel that *is* the key

For a **nostr-native channel (NIP-59 DM / NIP-46)**, the channel address and the
npub are the same object: a gift-wrapped DM is encrypted to the key (only the
nsec-holder opens it) and the reply is signed by that key. Delivery and
authentication are one act — **binding is intrinsic.** This is why nostr-DM /
NIP-46 is the default path for a real co-Director: "add Luke" reduces to "encrypt
to Luke's key, honor Luke's signature," impossible to fake and inert until he acts.

### The binding ceremony (for Telegram, email, Signal, …)

To bind an out-of-band channel, one **signed loop proves three things at once**:

1. **The channel reaches the key-holder** — deliver a fresh **nonce over the
   channel** (post a code into the chat). It can only be echoed by whoever
   received it there.
2. **They hold the key** — they **sign** with the nsec for the claimed npub.
3. **They consent to *this* channel** — the signed statement **names the channel
   explicitly**: *"I, npub X, accept Director authority on Nactor Z, over Telegram
   chat 12345, nonce=…"* — so consent is channel-specific and phishing-resistant
   (not a blank "I'm a Director").

The configurer cannot forge it: without the Director's nsec they can't complete
step 2, and the Director won't sign a statement naming a channel they don't hold.

### The data model and lifecycle

A Director entry is therefore never `(npub, channel)` alone — it is
`(npub, channel, binding-proof)`, with a status:

| channel type | binding | status when added |
| --- | --- | --- |
| nostr-DM / NIP-46 | intrinsic (channel = key) | **verified** on first signed reply |
| Telegram / out-of-band | the signed, channel-named challenge above | **pending** until completed |

- **Adding by npub + out-of-band handle is an *invitation*, not an authorization.**
  It routes proposals to a *claimed* channel and nothing more.
- **Unbound (`pending`) = deliver-but-don't-honor.** Nactor may *send* proposals to
  a pending channel, but must **refuse any approval that arrives over it**, because
  it cannot attribute that approval to the key. Only a `verified` binding lets a
  channel's approval count.
- The V1 web-queue path is already safe here: every enact is **NIP-98 signed by the
  Director's key**, so the channel *is* a signature — self-binding, like nostr-DM.
  The exposure is strictly the out-of-band adapters.

### The honest boundary

The ceremony proves *this key ↔ this channel ↔ consent*. It does **not** prove
that npub1luke… is the real-world human you mean by "Luke." That key-to-person
mapping is a separate assurance (NIP-05, a prior relationship, out-of-band
confirmation) and no channel binding supplies it — keep the two distinct so the
handshake is not over-claimed.

### Channel authority as a scoped grant (the executable binding)

Don't store the binding as a static proof in the owner's config. Make it a **live,
revocable, scoped grant the Director issues to the Nactor** — the same NIP-DA
primitive the whole stack runs on. This applies the Nave thesis ("revocation
isn't a policy, it's a key rotation") to *approval authority itself*.

**The grant.** Grantor = the Director (signs with their nsec — the key-control
proof); grantee = the Nactor (the scope is encrypted to its npub, gift-wrapped
per NIP-59); payload = the verified metadata for **one channel**:

```
{
  director: npub_luke,
  nactor:   npub_nactor,
  channel:  { type: "telegram", id: "12345", label: "Luke · ops" },
  delivery_proof: { nonce, echoed_at },              // from the ceremony (tap channels)
  authority: { identities: ["scout"], tiers: ["low","elevated"] },  // SCOPED
  expires:  <NIP-40 timestamp>,
  purpose:  "approval delivery + authority for this Nactor"
}
// signed by the Director's nsec → key-control + channel-naming + consent, in one artifact
```

Because it's signed by the Director *and* names the channel, the grant **is** the
binding proof — the three properties above travel inside a live grant instead of a
dead attestation.

**Issue → verify (per channel).**

1. Owner invites the Director → routes proposals to the *claimed* channel →
   `pending`.
2. Nactor delivers a **nonce over that channel**.
3. The Director (in a client / Mini App) receives the nonce *over the channel*,
   folds it into the scope, signs, and **gift-wraps the grant to the Nactor**.
4. Nactor dereferences it (over Nvoy's MCP, exactly as it reads its config) → the
   channel flips **pending → verified**, carrying the Director's *scoped* authority.

For a nostr-DM / NIP-46 channel the channel *is* the key, so steps 2–3 collapse —
the grant is essentially the first signed reply. The grant model is for the
out-of-band channels.

**Honor rule (deliver-but-don't-honor, live).** On every approval over a channel
the Nactor **dereferences the live grant**:

- no live grant (never issued / expired / revoked) → **don't honor** (it may still
  *deliver* there, but a tap over an unbound channel is refused);
- live grant whose `authority` scope covers this proposal (agent-identity + risk
  tier) → honor as the Director's approval;
- `critical` tier isn't granted to tap channels, so it falls through to
  sign-on-device (bunker). The scoped grant *is* how per-channel risk routing is
  expressed.

**Revoke.** A **key rotation on that one channel's grant** (or a NIP-DA revocation
event): the Nactor's next dereference returns nothing → the channel reverts to
don't-honor, instantly. Each channel is its **own scope key**, so revoking Luke's
Telegram touches neither his nostr-DM binding nor anyone else's — and the Director
can withdraw *their own* authority without config-edit access to the Nactor. The
authority literally originates from the Director's signed, revocable grant, never
from an npub the configurer typed — which is what makes "you can't implicate
someone" airtight.

**Separation of powers.** Owner config = which channels/identities/routing exist;
Director grants = authority to approve over a verified channel, scoped and
revocable. Neither forges nor silently outlives the other. And the owner's
"invite" is precisely a *request* for a channel-authority grant; the Director
"accepting" is *issuing* it — the request-is-a-grant-and-enact symmetry (see
`nostr-scoped-data-grants/FUTURE.md`).

*Caveats:* revocation takes effect on the next dereference + relay propagation
(seconds) — critical enacts should force a fresh dereference, not a cache; the
nonce-over-channel ceremony is not eliminated for tap channels, only *packaged*
(made live + revocable) by the grant; per-channel keys are the cost of granular
revoke.

## Implementation plan (phased)

- **Phase 1 — library (cheap, do first).** Freeze `created_at` at propose;
  compute + expose the event-id fingerprint; re-verify it before signing; enrich
  the draft passed to adapters with kind label, all tags, dangerous-kind flags,
  hidden/bidi-character flags; formalize per-kind risk tiers + a policy that
  critical kinds cannot take the one-tap custodial path.
- **Phase 2 — adapters.** Telegram card renders kind/tags/fingerprint/flags and,
  for critical items, swaps the approve button for a `web_app` "Sign in bunker"
  button. The nostr-DM adapter routes critical items to the approver's own client
  to sign (already native there).
- **Phase 3 — Mini App + control plane.** Build `nact.nave.pub/sign` (NIP-46
  client + faithful preview), then the app screens that configure tiers per
  identity/kind.
- **Phase 4 — protocol.** The public `approval` tag for third-party
  verifiability (Scoped Action Approvals), once cross-client demand appears.
- **Phase 5 — channel binding, as a scoped grant.** Model each verified channel
  as a **Director-issued, revocable, scoped grant** (schema + sequence in
  "Channel authority as a scoped grant" above), not a static config proof.
  nostr-DM/NIP-46 self-bind on first signed reply; out-of-band channels run the
  nonce-over-channel ceremony, and the Director gift-wraps the resulting
  channel-authority grant to the Nactor. The Nactor **dereferences the live grant
  on each approval** — delivers to `pending` channels but honors approvals only
  where a live grant's `authority` scope covers the proposal. Revocation is a
  per-channel key rotation, owned by the Director. The control-plane app frames
  "add Director" as an **invite** and shows `pending → verified`; the runtime
  reads these grants the same way it reads its config (Nvoy MCP — see
  `architecture.md`).

### Status (as shipped)

- **P1/P3 — library gates.** `created_at` frozen at propose; the fingerprint is
  re-verified *before* signing and again after; critical kinds cannot be one-tap
  enacted. Proven offline in `nactor/wysiwys.test.mjs`.
- **P2 — faithful render.** Hidden/bidi + homoglyph flags and full tag/kind
  surfacing (`src/inspect.mjs`), rendered in the adapters and the web app.
- **P4 — channel binding (this pass, nact#10).** `lib/channel-binding.mjs`
  implements the model + the nonce ceremony + the honor rule:
  - `bindingKind`/`mayHonor` — intrinsic channels (Web/NIP-59/Ngage) are always
    honorable; out-of-band channels **fail closed** until verified.
  - `bindingStatement`/`newNonce`/`verifyBinding` — the ceremony. `verifyBinding`
    additionally checks `getEventHash(event) === event.id`, because this
    nostr-tools `verifyEvent` checks the sig over the stored id *without*
    recomputing the hash — so a lone Director signature could otherwise be reused
    under a swapped statement. The forgery is caught (test:
    `nactor/channel-binding.test.mjs`).
  - `bindingGrantPayload`/`verifiedChannelOf`/`BINDING_SCOPE` — the binding as a
    revocable NIP-DA scope grant; a live grant ⇒ verified, key rotation ⇒ gone.
  - Enforced in `src/adapters/telegram.mjs`: `isApprover` now requires *id match
    AND a live binding*, dereferenced on every approval; `isBound()`/`channel`
    let a handler tell "wrong person" from "right person, unbound channel".
  - **Integration point (open):** the runtime feeds the adapter
    `verified: () => <Set of channel ids from live binding grants>`, sourced via
    the same grant-reader the Nactor already uses for config. The live enact path
    today is the NIP-98 web queue (intrinsically bound), so no live channel is
    unbound by this change; the gate arms the moment a Telegram/out-of-band
    approval path is wired.
- **P5 (open) — Mini-App signer** at `nact.nave.pub/sign` (NIP-46 + faithful
  preview) and the per-identity/kind tier control plane.

## Reporting

Security-relevant findings — a way to enact without the approver's signature, a
display-vs-signed divergence, a key-leak path — go to **help@nave.pub**, not a
public issue first.
