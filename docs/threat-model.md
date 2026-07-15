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

## Reporting

Security-relevant findings — a way to enact without the approver's signature, a
display-vs-signed divergence, a key-leak path — go to **help@nave.pub**, not a
public issue first.
