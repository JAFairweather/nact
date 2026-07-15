# Scoped Action Approvals — a sketch (non-normative)

**Status: exploratory. This is not a spec and not a NIP.** It records what a
standard *would* specify if adoption ever warrants one, so the idea and the name
have a stake in the ground. Today Nact needs none of this — see "Why not yet."

## What Nact is today (so we don't overclaim)

Nact is **software over existing standards**, not a new standard. Its output is
an ordinary nostr event (a kind-1 note, a reaction, whatever) that any relay or
client handles without knowing Nact exists. The approval flow happens out of
band (Telegram) or over primitives that are *already* NIPs — NIP-59 to deliver
the ask, NIP-46 to sign. Nothing new appears on the wire. That's a feature: Nact
ships with no committee and no multi-client coordination.

## The one standardizable thing: the approval handshake

The only part that *isn't* interoperable is **how an action is proposed for
approval and how that approval is granted**. Right now that's private to Nact (a
Telegram card, or a DM with an `ok <id>` reply). A standard would make it
cross-client: **any** nostr client could show you a pending proposal and let you
approve it, and **any** proposer could request enactment from **any** approver.

That is the whole scope of a potential spec — nothing more. The actions
themselves stay ordinary events.

## Naming (recorded thinking)

Deliberately rhymes with **Scoped Data Grants** (NIP-DA, the perceive side):

| | perceive | act |
| --- | --- | --- |
| object | data | **action** |
| mechanism (the authorizing act) | **grant** | **approval** |
| standard title | Scoped Data **Grants** | Scoped **Action** **Approvals** |

- **Concept / positioning:** *Scoped Agent Actions* — the act-out half of scoped
  autonomy, how Nact is described to people. Umbrella, evergreen.
- **The spec:** *Scoped Action Approvals* — general on purpose. It standardizes
  approving **actions**; an **agent action is the exemplary type** (the marquee,
  motivating case), not the only one. A human approving another human's
  co-managed action, a multisig-style team sign-off, a scheduled action held for
  review — all the same handshake. Generality is what makes a NIP worth adopting;
  scoping it to "agent" would shrink its reach. "Grant ↔ approval" keeps the peer
  relationship with Scoped Data Grants exact.

## The sketch

Two events, both delivered privately as **NIP-59 gift wraps** (the inner rumor
carries a new kind; numbers TBD, shown here as placeholders):

### 1. Action Proposal  (inner kind `PROPOSAL`, placeholder)

Sent by the proposer to the approver. Says "here is an action I want enacted —
approve it?"

```jsonc
{
  "kind": <PROPOSAL>,
  "content": "<the unsigned event template the proposer wants enacted>",
  "tags": [
    ["p", "<approver-pubkey>"],                 // who may approve
    ["act", "<acting-identity-pubkey>"],        // whose key would sign it
    ["k", "1"],                                  // the target event kind (scope)
    ["expiration", "<unix-ts>"],                 // NIP-40 TTL — approval is time-boxed
    ["context", "<rationale shown to the human, never broadcast>"]
  ]
}
```

`content` is the *template* (kind + content + tags), not a signed event. The
proposer holds no signing key for the acting identity.

### 2. Approval Response  (inner kind `APPROVAL`, placeholder)

Sent by the approver back to the proposer. It is the **authorization** — proof
that the designated approver approved *this specific* proposal.

```jsonc
{
  "kind": <APPROVAL>,
  "content": "",                                // or an optional note
  "tags": [
    ["e", "<proposal-event-id>"],               // binds to exactly one proposal
    ["verb", "approve"]                          // or "reject"
  ]
}
```

Because it's signed by the approver's key and references one proposal id, it
can't be replayed onto a different action.

### 3. (The interesting part) Verifiable human-in-the-loop provenance

Approval and *signature* are decoupled: the approval says "yes," but the acting
identity's key (custodial, or a NIP-46 bunker) still does the signing. That
separation lets the final, broadcast event optionally carry a tag pointing at the
approval:

```jsonc
["approval", "<approval-event-id>", "<approver-pubkey>"]
```

Now anyone can verify that Luke's post was approved by jaf's key — **public,
checkable proof that an agent action passed a human tap.** As agents proliferate,
"was this AI action human-approved, and by whom?" becomes a question worth being
able to answer on-protocol. This is the part that would justify a NIP; the rest
is convenience.

## How it composes (uses NIPs, doesn't replace them)

- **NIP-59 / NIP-17** — private delivery of proposals and approvals.
- **NIP-46** — signing the approved action; orthogonal to the approval itself.
- **NIP-40** — expiration = the proposal's TTL / scope-in-time.
- **NIP-DA (Nscope)** — the app layer (managing *which* approvers may approve
  *which* kinds for *which* identities) is itself scoped-grant management. An
  approval channel is a scoped grant of approval-authority; see `DESIGN.md`.

## Why not yet

- It works without a standard. Telegram and NIP-59 DMs already carry approvals.
- A NIP earns its keep only if multiple clients want to render and grant
  approvals interoperably — unproven until Nact has users.
- The strongest way to propose a NIP is with a working implementation in hand.
  Nscope did exactly this: spec + two implementations, *then* the PR. Leading
  with a spec for something that works fine as software is how ideas die in
  draft.

So: **ship Nact as software, gather use, and draft _Scoped Action Approvals_
only if the demand for cross-client approval actually shows up** — with the
verifiable-approval provenance as the headline reason it would be worth it.
