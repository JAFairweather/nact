# Nact in the community

Nact only matters if the people building agentic tools on nostr actually reach
for it. This is the plan to make that happen — concrete steps, not vibes.

## The one-sentence pitch

> **Nact is the action-out half of scoped autonomy: an AI agent can propose any
> nostr action, but it only happens when you enact it with a signature — the
> key never touches the agent.**

Everything below is in service of getting that sentence in front of the right
people with a working repo behind it.

## Where Nact fits (and where it doesn't)

- It is **not** another NIP-46 signer. It composes with NIP-46: the signer
  answers "sign this"; Nact adds the layer above — an agent that drafts the
  event and an asynchronous, messaging-based approval before anything is signed.
- It is **not** a bot framework. Your proposer (LLM, signals, voice) is yours;
  Nact takes the finished unsigned event and runs the enact pipeline.
- It **is** the missing safety story for "let an AI post for me" — the reason
  most people won't point a bot at their real npub. Nact's answer: it can't post
  without your signature, by construction.

## Alignment with the protocol

Meeting nostr where it is makes adoption frictionless:

- **NIP-17 / NIP-59** — the nostr-DM approval adapter delivers proposals as
  gift-wrapped DMs and reads signed replies. No third-party messenger required.
- **NIP-46** — the sovereign signer path; the key stays in the user's bunker.
- **NIP-05** — Nact will publish a handle (`nact@nave.pub`) so the project has a
  followable identity for release notes and demos (see "Give Nact a face").
- **Future NIP fit** — the proposal→enact flow generalizes cleanly to a small
  spec (an "action request" event kind + an "enact" response). If there's
  appetite, draft it as a NIP so approval UX can be standardized across clients.

## First moves (in order)

1. **Announce it — through Nact itself.** The most on-brand launch: draft the
   announcement with the agent, route it through the Luke/nave posting loop,
   approve the tap, and let it broadcast. The medium *is* the message. Draft in
   `assets/announcement.md`.
2. **Get it listed.** Open PRs / issues to add Nact to:
   - [awesome-nostr](https://github.com/aljazceru/awesome-nostr) — "Libraries"
     or "Tools" section.
   - [nostr.net](https://nostr.net/) resource list.
   - The NIP-46 / signer ecosystem pages that enumerate related tooling.
   Entry text is ready in "Listing copy" below — one paragraph, no fluff.
3. **Ship a runnable demo.** `examples/nostr-native.mjs` already fires a real
   proposal to your DMs. A 30-second screen capture (proposal arrives → reply
   `ok` → it posts) is the single most convincing artifact; link it from the
   README and the landing page.
4. **Engage where the builders are.** Post the demo in the nostr dev channels
   (Telegram "Nostr Developers", the `#nostr` dev relays, the awesome-nostr
   discussions). Lead with the safety inversion, not the code.

## Give Nact a face (nact@nave.pub)

A project account people can follow for updates. Keys are generated **on the
box**, never pasted anywhere:

```bash
# on the box, as root
KEY=$(docker run --rm luke:latest node -e "import('nostr-tools').then(t=>{const sk=t.generateSecretKey();console.log(t.nip19.nsecEncode(sk));console.log(t.getPublicKey(sk))})")
# → line 1 nsec (store in SOPS, like luke/nave), line 2 hex pubkey (publish)
```

Then: add the hex pubkey to `nave.pub/.well-known/nostr.json` under `nact`, add
`NACT_NSEC` to the SOPS-encrypted secrets, and give Nact a profile (kind 0) with
the seal avatar via the existing `publish-profiles.mjs`. This mirrors exactly
how `luke@` and `nave@` were set up.

## Listing copy (ready to paste)

> **[Nact](https://nact.nave.pub)** — Give an AI agent the ability to act on
> nostr without giving it your keys: it drafts an action, you enact it with a
> signature, it broadcasts. Human-in-the-loop by architecture, not policy.
> Ships Telegram and NIP-59 gift-wrap DM approval adapters and a NIP-46 signer
> so your key can stay on your phone. MIT.

## How to help

See `CONTRIBUTING.md`. The highest-value contributions right now: additional
approval adapters (Signal, Matrix, a web push endpoint), a persisted pending
store, and real-world proposers that show the pattern in a domain we haven't
tried.

---

Part of the [Nave](https://nave.pub) ecosystem · help@nave.pub
