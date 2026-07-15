# Nact — launch announcement

Draft for the launch note. The on-brand path: route it through the Luke/nave
posting loop, approve the tap, let it broadcast — Nact announcing itself is the
demo. Post from the `nave` identity (the ecosystem voice) or `nact@` once that
handle exists.

---

## Primary note (kind 1)

> Shipping **Nact** — give an AI agent a voice on nostr without giving it your keys.
>
> The agent drafts the action. You enact it with a signature. It broadcasts.
> The key never touches the agent. Human-in-the-loop by architecture, not policy.
>
> Approve from Telegram, or from any nostr client via a NIP-59 gift-wrapped DM.
> Sign custodially, or with a NIP-46 bunker so your key stays on your phone.
>
> It's the action-out half of scoped autonomy — a companion to nvoy, which
> governs what an agent may *perceive*. Nact governs what it may *do*.
>
> MIT, docs, and a runnable demo → https://nact.nave.pub

## Shorter variant (if the above runs long for a client)

> **Nact**: an AI agent proposes a nostr action; you enact it by signing; it
> broadcasts. The key never touches the agent — human-in-the-loop by
> architecture. Approve via Telegram or a NIP-59 DM; sign with NIP-46 so your
> key stays on your phone. MIT → https://nact.nave.pub

## Thread follow-ups (optional replies to the primary note)

1. Why this and not "just give the bot an nsec"? Because nobody sane points a
   bot at their real account. Nact inverts it: authorization is *your*
   signature, and the key that makes it never leaves you.
2. It composes with NIP-46 rather than replacing it. NIP-46 answers "how does a
   remote signer approve a signature?" Nact adds the layer above: an agent that
   drafts the event, and an async approval flow fit for an agent that proposes
   on a schedule and a human who enacts whenever.
3. Pairs with nvoy for both-ends bounding: scoped data in (nvoy), signature-
   gated actions out (Nact). An agent that can only see what you granted and
   only do what you signed.

## Tags to include

- `t` tags: `nostrdev`, `ai`, `agents` — never a plain `nostr` tag (tagging the
  platform you're posting on reads like `#twitter` on Twitter)
- Consider p-tagging maintainers of NIP-46 signers / awesome-nostr when replying
  in-thread, not in the primary note (avoid spammy mentions).
