# Keyless boot — unsealing the box from the Director, no secret on disk

**Status:** design direction (jaf's question, 2026-07). Extends
[`credential-sovereignty.md`](credential-sovereignty.md). The SOPS-seal keeps the
box's secrets encrypted at rest but still leaves **one** key on disk (the `age`
key that decrypts them, plus the runtime's own nsec). This doc asks: **can the
box hold *no* persistent secret at all, and be unsealed on boot by the Director
over nostr?** Answer: **yes** — it's the well-known *remote-unseal* pattern, with
nostr as the transport.

## The core realization

Decryption must happen where a private key is. So "no key on the box" cannot mean
"no key anywhere in the box's memory" — it means **no *persistent* secret on
disk**. The box may hold an **ephemeral key generated fresh at each boot, in RAM
only, never written down.** The *durable* secret (the root that unseals
everything) lives with the **Director**, whose key is on the Director's own
device — never on the box.

Steal the disk → you get ciphertext and nothing else. Reboot → the box is inert
until the Director unseals it again.

## The protocol (nostr remote-unseal)

```
   BOOT (the box)                             THE DIRECTOR (jaf's device)
   ┌───────────────────────────┐             ┌──────────────────────────────┐
   │ 1. gen ephemeral key E     │             │  holds the root secret        │
   │    (RAM only, never disk)  │             │  (or Shamir shares / age key) │
   │ 2. publish unseal REQUEST ─┼──relays────▶│  3. verify it's really MY box │
   │    (gift-wrap → Director):  │             │     (see "the hard part")     │
   │    { E.pub, boot_nonce,     │             │  4. NIP-44 encrypt root ─────┐│
   │      box_id, attestation }  │◀──relays────┼─────── secret TO E.pub       ││
   │ 5. decrypt with E (RAM),   │             │                              ◀┘│
   │    load root into RAM, boot │             └──────────────────────────────┘
   └───────────────────────────┘
   E and the root secret live only in RAM; a reboot loses both.
```

The request/response ride the same NIP-59 gift-wrapped channel the approval plane
already uses — so this is the **approval flow applied to boot**: the box asks, the
Director approves, nothing unlocks without the Director.

## The hard part: authenticating the box to the Director

Without a stored key, how does the Director know an unseal request is from **his**
box and not an attacker who copied the (public) boot image and is asking to be
unsealed? Options, weakest → strongest:

1. **Human eyeball + out-of-band nonce.** The request shows a nonce the Director
   cross-checks against what the box's console/IP shows. Simple, human-gated,
   matches the approval plane — but phishable.
2. **Context binding.** The Director's device only answers requests from the box's
   known network path / a private channel. Better, but IP ≠ identity.
3. **Hardware root of trust (TPM + measured/secure boot).** The box's TPM attests
   *"I am this physical machine running this exact, unmodified boot image."* The
   Director verifies the attestation before unsealing. This is **true
   keyless-at-rest**: the root of trust is hardware, not a stored secret. It's what
   production auto-unseal uses (Vault seal-wrap, cloud KMS, confidential
   computing). Nostr just carries the attestation blob + the encrypted response.

## The tradeoff you're actually choosing: uptime vs. sovereignty

- **Pure form** — every reboot pauses until the Director approves the unseal.
  Maximum sovereignty (nothing runs without live human consent); operational cost
  (you *are* the unlock ceremony, so an unattended 3am reboot stays down until you
  tap).
- **Delegated form** — the Director delegates unseal authority to an always-on
  custodian (a hardware token, a second device, or a policy-bound identity) that
  auto-approves within limits. This is exactly the *"delegate approval authority to
  Nact_jaf"* idea (credential-sovereignty task) applied to boot: trade some
  sovereignty for uptime, on a dial you control.

## Where it sits in the roadmap

- The **SOPS-seal** (age key box-only) is the pragmatic 80% — done.
- **Keyless boot** is the 100% — even the age key leaves the box; the box becomes
  genuinely **stateless-at-rest**, the endgame of the sovereignty ADR.
- The Director's unseal identity is the **nave-jaf / Director role** already being
  formalized (the same key that grants credentials and approves actions).

## Open question (jaf): where do you approve the unseal?

At boot, the box's own channels are down — Telegram isn't up (it needs the secret),
and nvoy runs *on the box*. So the approval interface **cannot depend on the thing
being unsealed.** The resolution is that the unseal request rides **external public
nostr relays**, and you approve from **your own device** (a phone/laptop nostr
client, or a tiny purpose-built "unseal" view) — neither the relays nor your device
depend on the box being up. This is the chicken-and-egg the design must respect:
the approval plane for *boot* is necessarily off-box, unlike the approval plane for
*actions* (which can be on-box because the box is already running). Deferred to the
keyless-boot phase; noted so it isn't rediscovered later.

**Tiered boot (jaf).** The knot loosens if the box boots in stages. Some services
need **no** secret and can come up first — a *tier 0* of Caddy + the static consoles
+ relay reachability. Crucially, **nvoy holds no box secret**: it's static files
served by Caddy, and it signs with the *Director's own browser key* (NIP-07), never
a key from the sealed bundle. So nvoy can be live in tier 0 and *be the very
interface where you approve the unseal* — you open the console (your key, your
device), approve, and that releases the root secret to the box's ephemeral boot
key, bringing up *tier 1* (Nactor loads the bundle; luke/director/etc. follow).
Open design work: which services are genuinely tier-0-safe, how the console hosts
an "unseal request" view, and how a half-booted box advertises the pending request.
Not yet fully specced — captured so the staging idea survives.

This is a self-hosted, nostr-transported version of a well-established pattern
(remote/auto unseal + measured boot). That it maps cleanly onto primitives we
already run — gift-wrapped Director approvals, ephemeral keys, NIP-44 — is a strong
signal it's sound. It is a **build**, not a research problem; the honest work is
(a) the boot-time request/response daemon and (b) choosing the box-authentication
tier (human nonce → TPM attestation).
