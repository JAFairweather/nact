// channel-binding.mjs — the approval-channel binding model (hardening P4,
// nact#10). The threat: a hijacked bot or spoofed chat injects an approval that
// the runtime mis-attributes to the Director's key. The fix, per
// docs/threat-model.md "Channel authority as a scoped grant":
//
//   • Some channels are SELF-AUTHENTICATING — the channel IS a key signature
//     (the NIP-98 web queue, a NIP-59 DM, the Ngage draft grant). Binding is
//     intrinsic; their approvals are always honorable.
//   • OUT-OF-BAND channels (Telegram, email, Signal) are not. An approval over
//     one carries no proof the key-holder consented, so it must be
//     DELIVER-BUT-DON'T-HONOR until a nonce ceremony verifies the binding — and
//     that binding is a live, revocable scoped grant, not a dead attestation.
//
// This module is pure and node-side (the runtime's concern). No DOM.

import { verifyEvent, getEventHash } from 'nostr-tools'
import { randomBytes } from 'node:crypto'

// Channel kinds whose transport IS a signature by the approver's key.
const INTRINSIC = new Set(['Web', 'NIP-59', 'Ngage'])
export function bindingKind(channel) {
  return INTRINSIC.has(String(channel?.kind || '').split(' ')[0]) ? 'intrinsic' : 'grant'
}

// THE HONOR RULE. May an approval arriving over this channel be honored?
// Intrinsic channels: always (the approval is itself a signature). Out-of-band
// channels: only if a live verified binding exists for this channel id. An
// unknown/undefined channel is out-of-band by default — fail closed.
export function mayHonor(channel, verified) {
  if (!channel) return false
  if (bindingKind(channel) === 'intrinsic') return true
  return !!(verified && verified.has && verified.has(channel.id))
}

// A fresh nonce delivered OVER the channel during the ceremony — only whoever
// received it there can echo it back, proving the channel reaches the key-holder.
export const newNonce = () => randomBytes(12).toString('hex')

// The exact statement the Director signs. It NAMES the channel + nonce, so
// consent is channel-specific and phishing-resistant (not a blank "I'm a
// Director"). Byte-stable — the verifier reconstructs and compares it exactly.
export function bindingStatement({ director, nactor, channelType, channelId, nonce }) {
  return `I, ${director}, accept Director approval authority on Nactor ${nactor}, ` +
    `over ${channelType} channel ${channelId}, nonce=${nonce}. (nact channel-binding v1)`
}

// Verify a signed binding proof against what we expect. The proof is a nostr
// event the Director signed, whose content is exactly the statement above. Three
// properties fall out of one check: valid signature (they hold the key), pubkey
// matches the claimed Director (it's THEM), content names this channel + the
// nonce WE delivered (consent to THIS channel, freshly). Returns
// { ok, why?, director?, channelId? }.
export function verifyBinding(event, expected) {
  if (!event || typeof event !== 'object') return { ok: false, why: 'no proof event' }
  let valid; try { valid = verifyEvent(event) } catch { valid = false }
  if (!valid) return { ok: false, why: 'invalid signature' }
  // The signature is over event.id only — verifyEvent does NOT recompute the
  // hash. Without this, any single Director-signed event could have its content
  // swapped to a forged statement under the same id+sig. Bind content to the
  // signature by proving the id commits to THESE bytes. (WYSIWYS, again.)
  let hash; try { hash = getEventHash(event) } catch { hash = null }
  if (hash !== event.id) return { ok: false, why: 'event id does not commit to its content — forged' }
  if (event.pubkey !== expected.directorHex) return { ok: false, why: 'proof not signed by the Director' }
  const want = bindingStatement({
    director: expected.director, nactor: expected.nactor,
    channelType: expected.channelType, channelId: expected.channelId, nonce: expected.nonce,
  })
  if ((event.content || '').trim() !== want) return { ok: false, why: 'statement mismatch — wrong channel or stale nonce' }
  return { ok: true, director: event.pubkey, channelId: String(expected.channelId) }
}

// The binding is persisted as a NIP-DA scope grant the Director gift-wraps to the
// Nactor — so revocation is a key rotation, like everything else. This is the
// scope name + the payload shape; the grant machinery (nipxx / grant-reader) is
// unchanged. A live grant for a channel id ⇒ that channel is verified; rotate the
// scope key and the binding is gone.
export const BINDING_SCOPE = 'channel:bind'
export function bindingGrantPayload({ director, nactor, channelType, channelId, label, nonce, echoedAt, identities, tiers, expires }) {
  return {
    kind: BINDING_SCOPE,
    director, nactor,
    channel: { type: channelType, id: String(channelId), label: label || undefined },
    delivery_proof: { nonce, echoed_at: echoedAt },      // from the ceremony
    authority: { identities: identities || [], tiers: tiers || ['low', 'elevated'] },  // SCOPED
    ...(expires ? { expires } : {}),
    purpose: 'approval delivery + authority for this Nactor',
  }
}

// Extract the verified channel id from a decrypted binding-grant payload — what
// the runtime adds to its `verified` set. Returns the channel id, or null if the
// payload isn't a binding grant. (Presence of a live grant IS the verification;
// its absence — via rotation — is the revocation.)
export function verifiedChannelOf(payload) {
  if (!payload || payload.kind !== BINDING_SCOPE) return null
  const id = payload.channel?.id
  return typeof id === 'string' && id ? id : null
}
