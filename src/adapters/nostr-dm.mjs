// Nostr-DM approval adapter for nact — the native path.
//
// Instead of a Telegram bot, the proposal is delivered to the approver as a
// NIP-59 gift-wrapped, NIP-17 direct message. The approver reads it in any
// nostr client that speaks NIP-17 (0xchat, Amethyst, nostrudel…) and replies
// with a short code to enact or reject. Their reply is itself a signed,
// gift-wrapped DM, so the approval is authenticated by *their* key — no
// third-party bot, no platform account, entirely inside nostr.
//
// nact DMs from a dedicated "channel" key (channelNsec) — a low-value key
// whose only job is to carry approval traffic. The authority still rests with
// the approver's signature and, when paired with the NIP-46 signer, their
// bunker; the channel key can't enact anything.
//
//   const approval = nostrDmApproval({ channelNsec, approver, relays })
//   const nact = new Nact({ identities, relays, approval })
//   approval.listen(wrap => nact.handleCallback(wrap))   // start receiving
import { getPublicKey, nip19 } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'
import { wrapEvent, unwrapEvent } from 'nostr-tools/nip59'
import { loadSecret } from '../util/secret.mjs'

export function nostrDmApproval({ channelNsec, approver, relays = [] } = {}) {
  const sk = loadSecret(channelNsec)
  if (!sk) throw new Error('nact/nostr-dm: channelNsec is required (the key nact sends DMs from)')
  const approverPk = toPubkey(approver)
  if (!approverPk) throw new Error('nact/nostr-dm: approver (npub or hex) is required')
  const channelPk = getPublicKey(sk)
  const pool = new SimplePool()

  // Wrap a NIP-17 chat message (kind 14) to the approver and publish it.
  async function dm(text) {
    const wrap = wrapEvent({ kind: 14, content: text, tags: [['p', approverPk]] }, sk, approverPk)
    const results = await Promise.allSettled(pool.publish(relays, wrap))
    return results.some(r => r.status === 'fulfilled')
  }

  return {
    channelPubkey: channelPk,
    channelNpub: nip19.npubEncode(channelPk),

    async send({ id, identity, npub, draft, context }) {
      const text =
        `📝 Enact as ${identity}  (${npub.slice(0, 16)}…)\n\n` +
        `${draft.content}` +
        (context ? `\n\n— ${context}` : '') +
        `\n\n↩︎ reply:  ok ${id}   ·   no ${id}`
      try { return await dm(text) } catch (e) { console.warn('nact/nostr-dm send:', e?.message); return false }
    },

    // `raw` is a kind-1059 gift wrap (from listen). Unwrap it, confirm it's a
    // chat message, and pull the verb + proposal id the approver typed.
    async parseDecision(raw) {
      let wrap; try { wrap = typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return null }
      if (!wrap || wrap.kind !== 1059) return null
      let rumor; try { rumor = unwrapEvent(wrap, sk) } catch { return null }
      if (!rumor || rumor.kind !== 14) return null
      // "ok <id>" / "approve <id>" → enact; "no <id>" / "reject <id>" → drop.
      // Requiring the id right after the verb avoids matching stray 8-char
      // words, and scopes the decision to exactly one proposal.
      const m = String(rumor.content || '').match(/\b(ok|yes|approve|approved|no|reject|rejected)\b[\s:]*([A-Za-z0-9_-]{8})\b/i)
      if (!m) return null
      const verb = /^(ok|yes|approve|approved)$/i.test(m[1]) ? 'ok' : 'no'
      return { id: m[2], verb, approver: rumor.pubkey }
    },

    isApprover(approver) { return approver === approverPk },

    async ack({ id, result }) {
      const mark = result.posted ? `✅ Enacted · ${result.id.slice(0, 12)}… · ${result.relays} relays`
        : result.rejected ? '❌ Rejected'
        : result.error === 'expired' ? '⏳ Expired (proposal aged out)'
        : `⚠️ ${result.error || 'failed'}`
      try { await dm(`re ${id}: ${mark}`) } catch { /* the outcome is best-effort */ }
    },

    // Subscribe for the approver's wrapped replies; hand each raw wrap to
    // `onWrap` (wire it to nact.handleCallback). Returns the sub so the caller
    // can close it. Only wraps addressed to the channel key arrive here; the
    // `since` floor skips history so old DMs don't re-fire on restart.
    listen(onWrap) {
      const since = Math.floor(Date.now() / 1000)
      return pool.subscribeMany(relays, [{ kinds: [1059], '#p': [channelPk], since }], {
        onevent: ev => { try { onWrap(ev) } catch (e) { console.warn('nact/nostr-dm listen:', e?.message) } },
      })
    },

    close() { try { pool.close(relays) } catch { /* idempotent */ } },
  }
}

function toPubkey(v) {
  const raw = (v ?? '').trim()
  if (!raw) return null
  if (raw.startsWith('npub1')) { try { return nip19.decode(raw).data } catch { return null } }
  if (/^[0-9a-f]{64}$/i.test(raw)) return raw.toLowerCase()
  return null
}
