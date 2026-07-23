// Telegram approval adapter for Nact.
//
// Delivers each proposed action to the approver as an Approve/Reject card,
// and edits the card to show the outcome. Only the configured Telegram user
// id may enact. NOTE: one Telegram bot serves ONE webhook — use a bot
// dedicated to Nact, not one shared with another integration.
//
// CHANNEL BINDING (hardening P4, nact#10). Telegram is an OUT-OF-BAND channel:
// a matching `from.id` is not proof the Director's KEY consented — a hijacked
// bot or spoofed webhook can present any id. So this adapter is DELIVER-BUT-
// DON'T-HONOR by default: it will SEND cards, but it refuses to enact until the
// channel is verified by a live binding grant (see lib/channel-binding.mjs).
//   • channel:  { id, kind:'Telegram', label } — this channel's identity.
//   • verified: () => Set<channelId> | boolean — dereferenced LIVE on every
//     approval, so revoking the binding (key rotation) stops honoring at once.
// Omit `verified` and the channel is unbound — cards still deliver, approvals
// are refused. The NIP-98 web queue and NIP-59 DMs are intrinsically bound and
// need none of this.

import { mayHonor } from '../../lib/channel-binding.mjs'

export function telegramApproval({ botToken, approverId, webhookSecret, channel, verified } = {}) {
  if (!botToken || !approverId) throw new Error('nact/telegram: botToken and approverId are required')
  const chan = channel || { id: `telegram:${approverId}`, kind: 'Telegram', label: 'Telegram approvals' }
  // Normalize `verified` to a live probe returning a Set for mayHonor().
  const verifiedSet = () => {
    const v = typeof verified === 'function' ? verified() : verified
    if (v instanceof Set) return v
    if (v === true) return new Set([chan.id])          // caller asserts this channel bound
    if (Array.isArray(v)) return new Set(v)
    return new Set()                                   // unbound → honors nothing
  }
  const TG = m => `https://api.telegram.org/bot${botToken}/${m}`
  const esc = s => String(s).replace(/[<&>]/g, c => ({ '<': '&lt;', '&': '&amp;', '>': '&gt;' }[c]))
  const cards = new Map()   // id → { chat_id, message_id, body }

  async function tg(method, body) {
    const r = await fetch(TG(method), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    if (!r.ok) console.warn(`nact/telegram ${method} → ${r.status} ${await r.text().catch(() => '')}`)
    return r
  }

  return {
    // Verify a webhook came from Telegram (call from your HTTP handler).
    verifyWebhook(headers = {}) {
      return !webhookSecret || headers['x-telegram-bot-api-secret-token'] === webhookSecret
    },

    async send({ id, identity, npub, draft, context, fingerprint, report }) {
      const rep = report || {}
      const risk = rep.risk || 'low'
      const badge = risk === 'critical' ? '🔴 CRITICAL' : risk === 'elevated' ? '🟡 elevated' : '🟢 low'
      const L = [`📝 <b>Enact as ${esc(identity)}</b> · ${badge}`, `<code>${esc(npub.slice(0, 16))}…</code>`, '']
      L.push(`<b>${esc(rep.kindLabel || 'kind ' + draft.kind)}</b>`)
      if (draft.content) L.push(esc(draft.content))
      if (rep.tags && rep.tags.length) L.push(`\n<i>tags:</i> <code>${esc(rep.tags.map(t => t.join(':')).join('  '))}</code>`)
      for (const w of (rep.warnings || [])) L.push(`⚠️ ${esc(w)}`)
      if (context) L.push(`\n<i>context (not published): ${esc(context)}</i>`)
      if (fingerprint) L.push(`\n<code>id ${esc(fingerprint.slice(0, 16))}…</code> — verify this matches your signer`)
      const body = L.join('\n')
      // Critical actions ideally step up to sign-on-device (a web_app button →
      // the bunker); until that ships, the badge + full render + fingerprint are
      // the WYSIWYS surface. See docs/threat-model.md.
      const okLabel = risk === 'critical' ? '🔐 Verify & enact' : '✅ Approve & enact'
      const r = await tg('sendMessage', {
        chat_id: approverId, text: body, parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [[
          { text: okLabel, callback_data: `ok:${id}` },
          { text: '❌ Reject', callback_data: `no:${id}` },
        ]] },
      })
      if (!r.ok) return false
      try { const j = await r.json(); cards.set(id, { chat_id: j.result.chat.id, message_id: j.result.message_id, body }) } catch {}
      return true
    },

    parseDecision(raw) {
      let u; try { u = typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return null }
      const cq = u?.callback_query; if (!cq) return null
      const [verb, id] = (cq.data || '').split(':')
      return { id, verb, approver: String(cq.from?.id || '') }
    },

    // Two gates, both required: the id must match (identity) AND this channel
    // must be verified (binding). An unbound Telegram channel fails the second
    // — deliver-but-don't-honor — even for the right id.
    isApprover(approver) {
      if (String(approver) !== String(approverId)) return false
      if (!mayHonor(chan, verifiedSet())) {
        console.warn(`nact/telegram: refusing approval over UNVERIFIED channel ${chan.id} — complete the binding ceremony (channel-binding.mjs)`)
        return false
      }
      return true
    },

    // Expose the channel + its live binding state, so a runtime/HTTP handler can
    // tell "wrong person" apart from "right person, unbound channel" and prompt
    // the ceremony instead of a bare "not authorized".
    channel: chan,
    isBound() { return mayHonor(chan, verifiedSet()) },

    async ack({ id, result }) {
      const card = cards.get(id); cards.delete(id)
      const mark = result.posted ? `✅ <b>Enacted</b> · <code>${result.id.slice(0, 12)}…</code> · ${result.relays} relays`
        : result.rejected ? '❌ <b>Rejected</b>'
        : result.error === 'expired' ? '⏳ <b>Expired</b>'
        : `⚠️ <b>${esc(result.error || 'failed')}</b>`
      // card.body is already valid HTML we composed — don't re-escape it.
      if (card) await tg('editMessageText', { chat_id: card.chat_id, message_id: card.message_id, text: `${card.body}\n\n${mark}`, parse_mode: 'HTML' })
    },
  }
}
