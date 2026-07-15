// Telegram approval adapter for Nact.
//
// Delivers each proposed action to the approver as an Approve/Reject card,
// and edits the card to show the outcome. Only the configured Telegram user
// id may enact. NOTE: one Telegram bot serves ONE webhook — use a bot
// dedicated to Nact, not one shared with another integration.

export function telegramApproval({ botToken, approverId, webhookSecret } = {}) {
  if (!botToken || !approverId) throw new Error('nact/telegram: botToken and approverId are required')
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

    async send({ id, identity, npub, draft, context }) {
      const body = `📝 <b>Enact as ${esc(identity)}</b>\n<code>${esc(npub.slice(0, 16))}…</code>\n\n`
        + `${esc(draft.content)}${context ? `\n\n<i>${esc(context)}</i>` : ''}`
      const r = await tg('sendMessage', {
        chat_id: approverId, text: body, parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [[
          { text: '✅ Approve & enact', callback_data: `ok:${id}` },
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

    isApprover(approver) { return String(approver) === String(approverId) },

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
