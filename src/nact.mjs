// nact — the enactment pipeline: propose an action, a human enacts it by
// signing, then it broadcasts. The agent proposes; it never holds the key
// that authorizes. Generalized from the Nave ecosystem's Luke agent.

import { finalizeEvent, getPublicKey, nip19 } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'
import { randomBytes } from 'node:crypto'

export class Nact {
  // identities: { name: { nsec } }  — role keys the agent may act AS.
  // relays:     string[]            — where enacted events publish.
  // approval:   an adapter (see adapters/telegram.mjs) implementing
  //             { send, parseDecision, isApprover, ack }.
  constructor({ identities = {}, relays = [], approval, ttlMs = 36 * 3600 * 1000 } = {}) {
    if (!approval) throw new Error('nact: an approval adapter is required')
    this.approval = approval
    this.relays = relays
    this.ttlMs = ttlMs
    this.pool = new SimplePool()
    this.pending = new Map()          // id → { identity, draft, created }
    this.identities = {}
    for (const [name, cfg] of Object.entries(identities)) {
      const sk = loadSecret(cfg?.nsec)
      if (!sk) { console.warn(`nact: identity '${name}' has no usable nsec — skipped`); continue }
      const pk = getPublicKey(sk)
      this.identities[name] = { sk, pk, npub: nip19.npubEncode(pk) }
    }
  }

  identityNames() { return Object.keys(this.identities) }

  // Propose an action. `event` is an unsigned template: { kind, content, tags }.
  // `context` is shown to the human to inform the decision; it is NOT published.
  async propose({ identity, event, context, replyTo } = {}) {
    const idn = this.identities[identity]
    if (!idn) throw new Error(`nact: unknown identity '${identity}'`)
    if (!event || typeof event.kind !== 'number') throw new Error('nact: event.kind is required')
    this._gc()
    const id = randomBytes(6).toString('base64url')
    const tags = event.tags ? [...event.tags] : []
    if (replyTo) tags.push(['e', replyTo, '', 'root'])
    const draft = { kind: event.kind, content: event.content ?? '', tags }
    this.pending.set(id, { identity, draft, created: Date.now() })
    const sent = await this.approval.send({ id, identity, npub: idn.npub, draft, context })
    if (!sent) { this.pending.delete(id); throw new Error('nact: approval delivery failed') }
    return { id, status: 'awaiting-approval' }
  }

  // Feed the raw approval-channel payload (e.g. a Telegram webhook body).
  async handleCallback(raw) {
    const decision = this.approval.parseDecision(raw)   // { id, verb, approver } | null
    if (!decision) return { handled: false }
    return this.enact(decision)
  }

  // Enact a decision: verify the human, then sign + broadcast (or discard).
  async enact({ id, verb, approver } = {}) {
    if (!this.approval.isApprover(approver)) {
      await this.approval.ack({ id, result: { error: 'not authorized' } })
      return { enacted: false, why: 'not authorized' }
    }
    const p = this.pending.get(id)
    if (!p) { await this.approval.ack({ id, result: { error: 'expired' } }); return { enacted: false, why: 'expired' } }
    this.pending.delete(id)
    if (verb !== 'ok') { await this.approval.ack({ id, result: { rejected: true } }); return { enacted: false, why: 'rejected' } }

    const { sk } = this.identities[p.identity]
    const signed = finalizeEvent({ ...p.draft, created_at: Math.floor(Date.now() / 1000) }, sk)
    const results = await Promise.allSettled(this.pool.publish(this.relays, signed))
    const seen = results.filter(r => r.status === 'fulfilled').length
    await this.approval.ack({ id, result: seen ? { posted: true, id: signed.id, relays: seen } : { error: 'no relay accepted' } })
    return seen ? { enacted: true, event: signed, relays: seen } : { enacted: false, why: 'broadcast failed' }
  }

  _gc() { const now = Date.now(); for (const [k, v] of this.pending) if (now - v.created > this.ttlMs) this.pending.delete(k) }
}

function loadSecret(v) {
  const raw = (v ?? '').trim()
  if (!raw) return null
  if (raw.startsWith('nsec1')) return nip19.decode(raw).data
  if (/^[0-9a-f]{64}$/i.test(raw)) return Uint8Array.from(raw.match(/.{1,2}/g).map(b => parseInt(b, 16)))
  return null
}
