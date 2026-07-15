// Nact — the enactment pipeline: propose an action, a human enacts it by
// signing, then it broadcasts. The agent proposes; it never holds the key
// that authorizes. Generalized from the Nave ecosystem's Luke agent.
//
// Two axes of pluggability:
//   • the APPROVAL adapter decides how a human is asked and how they answer
//     (Telegram today; a NIP-59 gift-wrapped nostr DM is the native path).
//   • the SIGNER decides where the authorizing key lives — custodial (nsec on
//     this host, your explicit choice) or NIP-46 (a remote bunker; the key
//     stays on your device and Nact never sees it).

import { nip19, getEventHash } from 'nostr-tools'
import { SimplePool } from 'nostr-tools/pool'
import { randomBytes } from 'node:crypto'
import { custodialSigner } from './signers/custodial.mjs'
import { nip46Signer } from './signers/nip46.mjs'
import { inspect } from './inspect.mjs'

export class Nact {
  // identities: { name: cfg } where cfg is one of
  //     { nsec }            — custodial signer (key on this host)
  //     { bunker,           — NIP-46 remote signer (key on your device)
  //       clientSecret? }
  //     { signer }          — any object with async publicKey()/sign()/close()
  // relays:   string[]      — where enacted events publish.
  // approval: an adapter implementing { send, parseDecision, isApprover, ack }.
  constructor({ identities = {}, relays = [], approval, ttlMs = 36 * 3600 * 1000 } = {}) {
    if (!approval) throw new Error('nact: an approval adapter is required')
    this.approval = approval
    this.relays = relays
    this.ttlMs = ttlMs
    this.pool = new SimplePool()
    this.pending = new Map()          // id → { identity, unsigned, fingerprint, created }
    this.identities = {}
    for (const [name, cfg] of Object.entries(identities)) {
      const signer = resolveSigner(cfg)
      if (!signer) { console.warn(`nact: identity '${name}' has no usable signer — skipped`); continue }
      // pk/npub resolve lazily: a NIP-46 bunker isn't reachable until first use,
      // so we don't block construction on a network round-trip.
      this.identities[name] = { signer, pk: null, npub: null }
    }
  }

  identityNames() { return Object.keys(this.identities) }

  // Register (or replace) an identity after construction — e.g. a role key
  // imported at runtime as a credential-scope, held only in memory. Same cfg
  // shape as the constructor ({ nsec } | { bunker } | { signer }). Returns
  // true if a usable signer resolved. pk/npub still resolve lazily on first use.
  addIdentity(name, cfg) {
    const signer = resolveSigner(cfg)
    if (!signer) return false
    this.identities[name] = { signer, pk: null, npub: null }
    return true
  }

  // Forget an identity (e.g. its credential-scope was revoked). It can no
  // longer be proposed or enacted as.
  removeIdentity(name) { return delete this.identities[name] }

  // Resolve (and cache) an identity's pubkey/npub, connecting the signer if
  // this is a remote bunker's first use.
  async _resolve(name) {
    const idn = this.identities[name]
    if (!idn) throw new Error(`nact: unknown identity '${name}'`)
    if (!idn.pk) {
      idn.pk = await idn.signer.publicKey()
      idn.npub = nip19.npubEncode(idn.pk)
    }
    return idn
  }

  // Propose an action. `event` is an unsigned template: { kind, content, tags }.
  // `context` is shown to the human to inform the decision; it is NOT published.
  async propose({ identity, event, context, replyTo } = {}) {
    const idn = await this._resolve(identity)
    if (!event || typeof event.kind !== 'number') throw new Error('nact: event.kind is required')
    this._gc()
    const id = randomBytes(6).toString('base64url')
    const tags = event.tags ? [...event.tags] : []
    if (replyTo) tags.push(['e', replyTo, '', 'root'])
    // Freeze the FULL event now — created_at and pubkey included — so its id is
    // fully determined at approval time and can be re-checked before signing.
    // (WYSIWYS: what's shown is exactly what will be signed. See docs/threat-model.md.)
    const unsigned = {
      pubkey: idn.pk,
      created_at: Math.floor(Date.now() / 1000),
      kind: event.kind,
      tags,
      content: event.content ?? '',
    }
    const fingerprint = getEventHash(unsigned)
    const report = inspect(unsigned)
    this.pending.set(id, { identity, unsigned, fingerprint, created: Date.now() })
    const draft = { kind: unsigned.kind, content: unsigned.content, tags: unsigned.tags }
    const sent = await this.approval.send({ id, identity, npub: idn.npub, draft, context, fingerprint, report })
    if (!sent) { this.pending.delete(id); throw new Error('nact: approval delivery failed') }
    return { id, status: 'awaiting-approval', fingerprint, risk: report.risk }
  }

  // Feed the raw approval-channel payload (e.g. a Telegram webhook body).
  async handleCallback(raw) {
    const decision = await this.approval.parseDecision(raw)   // { id, verb, approver } | null
    if (!decision) return { handled: false }
    return this.enact(decision)
  }

  // Enact a decision: verify the human, then sign + broadcast (or discard).
  async enact({ id, verb, approver } = {}) {
    if (!(await this.approval.isApprover(approver))) {
      await this.approval.ack({ id, result: { error: 'not authorized' } })
      return { enacted: false, why: 'not authorized' }
    }
    const p = this.pending.get(id)
    if (!p) { await this.approval.ack({ id, result: { error: 'expired' } }); return { enacted: false, why: 'expired' } }
    this.pending.delete(id)
    if (verb !== 'ok') { await this.approval.ack({ id, result: { rejected: true } }); return { enacted: false, why: 'rejected' } }

    const idn = await this._resolve(p.identity)
    let signed
    try {
      // Sign the EXACT frozen bytes that were shown and approved — never a
      // freshly-built event.
      signed = await idn.signer.sign(p.unsigned)
    } catch (e) {
      // A NIP-46 bunker can decline or time out — that's a legitimate second
      // veto, not a crash. Report it back through the same ack channel.
      await this.approval.ack({ id, result: { error: `signer: ${e?.message || 'declined'}` } })
      return { enacted: false, why: 'signer declined' }
    }
    // WYSIWYS gate: the signed event must be byte-identical to what was approved.
    // If a signer returned anything else (mutation, re-stamped fields), refuse.
    if (signed.id !== p.fingerprint) {
      await this.approval.ack({ id, result: { error: 'signed event diverged from approved (fingerprint mismatch)' } })
      return { enacted: false, why: 'fingerprint mismatch' }
    }
    const results = await Promise.allSettled(this.pool.publish(this.relays, signed))
    const seen = results.filter(r => r.status === 'fulfilled').length
    await this.approval.ack({ id, result: seen ? { posted: true, id: signed.id, relays: seen } : { error: 'no relay accepted' } })
    return seen ? { enacted: true, event: signed, relays: seen } : { enacted: false, why: 'broadcast failed' }
  }

  _gc() { const now = Date.now(); for (const [k, v] of this.pending) if (now - v.created > this.ttlMs) this.pending.delete(k) }
}

// Turn an identity config into a signer. Order matters: an explicit signer
// object wins, then a bunker URI, then a custodial nsec.
function resolveSigner(cfg) {
  if (!cfg) return null
  if (cfg.signer && typeof cfg.signer.sign === 'function') return cfg.signer
  if (cfg.bunker) return nip46Signer(cfg.bunker, { clientSecret: cfg.clientSecret })
  if (cfg.nsec) { try { return custodialSigner(cfg.nsec) } catch { return null } }
  return null
}

export { custodialSigner } from './signers/custodial.mjs'
export { nip46Signer } from './signers/nip46.mjs'
