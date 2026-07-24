// ngage-delivery.mjs — the director-path delivery runtime (nact#37, AD-10).
//
// A director-path identity is KEYLESS on this box: only the Director's key can
// sign its events, and that key lives with him. So its proposals cannot enter
// the Nact enact pipeline at all — there is no signer to resolve. Instead the
// draft is RAISED to the Director over the wire Ngage already speaks
// (ngage/drafts.mjs; the same send-side as luke's jaf-scribe):
//
//   kind-30440 scope   — the draft payload, encrypted under a fresh scope key,
//                        published and signed by NACTOR's OWN key (the box
//                        signs as itself — never as the keyless identity);
//   kind-440 grant     — the scope key, gift-wrapped (NIP-59) to the Director
//                        npub the identity's Ngage channel names.
//
// He reviews on his desk and signs the kind-1 in his own hand — approval
// happens where the signing key lives, enforced by encryption, not policy.
// There is deliberately NO approval callback here: on this path the Director's
// signature IS the enactment, published from his own client. The box only ever
// offers, and can take an offer back (withdraw = tombstone the scope).
//
// Trust prerequisite (documented in the README): the Director's Ngage
// allowlist must carry the NACTOR npub — Ngage's admission gates accept
// first-hand drafts from allowlisted authors only.

import { randomBytes } from 'node:crypto'
import { nip19 } from 'nostr-tools'
import { approvalBindingOf, isDirectorPath } from '../lib/routing.mjs'
import { newScopeKey, publishScope, grant, deleteScope } from './lib/nipxx.mjs'

// The single Ngage channel an identity's drafts raise through: its approval
// binding, if that binding is an active director-path channel. Pure.
export function ngageChannelFor(cfg, identityKey) {
  const ch = approvalBindingOf(cfg?.channels, identityKey)
  return ch && isDirectorPath(ch) && (ch.status || 'active') === 'active' ? ch : null
}

// Map a proposal template onto the draft payload Ngage renders
// (ngage/drafts.mjs readDraftPayload — every field optional, kind-1 only).
// Returns { ok, payload } or { ok:false, code, error }. Pure.
//
// v1 scope: fresh posts. Ngage's desk assembles a kind-1 from text (+hashtags);
// it cannot faithfully render other kinds or carry reply/mention tags, and a
// draft it cannot render byte-for-byte must never reach the Director's signer
// (WYSIWYS). So anything but a bare kind-1 is refused loudly here.
export function draftPayloadFrom({ event, context, proposedBy } = {}) {
  if (!event || typeof event.kind !== 'number') return { ok: false, code: 400, error: 'event.kind is required' }
  if (event.kind !== 1) {
    return { ok: false, code: 422, error: `kind ${event.kind} cannot ride the Ngage draft wire — the desk composes kind-1 posts only (extending it is ngage-side work)` }
  }
  const text = typeof event.content === 'string' ? event.content.trim() : ''
  if (!text) return { ok: false, code: 422, error: 'an empty post cannot be raised' }
  const tags = Array.isArray(event.tags) ? event.tags : []
  const foreign = tags.filter(t => t?.[0] !== 't')
  if (foreign.length) {
    return { ok: false, code: 422, error: `tags [${foreign.map(t => t?.[0]).join(', ')}] cannot ride the Ngage draft wire — the Director's desk composes fresh posts (hashtag 't' tags only)` }
  }
  return {
    ok: true,
    payload: {
      kind: 'draft:post',
      text,
      image: null,
      hashtags: tags.map(t => String(t[1] || '')).filter(Boolean),
      rationale: typeof context === 'string' && context.trim() ? context.trim() : null,
      proposedBy: proposedBy || null,
      proposedAt: Math.floor(Date.now() / 1000),
    },
  }
}

/**
 * The runtime. `sk` is NACTOR's key (the sending author), `relay` any
 * {publish, query} adapter, `config` a live accessor (edits apply without a
 * restart, matching the rest of the runtime), `onEvent` the AD-1 audit feed.
 */
export function ngageDelivery({ sk, relay, config, onEvent = () => {} } = {}) {
  const raised = new Map()   // scopeId → { identity, grantee, scopeName, generation, text, at, status }

  // Raise a director-path proposal to the Director's desk. Returns
  // { ok:true, id, status:'raised-to-director', … } or { ok:false, code, error }.
  async function raise({ identity, event, context } = {}) {
    const cfg = config()
    const meta = cfg?.identitiesMeta?.[identity]
    if (!meta || meta.signer !== 'director') return { ok: false, code: 400, error: `'${identity}' is not a director-path identity` }
    if ((meta.status || 'active') !== 'active') return { ok: false, code: 409, error: `'${identity}' is revoked` }
    if (!sk) return { ok: false, code: 503, error: 'this runtime holds no NACTOR_NSEC — it cannot author draft grants (grant transport: mcp?)' }
    const ch = ngageChannelFor(cfg, identity)
    if (!ch) return { ok: false, code: 409, error: `'${identity}' has no Ngage approval path — bind it under the Ngage column in Routing first` }
    let grantee; try { grantee = nip19.decode(String(ch.approver || '')).data } catch { grantee = null }
    if (typeof grantee !== 'string' || grantee.length !== 64) {
      return { ok: false, code: 409, error: `the Ngage channel '${ch.name || ch.id}' names no Director npub — set its Director field` }
    }
    const mapped = draftPayloadFrom({ event, context, proposedBy: meta.handle || identity })
    if (!mapped.ok) return mapped

    const scopeId = randomBytes(12).toString('hex')             // opaque d tag
    const scopeKey = newScopeKey()
    const scopeName = `draft:post/${scopeId.slice(0, 8)}`       // the scribe's shape, verbatim
    await publishScope(relay, sk, { scopeId, generation: 1, scopeKey, payload: mapped.payload })
    const { acks } = await grant(relay, sk, grantee, { scopeId, generation: 1, scopeKey, scopeName })

    const rec = {
      identity, grantee: nip19.npubEncode(grantee), scopeName, generation: 1,
      text: mapped.payload.text, at: Date.now(), status: 'raised',
    }
    raised.set(scopeId, rec)
    onEvent({ t: 'ngage-raise', identity, scopeId, scopeName, when: rec.at })
    return { ok: true, id: scopeId, status: 'raised-to-director', scopeName, grantee: rec.grantee, relays: acks }
  }

  // Take an offer back: tombstone the scope (empty payload, a key granted to no
  // one, bumped generation + NIP-09). His desk shows it withdrawn, unpostable.
  async function withdraw(scopeId) {
    const rec = raised.get(scopeId)
    if (!rec) return { ok: false, code: 404, error: 'no such raised draft (this runtime raised nothing under that id)' }
    if (rec.status === 'withdrawn') return { ok: true, id: scopeId, status: 'withdrawn' }
    if (!sk) return { ok: false, code: 503, error: 'this runtime holds no NACTOR_NSEC' }
    await deleteScope(relay, sk, { scopeId, generation: rec.generation })
    rec.status = 'withdrawn'
    onEvent({ t: 'ngage-withdraw', identity: rec.identity, scopeId, when: Date.now() })
    return { ok: true, id: scopeId, status: 'withdrawn' }
  }

  // The raised ledger for /api/state — in-memory, like the pending queue: the
  // grants themselves live on the relays; this is the runtime's session view.
  const listRaised = () => [...raised.entries()].map(([scopeId, r]) => ({ scopeId, ...r }))

  return { raise, withdraw, listRaised }
}
