// Offline proof of the director-path delivery runtime (nact#37): a proposal
// for a keyless `signer:'director'` identity is raised to the Director as a
// NIP-DA draft grant over the EXACT wire Ngage consumes — and everything that
// must not ride (wrong kinds, foreign tags, unbound identities) is refused
// loudly before anything touches a relay. The Director side below performs the
// same unwrap + admission gates as ngage/drafts.mjs (namespace / first-hand /
// allowlist), so wire conformance is proven, not assumed.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey, nip19, finalizeEvent } from 'nostr-tools'
import { receiveGrants, latestGrants, fetchScope } from './lib/nipxx.mjs'
import { Relay } from './lib/relay.mjs'
import { LocalRelay } from './lib/liverelay.mjs'
import { ngageDelivery, ngageChannelFor, draftPayloadFrom, penVerdict, KIND_PEN_ATTEST } from './ngage-delivery.mjs'

const nactorSk = generateSecretKey()            // the box's own key — the draft author
const nactorPub = getPublicKey(nactorSk)
const directorSk = generateSecretKey()          // the Director — grantee, sovereign signer
const directorNpub = nip19.npubEncode(getPublicKey(directorSk))
const penSk = generateSecretKey()               // jaf-quill's key — THE PEN (off-box in prod)
const penNpub = nip19.npubEncode(getPublicKey(penSk))
const relay = new LocalRelay(new Relay())

// A pen attestation: the draft core signed by the pen's key (nact#44).
const penned = (core, sk = penSk) => finalizeEvent(
  { kind: KIND_PEN_ATTEST, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify(core) }, sk)

// The config the app would persist: one keyless director-path identity bound to
// an Ngage channel, one custodial identity bound to the box gate.
const cfg = {
  identitiesMeta: {
    jafquill: { handle: 'jaf-quill@dequalsf.com', signer: 'director', npub: penNpub, status: 'active' },
    luke: { handle: 'luke@nave.pub', signer: 'custodial', status: 'active' },
  },
  channels: [
    { id: 'web', name: 'Nact app', kind: 'Web queue (NIP-98)', purpose: 'approval', approver: 'director', covers: ['luke'], status: 'active' },
    { id: 'ngage1', name: 'Ngage desk', kind: 'Ngage draft-grant', purpose: 'approval', approver: directorNpub, covers: ['jafquill'], status: 'active' },
  ],
}

const events = []                               // AD-1 audit feed under test
const ngage = ngageDelivery({ sk: nactorSk, relay, config: () => cfg, onEvent: e => events.push(e) })

// Ngage's admission gates (drafts.mjs trustedDrafts). Gate 2 (author ===
// publisher, no re-wraps) can't be filtered here — nipxx's receiveGrants drops
// the seal-verified author — so it is ASSERTED below instead: the dereferenced
// scope is the publisher's own signed 30440, and we require that publisher to
// be the Nactor that raised the draft.
const directorDesk = async (allowlist) => {
  const grants = latestGrants(await receiveGrants(relay, directorSk))
  return grants
    .filter(g => typeof g.scopeName === 'string' && g.scopeName.startsWith('draft:'))  // 1. namespace
    .filter(g => allowlist.has(g.publisher))                                           // 3. allowlist
}

// --- the routing + mapping specs (pure) -----------------------------------
assert.equal(ngageChannelFor(cfg, 'jafquill')?.id, 'ngage1', 'director-path identity resolves its Ngage channel')
assert.equal(ngageChannelFor(cfg, 'luke'), null, 'a box-gate binding is NOT an Ngage path')
assert.equal(draftPayloadFrom({ event: { kind: 30023, content: 'x' } }).code, 422, 'non-kind-1 refused')
assert.equal(draftPayloadFrom({ event: { kind: 1, content: 'hi', tags: [['e', 'abc']] } }).code, 422, 'reply tags refused')
assert.equal(draftPayloadFrom({ event: { kind: 1, content: '   ' } }).code, 422, 'empty text refused')
const mapped = draftPayloadFrom({ event: { kind: 1, content: 'a real thought #nave', tags: [['t', 'nave']] }, context: 'why', proposedBy: 'jaf-quill@dequalsf.com' })
assert.equal(mapped.ok, true)
assert.equal(mapped.payload.text, 'a real thought #nave', 'text rides byte-identical')
assert.deepEqual(mapped.payload.hashtags, ['nave'])
assert.equal(mapped.payload.rationale, 'why')
console.log('✓ routing + payload mapping: kind-1 only, foreign tags refused, text byte-identical')

// --- refusals happen BEFORE the wire --------------------------------------
assert.equal((await ngage.raise({ identity: 'luke', event: { kind: 1, content: 'x' } })).code, 400, 'custodial identity refused here')
assert.equal((await ngage.raise({ identity: 'ghost', event: { kind: 1, content: 'x' } })).code, 400, 'unknown identity refused')
const okPen = () => penned({ text: 'x' })
const unbound = { ...cfg, channels: [cfg.channels[0]] }
const ngageUnbound = ngageDelivery({ sk: nactorSk, relay, config: () => unbound })
assert.equal((await ngageUnbound.raise({ identity: 'jafquill', pen: okPen() })).code, 409, 'no Ngage binding → 409')
const badApprover = { ...cfg, channels: [{ ...cfg.channels[1], approver: '12345' }] }
const ngageBadApprover = ngageDelivery({ sk: nactorSk, relay, config: () => badApprover })
assert.equal((await ngageBadApprover.raise({ identity: 'jafquill', pen: okPen() })).code, 409, 'channel without a Director npub → 409')
const ngageNoKey = ngageDelivery({ sk: null, relay, config: () => cfg })
assert.equal((await ngageNoKey.raise({ identity: 'jafquill', pen: okPen() })).code, 503, 'no NACTOR key → honest 503')
assert.equal(relay.inner.events.length, 0, 'every refusal happened before anything reached the relay')
console.log('✓ refusals: 400 wrong path · 409 unbound/no-npub · 503 keyless — nothing published')

// --- the pen rule (nact#44): the courier may only carry pen-signed words ----
assert.equal((await ngage.raise({ identity: 'jafquill', event: { kind: 1, content: 'x' } })).code, 403, 'no pen → 403, the courier authors nothing')
assert.equal((await ngage.raise({ identity: 'jafquill', pen: penned({ text: 'x' }, generateSecretKey()) })).code, 403, 'a pen signature from the WRONG key → 403')
const forged = { ...penned({ text: 'the pen wrote this' }), content: JSON.stringify({ text: 'the attacker wrote this' }) }
assert.equal((await ngage.raise({ identity: 'jafquill', pen: forged })).code, 403, 'signature reuse under swapped content → 403 (the P4 lesson, recomputed hash)')
assert.equal((await ngage.raise({ identity: 'jafquill', pen: okPen(), event: { kind: 1, content: 'different words' } })).code, 422, 'caller event disagreeing with its own pen → 422')
assert.equal(penVerdict(penned({ text: 'x' }), getPublicKey(penSk)).ok, true)
assert.equal(relay.inner.events.length, 0, 'still nothing on the relay')
console.log('✓ the pen rule: unpenned/wrong-key/forged/mismatched raises all refused before the wire')

// --- the happy path, proven on the Director's side -------------------------
const out = await ngage.raise({
  identity: 'jafquill',
  pen: penned({
    text: 'shipping the director path tonight #nave',
    hashtags: ['nave'],
    rationale: 'the routing board has an Ngage column now — this proves drafts reach it',
  }),
})
assert.equal(out.ok, true)
assert.equal(out.status, 'raised-to-director')
assert.equal(out.grantee, directorNpub, 'granted to the channel-named Director')
assert.ok(out.scopeName.startsWith('draft:post/'), 'the scribe\'s scope-name shape, verbatim')

// The Director's desk: unwrap with HIS key, apply Ngage's admission gates.
const desk = await directorDesk(new Set([nactorPub]))
assert.equal(desk.length, 1, 'exactly one draft grant on the desk')
assert.equal(desk[0].publisher, nactorPub, 'first-hand: the scope publisher IS the raising Nactor (gate 2)')
const scope = await fetchScope(relay, desk[0])
assert.equal(scope.status, 'ok', 'the scope dereferences with the granted key')
assert.equal(scope.data.text, 'shipping the director path tonight #nave', 'WYSIWYS: the desk reads the exact pen-attested text')
assert.equal(scope.data.proposedBy, 'jaf-quill@dequalsf.com')
assert.equal(scope.data.kind, 'draft:post')
assert.deepEqual(scope.data.hashtags, ['nave'])
assert.ok(scope.data.rationale.includes('routing board'))
// The desk can re-verify the pen INDEPENDENTLY (ngage#11): the attestation
// rides the payload, verifies, is the pen's key, and its bytes ARE the draft.
assert.equal(penVerdict(scope.data.pen, getPublicKey(penSk)).ok, true, 'embedded attestation verifies on the desk side')
assert.equal(JSON.parse(scope.data.pen.content).text, scope.data.text, 'the attested bytes are the rendered draft')

// An allowlist WITHOUT the Nactor rejects the draft — the documented prerequisite.
assert.equal((await directorDesk(new Set(['someone-else'])).then(d => d.length)), 0, 'not allowlisted → empty desk')
console.log('✓ raise → the Director\'s desk unwraps it through Ngage\'s gates; strangers see nothing')

// --- state + audit ---------------------------------------------------------
const ledger = ngage.listRaised()
assert.equal(ledger.length, 1)
assert.equal(ledger[0].status, 'raised')
assert.equal(ledger[0].identity, 'jafquill')
assert.deepEqual(events.map(e => e.t), ['ngage-raise'])
console.log('✓ raised ledger + AD-1 audit event')

// --- withdrawal ------------------------------------------------------------
assert.equal((await ngage.withdraw('nope')).code, 404, 'unknown scopeId → 404')
const w = await ngage.withdraw(out.id)
assert.equal(w.status, 'withdrawn')
const after = await fetchScope(relay, desk[0])
assert.notEqual(after.status, 'ok', 'the Director\'s key no longer opens the scope (tombstoned)')
assert.equal(ngage.listRaised()[0].status, 'withdrawn')
assert.equal((await ngage.withdraw(out.id)).status, 'withdrawn', 'withdraw is idempotent')
assert.deepEqual(events.map(e => e.t), ['ngage-raise', 'ngage-withdraw'])
console.log('✓ withdraw: tombstoned — the desk shows it withdrawn, nothing signable')

// --- the mcp authoring path (nact#39 / nvoy#28) ----------------------------
// The M7 box: no NACTOR_NSEC in this process — the key lives with nvoy-mcp,
// whose draft tools mint and withdraw. The fake below does EXACTLY what the
// service's DraftDesk does (fresh scope + key, gen 1, publishScope + grant,
// withdraw by supersession), signed by the same "service-held" key, so the
// Director-side proof is as real as the local path's.
import { publishScope, grant, newScopeKey } from './lib/nipxx.mjs'
import { randomBytes } from 'node:crypto'
const serviceSk = nactorSk                        // same identity, one service over
const minted = new Map()                          // d → generation
const fakeMcp = {
  draftPublish: async ({ granteeNpub, payload }) => {
    const d = randomBytes(12).toString('hex')
    const scopeKey = newScopeKey()
    const scope_name = `draft:post/${d.slice(0, 8)}`
    await publishScope(relay, serviceSk, { scopeId: d, generation: 1, scopeKey, payload })
    await grant(relay, serviceSk, nip19.decode(granteeNpub).data, { scopeId: d, generation: 1, scopeKey, scopeName: scope_name })
    minted.set(d, 1)
    return { d, v: 1, scope_name, granted_to: granteeNpub }
  },
  draftWithdraw: async (d) => {
    if (!minted.has(d)) throw new Error('nvoy_draft_withdraw: NVOY_UNKNOWN_DRAFT')
    await publishScope(relay, serviceSk, { scopeId: d, generation: 2, scopeKey: newScopeKey(), payload: {} })
    minted.set(d, 2)
    return { withdrawn: true, d, v: 2 }
  },
}

const mcpEvents = []
const ngageMcp = ngageDelivery({ sk: null, mcp: fakeMcp, relay, config: () => cfg, onEvent: e => mcpEvents.push(e) })
const mout = await ngageMcp.raise({ identity: 'jafquill', pen: penned({ text: 'raised keyless, through the mcp desk' }) })
assert.equal(mout.ok, true)
assert.equal(mout.status, 'raised-to-director')
assert.ok(mout.scopeName.startsWith('draft:post/'))
const mdesk = (await directorDesk(new Set([nactorPub]))).filter(g => g.scopeId === mout.id)
assert.equal(mdesk.length, 1, 'the mcp-raised draft reaches the same desk')
const mscope = await fetchScope(relay, mdesk[0])
assert.equal(mscope.status, 'ok')
assert.equal(mscope.data.text, 'raised keyless, through the mcp desk', 'byte-identical through the mcp path')
assert.equal(ngageMcp.listRaised()[0].via, 'mcp')
const mw = await ngageMcp.withdraw(mout.id)
assert.equal(mw.status, 'withdrawn')
assert.notEqual((await fetchScope(relay, mdesk[0])).status, 'ok', 'mcp withdraw tombstones')
assert.deepEqual(mcpEvents.map(e => e.t), ['ngage-raise', 'ngage-withdraw'])

// a failing mcp path surfaces as 502, never a silent half-raise
const ngageMcpDown = ngageDelivery({ sk: null, mcp: { draftPublish: async () => { throw new Error('ECONNREFUSED') } }, relay, config: () => cfg })
assert.equal((await ngageMcpDown.raise({ identity: 'jafquill', pen: penned({ text: 'x' }) })).code, 502)

// neither path → the honest 503 stands
const ngageNeither = ngageDelivery({ sk: null, mcp: null, relay, config: () => cfg })
assert.equal((await ngageNeither.raise({ identity: 'jafquill', pen: penned({ text: 'x' }) })).code, 503)
console.log('✓ mcp path: keyless raise → same desk, same gates; withdraw tombstones; down → 502, neither → 503')

console.log('\nngage-delivery: all proofs pass')
