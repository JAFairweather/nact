// Offline test for the credential-scope reader: an in-memory relay stands in for
// the public relays. Proves the whole delivery half without touching the box —
// issue → read → rotate(revoke) → drop — plus the M2 acceptance surface:
// Director-only trust, env-fallback flagging, audit events, and the
// grant-derived entitlement map with its revocation + failure semantics.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { publishScope, grant, rotateScope, newScopeKey } from './lib/nipxx.mjs'
import { Relay } from './lib/relay.mjs'
import { LocalRelay } from './lib/liverelay.mjs'
import { syncCredentialGrants, syncIdentityEntitlements, envFallbackNames } from './grant-reader.mjs'

const dir = generateSecretKey()                 // the Director (delegator/publisher)
const dirPub = getPublicKey(dir)
const nactor = generateSecretKey()              // the runtime
const nactorPub = getPublicKey(nactor)
const relay = new LocalRelay(new Relay())
const DIRECTORS = new Set([dirPub])             // the trust set production passes

const events = []                               // AD-1 audit feed under test
const onEvent = e => events.push(e)
const eventTs = () => events.map(e => e.t).join(' ')

const scopeId = 'cred-tglk'
let gen = 1
const scopeKey = newScopeKey()
const scopeName = 'credential:telegram-luke'

// 1) Director issues the credential-scope and grants it to Nactor.
await publishScope(relay, dir, { scopeId, generation: gen, scopeKey, payload: { value: '123456:AA-token' } })
await grant(relay, dir, nactorPub, { scopeId, generation: gen, scopeKey, scopeName })

// Pre-existing credentials that must NEVER be touched by the reader: a
// bootstrap-env one (the fallback tier being drained) and a director-put one
// (the V1 HTTP fallback) — neither is grant-sourced.
const creds = new Map([
  ['anthropic', { type: 'secret', value: 'sk-boot', source: 'bootstrap-env' }],
  ['replicate', { type: 'secret', value: 'r8-put', source: 'director-put' }],
])

// 2) Nactor reads its grants from the relay.
let s = await syncCredentialGrants({ relay, nactorSk: nactor, creds, allowedPublishers: DIRECTORS, onEvent })
assert.deepEqual(s.loaded, ['telegram-luke'], 'loaded the granted credential')
assert.equal(creds.get('telegram-luke').value, '123456:AA-token', 'value decrypted from the scope')
assert.equal(creds.get('telegram-luke').source, 'grant', 'tagged as grant-sourced')
assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap cred untouched')
assert.equal(eventTs(), 'grant-load', 'first read emits ONE grant-load audit event')
assert.equal(events[0].credential, 'telegram-luke')
console.log('✓ issue → Nactor reads the credential from the relay (+ grant-load audit event)');

// 2b) env-fallback flag: only bootstrap-env* creds count — not grant-sourced,
// not director-put. This is the honest measure of migration remaining.
assert.deepEqual(s.envFallback, ['anthropic'], 'envFallback lists exactly the bootstrap-env credential')
assert.deepEqual(envFallbackNames(creds), ['anthropic'], 'envFallbackNames helper agrees')
console.log('✓ env fallback flagged: bootstrap-env creds only (grant + director-put excluded)');

// 2c) steady-state re-read: same value, NO new audit events (audit stays signal).
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds, allowedPublishers: DIRECTORS, onEvent })
assert.equal(eventTs(), 'grant-load', 'unchanged re-read emits no audit event')
console.log('✓ steady-state re-read is audit-silent');

// 3) Idempotent re-read: value updates live (Director republishes same key).
await publishScope(relay, dir, { scopeId, generation: gen, scopeKey, payload: { value: '123456:AA-rotated-value' } })
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds, allowedPublishers: DIRECTORS, onEvent })
assert.equal(creds.get('telegram-luke').value, '123456:AA-rotated-value', 'live update flows through')
assert.equal(eventTs(), 'grant-load grant-update', 'value change emits grant-update')
console.log('✓ live update (republish same key) reflected on next sweep (+ grant-update audit event)');

// 3b) A spoofed grant from a NON-Director publisher must not shadow the real
// value — even though it is newer (newest-wins ordering) and carries the right
// scope name. Without the Director filter this would poison the credential.
const mallory = generateSecretKey()
const spoofId = 'cred-tglk-evil', spoofKey = newScopeKey()
await publishScope(relay, mallory, { scopeId: spoofId, generation: 1, scopeKey: spoofKey, payload: { value: 'EVIL-token' } })
await grant(relay, mallory, nactorPub, { scopeId: spoofId, generation: 1, scopeKey: spoofKey, scopeName })
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds, allowedPublishers: DIRECTORS, onEvent })
assert.equal(s.untrusted, 1, 'the spoofed grant is counted as untrusted')
assert.equal(creds.get('telegram-luke').value, '123456:AA-rotated-value', 'real value NOT shadowed by the spoof')
assert.equal(eventTs(), 'grant-load grant-update', 'spoof emits no audit event')
console.log('✓ non-Director publisher ignored — spoofed grant cannot shadow a credential');

// 4) Revocation = rotate the scope key with NO survivors → Nactor goes stale → dropped.
await rotateScope(relay, dir, { scopeId, generation: gen, payload: { value: 'secret' }, scopeName, survivors: [] })
gen++
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds, allowedPublishers: DIRECTORS, onEvent })
assert.deepEqual(s.dropped, ['telegram-luke'], 'stale grant dropped')
assert.equal(creds.has('telegram-luke'), false, 'credential gone after revocation')
assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap cred STILL untouched through a revoke')
assert.equal(creds.get('replicate').value, 'r8-put', 'director-put cred untouched through a revoke')
assert.equal(eventTs(), 'grant-load grant-update grant-drop', 'revocation emits grant-drop')
console.log('✓ revocation (key rotation) drops the credential; bootstrap + put creds safe (+ grant-drop audit event)');

// 5) Non-credential grants to Nactor are ignored — scope names are NAMESPACED
// STRINGS (AD-8), and only credential:* is consumed here. A bare name and a
// data:* scope both pass through untouched.
const creds2 = new Map()
for (const [sid, sname] of [['plain-scope', 'travel-prefs'], ['data-scope', 'data:contact-log']]) {
  const k = newScopeKey()
  await publishScope(relay, dir, { scopeId: sid, generation: 1, scopeKey: k, payload: { hello: 'world' } })
  await grant(relay, dir, nactorPub, { scopeId: sid, generation: 1, scopeKey: k, scopeName: sname })
}
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds: creds2, allowedPublishers: DIRECTORS })
assert.equal(creds2.size, 0, 'non-credential namespaces (bare + data:*) are ignored')
console.log('✓ non-credential grants ignored (namespaced strings, not enums)');

// 5b) Tolerant payload keys: `.value` is canonical (what Nvoy issues), but the
// shared gate also honors `.key`/`.api_key`/`.secret` so one issuance can feed
// every reader (warm.contact's tolerates key/api_key/value).
const creds3 = new Map()
for (const [sid, sname, payload] of [
  ['alt-key', 'credential:alt-key', { key: 'k-1' }],
  ['alt-api', 'credential:alt-api', { api_key: 'ak-2' }],
]) {
  const k = newScopeKey()
  await publishScope(relay, dir, { scopeId: sid, generation: 1, scopeKey: k, payload })
  await grant(relay, dir, nactorPub, { scopeId: sid, generation: 1, scopeKey: k, scopeName: sname })
}
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds: creds3, allowedPublishers: DIRECTORS })
assert.equal(creds3.get('alt-key').value, 'k-1', '.key payload honored')
assert.equal(creds3.get('alt-api').value, 'ak-2', '.api_key payload honored')
console.log('✓ tolerant payload keys (.key/.api_key) — one issuance feeds every reader');

// ---------------------------------------------------------------------------
// Entitlements — the grant → entitlement half (A1/A2).

const luke = generateSecretKey()
const lukePub = getPublicKey(luke)
const ids = [{ name: 'luke', sk: luke, pub: lukePub }]
const entitlements = new Map()
const eEvents = []
const eTs = () => eEvents.map(e => `${e.t}:${e.credential}`).join(' ')

// 6) Director grants luke a credential-scope → entitlement appears (+ gain event).
let eScopeId = 'ent-tglk', eGen = 1, eKey = newScopeKey()
await publishScope(relay, dir, { scopeId: eScopeId, generation: eGen, scopeKey: eKey, payload: { value: 'tok' } })
await grant(relay, dir, lukePub, { scopeId: eScopeId, generation: eGen, scopeKey: eKey, scopeName: 'credential:telegram-luke' })
// …plus a data:* scope that must NOT become an entitlement.
const dKey = newScopeKey()
await publishScope(relay, dir, { scopeId: 'ent-data', generation: 1, scopeKey: dKey, payload: { x: 1 } })
await grant(relay, dir, lukePub, { scopeId: 'ent-data', generation: 1, scopeKey: dKey, scopeName: 'data:travel-prefs' })
let e = await syncIdentityEntitlements({ relay, identities: ids, entitlements, allowedPublishers: DIRECTORS, onEvent: ev => eEvents.push(ev) })
assert.deepEqual(e.luke, ['telegram-luke'], 'entitlement derived from the grant')
assert.deepEqual([...entitlements.get(lukePub)], ['telegram-luke'], 'entitlement map populated')
assert.equal(eTs(), 'entitlement-gain:telegram-luke', 'gain audit event emitted; data:* ignored')
console.log('✓ grant → entitlement derived (+ entitlement-gain audit event; data:* not an entitlement)');

// 6b) identities may be a FUNCTION (evaluated per sweep — runtime-imported
// identities are swept without a restart).
const entitlements2 = new Map()
e = await syncIdentityEntitlements({ relay, identities: () => ids, entitlements: entitlements2, allowedPublishers: DIRECTORS })
assert.deepEqual(e.luke, ['telegram-luke'], 'identities-as-function works')
console.log('✓ identities may be a function (runtime-imported identities swept)');

// 7) TRANSIENT relay failure (receiveGrants throws) → prior set retained, no
// loss events. An outage must never strip an identity of its entitlements.
const failingRelay = { publish: ev => relay.publish(ev), query: () => { throw new Error('relay down') } }
e = await syncIdentityEntitlements({ relay: failingRelay, identities: ids, entitlements, allowedPublishers: DIRECTORS, onEvent: ev => eEvents.push(ev) })
assert.deepEqual(e.luke, ['telegram-luke'], 'transient read failure keeps the prior entitlement set')
assert.equal(eTs(), 'entitlement-gain:telegram-luke', 'no loss event on a transient failure')
console.log('✓ transient relay failure retains prior entitlements (no false revocation)');

// 7b) TRANSIENT single-scope fetch blip (grants readable, ONE scope fetch
// throws) → that credential keeps its prior membership (sticky), not dropped.
const scopeBlipRelay = { publish: ev => relay.publish(ev), query: f => { if ((f.kinds || []).includes(30440)) throw new Error('scope fetch blip'); return relay.query(f) } }
e = await syncIdentityEntitlements({ relay: scopeBlipRelay, identities: ids, entitlements, allowedPublishers: DIRECTORS, onEvent: ev => eEvents.push(ev) })
assert.deepEqual(e.luke, ['telegram-luke'], 'scope-fetch blip keeps prior membership')
assert.equal(eTs(), 'entitlement-gain:telegram-luke', 'no loss event on a scope-fetch blip')
console.log('✓ single-scope fetch blip is sticky (prior membership kept)');

// 8) REVOKING THE LAST GRANT clears the entitlement. This is the regression
// case: a successful read with zero grants is authoritative — it must NOT be
// mistaken for a failed read and leave the stale entitlement in place.
await rotateScope(relay, dir, { scopeId: eScopeId, generation: eGen, payload: { value: 'tok' }, scopeName: 'credential:telegram-luke', survivors: [] })
e = await syncIdentityEntitlements({ relay, identities: ids, entitlements, allowedPublishers: DIRECTORS, onEvent: ev => eEvents.push(ev) })
assert.deepEqual(e.luke, [], 'revoking the LAST grant clears the entitlement')
assert.deepEqual([...entitlements.get(lukePub)], [], 'entitlement map cleared')
assert.equal(eTs(), 'entitlement-gain:telegram-luke entitlement-loss:telegram-luke', 'loss audit event emitted')
console.log('✓ revoking the last grant clears the entitlement (+ entitlement-loss audit event)');

// 8b) …and a LATER transient failure still retains the (now empty) state
// without resurrecting anything.
e = await syncIdentityEntitlements({ relay: failingRelay, identities: ids, entitlements, allowedPublishers: DIRECTORS, onEvent: ev => eEvents.push(ev) })
assert.deepEqual(e.luke, [], 'post-revocation transient failure stays empty')
console.log('✓ post-revocation transient failure does not resurrect entitlements');

// 9) Entitlement grants from a NON-Director publisher are not counted.
const entitlements3 = new Map()
const mKey = newScopeKey()
await publishScope(relay, mallory, { scopeId: 'evil-ent', generation: 1, scopeKey: mKey, payload: { value: 'x' } })
await grant(relay, mallory, lukePub, { scopeId: 'evil-ent', generation: 1, scopeKey: mKey, scopeName: 'credential:anthropic' })
e = await syncIdentityEntitlements({ relay, identities: ids, entitlements: entitlements3, allowedPublishers: DIRECTORS })
assert.deepEqual(e.luke, [], 'non-Director grant yields no entitlement')
console.log('✓ non-Director publisher cannot mint entitlements');

// ---------------------------------------------------------------------------
// A2 stage 2 — the OWNER's grant supplies the VALUE (the identity lends the
// capability to the co-resident runtime); Nactor-addressed copies become
// revocable fallback.

// 10) Owner value load: grant a credential to luke, sweep with `creds` passed.
const a2creds = new Map()
const a2ents = new Map()
const a2Events = []
let oScopeId = 'own-gg', oGen = 1, oKey = newScopeKey()
await publishScope(relay, dir, { scopeId: oScopeId, generation: oGen, scopeKey: oKey, payload: { value: 'owner-google-key' } })
await grant(relay, dir, lukePub, { scopeId: oScopeId, generation: oGen, scopeKey: oKey, scopeName: 'credential:google' })
let a2 = await syncIdentityEntitlements({ relay, identities: ids, entitlements: a2ents, creds: a2creds, allowedPublishers: DIRECTORS, onEvent: ev => a2Events.push(ev) })
assert.equal(a2creds.get('google')?.value, 'owner-google-key', 'owner grant supplied the value')
assert.equal(a2creds.get('google')?.source, 'grant-owner', 'tagged grant-owner')
assert.equal(a2creds.get('google')?.owner, 'luke', 'owner recorded')
assert.ok(a2Events.some(e => e.t === 'grant-load' && e.owner === 'luke' && e.credential === 'google'), 'owner-tagged grant-load audit event')
console.log('✓ A2: owner grant supplies the value into CREDS (grant-owner, owner recorded)');

// 10b) Steady-state owner re-sweep: no new audit events.
const evCount = a2Events.length
await syncIdentityEntitlements({ relay, identities: ids, entitlements: a2ents, creds: a2creds, allowedPublishers: DIRECTORS, onEvent: ev => a2Events.push(ev) })
assert.equal(a2Events.length, evCount, 'unchanged owner re-sweep is audit-silent')
console.log('✓ A2: steady-state owner re-sweep is audit-silent');

// 11) Precedence: a NACTOR-addressed copy of the same name must NOT clobber the
// owner-sourced value.
const nScopeId = 'nact-gg', nKey = newScopeKey()
await publishScope(relay, dir, { scopeId: nScopeId, generation: 1, scopeKey: nKey, payload: { value: 'nactor-copy-key' } })
await grant(relay, dir, nactorPub, { scopeId: nScopeId, generation: 1, scopeKey: nKey, scopeName: 'credential:google' })
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds: a2creds, allowedPublishers: DIRECTORS })
assert.equal(a2creds.get('google').value, 'owner-google-key', 'owner value outranks the Nactor-addressed copy')
assert.equal(a2creds.get('google').source, 'grant-owner', 'source stays grant-owner')
console.log('✓ A2: precedence — grant-owner outranks the Nactor-addressed grant');

// 12) Owner revocation → graceful fallback to the Nactor-addressed copy.
await rotateScope(relay, dir, { scopeId: oScopeId, generation: oGen, payload: { value: 'owner-google-key' }, scopeName: 'credential:google', survivors: [] })
await syncIdentityEntitlements({ relay, identities: ids, entitlements: a2ents, creds: a2creds, allowedPublishers: DIRECTORS, onEvent: ev => a2Events.push(ev) })
assert.equal(a2creds.has('google'), false, 'owner revocation drops the grant-owner entry')
assert.ok(a2Events.some(e => e.t === 'grant-drop' && e.owner === 'luke'), 'owner-tagged grant-drop audit event')
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds: a2creds, allowedPublishers: DIRECTORS })
assert.equal(a2creds.get('google')?.value, 'nactor-copy-key', 'Nactor-addressed copy restores supply on the next sweep')
assert.equal(a2creds.get('google')?.source, 'grant', 'fallback tagged plain grant')
console.log('✓ A2: owner revocation falls back to the Nactor-addressed copy (no gap)');

console.log('\nGRANT-READER TESTS PASS — issue, read, live-update, revoke-drop, isolation,')
console.log('Director-only trust, env-fallback flag, audit events, entitlement')
console.log('derivation/revocation/failure semantics, and A2 owner-value supply +')
console.log('precedence + fallback all verified')
