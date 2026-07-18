// Offline test for the credential-scope reader: an in-memory relay stands in for
// the public relays. Proves the whole delivery half without touching the box —
// issue → read → rotate(revoke) → drop → and that bootstrap-env creds are safe.

import assert from 'node:assert'
import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { publishScope, grant, rotateScope, newScopeKey } from './lib/nipxx.mjs'
import { Relay } from './lib/relay.mjs'
import { LocalRelay } from './lib/liverelay.mjs'
import { syncCredentialGrants } from './grant-reader.mjs'

const dir = generateSecretKey()                 // the Director (delegator/publisher)
const dirPub = getPublicKey(dir)
const nactor = generateSecretKey()              // the runtime
const nactorPub = getPublicKey(nactor)
const relay = new LocalRelay(new Relay())

const scopeId = 'cred-tglk'
let gen = 1
const scopeKey = newScopeKey()
const scopeName = 'credential:telegram-luke'

// 1) Director issues the credential-scope and grants it to Nactor.
await publishScope(relay, dir, { scopeId, generation: gen, scopeKey, payload: { value: '123456:AA-token' } })
await grant(relay, dir, nactorPub, { scopeId, generation: gen, scopeKey, scopeName })

// A pre-existing bootstrap-env credential that must NEVER be touched by the reader.
const creds = new Map([['anthropic', { type: 'secret', value: 'sk-boot', source: 'bootstrap' }]])

// 2) Nactor reads its grants from the relay.
let s = await syncCredentialGrants({ relay, nactorSk: nactor, creds })
assert.deepEqual(s.loaded, ['telegram-luke'], 'loaded the granted credential')
assert.equal(creds.get('telegram-luke').value, '123456:AA-token', 'value decrypted from the scope')
assert.equal(creds.get('telegram-luke').source, 'grant', 'tagged as grant-sourced')
assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap cred untouched')
console.log('✓ issue → Nactor reads the credential from the relay');

// 3) Idempotent re-read: value updates live (Director republishes same key).
await publishScope(relay, dir, { scopeId, generation: gen, scopeKey, payload: { value: '123456:AA-rotated-value' } })
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds })
assert.equal(creds.get('telegram-luke').value, '123456:AA-rotated-value', 'live update flows through')
console.log('✓ live update (republish same key) reflected on next sweep');

// 4) Revocation = rotate the scope key with NO survivors → Nactor goes stale → dropped.
await rotateScope(relay, dir, { scopeId, generation: gen, payload: { value: 'secret' }, scopeName, survivors: [] })
gen++
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds })
assert.deepEqual(s.dropped, ['telegram-luke'], 'stale grant dropped')
assert.equal(creds.has('telegram-luke'), false, 'credential gone after revocation')
assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap cred STILL untouched through a revoke')
console.log('✓ revocation (key rotation) drops the credential; bootstrap creds safe');

// 5) A non-credential grant to Nactor is ignored.
const other = 'plain-scope', ok2 = newScopeKey()
await publishScope(relay, dir, { scopeId: other, generation: 1, scopeKey: ok2, payload: { hello: 'world' } })
await grant(relay, dir, nactorPub, { scopeId: other, generation: 1, scopeKey: ok2, scopeName: 'travel-prefs' })
const creds2 = new Map()
s = await syncCredentialGrants({ relay, nactorSk: nactor, creds: creds2 })
assert.equal(creds2.size, 0, 'non-credential scopes are ignored')
console.log('✓ non-credential grants ignored');

console.log('\nGRANT-READER TESTS PASS — issue, read, live-update, revoke-drop, isolation all verified')
