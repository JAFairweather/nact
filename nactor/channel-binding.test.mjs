// Channel binding — hardening P4 (nact#10), proven offline.
//
// The property: an approval over an OUT-OF-BAND channel (Telegram) is refused
// until a nonce ceremony verifies the binding, and that binding is a live,
// revocable grant. Self-authenticating channels (the NIP-98 web queue, NIP-59
// DMs) are always honorable. Everything here is offline — real Schnorr sign/
// verify (nostr-tools), no relay, no network.
//
//   node nactor/channel-binding.test.mjs
import assert from 'node:assert'
import { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools'
import {
  bindingKind, mayHonor, newNonce, bindingStatement, verifyBinding,
  BINDING_SCOPE, bindingGrantPayload, verifiedChannelOf,
} from '../lib/channel-binding.mjs'
import { telegramApproval } from '../src/adapters/telegram.mjs'

let n = 0, pass = 0
const t = async (name, fn) => {
  n++
  try { await fn(); pass++; console.log(`ok - ${name}`) }
  catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) }
}

// A Director key + a helper that signs the ceremony statement as a nostr event.
const sk = generateSecretKey()
const directorHex = getPublicKey(sk)
const director = 'npub-director'   // display handle woven into the statement
const nactor = 'nactor-box-1'
const signStatement = (statement) => finalizeEvent({ kind: 27235, created_at: 1700000000, tags: [], content: statement }, sk)

// ---- the binding model -----------------------------------------------------
await t('intrinsic channels (Web / NIP-59 / Ngage) are always honorable', () => {
  for (const kind of ['Web queue', 'NIP-59 DM', 'Ngage draft']) {
    assert.equal(bindingKind({ kind }), 'intrinsic')
    assert.equal(mayHonor({ kind, id: 'x' }, new Set()), true, `${kind} honored with no bindings`)
  }
})

await t('out-of-band channels need a live binding — fail closed', () => {
  const tg = { kind: 'Telegram', id: 'telegram:555' }
  assert.equal(bindingKind(tg), 'grant')
  assert.equal(mayHonor(tg, new Set()), false, 'unbound → not honored')
  assert.equal(mayHonor(tg, new Set(['telegram:555'])), true, 'a live binding → honored')
  assert.equal(mayHonor(tg, new Set(['telegram:999'])), false, 'a binding for ANOTHER channel does not count')
  assert.equal(mayHonor(null, new Set(['anything'])), false, 'an unknown channel is never honored')
})

// ---- the nonce ceremony ----------------------------------------------------
await t('a correctly-signed proof over the delivered nonce verifies', () => {
  const nonce = newNonce()
  const channelType = 'Telegram', channelId = 'telegram:555'
  const proof = signStatement(bindingStatement({ director, nactor, channelType, channelId, nonce }))
  const r = verifyBinding(proof, { directorHex, director, nactor, channelType, channelId, nonce })
  assert.equal(r.ok, true)
  assert.equal(r.channelId, channelId)
})

await t('a proof echoing a STALE nonce is rejected (freshness)', () => {
  const channelType = 'Telegram', channelId = 'telegram:555'
  const proof = signStatement(bindingStatement({ director, nactor, channelType, channelId, nonce: newNonce() }))
  const r = verifyBinding(proof, { directorHex, director, nactor, channelType, channelId, nonce: newNonce() /* a different one */ })
  assert.equal(r.ok, false)
  assert.match(r.why, /stale nonce|mismatch/)
})

await t('a proof naming a DIFFERENT channel is rejected (channel-specific consent)', () => {
  const nonce = newNonce()
  // Signed for channel A…
  const proof = signStatement(bindingStatement({ director, nactor, channelType: 'Telegram', channelId: 'telegram:AAA', nonce }))
  // …replayed to bind channel B with the same nonce.
  const r = verifyBinding(proof, { directorHex, director, nactor, channelType: 'Telegram', channelId: 'telegram:BBB', nonce })
  assert.equal(r.ok, false, 'a proof for channel A cannot bind channel B')
})

await t('a proof signed by a NON-Director key is rejected', () => {
  const nonce = newNonce()
  const other = generateSecretKey()
  const channelId = 'telegram:555'
  const evil = finalizeEvent({ kind: 27235, created_at: 1700000000, tags: [], content: bindingStatement({ director, nactor, channelType: 'Telegram', channelId, nonce }) }, other)
  const r = verifyBinding(evil, { directorHex, director, nactor, channelType: 'Telegram', channelId, nonce })
  assert.equal(r.ok, false)
  assert.match(r.why, /not signed by the Director/)
})

await t('FORGERY: a Director signature reused under a swapped content is rejected', () => {
  // nostr-tools verifyEvent checks the sig over event.id but does NOT recompute
  // the hash — so an attacker who holds ANY Director-signed event can paste the
  // exact statement we expect into its content, keep the id+sig, and pass a
  // naive verifyEvent. verifyBinding must bind content to the id and refuse.
  const nonce = newNonce(), channelId = 'telegram:555'
  const innocent = signStatement('gm — an unrelated note the Director once signed')
  const want = bindingStatement({ director, nactor, channelType: 'Telegram', channelId, nonce })
  const forged = { ...innocent, content: want }            // real sig, forged statement, stale id
  assert.equal(verifyEvent(forged), true, 'the raw signature still "verifies" — this is the trap')
  const r = verifyBinding(forged, { directorHex, director, nactor, channelType: 'Telegram', channelId, nonce })
  assert.equal(r.ok, false, 'but verifyBinding refuses it')
  assert.match(r.why, /does not commit to its content|forged/)
})

await t('a tampered proof (content changed after signing) is rejected', () => {
  const nonce = newNonce(), channelId = 'telegram:555'
  const proof = signStatement(bindingStatement({ director, nactor, channelType: 'Telegram', channelId, nonce }))
  const tampered = { ...proof, content: proof.content.replace('nonce=', 'nonce=deadbeef ') }
  const r = verifyBinding(tampered, { directorHex, director, nactor, channelType: 'Telegram', channelId, nonce })
  assert.equal(r.ok, false)
})

// ---- the binding as a revocable grant --------------------------------------
await t('the binding is a scoped grant; a live grant marks the channel verified', () => {
  const payload = bindingGrantPayload({
    director, nactor, channelType: 'Telegram', channelId: 'telegram:555',
    label: 'Approvals', nonce: newNonce(), echoedAt: 1700000001,
    identities: ['luke'], tiers: ['low', 'elevated'],
  })
  assert.equal(payload.kind, BINDING_SCOPE)
  assert.deepEqual(payload.authority.identities, ['luke'], 'authority is SCOPED, not blanket')
  assert.equal(verifiedChannelOf(payload), 'telegram:555', 'a live grant ⇒ verified channel id')
  assert.equal(verifiedChannelOf({ kind: 'steer:draft', channel: { id: 'x' } }), null, 'a non-binding scope is ignored')
  assert.equal(verifiedChannelOf(null), null)
})

// ---- the honor rule, enforced in the Telegram adapter ----------------------
const BOT = '123:ABC', UID = '555'
await t('adapter: right person, UNVERIFIED channel → refused (deliver-but-don\'t-honor)', () => {
  const a = telegramApproval({ botToken: BOT, approverId: UID })   // no binding
  assert.equal(a.isBound(), false)
  assert.equal(a.isApprover(UID), false, 'the correct id is still refused over an unbound channel')
})

await t('adapter: right person, VERIFIED channel → honored', () => {
  const a = telegramApproval({
    botToken: BOT, approverId: UID,
    channel: { id: 'telegram:555', kind: 'Telegram' },
    verified: () => new Set(['telegram:555']),
  })
  assert.equal(a.isBound(), true)
  assert.equal(a.isApprover(UID), true)
})

await t('adapter: revoking the binding (live deref) stops honoring immediately', () => {
  let bound = new Set(['telegram:555'])
  const a = telegramApproval({
    botToken: BOT, approverId: UID,
    channel: { id: 'telegram:555', kind: 'Telegram' },
    verified: () => bound,                                  // dereferenced each call
  })
  assert.equal(a.isApprover(UID), true, 'honored while bound')
  bound = new Set()                                         // rotation/revocation
  assert.equal(a.isApprover(UID), false, 'refused the instant the binding is gone')
})

await t('adapter: wrong person is refused even over a verified channel', () => {
  const a = telegramApproval({
    botToken: BOT, approverId: UID,
    channel: { id: 'telegram:555', kind: 'Telegram' },
    verified: () => new Set(['telegram:555']),
  })
  assert.equal(a.isApprover('999'), false)
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
