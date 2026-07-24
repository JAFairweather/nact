// The AD-10 approval-path model, proven offline.
//
//   node lib/routing.test.mjs
//
// The properties that matter (#42): the PATH is derived from key custody and
// exclusive by construction — never by click; within the box gate, channels
// are independent TRANSPORTS of one shared gate.

import assert from 'node:assert'
import {
  isDirectorPath, approvalPathOf, approvalBindingOf, pathForSigner,
  toggleTransport, healCovers, unbind, needsSecret,
} from './routing.mjs'

let n = 0, pass = 0
const t = (name, fn) => { n++; try { fn(); pass++; console.log(`ok - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) } }

// A fleet-shaped channel set: two box-path approval channels, one Ngage
// (director) channel, and one comms channel that must never be affected.
const fresh = () => ([
  { id: 'web',   kind: 'Web queue (NIP-98)', purpose: 'approval', covers: ['nave', 'luke', 'brain'] },
  { id: 'tg',    kind: 'Telegram bot',       purpose: 'approval', covers: [] },
  { id: 'ngage', kind: 'Ngage draft-grant',  purpose: 'approval', covers: [] },
  { id: 'luke-comms', kind: 'Telegram bot',  purpose: 'comms',    covers: ['luke'], owner: 'luke' },
])
const SIGNERS = { nave: 'custodial', luke: 'custodial', brain: 'custodial', jafquill: 'director' }
const signerOf = (k) => SIGNERS[k] || 'custodial'

t('path classification: Ngage is the director path, everything else is box', () => {
  assert.equal(isDirectorPath({ kind: 'Ngage draft-grant' }), true)
  assert.equal(approvalPathOf({ kind: 'Ngage draft-grant' }), 'director')
  assert.equal(approvalPathOf({ kind: 'Telegram bot' }), 'box')
  assert.equal(approvalPathOf({ kind: 'Web queue (NIP-98)' }), 'box')
  assert.equal(approvalPathOf({ kind: 'NIP-59 gift-wrap' }), 'box')
})

t('custody derives the path: keyed signers → box, keyless director → Ngage', () => {
  assert.equal(pathForSigner('custodial'), 'box')
  assert.equal(pathForSigner('bunker'), 'box')
  assert.equal(pathForSigner('director'), 'director')
  assert.equal(pathForSigner(undefined), 'box', 'unknown signer defaults to the keyed path')
})

t('box transports are INDEPENDENT: wiring telegram never unwires the web queue (#42)', () => {
  const chans = fresh()
  const r = toggleTransport(chans, 'nave', 'tg', 'custodial')
  assert.deepStrictEqual(r, { action: 'wired', path: 'box' })
  assert.ok(chans.find(c => c.id === 'web').covers.includes('nave'), 'still on the web queue')
  assert.ok(chans.find(c => c.id === 'tg').covers.includes('nave'), 'AND on telegram — one gate, two transports')
  const r2 = toggleTransport(chans, 'nave', 'tg', 'custodial')   // click again → unwire that one only
  assert.deepStrictEqual(r2, { action: 'unwired', path: 'box' })
  assert.ok(chans.find(c => c.id === 'web').covers.includes('nave'), 'web queue untouched by the telegram unwire')
})

t('cross-path clicks are REFUSED with the reason — custody decides, not preference', () => {
  const chans = fresh()
  const box = toggleTransport(chans, 'luke', 'ngage', 'custodial')
  assert.equal(box.action, 'refused')
  assert.match(box.reason, /box gate/)
  assert.equal(chans.find(c => c.id === 'ngage').covers.length, 0, 'nothing wired by a refused click')
  const dir = toggleTransport(chans, 'jafquill', 'tg', 'director')
  assert.equal(dir.action, 'refused')
  assert.match(dir.reason, /Ngage/)
})

t('a director-path identity wires to Ngage — and only there', () => {
  const chans = fresh()
  const r = toggleTransport(chans, 'jafquill', 'ngage', 'director')
  assert.deepStrictEqual(r, { action: 'wired', path: 'director' })
  assert.deepStrictEqual(chans.find(c => c.id === 'ngage').covers, ['jafquill'])
})

t('the pre-#42 backfill pollution heals: box identities fall out of Ngage covers on any toggle', () => {
  const chans = fresh()
  chans.find(c => c.id === 'ngage').covers = ['nave', 'luke', 'brain', 'jafquill']   // the busted board
  toggleTransport(chans, 'nave', 'web', 'custodial')   // any legitimate click heals nave's memberships
  assert.ok(!chans.find(c => c.id === 'ngage').covers.includes('nave'), 'nave healed out of Ngage')
  assert.ok(chans.find(c => c.id === 'ngage').covers.includes('jafquill'), 'the rightful tenant stays')
})

t('healCovers strips every custody-contradicting membership in one pass', () => {
  const chans = fresh()
  chans.find(c => c.id === 'ngage').covers = ['nave', 'luke', 'jafquill']
  chans.find(c => c.id === 'web').covers.push('jafquill')
  assert.equal(healCovers(chans, signerOf), true)
  assert.deepStrictEqual(chans.find(c => c.id === 'ngage').covers, ['jafquill'])
  assert.ok(!chans.find(c => c.id === 'web').covers.includes('jafquill'), 'keyless identity off the box gate')
  assert.deepStrictEqual(chans.find(c => c.id === 'luke-comms').covers, ['luke'], 'comms never touched')
  assert.equal(healCovers(chans, signerOf), false, 'second pass is a no-op')
})

t('approvalBindingOf still yields a covering approval channel (the delivery runtime path check)', () => {
  const chans = fresh()
  toggleTransport(chans, 'jafquill', 'ngage', 'director')
  assert.equal(approvalBindingOf(chans, 'jafquill').id, 'ngage')
  assert.equal(approvalBindingOf(chans, 'nave').id, 'web')
  assert.equal(approvalBindingOf(chans, 'ghost'), null)
})

t('comms channels are never touched by approval toggles', () => {
  const chans = fresh()
  toggleTransport(chans, 'luke', 'tg', 'custodial')
  assert.deepStrictEqual(chans.find(c => c.id === 'luke-comms').covers, ['luke'])
})

t('null-safety: empty/missing inputs never throw', () => {
  assert.equal(approvalBindingOf(undefined, 'x'), null)
  assert.equal(approvalBindingOf([], 'x'), null)
  unbind(null, 'x', 'y')                              // no throw
  assert.deepStrictEqual(toggleTransport([], 'x', 'y', 'custodial'), { action: 'noop', path: null })
  assert.equal(healCovers(undefined, signerOf), false)
})

t('the director path needs no on-box secret; box transports do', () => {
  assert.equal(needsSecret('Ngage draft-grant'), false)
  assert.equal(needsSecret('Telegram bot'), true)
  assert.equal(needsSecret('NIP-59 gift-wrap'), true)
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
