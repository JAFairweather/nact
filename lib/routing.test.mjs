// The AD-10 approval-path model, proven offline.
//
//   node lib/routing.test.mjs
//
// The property that matters: an identity binds to exactly ONE approval path, and
// the two paths are distinguished by who signs (box vs the Director's own hand).

import assert from 'node:assert'
import {
  isDirectorPath, approvalPathOf, approvalBindingOf,
  bindToPath, unbind, toggleBinding, needsSecret,
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

t('path classification: Ngage is the director path, everything else is box', () => {
  assert.equal(isDirectorPath({ kind: 'Ngage draft-grant' }), true)
  assert.equal(approvalPathOf({ kind: 'Ngage draft-grant' }), 'director')
  assert.equal(approvalPathOf({ kind: 'Telegram bot' }), 'box')
  assert.equal(approvalPathOf({ kind: 'Web queue (NIP-98)' }), 'box')
  assert.equal(approvalPathOf({ kind: 'NIP-59 gift-wrap' }), 'box')
})

t('binding is EXCLUSIVE: moving an identity to a path removes it from all others', () => {
  const chans = fresh()
  bindToPath(chans, 'nave', 'tg')                     // nave was on web; move to tg
  assert.deepStrictEqual(chans.find(c => c.id === 'web').covers, ['luke', 'brain'])
  assert.deepStrictEqual(chans.find(c => c.id === 'tg').covers, ['nave'])
  assert.equal(approvalBindingOf(chans, 'nave').id, 'tg', 'nave now has exactly one path')
})

t('the overloaded case (nact#26): an identity cannot sit on box AND director paths', () => {
  const chans = fresh()
  bindToPath(chans, 'luke', 'web')                    // luke on the box path (already there)
  bindToPath(chans, 'luke', 'ngage')                  // ...then bound to the director path
  // the second bind must have MOVED it, not added a second path
  assert.equal(chans.find(c => c.id === 'web').covers.includes('luke'), false)
  assert.deepStrictEqual(chans.find(c => c.id === 'ngage').covers, ['luke'])
  assert.equal(approvalBindingOf(chans, 'luke').id, 'ngage')
})

t('toggle: clicking the current path unbinds; clicking another moves it', () => {
  const chans = fresh()
  let r = toggleBinding(chans, 'nave', 'ngage')       // nave: web → ngage
  assert.deepStrictEqual(r, { action: 'bound', path: 'director' })
  assert.equal(approvalBindingOf(chans, 'nave').id, 'ngage')

  r = toggleBinding(chans, 'nave', 'ngage')           // click again → unbind
  assert.deepStrictEqual(r, { action: 'unbound', path: null })
  assert.equal(approvalBindingOf(chans, 'nave'), null, 'nave now has no path')

  r = toggleBinding(chans, 'nave', 'tg')              // bind fresh to box path
  assert.deepStrictEqual(r, { action: 'bound', path: 'box' })
})

t('comms channels are never touched by approval binding', () => {
  const chans = fresh()
  bindToPath(chans, 'luke', 'ngage')                  // move luke's APPROVAL path
  const comms = chans.find(c => c.id === 'luke-comms')
  assert.deepStrictEqual(comms.covers, ['luke'], "luke's own comms line is untouched")
})

t('approvalBindingOf tolerates a stale multi-bind by taking the first', () => {
  const chans = [
    { id: 'a', kind: 'Telegram bot', purpose: 'approval', covers: ['x'] },
    { id: 'b', kind: 'Ngage', purpose: 'approval', covers: ['x'] },
  ]
  assert.equal(approvalBindingOf(chans, 'x').id, 'a')
  // one toggle heals it back to a single path
  toggleBinding(chans, 'x', 'b')
  assert.equal(chans[0].covers.includes('x'), false)
  assert.deepStrictEqual(chans[1].covers, ['x'])
})

t('null-safety: empty/missing inputs never throw', () => {
  assert.equal(approvalBindingOf(undefined, 'x'), null)
  assert.equal(approvalBindingOf([], 'x'), null)
  bindToPath(undefined, 'x', 'y')                     // no throw
  unbind(null, 'x', 'y')                              // no throw
  assert.deepStrictEqual(toggleBinding([], 'x', 'y'), { action: 'bound', path: null })
})

t('the director path needs no on-box secret; box transports do', () => {
  assert.equal(needsSecret('Ngage draft-grant'), false)
  assert.equal(needsSecret('Telegram bot'), true)
  assert.equal(needsSecret('NIP-59 gift-wrap'), true)
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
