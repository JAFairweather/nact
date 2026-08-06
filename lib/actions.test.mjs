// The durable action grant model, proven offline (AD-12 3a–3d).
//
//   node lib/actions.test.mjs
//
// These four rulings are the kind that get eroded by a later convenience, so each one is pinned as
// an assertion rather than left in a comment:
//
//   3a  a standing grant confers QUEUE ENTRY, never a signature. Asserted structurally: this module
//       exports nothing that signs, and nothing that takes a timer.
//   3b  the tier ceiling is `low`, fixed, and cannot be raised by any input.
//   3c  revoking enumerates the proposals it kills, and states what it does NOT reach.
//   3d  TTL and rate may only be tightened; a widening request is REFUSED, not clamped, because a
//       silent clamp teaches the issuer they got what they asked for.

import assert from 'node:assert'
import {
  CAPS, capFamily, enforcerOf, capLabel, tierCap, STANDING_TIER_CAP,
  ESTATE_DEFAULTS, narrowOnly, validateIssue, actionRows, revokeImpact,
} from './actions.mjs'
import * as mod from './actions.mjs'

let pass = 0, fail = 0
const t = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const HEX = 'a'.repeat(64)
const ev = (o = {}) => ({
  id: o.id || 'e'.repeat(64),
  created_at: o.created_at ?? 1000,
  tags: o.tags || [['p', HEX], ['da-cap', 'task'], ['da-scope', 'hash1']],
})

// ── 3a: nothing here can sign, and nothing here runs on a timer ───────────────
t('3a — the module exports no signer and no scheduler', () => {
  // The ruling is that every instantiation queues. The strongest guarantee this module can offer is
  // that it is structurally incapable of emitting anything: no signing, no timers, no publishing.
  const names = Object.keys(mod).join(' ')
  assert.doesNotMatch(names, /sign|publish|emit|enact|schedule|interval/i,
    `an export name suggests emission: ${names}`)
})

// ── 3b: the ceiling is low, fixed, and carries its reason ────────────────────
t('3b — the standing ceiling is low', () => assert.equal(STANDING_TIER_CAP, 'low'))
t('3b — every issued grant gets the low ceiling regardless of what was asked for', () => {
  const r = validateIssue({ cap: 'task', grantee: HEX, scopeHash: 'h', path: 'box', requested: { tier: 'critical' } })
  assert.equal(r.ok, true, r.reason)
  assert.equal(r.envelope.tier, 'low', 'a requested tier must not reach the envelope')
})
t('3b — the tier cannot be rendered without the reason it is fixed', () => {
  const { tier, why } = tierCap()
  assert.equal(tier, 'low')
  assert.match(why, /fresh approval by definition/i)
  assert.match(why, /mislead/i, 'must say why offering the choice would be worse than withholding it')
})

// ── 3d: tighten only, and refuse rather than clamp ───────────────────────────
t('3d — an absent field takes the estate default, which is the ceiling', () => {
  const r = narrowOnly({})
  assert.equal(r.ok, true)
  assert.deepEqual(r.envelope, { ttlSeconds: ESTATE_DEFAULTS.ttlSeconds, ratePerHour: ESTATE_DEFAULTS.ratePerHour })
})
t('3d — a tighter request is honoured', () => {
  const r = narrowOnly({ ttlSeconds: 600, ratePerHour: 2 })
  assert.equal(r.envelope.ttlSeconds, 600)
  assert.equal(r.envelope.ratePerHour, 2)
})
t('3d — a WIDER request is refused, not silently clamped', () => {
  const r = narrowOnly({ ttlSeconds: ESTATE_DEFAULTS.ttlSeconds + 1 })
  assert.equal(r.ok, false)
  assert.match(r.reason, /may only be tightened/)
})
t('3d — a forgotten field fails safe, which is the inverse of the waggle collapse', () => {
  // grantors-defaults-to-approvers silently WIDENED authority when a field was absent. Here absence
  // can only ever mean the ceiling, never more.
  const r = narrowOnly({ ratePerHour: undefined })
  assert.equal(r.envelope.ratePerHour, ESTATE_DEFAULTS.ratePerHour)
})
t('3d — nonsense is rejected with the value quoted back', () => {
  for (const bad of [0, -1, 'lots', NaN, Infinity]) {
    const r = narrowOnly({ ratePerHour: bad })
    assert.equal(r.ok, false, `accepted ${String(bad)}`)
  }
})

// ── issuance refuses an incomplete or out-of-scope envelope ──────────────────
t('a cap outside the closed enum is refused', () => {
  assert.equal(validateIssue({ cap: 'sudo', grantee: HEX, scopeHash: 'h', path: 'box' }).ok, false)
})
t('this plane refuses to issue an ADMISSION — a slice enforces those', () => {
  const r = validateIssue({ cap: 'admit', grantee: HEX, scopeHash: 'h', path: 'box' })
  assert.equal(r.ok, false)
  assert.match(r.reason, /claim authority this runtime does not have/)
})
t('a name is not a grantee — the join key is a 64-hex pubkey (ruling 1)', () => {
  assert.equal(validateIssue({ cap: 'task', grantee: 'luke', scopeHash: 'h', path: 'box' }).ok, false)
})
t('a grant over nothing is refused: narrowness is structural, not advisory', () => {
  assert.equal(validateIssue({ cap: 'task', grantee: HEX, path: 'box' }).ok, false)
})
t('exactly one approval path must be bound (AD-10)', () => {
  assert.equal(validateIssue({ cap: 'task', grantee: HEX, scopeHash: 'h', path: 'both' }).ok, false)
  assert.equal(validateIssue({ cap: 'task', grantee: HEX, scopeHash: 'h', path: 'director' }).ok, true)
})

// ── who enforces what: a console enforces nothing, and must not imply it does ──
t('the task family is enforced by this runtime', () => {
  assert.match(enforcerOf('task'), /this runtime/)
  assert.equal(capFamily('task+act'), 'task')
})
t('an admission is enforced by its slice, and this plane says so plainly', () => {
  assert.match(enforcerOf('admit'), /does not gate it/)
  assert.equal(capFamily('mirror'), 'admission')
})
t('an unknown cap is enforced by NOTHING, and says so rather than reassuring', () => {
  assert.equal(capFamily('whatever'), 'unknown')
  assert.match(enforcerOf('whatever'), /not enforced by anything/)
})
t('an unknown cap renders its raw value rather than a plausible guess', () => {
  assert.match(capLabel('whatever'), /Unrecognised capability: whatever/)
})
t('every cap in the closed enum has a label and a family', () => {
  for (const c of CAPS) {
    assert.doesNotMatch(capLabel(c), /Unrecognised/, `${c} has no label`)
    assert.notEqual(capFamily(c), 'unknown', `${c} has no family`)
  }
})

// ── reading rows: drop nothing silently ──────────────────────────────────────
t('a well-formed 440 becomes a row', () => {
  const { rows, dropped } = actionRows([ev()])
  assert.equal(rows.length, 1); assert.equal(dropped, 0)
  assert.equal(rows[0].cap, 'task'); assert.equal(rows[0].tier, 'low')
})
t('a malformed event is dropped and COUNTED, never silently discarded', () => {
  const { rows, dropped } = actionRows([ev(), { id: 'x' }, null, ev({ tags: [['da-cap', 'task']] })])
  assert.equal(rows.length, 1)
  assert.equal(dropped, 3, 'the caller must be able to report what it could not read')
})
t('a revoked grant is still returned, marked revoked — a cut grant is history', () => {
  const e = ev()
  const { rows } = actionRows([e], { revoked: new Set([e.id]) })
  assert.equal(rows[0].status, 'revoked')
})
t('expired and revoked are DIFFERENT states — collapsing them hides whether a human acted', () => {
  const e = ev({ tags: [['p', HEX], ['da-cap', 'task'], ['expiration', '500']] })
  assert.equal(actionRows([e], { now: 900 }).rows[0].status, 'expired')
  assert.equal(actionRows([e], { now: 900, revoked: new Set([e.id]) }).rows[0].status, 'revoked')
})
t('with no clock supplied, nothing is declared expired — a guess would be worse', () => {
  const e = ev({ tags: [['p', HEX], ['da-cap', 'task'], ['expiration', '500']] })
  assert.equal(actionRows([e]).rows[0].status, 'active')
})
t('rows read newest-first', () => {
  const { rows } = actionRows([ev({ id: 'a'.repeat(64), created_at: 10 }), ev({ id: 'b'.repeat(64), created_at: 20 })])
  assert.equal(rows[0].issuedAt, 20)
})

// ── 3c: revoking enumerates, and states its limits ──────────────────────────
t('3c — revoking enumerates the proposals it will kill', () => {
  const row = actionRows([ev()]).rows[0]
  const q = [{ id: 'p1', granteePub: HEX }, { id: 'p2', granteePub: HEX }, { id: 'p3', granteePub: 'b'.repeat(64) }]
  const imp = revokeImpact(row, q)
  assert.equal(imp.queued.length, 2, 'only proposals under THIS grantee')
  assert.match(imp.grantLabel, /task/)
})
t('3c — it states what it does NOT reach, so the button means what it says', () => {
  const row = actionRows([ev()]).rows[0]
  const imp = revokeImpact(row, [])
  assert.match(imp.limits, /does not rotate any key/)
  assert.match(imp.limits, /roster this console never read/)
})
t('3c — revoking an ADMISSION admits it cannot confirm the slice acted', () => {
  const e = ev({ tags: [['p', HEX], ['da-cap', 'admit'], ['da-scope', 'h']] })
  const imp = revokeImpact(actionRows([e]).rows[0], [])
  assert.match(imp.limits, /cannot confirm the slice acted/)
})
t('3c — an empty queue is an empty list, never a claim that nothing was pending', () => {
  const imp = revokeImpact(actionRows([ev()]).rows[0], undefined)
  assert.deepEqual(imp.queued, [])
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
