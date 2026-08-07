// Reading the delegator's roster projection, and refusing to guess when it cannot be read.
//
//   node nactor/registry-reader.test.mjs
//
// THE ONE PROPERTY THIS SUITE EXISTS FOR: `agents: null` and `agents: []` are different answers and
// must never collapse. Null means nobody asked or nobody answered — the honest report is "not
// verified". Empty means the Director's registry really is empty, which makes every on-box key a real
// divergence. A reader that returned `[]` on failure would convert "I could not check" into "Nvoy does
// not know this key" — the original bug wearing a fix's clothing, and undetectable from the outside.
//
// So every failure path is asserted to return null WITH a reason, and the reasons are asserted to be
// distinguishable, because "why can't I see the roster" is the question an operator will actually ask.

import assert from 'node:assert'
import { readRegistry, registryView, REGISTRY_SCOPE, REGISTRY_MAX_VERSION } from './registry-reader.mjs'
import { diffRosters } from '../lib/registry.mjs'

let pass = 0, fail = 0
const t = async (name, fn) => {
  try { await fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const A = 'a'.repeat(64), B = 'b'.repeat(64), C = 'c'.repeat(64)

// THE FIXTURE IS THE FIX. This suite used to set `{ d: REGISTRY_SCOPE }` and mock `readScope` as
// `async () => (…)` — a stub that ignores its arguments. Between them, those two lines let the reader
// match on the wrong field AND dereference by the wrong value, and pinned the mistake as the expected
// contract. Both halves of the join passed their own suites and could never have worked together,
// because each mocked the other side to its own assumption.
//
// So: the grant now has the shape nvoy's `grantSummary` actually emits — an OPAQUE `d`, distinct from
// `scope_name` — and the mock ASSERTS what it was called with. A stub that accepts anything verifies
// nothing.
const SCOPE_ID = 'kx7m2q'                        // opaque, as every nvoy scope id is
const grant = { d: SCOPE_ID, scope_name: REGISTRY_SCOPE, author_npub: 'npub1director', status: 'active' }
const clientReturning = (data, generation = 3) => ({
  readScope: async (d, authorNpub) => {
    assert.equal(d, SCOPE_ID,
      'the reader must dereference the scope ID from the grant, not the scope NAME — nvoy publishes '
      + 'under an opaque `d` on purpose, and reading by name finds nothing')
    assert.equal(authorNpub, grant.author_npub, 'the roster must be read from the granting delegator')
    return { data, generation }
  },
})

// ── every failure is null WITH a reason, never [] ────────────────────────────
await t('no MCP client → null, and says there is no path', async () => {
  const r = await readRegistry({ client: null, grants: [grant] })
  assert.equal(r.agents, null)
  assert.match(r.why, /no path to the delegator/)
})
await t('no grant on the scope → null, and names the missing grant', async () => {
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [] }), grants: [] })
  assert.equal(r.agents, null)
  assert.match(r.why, new RegExp(REGISTRY_SCOPE.replace('/', '\\/')))
  assert.match(r.why, /has not granted this runtime read/)
})
// ── the join seam: match on the NAME, dereference by the ID ─────────────────
await t('THE BUG: a grant identified only by `d === REGISTRY_SCOPE` is NOT a match', async () => {
  // This is the exact shape the old reader looked for, and the shape nvoy will never publish, because
  // a semantic `d` tag leaks that this pubkey maintains an agent roster. Matching it would mean the
  // only projection this runtime can read is one that already leaked.
  const r = await readRegistry({
    client: clientReturning({ v: 1, agents: [{ pub: A }] }),
    grants: [{ d: REGISTRY_SCOPE, author_npub: 'npub1director', status: 'active' }],
  })
  assert.equal(r.agents, null, 'matched a scope name in the `d` field')
  assert.match(r.why, /has not granted this runtime read/)
})
await t('the roster is dereferenced by the opaque scope id, and the mock proves it', async () => {
  // The assertions live in clientReturning: called with the NAME, this test fails.
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [{ pub: A }] }), grants: [grant] })
  assert.deepEqual(r.agents, [A])
})
await t('a REVOKED grant reads differently from a missing one', async () => {
  // Rotation-based revocation leaves the grantee's row visible, so this is reachable in normal
  // operation. "never granted" sends an operator to Nvoy to grant it; "revoked" tells them it was taken
  // away. One sentence for both would send them to do the wrong thing.
  const r = await readRegistry({
    client: clientReturning({ v: 1, agents: [{ pub: A }] }),
    grants: [{ ...grant, status: 'revoked' }],
  })
  assert.equal(r.agents, null)
  assert.match(r.why, /not active/)
  assert.doesNotMatch(r.why, /has not granted this runtime read/,
    'a revoked grant must not be reported as one that was never issued')
})
await t('an active grant is preferred over a stale one for the same scope', async () => {
  const r = await readRegistry({
    client: clientReturning({ v: 1, agents: [{ pub: B }] }),
    grants: [{ ...grant, d: 'old000', status: 'revoked' }, grant],
  })
  assert.deepEqual(r.agents, [B], 'the reader did not pick the active grant')
})
await t('a grant with no scope id → null, rather than dereferencing undefined', async () => {
  const r = await readRegistry({
    client: clientReturning({ v: 1, agents: [{ pub: A }] }),
    grants: [{ scope_name: REGISTRY_SCOPE, author_npub: 'npub1director', status: 'active' }],
  })
  assert.equal(r.agents, null)
  assert.match(r.why, /no scope id/)
})

await t('a read that throws → null, and surfaces the transport error', async () => {
  const r = await readRegistry({ client: { readScope: async () => { throw new Error('relay down') } }, grants: [grant] })
  assert.equal(r.agents, null)
  assert.match(r.why, /relay down/)
})
await t('an unreadable payload → null, not an empty roster', async () => {
  for (const bad of [null, undefined, 'nope', 42]) {
    const r = await readRegistry({ client: clientReturning(bad), grants: [grant] })
    assert.equal(r.agents, null, `accepted ${JSON.stringify(bad)}`)
  }
})
await t('a FUTURE schema version → null, and refuses to guess', async () => {
  // A later field could change what a row MEANS. A roster misread is worse than a roster unread.
  const r = await readRegistry({ client: clientReturning({ v: REGISTRY_MAX_VERSION + 1, agents: [{ pub: A }] }), grants: [grant] })
  assert.equal(r.agents, null)
  assert.match(r.why, /Refusing to guess/)
})
await t('a missing version → null: an unversioned payload is not a known shape', async () => {
  assert.equal((await readRegistry({ client: clientReturning({ agents: [{ pub: A }] }), grants: [grant] })).agents, null)
})
await t('the failure reasons are DISTINGUISHABLE — an operator has to act on them', async () => {
  const whys = new Set()
  whys.add((await readRegistry({ client: null, grants: [grant] })).why)
  whys.add((await readRegistry({ client: clientReturning({ v: 1 }), grants: [] })).why)
  whys.add((await readRegistry({ client: { readScope: async () => { throw new Error('x') } }, grants: [grant] })).why)
  whys.add((await readRegistry({ client: clientReturning({ v: 99 }), grants: [grant] })).why)
  assert.equal(whys.size, 4, 'each failure must be tellable from the others')
})

// ── a successful read ───────────────────────────────────────────────────────
await t('a good projection yields the pubkeys', async () => {
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [{ pub: A }, { pub: B }], generated_at: 100 }), grants: [grant] })
  assert.deepEqual(r.agents, [A, B])
  assert.equal(r.generatedAt, 100)
  assert.equal(r.generation, 3)
  assert.equal(r.why, null)
})
await t('an EMPTY projection is an ANSWER — agents:[] with no reason attached', async () => {
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [] }), grants: [grant] })
  assert.deepEqual(r.agents, [])
  assert.equal(r.why, null, 'an empty roster is not a failure and must carry no excuse')
})
await t('a malformed projected row is dropped and counted', async () => {
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [{ pub: A }, { pub: 'x' }, null] }), grants: [grant] })
  assert.deepEqual(r.agents, [A]); assert.equal(r.dropped, 2)
})
await t('a pubkey is lowercased, so one key cannot read as two agents', async () => {
  const r = await readRegistry({ client: clientReturning({ v: 1, agents: [{ pub: A.toUpperCase() }] }), grants: [grant] })
  assert.deepEqual(r.agents, [A])
})
await t('the roster is read LIVE (maxAge 0) — a cached roster would keep a revoked agent registered', async () => {
  let seen = null
  await readRegistry({ client: { readScope: async (_d, _a, o) => { seen = o; return { data: { v: 1, agents: [] } } } }, grants: [grant] })
  assert.equal(seen.maxAge, 0)
})

// ── the view the console consumes ──────────────────────────────────────────
await t('the view reports staleness rather than hiding it — the projection is a copy', () => {
  const v = registryView({ agents: [A], generatedAt: 1000 }, { now: 1000 + 2 * 24 * 3600 })
  assert.equal(v.stale, true)
  assert.equal(v.ageSeconds, 2 * 24 * 3600)
})
await t('a fresh projection is not stale', () => {
  assert.equal(registryView({ agents: [A], generatedAt: 1000 }, { now: 1100 }).stale, false)
})
await t('with no timestamp, staleness is null — unknown, never asserted as fresh', () => {
  assert.equal(registryView({ agents: [A], generatedAt: null }, { now: 5000 }).stale, null)
})
await t('the view preserves null agents and carries the reason through', () => {
  const v = registryView({ agents: null, why: 'because' })
  assert.equal(v.agents, null); assert.equal(v.why, 'because')
})

// ── THE ACCEPTANCE TEST for the Director's actual complaint ────────────────
await t('ACCEPTANCE: an agent registered in Nvoy with no key here renders as a DIVERGENCE, not silence', async () => {
  const read = await readRegistry({ client: clientReturning({ v: 1, agents: [{ pub: A }, { pub: B }] }), grants: [grant] })
  const d = diffRosters({ registry: registryView(read).agents, box: [A, C] })
  assert.deepEqual(d.onlyRegistry, [B], 'B is in Nvoy and has no key here — this is the reported symptom')
  assert.deepEqual(d.onlyBox, [C], 'C is on the box and unregistered — the converse')
  assert.deepEqual(d.both, [A])
  // Nothing may be silently absent — the property whose lack caused the complaint.
  const all = [...d.both, ...d.onlyRegistry, ...d.onlyBox, ...d.unverified].sort()
  assert.deepEqual(all, [A, B, C].sort())
})
await t('ACCEPTANCE: an UNREAD projection claims no divergence in either direction', async () => {
  const read = await readRegistry({ client: null, grants: [] })
  const d = diffRosters({ registry: registryView(read).agents, box: [A, C] })
  assert.equal(d.registryKnown, false)
  assert.deepEqual(d.onlyBox, [], 'must not accuse the box of holding unregistered keys it never checked')
  assert.deepEqual(d.onlyRegistry, [])
  assert.deepEqual(d.unverified, [A, C].sort())
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
