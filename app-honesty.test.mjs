// app-honesty.test.mjs — the control plane does not claim things it cannot do (#56).
//
//   node app-honesty.test.mjs
//
// WHAT THIS PROVES, AND WHAT IT DOES NOT. `app.html` is one file with inline script; there is no
// module to import and no build step, so this asserts over its SOURCE, not over a render. It can
// prove a fabrication is absent and a field is read; it cannot prove the resulting markup looks
// right. That is a real limit and it is stated rather than implied away — the same posture as
// nactor/join-key.test.mjs. It is still the right test for these three defects, because each was
// either the PRESENCE of a lie or the ABSENCE of a field, and both are statically visible.
//
// WHY IT EXISTS. Three claims this plane made that were not true:
//
//   1. `+ Add identity` minted `'npub1' + 38 random chars` and pushed it into local state as an
//      active identity. No API call, nothing on the box, a key that does not exist rendering
//      identically to one that does. Twenty lines above the seed data, the same file says an
//      approval queue that invents approvals is the one thing a control plane must never do —
//      and inventing the IDENTITY is strictly worse, because every approval it ever appears to
//      give is downstream of it.
//   2. `Revoke authority (rotate key)` had no API call behind it. A revoke that revokes nothing is
//      the most dangerous button in the fleet: you would believe you had cut an agent off.
//   3. `/api/state` returned `raised` — the director-path drafts on the Director's desk — and
//      mapState dropped the field, so every director-path proposal was invisible in the plane whose
//      whole purpose is proposals.
//
// The first two are lies of commission, the third of omission. All three are the same failure:
// the interface asserting more, or less, than the runtime told it.

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'app.html'), 'utf8')

let pass = 0, fail = 0
const t = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

// ── 1. no fabricated identities ───────────────────────────────────────────────
t('no npub is ever constructed from randomness', () => {
  // Deliberately broad: any Math.random() near an npub literal is the shape of the original bug,
  // whatever the alphabet or length. A narrow match on the old string would pass the moment
  // somebody rewrote the same idea slightly differently.
  const lines = src.split('\n')
  const guilty = lines.filter(l => /Math\.random\(\)/.test(l) && /npub/i.test(l))
  assert.equal(guilty.length, 0, `fabrication at: ${guilty.join(' | ')}`)
})
t('no npub literal is assembled by concatenation onto the prefix at all', () => {
  assert.doesNotMatch(src, /['"`]npub1['"`]\s*\+/, 'a built npub is a claimed key')
})
t('the unprovisionable signer options are disabled in the picker', () => {
  const sel = src.slice(src.indexOf('id="ni-signer"'), src.indexOf('id="ni-signer"') + 900)
  assert.match(sel, /value="custodial"[^>]*disabled/, 'custodial must be disabled')
  assert.match(sel, /value="bunker"[^>]*disabled/, 'bunker must be disabled')
  assert.doesNotMatch(sel, /value="director"[^>]*disabled/, 'the one path that works must stay enabled')
})
t('a refusal states the route that DOES work, so it teaches instead of blocking', () => {
  assert.match(src, /_NSEC on the box/, 'custodial refusal must name the box workaround')
  assert.match(src, /Nothing was created/, 'a refusal must say nothing happened')
})
t('the create handler cannot fall through to a success it did not perform', () => {
  // Every non-director branch must `return` before any state push. Asserted as: no `S.identities.push`
  // survives anywhere in the file.
  assert.doesNotMatch(src, /S\.identities\.push/, 'the console must not add an identity locally')
})

// ── 2. no revoke that revokes nothing ────────────────────────────────────────
t('the rotate-key button is disabled, not merely relabelled', () => {
  assert.match(src, /<button class="btn danger" disabled[^>]*Rotating a key on the box/s)
})
t('…and points at the revocation that is real today', () => {
  assert.match(src, /revoke its grants in the Nvoy Ledger/i)
  assert.match(src, /nvoy\.nave\.pub\/console\/#agent\//, 'must deep-link by the join key (AD-12)')
})
t('the local-only action is NAMED local-only', () => {
  assert.match(src, /Forget on this device/)
  assert.doesNotMatch(src, />Remove identity</, 'the old label implied it removed the identity itself')
})

// ── 3. raised is read, and honestly framed ───────────────────────────────────
t('mapState reads the raised field the API has always returned', () => {
  assert.match(src, /S\.raised\s*=\s*\(st\.raised\s*\|\|\s*\[\]\)/)
})
t('raised has a home in the state object, so a disconnected plane renders empty not undefined', () => {
  assert.match(src, /^\s*raised:\s*\[\],/m)
})
t('the desk section exists and is separated from what this box can sign', () => {
  assert.match(src, /On your Ngage desk/)
  assert.match(src, /Awaiting your key here/)
})
t('it says plainly that this box cannot sign these, and why', () => {
  assert.match(src, /cannot sign them/)
  assert.match(src, /enforced by encryption, not by policy/, 'AD-10: the constraint is cryptographic')
})
t('it hands the reader the door rather than stranding them', () => {
  assert.match(src, /ngage\.nave\.pub\/#draft\//, 'deep-link to the desk, per the spec receiver')
  assert.match(src, /Open on your Ngage desk/)
})
t('a raised entry with no scope id is dropped, not rendered as an unopenable card', () => {
  assert.match(src, /\.filter\(r=>r&&r\.scopeId\)/)
})
t('the section header class it uses actually exists in the stylesheet', () => {
  // The kind of gap that renders as unstyled text in production and is invisible in review.
  assert.match(src, /^\.sect\{/m, 'app.html uses <h2 class="sect"> — the rule must be defined')
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
