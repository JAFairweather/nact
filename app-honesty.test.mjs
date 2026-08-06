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

// ── the Actions screen, and the tab order that frames it (#56 part 3) ────────
t('Actions is a tab, and Directors is not', () => {
  assert.match(src, /\['actions', 'Actions'\]/)
  assert.doesNotMatch(src, /\['directors',/, 'a Director is an approval path, not a peer of an agent')
})
t('the tab order puts decisions before plumbing, with a divider between', () => {
  const order = [...src.matchAll(/\['(queue|identities|actions|routing|history|--|channels|policy|deployment)'/g)].map(m => m[1])
  assert.deepEqual(order.slice(0, 9),
    ['queue', 'identities', 'actions', 'routing', 'history', '--', 'channels', 'policy', 'deployment'])
})
t('the divider is a real element, not a comment about one', () => {
  assert.match(src, /^\.tab-div\{/m, 'the class must exist in the stylesheet')
  assert.match(src, /class="tab-div"/)
})
t('the badge law holds: the Queue counts BOTH what it can sign and what it cannot', () => {
  // A badge means a human decision is waiting. A director-path draft is waiting on a human just as
  // much as a box-path proposal, so counting only the box path would under-report the ask.
  assert.match(src, /S\.queue\.length \+ S\.raised\.length/)
})
t('hash routing exists, so a cross-plane deep link can land', () => {
  assert.match(src, /function tabFromHash/)
  assert.match(src, /addEventListener\('hashchange'/)
  assert.match(src, /\{ const k=tabFromHash\(\); if\(k\) tab=k; \}/, 'the boot must honour the hash BEFORE the first draw')
})
t('an unknown tab falls back rather than rendering a blank plane', () => {
  assert.match(src, /if\(!TAB_KEYS\.includes\(k\)\) k = 'queue'/)
})

t('Actions reads PUBLIC 440s and needs no key, per AD-12 ruling 4', () => {
  assert.match(src, /kinds:\[440\]/)
  assert.match(src, /NO KEY IS USED/)
})
t('…and collects 441 revocations by their e-tag, so a revoked grant cannot read as active', () => {
  assert.match(src, /kinds:\[441\]/)
  assert.match(src, /t\[0\]==='e'&&t\[1\]/)
})
t('a silent relay renders "no relay answered", NEVER an empty list', () => {
  // The load-bearing assertion of the whole screen. An empty list claims nothing is granted; silence
  // is a claim about the relays only, and conflating them is how unobservable authority happens.
  assert.match(src, /state:'silent'/)
  assert.match(src, /No relay answered\. Nothing is shown because nothing could be verified/)
  // Whitespace- and markup-tolerant: the sentence wraps in the template and carries a <b> in the
  // middle. Pinning the exact spacing would make this a formatting test.
  assert.match(src, /this is[\s\S]{0,40}the same as “nothing granted\.”/)
})
t('an empty ANSWERED result is affirmative — an answer, not a gap', () => {
  assert.match(src, /this is an answer, not a gap/)
})
t('unreadable events are counted in the stamp, not dropped in silence', () => {
  assert.match(src, /unreadable and not shown/)
})
t('the relay answer count is reported, so partial coverage is visible', () => {
  assert.match(src, /relays answered/)
})
t('every row states WHO ENFORCES it — a console enforces nothing', () => {
  assert.match(src, /Enforced by: /)
})
t('the tier is shown as fixed, and carries the reason it cannot be raised (3b)', () => {
  assert.match(src, /tier <b>\$\{esc\(r\.tier\)\}<\/b> · fixed/)
  assert.match(src, /A\?\.tierCap\?\.\(\)\.why/, 'the reason must ride with the number')
})
t('the composer refuses instead of pretending, and says what the envelope requires', () => {
  assert.match(src, /will not pretend/)
  assert.match(src, /<button class="btn" disabled title="No runtime endpoint issues a capability grant yet/)
  assert.match(src, /may only be <b>tightened<\/b>/)
})
t('admissions are not issuable here, and the refusal says why', () => {
  assert.match(src, /claim authority this runtime does not have/)
})
t('revoke enumerates the queued proposals first (3c), and signs nothing it cannot', () => {
  assert.match(src, /revokeImpact/)
  assert.match(src, /queued proposal/)
  assert.match(src, /NOTHING WAS SIGNED/, 'an unwired action must say so rather than appear to work')
})
t('the queue↔grant join is on the PUBKEY, never the display name (ruling 1)', () => {
  assert.match(src, /window\.__nact\?\.toHex/)
  assert.match(src, /window\.__nact\.toHex = function/)
})
t('"Forget on this device" no longer marks the row revoked', () => {
  // It had set status='revoked' locally — claiming an authority change that never happened.
  assert.doesNotMatch(src, /i\.status='revoked';draw\(\)/)
  assert.match(src, /No grant is revoked, no key is touched/)
})
t('the shared model is imported, not restated — one implementation, not two descriptions', () => {
  assert.match(src, /import \* as ACTIONS from 'nact-actions'/)
  assert.match(src, /"nact-actions": "\.\/lib\/actions\.mjs/)
  assert.match(src, /window\.__nact\.actions = ACTIONS/)
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
