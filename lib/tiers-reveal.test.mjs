// The shared P5 surfaces spec — the tier ceremony (lib/tiers.mjs) and the
// faithful render (lib/reveal.mjs). The render's character ranges are PINNED to
// the canonical scanner (src/inspect.mjs) so the signing surface can never show
// a softer picture than the review console or the runtime's own flags.
//
//   node lib/tiers-reveal.test.mjs
import assert from 'node:assert'
import { ceremonyFor, needsConfirm, needsDevice, nextTier, TIERS } from './tiers.mjs'
import { revealContent, esc, REVEAL_HIDDEN, REVEAL_CONFUSABLE } from './reveal.mjs'
import { HIDDEN_G, CONFUSABLE_G, kindInfo, scanContent } from '../src/inspect.mjs'

let n = 0, pass = 0
const t = (name, fn) => { n++; try { fn(); pass++; console.log(`ok - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) } }

// ---- tier ceremony ---------------------------------------------------------
t('critical is never one-tap: confirm + device', () => {
  const c = ceremonyFor('critical')
  assert.equal(c.oneTap, false)
  assert.equal(c.needsConfirm, true)
  assert.equal(c.needsDevice, true)
  assert.equal(needsConfirm('critical'), true)
  assert.equal(needsDevice('critical'), true)
})

t('low + elevated are one-tap (elevated only after full render)', () => {
  assert.equal(ceremonyFor('low').oneTap, true)
  assert.equal(needsConfirm('low'), false)
  assert.equal(ceremonyFor('elevated').oneTap, true)
  assert.equal(needsConfirm('elevated'), false)
  assert.match(ceremonyFor('elevated').requirement, /full tags/)
})

t('an unknown tier fails conservative — never a silent one-tap-low', () => {
  const c = ceremonyFor('wat')
  assert.deepEqual(c, ceremonyFor('elevated'), 'unknown → elevated, not low')
})

t('nextTier cycles low→elevated→critical→low', () => {
  assert.equal(nextTier('low'), 'elevated')
  assert.equal(nextTier('elevated'), 'critical')
  assert.equal(nextTier('critical'), 'low')
  assert.deepEqual(TIERS, ['low', 'elevated', 'critical'])
})

// The ceremony spec must agree with the runtime's tier assignment: every kind
// inspect calls 'critical' must be a no-one-tap ceremony here (the P3 gate).
t('every critical KIND maps to a no-one-tap ceremony (spec ⟷ runtime agree)', () => {
  for (const kind of [0, 3, 5, 10002]) {
    assert.equal(kindInfo(kind).risk, 'critical', `kind ${kind} is critical`)
    assert.equal(ceremonyFor(kindInfo(kind).risk).oneTap, false, `kind ${kind} is not one-tap`)
  }
})

// ---- faithful render -------------------------------------------------------
t('esc neutralizes HTML metacharacters', () => {
  assert.equal(esc('<b>&</b>'), '&lt;b&gt;&amp;&lt;/b&gt;')
})

t('a zero-width character is revealed as a labeled chip, not swallowed', () => {
  const out = revealContent('ab​c')          // U+200B ZERO WIDTH SPACE
  assert.match(out, /U\+200B/)
  assert.match(out, /class="lint hidden"/)
  assert.ok(!out.includes('​'), 'the raw invisible char is gone from the output')
})

t('a Cyrillic look-alike is boxed as a possible spoof', () => {
  const out = revealContent('pа')                 // Latin p + Cyrillic а (U+0430)
  assert.match(out, /class="lint confuse"/)
  assert.match(out, /U\+0430/)
})

t('a Greek look-alike in the full block is boxed', () => {
  // U+03BF GREEK SMALL LETTER OMICRON — inside the canonical U+0370-U+03FF Greek
  // range inspect flags. The shared render must catch it too.
  const out = revealContent('cοde')
  assert.match(out, /class="lint confuse"/, 'omicron is revealed')
})

t('clean ASCII renders unchanged (no false positives)', () => {
  assert.equal(revealContent('hello world 123'), 'hello world 123')
})

// ---- the pin: reveal ranges ≡ the canonical scanner ------------------------
t('REVEAL_HIDDEN covers exactly what inspect HIDDEN_G flags', () => {
  // Probe every code point either range could plausibly cover; they must agree.
  for (let cp = 0; cp <= 0xffff; cp++) {
    const ch = String.fromCharCode(cp)
    const a = new RegExp(REVEAL_HIDDEN.source).test(ch)
    const b = new RegExp(HIDDEN_G.source).test(ch)
    assert.equal(a, b, `divergence at U+${cp.toString(16).toUpperCase()} (reveal=${a} inspect=${b})`)
  }
})

t('REVEAL_CONFUSABLE covers exactly what inspect CONFUSABLE_G flags', () => {
  for (let cp = 0; cp <= 0xffff; cp++) {
    const ch = String.fromCharCode(cp)
    const a = new RegExp(REVEAL_CONFUSABLE.source).test(ch)
    const b = new RegExp(CONFUSABLE_G.source).test(ch)
    assert.equal(a, b, `divergence at U+${cp.toString(16).toUpperCase()} (reveal=${a} inspect=${b})`)
  }
})

t('anything the render boxes, the scanner also flags (no surface-vs-flag gap)', () => {
  const samples = ['ab​c', 'pа', 'cοde', 'plain']
  for (const s of samples) {
    const boxed = /class="lint (hidden|confuse)"/.test(revealContent(s))
    const flagged = scanContent(s).length > 0
    assert.equal(boxed, flagged, `render/flag mismatch for ${JSON.stringify(s)}`)
  }
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
