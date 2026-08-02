// WYSIWYS inspection (hardening P2, nact#8): the approval surface must classify
// an event faithfully and flag anything that makes the render differ from the
// bytes — hidden/bidi characters, homoglyph (mixed-script) spoofs, risky kinds.
//
//   node src/inspect.mjs.test  →  node src/inspect.test.mjs

import assert from 'node:assert'
import { inspect, scanContent, kindInfo, confusableTokens, HIDDEN, CONFUSABLE } from './inspect.mjs'

let n = 0, pass = 0
const t = (name, fn) => { n++; try { fn(); pass++; console.log(`ok - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) } }
const hasWarn = (rep, re) => rep.warnings.some(w => re.test(w))

// ---- kind classification ---------------------------------------------------
t('known kinds carry a label and a risk tier', () => {
  assert.equal(kindInfo(1).risk, 'low')
  assert.equal(kindInfo(0).risk, 'critical')          // profile edit
  assert.equal(kindInfo(3).risk, 'critical')          // contact list REPLACES
  assert.equal(kindInfo(10002).risk, 'critical')      // relay list REPLACES
})
t('unknown / range kinds default conservatively', () => {
  assert.equal(kindInfo(31337).risk, 'critical')      // addressable → replaces
  assert.equal(kindInfo(10050).risk, 'elevated')      // replaceable
  assert.equal(kindInfo(99999).risk, 'elevated')      // unknown → not low
})
t('a critical kind pushes a verify-carefully warning to the front', () => {
  const rep = inspect({ kind: 0, tags: [], content: '{}' })
  assert.equal(rep.risk, 'critical')
  assert.match(rep.warnings[0], /high-impact, verify carefully/)
})

// ---- NIP-DA grants ---------------------------------------------------------
// These reached the queue before this mapping existed, via the unknown-kind fallback: correctly
// conservative about risk, and rendered as the bare string "kind 440". The defect was never the
// tier — it was that a Director could not tell what they were approving. So these assertions are
// about MEANING as much as risk, and a label that reverts to the fallback must fail here.
t('a NIP-DA grant is critical and says what it does', () => {
  const ki = kindInfo(440)
  assert.equal(ki.risk, 'critical')
  assert.notEqual(ki.label, 'kind 440')               // the fallback label IS the defect
  assert.match(ki.label, /grant/i)
  assert.match(ki.label, /GIVES/)                     // names the direction, as kind 3 and 10002 do
})
t('revoking is elevated, not critical — the asymmetry is deliberate', () => {
  // Granting cannot be undone in the way that matters: a later revoke stops future access but
  // cannot un-see what was already read. Revoking fails closed and is undone by re-issuing. If
  // these two ever read the same, the ranking has lost the distinction it exists to make.
  assert.equal(kindInfo(441).risk, 'elevated')
  assert.match(kindInfo(441).label, /REMOVES/)
  assert.notEqual(kindInfo(440).risk, kindInfo(441).risk)
})
t('the NIP-DA index and data set are critical and labelled as replacing', () => {
  assert.equal(kindInfo(10440).risk, 'critical')
  assert.match(kindInfo(10440).label, /REPLACES/)
  assert.equal(kindInfo(30440).risk, 'critical')
  assert.match(kindInfo(30440).label, /REPLACES/)
  // 30440 was already critical via the addressable range; what changed is that it no longer
  // renders as a generic "Addressable list (kind 30440)".
  assert.doesNotMatch(kindInfo(30440).label, /Addressable list/)
})
t('naming NIP-DA kinds did not drag ordinary kinds upward', () => {
  // The paired direction. A mapping change that quietly promoted everything would satisfy every
  // assertion above and leave the tier system meaningless.
  assert.equal(kindInfo(1).risk, 'low')
  assert.equal(kindInfo(7).risk, 'low')
  assert.equal(kindInfo(9734).risk, 'elevated')
  assert.equal(kindInfo(99999).risk, 'elevated')      // the fallback still applies to real unknowns
})
t('a grant proposal surfaces the verify-carefully warning first', () => {
  const rep = inspect({ kind: 440, tags: [['p', 'a'.repeat(64)], ['da-cap', 'admit']], content: '' })
  assert.equal(rep.risk, 'critical')
  assert.match(rep.warnings[0], /high-impact, verify carefully/)
  assert.match(rep.kindLabel, /grant/i)
  assert.ok(rep.notableTags.some(x => /\(p\)/.test(x)))   // the grantee rides in a p tag
})

// ---- hidden / bidi characters ----------------------------------------------
t('zero-width and bidi characters in content are flagged', () => {
  const rep = inspect({ kind: 1, tags: [], content: 'hello​world‮ reversed' })
  assert.ok(hasWarn(rep, /hidden \/ bidi control character/))
})
t('clean content raises no hidden-char warning', () => {
  assert.equal(scanContent('a perfectly normal note about nave.pub').some(w => /hidden/.test(w)), false)
})

// ---- homoglyph / mixed-script spoofs (the P2 addition) ---------------------
t('a Latin word with a Cyrillic look-alike is flagged as a possible spoof', () => {
  // "аpple" — the leading а is Cyrillic U+0430, the rest Latin.
  const rep = inspect({ kind: 1, tags: [], content: 'log in at аpple.com now' })
  assert.ok(hasWarn(rep, /homoglyph spoof/), 'should flag the mixed-script token')
  assert.deepEqual(confusableTokens('аpple.com'), ['аpple.com'])
})
t('a Cyrillic о inside google is caught', () => {
  assert.equal(confusableTokens('gооgle').length, 1)   // Cyrillic о×2
})
t('legitimate all-Cyrillic (or all-Greek) text is NOT flagged', () => {
  assert.deepEqual(confusableTokens('привет мир'), [])  // "привет мир", pure Cyrillic
  assert.equal(inspect({ kind: 1, tags: [], content: 'Αθήνα' }).warnings.some(w => /homoglyph/.test(w)), false)  // Greek "Αθήνα"
})
t('plain ASCII never trips the confusable scan', () => {
  assert.deepEqual(confusableTokens('the quick brown fox jumps'), [])
})

// ---- tag-value scanning ----------------------------------------------------
t('a hidden character in a tag value is flagged', () => {
  const rep = inspect({ kind: 1, tags: [['r', 'https://nave.pub​.evil.com']], content: 'ok' })
  assert.ok(hasWarn(rep, /hidden \/ control character in a "r" tag/))
})
t('a look-alike character in a tag value is flagged', () => {
  const rep = inspect({ kind: 1, tags: [['r', 'https://navе.pub']], content: 'ok' })  // Cyrillic е
  assert.ok(hasWarn(rep, /look-alike character in a "r" tag/))
})
t('notable tags (p/e/q) are surfaced, full tags preserved', () => {
  const rep = inspect({ kind: 1, tags: [['p', 'abc'], ['e', 'def'], ['t', 'nostr']], content: 'hi' })
  assert.ok(rep.notableTags.some(x => /mentions/.test(x)))
  assert.deepEqual(rep.tags, [['p', 'abc'], ['e', 'def'], ['t', 'nostr']], 'full tags passed through, not summarized')
})

// ---- adversarial fixtures (the whole point) --------------------------------
t('adversarial: a phishing note stacks every flag', () => {
  const rep = inspect({
    kind: 0,   // critical: profile edit disguised as harmless
    tags: [['p', 'victim'], ['r', 'https://cоinbase.com']],   // Cyrillic о in the URL tag
    content: 'Verify your account ‮elgooG‬ at gооgle​.com  ',  // bidi + homoglyph + zero-width + trailing space
  })
  assert.equal(rep.risk, 'critical')
  assert.ok(hasWarn(rep, /verify carefully/))
  assert.ok(hasWarn(rep, /hidden \/ bidi/))
  assert.ok(hasWarn(rep, /homoglyph spoof/))
  assert.ok(hasWarn(rep, /look-alike character in a "r" tag/))
  assert.ok(hasWarn(rep, /trailing whitespace/))
})
t('the regexes are exported for the client-side faithful render', () => {
  assert.ok(HIDDEN.test('​'))
  assert.ok(CONFUSABLE.test('а'))
  assert.ok(!CONFUSABLE.test('a'))
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
