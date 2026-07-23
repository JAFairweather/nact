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
