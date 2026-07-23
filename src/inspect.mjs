// WYSIWYS inspection: classify an unsigned event and surface anything that
// could make the rendered action differ from the bytes that get signed.
// See docs/threat-model.md.

const KINDS = {
  0:     { label: 'Profile / metadata edit', risk: 'critical' },
  1:     { label: 'Note',                     risk: 'low' },
  3:     { label: 'Contact list — REPLACES all follows', risk: 'critical' },
  4:     { label: 'Encrypted DM (legacy)',    risk: 'elevated' },
  5:     { label: 'Deletion request',         risk: 'critical' },
  6:     { label: 'Repost',                   risk: 'low' },
  7:     { label: 'Reaction',                 risk: 'low' },
  1059:  { label: 'Gift wrap',                risk: 'elevated' },
  9734:  { label: 'Zap request',              risk: 'elevated' },
  10002: { label: 'Relay list — REPLACES your relays', risk: 'critical' },
}

// Zero-width, bidi override/isolate, word-joiner, BOM, soft-hyphen — characters
// that let displayed text differ from the actual bytes. Written as escapes so
// the pattern itself stays visible in source.
export const HIDDEN = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/       // non-global: safe for .test()
export const HIDDEN_G = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g     // global: for match/count/replace
// Confusable scripts: Cyrillic and Greek letters that mimic Latin ones. A token
// mixing Latin with these is almost always a homoglyph spoof \u2014 "\u0430pple" with a
// Cyrillic \u0430, "g\u043e\u043egle.com" with Cyrillic \u043e. (Whole-Cyrillic or whole-Greek
// text is legitimate and is NOT flagged; only the MIX inside a token is.)
export const CONFUSABLE = /[\u0400-\u04ff\u0370-\u03ff]/
export const CONFUSABLE_G = /[\u0400-\u04ff\u0370-\u03ff]/g
const LATIN = /[a-z]/i

// The suspicious tokens in a string: whitespace-delimited runs containing BOTH a
// Latin letter and a confusable non-Latin letter. Shared by content + tag scans.
export function confusableTokens(s = '') {
  const out = []
  for (const tok of String(s).split(/\s+/)) {
    if (tok && LATIN.test(tok) && CONFUSABLE.test(tok)) out.push(tok)
  }
  return out
}

export function kindInfo(kind) {
  if (KINDS[kind]) return KINDS[kind]
  if (kind >= 30000 && kind < 40000) return { label: `Addressable list (kind ${kind}) — replaces`, risk: 'critical' }
  if (kind >= 10000 && kind < 20000) return { label: `Replaceable event (kind ${kind})`, risk: 'elevated' }
  return { label: `kind ${kind}`, risk: 'elevated' }   // unknown → conservative
}

export function scanContent(s = '') {
  const warnings = []
  const hidden = (s.match(HIDDEN_G) || []).length
  if (hidden) warnings.push(`${hidden} hidden / bidi control character(s) in content`)
  const confusables = confusableTokens(s)
  if (confusables.length) warnings.push(
    `${confusables.length} word(s) mix Latin with look-alike letters (possible homoglyph spoof): ${confusables.slice(0, 3).map(t => `"${t}"`).join(', ')}`)
  if (s.length && s !== s.trim()) warnings.push('leading or trailing whitespace in content')
  return warnings
}

// Inspect a full unsigned event (pubkey, created_at, kind, tags, content).
export function inspect(unsigned) {
  const ki = kindInfo(unsigned.kind)
  const warnings = scanContent(unsigned.content || '')
  if (ki.risk === 'critical') warnings.unshift(`${ki.label} — high-impact, verify carefully`)

  const tags = unsigned.tags || []
  const has = k => tags.some(t => t[0] === k)
  const notableTags = []
  if (has('p')) notableTags.push('mentions/notifies accounts (p)')
  if (has('e')) notableTags.push('references events (e)')
  if (has('q')) notableTags.push('quotes an event (q)')

  // Tag values carry URLs, relays, and identifiers — spoof-scan them too. A
  // hidden or look-alike character in a tag is as dangerous as one in content.
  for (const t of tags) {
    for (const v of t.slice(1)) {
      if (typeof v !== 'string') continue
      if (HIDDEN.test(v)) warnings.push(`hidden / control character in a "${t[0]}" tag value`)
      const conf = confusableTokens(v)
      if (conf.length) warnings.push(`look-alike character in a "${t[0]}" tag value (possible spoof): "${conf[0]}"`)
    }
  }

  return {
    kind: unsigned.kind,
    kindLabel: ki.label,
    risk: ki.risk,                       // 'low' | 'elevated' | 'critical'
    contentLength: (unsigned.content || '').length,
    tags,
    notableTags,
    warnings,
  }
}
