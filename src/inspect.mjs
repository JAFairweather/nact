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
const HIDDEN = /[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g

export function kindInfo(kind) {
  if (KINDS[kind]) return KINDS[kind]
  if (kind >= 30000 && kind < 40000) return { label: `Addressable list (kind ${kind}) — replaces`, risk: 'critical' }
  if (kind >= 10000 && kind < 20000) return { label: `Replaceable event (kind ${kind})`, risk: 'elevated' }
  return { label: `kind ${kind}`, risk: 'elevated' }   // unknown → conservative
}

export function scanContent(s = '') {
  const warnings = []
  const hidden = (s.match(HIDDEN) || []).length
  if (hidden) warnings.push(`${hidden} hidden / bidi control character(s) in content`)
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
