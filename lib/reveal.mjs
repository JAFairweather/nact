// reveal.mjs — the faithful WYSIWYS render (hardening P2 → shared for P5). Turns
// a proposed event's text into HTML that HIDES NOTHING: zero-width / bidi /
// control characters become visible ⟨U+XXXX⟩ chips, and non-Latin look-alikes
// (Cyrillic/Greek confusables) are boxed as possible spoofs. What the approver
// sees is exactly what will be signed.
//
// Extracted so the console (app.html) and the /sign Mini-App render byte-for-byte
// identically — a signing surface must never show the human a softer picture than
// the one the review console showed. The character ranges are pinned to the
// canonical scanner in src/inspect.mjs by reveal.test.mjs, so they can't drift.
//
// Pure and isomorphic (imported in the browser via the importmap). Caller must
// supply the matching CSS (.lint.hidden / .lint.confuse).

export const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))

// Hidden/formatting/control characters — same set inspect.mjs flags (HIDDEN_G).
export const REVEAL_HIDDEN = /[­​-‏‪-‮⁠-⁯﻿]/g
// Cyrillic + full Greek blocks — the confusable ranges inspect.mjs flags (CONFUSABLE_G).
export const REVEAL_CONFUSABLE = /[Ѐ-ӿͰ-Ͽ]/g

export const cpLabel = (ch) => 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')

export function revealContent(s) {
  return esc(s)
    .replace(REVEAL_HIDDEN, (ch) => `<span class="lint hidden" title="${cpLabel(ch)} hidden / control character">⟨${cpLabel(ch)}⟩</span>`)
    .replace(REVEAL_CONFUSABLE, (ch) => `<span class="lint confuse" title="${cpLabel(ch)} non-Latin look-alike — possible spoof">${ch}</span>`)
}
