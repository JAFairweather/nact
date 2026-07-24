// routing.mjs — the approval-path model (AD-10), the one tested spec the
// control plane's Routing board renders. Pure; no DOM, no state.
//
// Every identity binds to exactly ONE approval path, and which path is forced by
// WHO signs the published event — not by preference:
//
//   • box path      — the agent's key lives on the box, so Nactor can sign the
//                     moment approval arrives. Transports: Telegram, NIP-59 DM,
//                     the Web queue. This is the shared gate.
//   • director path — only the Director's key can sign, and it is NOT on the box,
//                     so approval must happen where that key is: the draft is
//                     gift-wrapped to his npub as a `draft:` grant → Ngage → his
//                     own signature. "Only the Director can approve" is enforced
//                     by encryption, not policy — nobody else can read the draft.
//
// The PATH is exclusive — and it is DERIVED, not chosen (#42): key custody
// decides. A keyless `signer:'director'` identity can only ride Ngage; a keyed
// identity's approvals can only ride the box gate. Within the box gate the
// channels are TRANSPORTS of one shared gate (Telegram, NIP-59, Web queue —
// threat-model.md), so an identity may be reachable over several at once;
// only across paths is membership exclusive, and that by construction.
// This is the dichotomy nact#26 kills (Luke was on both at once). See AD-10.

// A channel's kind head — mirrors app.html's chanShort (kind.split(' ')[0]).
const head = (channel) => String(channel?.kind || '').split(' ')[0]

// Ngage is the director-path transport; every other approval channel is box-path.
export const isDirectorPath = (channel) => head(channel) === 'Ngage'
export const approvalPathOf = (channel) => (isDirectorPath(channel) ? 'director' : 'box')

const isApproval = (c) => (c?.purpose || 'approval') === 'approval'

// The single approval channel an identity is bound to (its path), or null. If a
// stale config ever bound an identity to more than one, the first wins — the
// board then heals it on the next toggle.
export function approvalBindingOf(channels, identityKey) {
  return (channels || []).find((c) => isApproval(c) && (c.covers || []).includes(identityKey)) || null
}

// The path an identity's key custody FORCES: keyless (the Director signs) →
// director; any keyed signer (custodial / bunker) → box. This, not a click,
// is what decides where approval happens (#42, AD-10).
export const pathForSigner = (signer) => (signer === 'director' ? 'director' : 'box')

// Remove an identity from an approval channel.
export function unbind(channels, identityKey, channelId) {
  const c = (channels || []).find((x) => x.id === channelId)
  if (c && Array.isArray(c.covers)) {
    const at = c.covers.indexOf(identityKey)
    if (at >= 0) c.covers.splice(at, 1)
  }
  return channels
}

// The board's cell click (#42): toggle an identity's membership in ONE
// approval channel — transports within its custody path are independent
// checkboxes, so wiring Telegram never unwires the Web queue. A click on a
// channel of the WRONG path is refused with the reason (custody decides, not
// preference). Any stale cross-path membership is healed on the way through.
// Returns { action:'wired'|'unwired'|'refused'|'noop', path, reason? }.
export function toggleTransport(channels, identityKey, channelId, signerType) {
  const ch = (channels || []).find((x) => x.id === channelId)
  if (!ch || !isApproval(ch)) return { action: 'noop', path: null }
  const need = pathForSigner(signerType)
  const chPath = approvalPathOf(ch)
  if (chPath !== need) {
    return {
      action: 'refused', path: chPath,
      reason: need === 'box'
        ? 'key custody decides the path: this identity signs on the box, so its approvals ride the 🛡 box gate — not Ngage'
        : "key custody decides the path: only the Director's key can sign for this identity, so its drafts ride ✋ Ngage — not the box gate",
    }
  }
  for (const c of channels) {                          // heal cross-path pollution in passing
    if (!isApproval(c) || approvalPathOf(c) === need || !Array.isArray(c.covers)) continue
    const at = c.covers.indexOf(identityKey)
    if (at >= 0) c.covers.splice(at, 1)
  }
  ch.covers = ch.covers || []
  const at = ch.covers.indexOf(identityKey)
  if (at >= 0) { ch.covers.splice(at, 1); return { action: 'unwired', path: need } }
  ch.covers.push(identityKey)
  return { action: 'wired', path: need }
}

// Strip every approval-channel membership that contradicts an identity's
// custody-derived path — the healer for the pre-#42 backfill pollution
// (box identities stuffed into Ngage covers, and vice versa). `signerOf`
// maps identityKey → its signer type. Returns true when anything changed.
export function healCovers(channels, signerOf) {
  let changed = false
  for (const c of channels || []) {
    if (!isApproval(c) || !Array.isArray(c.covers)) continue
    const keep = c.covers.filter((k) => pathForSigner(signerOf(k)) === approvalPathOf(c))
    if (keep.length !== c.covers.length) { c.covers = keep; changed = true }
  }
  return changed
}

// An Ngage channel needs no on-box secret: its "approver" is the Director's npub
// and delivery is a grant encrypted to it. This is what lets the Add-channel
// form skip the bot-token/nsec field for the director path.
export const needsSecret = (kind) => head({ kind }) !== 'Ngage'
