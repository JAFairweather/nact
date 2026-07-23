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
// The binding is EXCLUSIVE precisely because the director path exists only when
// the key is off-box. An identity is one or the other, never both — which is the
// dichotomy nact#26 kills (Luke was on both at once). See nave.pub AD-10.

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

// Bind an identity to exactly ONE approval channel: ensure it is in `channelId`'s
// covers and in NO other approval channel's. Comms channels are never touched —
// ownership there comes from the credential grant, not this toggle. Mutates
// covers in place (matching the board's existing style) and returns `channels`.
export function bindToPath(channels, identityKey, channelId) {
  for (const c of channels || []) {
    if (!isApproval(c)) continue
    c.covers = c.covers || []
    const at = c.covers.indexOf(identityKey)
    if (c.id === channelId) { if (at < 0) c.covers.push(identityKey) }
    else if (at >= 0) c.covers.splice(at, 1)
  }
  return channels
}

// Remove an identity from an approval channel, leaving it with NO path.
export function unbind(channels, identityKey, channelId) {
  const c = (channels || []).find((x) => x.id === channelId)
  if (c && Array.isArray(c.covers)) {
    const at = c.covers.indexOf(identityKey)
    if (at >= 0) c.covers.splice(at, 1)
  }
  return channels
}

// The board's cell click: toggle an identity in an approval column. Already
// bound there → unbind (no path). Otherwise → move its binding here, exclusively.
// Returns { action:'bound'|'unbound', path } for the caller to reflect.
export function toggleBinding(channels, identityKey, channelId) {
  const current = approvalBindingOf(channels, identityKey)
  if (current && current.id === channelId) {
    unbind(channels, identityKey, channelId)
    return { action: 'unbound', path: null }
  }
  bindToPath(channels, identityKey, channelId)
  const c = (channels || []).find((x) => x.id === channelId)
  return { action: 'bound', path: c ? approvalPathOf(c) : null }
}

// An Ngage channel needs no on-box secret: its "approver" is the Director's npub
// and delivery is a grant encrypted to it. This is what lets the Add-channel
// form skip the bot-token/nsec field for the director path.
export const needsSecret = (kind) => head({ kind }) !== 'Ngage'
