// tiers.mjs — the per-risk CEREMONY spec (hardening P5, nact#11). One source of
// truth for "what does approving a low / elevated / critical action require."
//
// The tier ASSIGNMENT (which kind is which risk) lives in src/inspect.mjs
// (kindInfo) — the runtime's authority. This module answers the next question,
// which used to be scattered across app.html's decide(), the tiers tab's
// requirement strings, and the Telegram badge: given a risk, what ceremony is
// owed? The runtime, the console, and the /sign Mini-App all read it here so the
// bar is identical everywhere.
//
// Pure and isomorphic — no DOM, no node built-ins; imported by both the browser
// surfaces (via the importmap) and the node runtime.

// low      — a routine, low-blast-radius event (note, reaction, repost). One tap.
// elevated — worth a careful look (DM, zap, gift wrap, replaceable). One tap, but
//            only after the full tags/content are shown (no hidden surprises).
// critical — replaces or destroys standing state (profile, follows, relays,
//            deletion). NEVER one-tap: a deliberate confirm, and the surface
//            routes it to sign-on-device (the key-holder's own signer), never a
//            box-custodial tap. This is AD-10 at the tier level.
const CEREMONY = {
  low: { oneTap: true, needsConfirm: false, needsDevice: false, requirement: 'one-tap approve' },
  elevated: { oneTap: true, needsConfirm: false, needsDevice: false, requirement: 'approve after full tags shown' },
  critical: { oneTap: false, needsConfirm: true, needsDevice: true, requirement: 'sign-on-device' },
}

export const TIERS = ['low', 'elevated', 'critical']

// The ceremony owed for a risk tier. Unknown/missing → treat as elevated
// (conservative: never silently downgrade an unrecognized tier to one-tap-low).
export function ceremonyFor(risk) {
  return CEREMONY[risk] || CEREMONY.elevated
}

// Does enacting this tier require an explicit confirm (never a single tap)? The
// runtime gate and the console both ask exactly this.
export const needsConfirm = (risk) => ceremonyFor(risk).needsConfirm

// Should the surface route this tier to the key-holder's own signer rather than
// offer a box-custodial approve? (Advisory to the UI; the runtime's hard gate is
// needsConfirm. See docs/threat-model.md P5.)
export const needsDevice = (risk) => ceremonyFor(risk).needsDevice

// Cycle a tier for the console's click-to-change tier button (low→elevated→
// critical→low), keeping the one place that order is defined.
export function nextTier(risk) {
  const i = TIERS.indexOf(risk)
  return TIERS[(i < 0 ? 0 : i + 1) % TIERS.length]
}
