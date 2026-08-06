// actions.mjs — durable action grants, as AD-12 3a–3d rules them.
//
// Nact issues and lists these; Nvoy's Ledger mirrors them read-only (AD-12 ruling 10). Until now
// there was no object at all: Nvoy could issue a `da-cap` and nothing on the act side could list
// one, revoke one, or say what it permitted.
//
// WHY THIS READS RELAYS WITHOUT A KEY. A durable action grant is a PUBLIC 440 carrying `da-cap`
// (the enforceable claim) and `da-scope` (a salted hash of the subject, so the subject stays
// private). AD-12 ruling 4 requires that enforcement never need a key — "being unable to check is
// not permission" — so listing them must not need one either. A console that could only show the
// grants it happened to hold a key for would under-report authority, which is the failure this
// whole plane exists to end.
//
// THE FOUR RULINGS, ENCODED HERE RATHER THAN REMEMBERED:
//   3a  every instantiation queues — so a standing grant confers QUEUE ENTRY, never a signature.
//       There is deliberately no code path here that signs anything on a schedule.
//   3b  the tier ceiling is `low`, fixed at issuance, and is not a control.
//   3c  revoking kills proposals already queued under the grant, enumerated before signing.
//   3d  TTL and rate limit may only be TIGHTENED from the estate default, never widened.
//
// Pure and DOM-free so lib/actions.test.mjs can drive it, the same reason lib/routing.mjs is.

/** The closed `da-cap` enum (AD-12 ruling 4). A cap outside it is honest `unknown`, never guessed. */
export const CAPS = ['admit', 'admit+read', 'task', 'task+act', 'task-relay', 'mirror']

/**
 * Which family a cap belongs to, and therefore whose screen it belongs on.
 *
 * The task family is what THIS runtime enforces: an agent proposes, Nactor queues, a human taps.
 * The admission family is enforced by a slice's bridge and is shown here read-only — listing it is
 * how "an approval made in waggle is invisible on the act side" stops being true, but Nact must not
 * pretend it gates something it does not.
 */
export const CAP_FAMILY = {
  task: 'task', 'task+act': 'task', 'task-relay': 'task',
  admit: 'admission', 'admit+read': 'admission', mirror: 'admission',
}
export const capFamily = (cap) => CAP_FAMILY[cap] || 'unknown'

/** Who actually refuses when this cap is exceeded. Never "the console" — a console enforces nothing. */
export function enforcerOf(cap) {
  const f = capFamily(cap)
  if (f === 'task') return 'this runtime — the queue refuses an unapproved proposal'
  if (f === 'admission') return 'the slice that issued it — this plane lists it, and does not gate it'
  return 'unknown — an unrecognised capability is not enforced by anything here'
}

/** Capability in English. Unknown caps render their raw value rather than a reassuring guess. */
export const CAP_LABEL = {
  task: 'Take tasks from you',
  'task+act': 'Take tasks, and act on them',
  'task-relay': 'Carry tasks for others',
  admit: 'Post into the channel',
  'admit+read': 'Post into the channel, and read it',
  mirror: 'Be mirrored into the channel',
}
export const capLabel = (cap) => CAP_LABEL[cap] || `Unrecognised capability: ${cap}`

/**
 * AD-12 3b: the ceiling is `low`, fixed at issuance, and it is NOT a control.
 *
 * `elevated` and `critical` already require a full render or on-device signing, which IS a fresh tap
 * by definition — so a higher standing ceiling would be unreachable in practice and would exist only
 * to mislead whoever reads the grant. Returned with its reason so a UI cannot render the number
 * without the sentence.
 */
export const STANDING_TIER_CAP = 'low'
export const tierCap = () => ({
  tier: STANDING_TIER_CAP,
  why: 'Fixed at issuance and not adjustable. Elevated and critical actions require a full render or '
    + 'on-device signing, which is a fresh approval by definition — so a standing grant can never '
    + 'reach them, and offering the choice would only mislead.',
})

/**
 * AD-12 3d: estate defaults, tightenable only.
 *
 * A forgotten field must therefore fail SAFE. This is the deliberate inverse of waggle's
 * `grantors`-defaults-to-`approvers` collapse, where an absent field silently widened authority.
 */
export const ESTATE_DEFAULTS = Object.freeze({
  ttlSeconds: 24 * 3600,     // one day
  ratePerHour: 6,
})

/**
 * Narrow a requested envelope against the estate default. Widening is REFUSED, not clamped
 * silently — a request to widen is a misunderstanding worth surfacing, and a silent clamp would
 * teach the issuer that they got what they asked for.
 *
 * @returns { ok: true, envelope } | { ok: false, reason }
 */
export function narrowOnly(requested = {}, defaults = ESTATE_DEFAULTS) {
  const out = { ttlSeconds: defaults.ttlSeconds, ratePerHour: defaults.ratePerHour }
  for (const [field, max] of [['ttlSeconds', defaults.ttlSeconds], ['ratePerHour', defaults.ratePerHour]]) {
    const v = requested[field]
    if (v === undefined || v === null) continue          // absent → the default, which is the ceiling
    if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
      return { ok: false, reason: `${field} must be a positive number; got ${JSON.stringify(v)}` }
    }
    if (v > max) {
      return { ok: false, reason: `${field} may only be tightened: ${v} exceeds the estate default of ${max}` }
    }
    out[field] = v
  }
  return { ok: true, envelope: out }
}

/** A grant is refused at issuance if the envelope is incomplete (AD-12 ruling 3). */
export function validateIssue({ cap, grantee, scopeHash, path, requested } = {}) {
  if (!CAPS.includes(cap)) return { ok: false, reason: `cap must be one of the closed enum: ${CAPS.join(' · ')}` }
  if (capFamily(cap) !== 'task') {
    return { ok: false, reason: `this plane issues the task family only. ${cap} is enforced by a slice, `
      + 'and issuing it here would claim authority this runtime does not have.' }
  }
  if (!/^[0-9a-f]{64}$/.test(String(grantee || ''))) return { ok: false, reason: 'grantee must be a 64-hex pubkey — the join key (AD-12 ruling 1)' }
  if (!scopeHash) return { ok: false, reason: 'a da-scope is required: a grant over nothing is not narrow' }
  if (path !== 'box' && path !== 'director') return { ok: false, reason: 'exactly one approval path must be bound (AD-10)' }
  const env = narrowOnly(requested)
  if (!env.ok) return env
  return { ok: true, envelope: { ...env.envelope, cap, grantee, scopeHash, path, tier: STANDING_TIER_CAP } }
}

const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null }

/**
 * Rows from public 440 events. Malformed events are DROPPED with a count the caller must report —
 * never silently, because a dropped grant is authority the reader cannot see.
 *
 * @param events   public 440s, as read from relays
 * @param revoked  Set of 440 event ids that a 441 has revoked
 */
export function actionRows(events = [], { revoked = new Set(), now = 0 } = {}) {
  const rows = []
  let dropped = 0
  for (const ev of events) {
    const tags = Array.isArray(ev?.tags) ? ev.tags : null
    if (!tags || typeof ev.id !== 'string') { dropped++; continue }
    const tag = (k) => tags.find(t => Array.isArray(t) && t[0] === k)
    const cap = tag('da-cap')?.[1]
    const grantee = tag('p')?.[1]
    if (!cap || !/^[0-9a-f]{64}$/.test(String(grantee || ''))) { dropped++; continue }
    const expiresAt = num(tag('expiration')?.[1])
    rows.push({
      id: ev.id,
      cap,
      family: capFamily(cap),
      label: capLabel(cap),
      enforcer: enforcerOf(cap),
      grantee,
      scopeHash: tag('da-scope')?.[1] || null,
      issuedAt: num(ev.created_at),
      expiresAt,
      // `expired` is a distinct state from `revoked`: one lapsed, the other was cut. Collapsing them
      // would hide whether a human ever acted.
      status: revoked.has(ev.id) ? 'revoked' : (expiresAt !== null && now > 0 && expiresAt <= now ? 'expired' : 'active'),
      ratePerHour: num(tag('rate')?.[1]),
      tier: STANDING_TIER_CAP,
    })
  }
  rows.sort((a, b) => (b.issuedAt || 0) - (a.issuedAt || 0))
  return { rows, dropped }
}

/**
 * AD-12 3c: what revoking this grant also kills.
 *
 * A queued proposal is authority still in flight. Leaving it live would mean the revoke button does
 * not mean what it says — the same defect as this console's rotate button, which claimed a
 * revocation it never performed. The caller MUST show `queued` before signing.
 */
export function revokeImpact(row, queue = []) {
  const queued = (Array.isArray(queue) ? queue : []).filter(q => q && q.granteePub === row?.grantee)
  return {
    grantLabel: row ? `${row.label} (${row.cap})` : 'this grant',
    queued,
    // Stated as a limit, not a promise. A 441 revokes the grant; it does not reach into a slice's
    // own roster, and it does not rotate any key.
    limits: capFamily(row?.cap) === 'admission'
      ? 'This publishes a 441 against the grant. The slice that enforces it decides when it notices; '
        + 'this plane cannot confirm the slice acted.'
      : 'This publishes a 441 against the grant and drops the queued proposals above. It does not '
        + 'rotate any key, and it does not remove this agent from any app whose roster this console never read.',
  }
}
