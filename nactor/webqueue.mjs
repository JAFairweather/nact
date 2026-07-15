// Web-queue approval adapter for Nact — the app IS the approval channel.
//
// Instead of Telegram or a nostr DM, proposals land in an in-memory queue that
// the control-plane app reads over the NIP-98-gated API, and are enacted by a
// POST from the app. Only a configured Director (the NIP-98 identity) may enact —
// `isDirector(pubkey)` is checked against the live Director set, so quorum/co-
// Directors added in config authorize without a restart.

export function webQueueApproval({ isDirector } = {}) {
  const pending = new Map()   // id → { id, identity, npub, draft, context, fingerprint, report, created }
  const history = []          // most-recent-first, capped
  const authorized = typeof isDirector === 'function' ? isDirector : () => false

  return {
    // Nact calls this on propose(): stash the full render for the app to show.
    async send(p) {
      pending.set(p.id, { ...p, created: Date.now() })
      return true
    },
    // The app POSTs { id, verb }; the API attaches the authenticated Director.
    async parseDecision(raw) { return raw },
    isApprover(a) { return authorized(a) },
    async ack({ id, result }) {
      const p = pending.get(id)
      pending.delete(id)                       // drain the queue on any decision
      history.unshift({
        id,
        identity: p?.identity,
        kindLabel: p?.report?.kindLabel,
        fingerprint: p?.fingerprint,
        outcome: result.posted ? 'enacted' : result.rejected ? 'rejected' : 'failed',
        detail: result.posted ? `${result.relays} relays` : result.error || '',
        when: Date.now(),
      })
      if (history.length > 100) history.length = 100
    },

    // Read side for the API.
    listPending() {
      return [...pending.values()].map(p => ({
        id: p.id, identity: p.identity, npub: p.npub,
        draft: p.draft, context: p.context,
        fingerprint: p.fingerprint, report: p.report, created: p.created,
      }))
    },
    listHistory() { return history },
  }
}
