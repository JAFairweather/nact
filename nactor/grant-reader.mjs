// grant-reader — Nactor reads its credential-scopes from the relays.
//
// The DELIVERY half of the credential migration (docs/migration-status-2026-07.md).
// Credentials are issued from Nvoy as NIP-DA scopes: the token rides as the
// scope's data, gift-wrapped and granted to Nactor's npub. Here Nactor
// dereferences those grants WITH ITS OWN NSEC and loads the values into the
// in-memory CREDS store — on boot and on a timer.
//
// Durable by construction: a restart just re-reads from the relays; nothing is
// cached on disk. Revocation is a scope-key rotation on the Director's side —
// fetchScope then returns 'stale', and the credential is dropped here on the
// next sweep. Same guarantee as any NIP-DA data: rotate the key → cut off.
//
// Convention (must match how Nvoy issues): a credential-scope's scope_name is
// `credential:<name>`, and its decrypted payload carries the value under
// `.value` (or `.secret`). Only these scopes are consumed; anything else granted
// to Nactor is ignored here.

import { receiveGrants, latestGrants, fetchScope } from './lib/nipxx.mjs'
import { LiveRelay } from './lib/liverelay.mjs'

export const CREDENTIAL_PREFIX = 'credential:'

// Sweep once. Pass EITHER a ready `relay` (any {query,publish,close}) — used by
// the test — OR `relayUrls` to build a LiveRelay. `creds` is the live CREDS Map.
// We only ever mutate entries WE set (source:'grant'), so a same-named
// bootstrap-env credential is never dropped by a transient read failure.
export async function syncCredentialGrants({ relay, relayUrls, nactorSk, creds, log = () => {} }) {
  const own = relay || new LiveRelay(relayUrls)
  const owned = !relay
  const summary = { loaded: [], dropped: [], stale: [], errors: [] }
  try {
    const grants = latestGrants(await receiveGrants(own, nactorSk))
      .filter(g => (g.scopeName || '').startsWith(CREDENTIAL_PREFIX))
    for (const g of grants) {
      const name = g.scopeName.slice(CREDENTIAL_PREFIX.length)
      if (!name) { summary.errors.push('empty credential name'); continue }
      try {
        const s = await fetchScope(own, g)
        if (s.status === 'ok') {
          const value = s.data?.value ?? s.data?.secret ?? null
          if (value == null) { summary.errors.push(`${name}: scope carried no value`); continue }
          creds.set(name, {
            type: 'secret', target: CREDENTIAL_PREFIX + name, value,
            source: 'grant', importedAt: Date.now(), generation: s.generation,
          })
          summary.loaded.push(name)
        } else {
          // 'stale' (rotated past this grant) or 'missing' → revoked. Only ever
          // drop a credential WE loaded from a grant; never a bootstrap-env one.
          const cur = creds.get(name)
          if (cur && cur.source === 'grant') { creds.delete(name); summary.dropped.push(name) }
          summary.stale.push(name)
        }
      } catch (e) { summary.errors.push(`${name}: ${e?.message || e}`) }
    }
  } finally {
    if (owned) try { own.close() } catch {}
  }
  if (summary.loaded.length || summary.dropped.length || summary.errors.length) {
    log(`  credential-grants: loaded [${summary.loaded.join(', ') || '—'}]`
      + (summary.dropped.length ? ` · dropped [${summary.dropped.join(', ')}]` : '')
      + (summary.errors.length ? ` · errors: ${summary.errors.join('; ')}` : ''))
  }
  return summary
}

// Start the boot sweep + a periodic re-sweep. Returns a stop() handle.
export function startGrantReader({ relayUrls, nactorSk, creds, intervalMs = 5 * 60 * 1000, log = () => {} }) {
  if (!nactorSk || !relayUrls?.length) { log('  credential-grants: reader disabled (no nactor key / relays)'); return { stop() {} } }
  const sweep = () => syncCredentialGrants({ relayUrls, nactorSk, creds, log }).catch(e => log(`  credential-grants: sweep error ${e?.message || e}`))
  sweep()                                   // boot read
  const t = setInterval(sweep, intervalMs)  // periodic re-read (durability + revocation pickup)
  if (t.unref) t.unref()
  return { stop() { clearInterval(t) } }
}
