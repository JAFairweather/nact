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
    // `latestGrants` dedups per SCOPE (scopeId), so two grants that share a
    // credential NAME but live in different scopes — e.g. a value re-issued as a
    // fresh delegation to correct a mistyped token — both survive. Process them
    // oldest→newest by issuedAt so the NEWEST grant is the last `creds.set` and
    // wins: a corrected re-issue supersedes the stale one with no manual
    // revocation. (Ties keep prior order — harmless; identical names, one value.)
    const grants = latestGrants(await receiveGrants(own, nactorSk))
      .filter(g => (g.scopeName || '').startsWith(CREDENTIAL_PREFIX))
      .sort((a, b) => (a.issuedAt || 0) - (b.issuedAt || 0))
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

// ---------------------------------------------------------------------------
// A1/A2 — grant-derived entitlements (credential sovereignty).
//
// The step beyond "Nactor reads ITS OWN grants": read EACH on-box identity's
// grants with THAT identity's key, so the broker can gate a call on whether a
// Director-signed grant actually names the caller for the requested credential.
// This is NOT a box-local ACL — the authority is the grant itself; the box only
// verifies (decrypts) it. It's how "any activated identity may use any
// credential" (blanket trust) becomes "an identity may use exactly the
// credentials granted to it." `entitlements` is a live Map<pubHex, Set<name>>.
//
// A revoked grant (scope-key rotated past this identity) fetches 'stale' and is
// simply not counted — revocation flows through with no extra machinery.
export async function syncIdentityEntitlements({ relay, relayUrls, identities, entitlements, log = () => {} }) {
  const own = relay || new LiveRelay(relayUrls)
  const owned = !relay
  const summary = {}
  try {
    for (const id of identities) {
      const held = new Set()
      try {
        const grants = latestGrants(await receiveGrants(own, id.sk))
          .filter(g => (g.scopeName || '').startsWith(CREDENTIAL_PREFIX))
        for (const g of grants) {
          const name = g.scopeName.slice(CREDENTIAL_PREFIX.length)
          if (!name) continue
          try { const s = await fetchScope(own, g); if (s.status === 'ok') held.add(name) } catch {}
        }
      } catch { /* transient read failure: keep the PRIOR entitlement set below */ }
      // Only overwrite when we actually read something, so a transient relay
      // failure never silently strips an identity of its entitlements mid-run.
      if (held.size || !entitlements.has(id.pub)) entitlements.set(id.pub, held)
      summary[id.name] = [...(entitlements.get(id.pub) || [])]
    }
  } finally {
    if (owned) try { own.close() } catch {}
  }
  const line = Object.entries(summary).map(([n, cs]) => `${n}:[${cs.join(',') || '—'}]`).join(' ')
  if (line) log(`  entitlements: ${line}`)
  return summary
}

// Boot sweep + periodic re-sweep for the entitlement map. Returns stop().
export function startEntitlementReader({ relayUrls, identities, entitlements, intervalMs = 5 * 60 * 1000, log = () => {} }) {
  if (!identities?.length || !relayUrls?.length) { log('  entitlements: reader disabled (no identities / relays)'); return { stop() {} } }
  const sweep = () => syncIdentityEntitlements({ relayUrls, identities, entitlements, log })
    .catch(e => log(`  entitlements: sweep error ${e?.message || e}`))
  sweep()
  const t = setInterval(sweep, intervalMs)
  if (t.unref) t.unref()
  return { stop() { clearInterval(t) } }
}
