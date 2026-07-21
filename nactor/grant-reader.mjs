// grant-reader — Nactor reads its credential-scopes from the relays.
//
// The DELIVERY half of the credential migration (docs/migration-status-2026-07.md).
// Credentials are issued from Nvoy as NIP-DA scopes: the token rides as the
// scope's data, gift-wrapped and granted to Nactor's npub. Here Nactor
// dereferences those grants WITH ITS OWN NSEC and loads the values into the
// in-memory CREDS store — on boot and on a timer.
//
// TWO TRANSPORTS since M7 (nact#6): the direct-relay reader below (V1, the
// default and the fallback) and an MCP twin (syncCredentialGrantsMcp) that
// reads the same grants through the nvoy-mcp service — which then custodies
// Nactor's nsec — via NACT_GRANT_TRANSPORT=mcp. Same CREDS semantics either
// way. The per-identity entitlement/A2 sweeps further down stay DIRECT-RELAY
// in both modes (Director-approved M7 scope cut: moving them means moving the
// role keys out of this runtime, which is v2 enclave work).
//
// Durable by construction: a restart just re-reads from the relays; nothing is
// cached on disk. Revocation is a scope-key rotation on the Director's side —
// fetchScope then returns 'stale', and the credential is dropped here on the
// next sweep. Same guarantee as any NIP-DA data: rotate the key → cut off.
//
// Convention (must match how Nvoy issues): a credential-scope's scope_name is
// `credential:<name>`, and its decrypted payload carries the value under
// `.value` — the CANONICAL issuance key, the one the Nvoy console writes and
// the warm.contact reader (their #6) also accepts. Being the shared gate, this
// reader is tolerant on read (`.secret`/`.key`/`.api_key`/bare-string are
// honored) but issuers should write `.value`. Scope names are NAMESPACED
// STRINGS (AD-8:
// profile:* · credential:* · data:* · capability:*), not enums — only the
// credential:* namespace is consumed here; anything else granted to Nactor
// (a data:* scope, a capability:* management grant) is ignored, not an error.
//
// Trust: a grant is honored only if its PUBLISHER is in `allowedPublishers`
// (the Director set) — otherwise any pubkey could gift-wrap a spoofed
// credential:* scope to Nactor's npub and, being newest, shadow the real
// value. Callers that pass no set (offline tools, tests that build their own
// Director) get no filtering — production wiring passes directorPubs.
//
// Observability: every state TRANSITION (a credential loaded from a grant,
// updated, dropped on revocation; an entitlement gained or lost) is emitted
// through `onEvent` so the runtime audit (AD-1) can record what this box
// observed. Steady-state re-reads emit nothing — the audit stays signal.

import { nip19 } from 'nostr-tools'
import { receiveGrants, latestGrants, fetchScope } from './lib/nipxx.mjs'
import { LiveRelay } from './lib/liverelay.mjs'
import { McpGrantClient, McpToolError } from './mcp-grant-client.mjs'

export const CREDENTIAL_PREFIX = 'credential:'

// Names of credentials still riding the bootstrap-env fallback (the tier the
// migration drains): source 'bootstrap-env' or 'bootstrap-env-parts'. A
// director-put (V1 HTTP fallback) or grant-sourced credential is not env.
export const envFallbackNames = creds => [...creds.entries()]
  .filter(([, c]) => String(c.source || '').startsWith('bootstrap-env'))
  .map(([name]) => name).sort()

// Normalize allowedPublishers (Set | array | function → either | null) into a
// Set for this sweep, or null for "no filtering".
const publisherSet = (allowed) => {
  const v = typeof allowed === 'function' ? allowed() : allowed
  if (!v) return null
  return v instanceof Set ? v : new Set(v)
}

// Sweep once. Pass EITHER a ready `relay` (any {query,publish,close}) — used by
// the test — OR `relayUrls` to build a LiveRelay. `creds` is the live CREDS Map.
// We only ever mutate entries WE set (source:'grant'), so a same-named
// bootstrap-env credential is never dropped by a transient read failure.
export async function syncCredentialGrants({ relay, relayUrls, nactorSk, creds, allowedPublishers, log = () => {}, onEvent = () => {} }) {
  const own = relay || new LiveRelay(relayUrls)
  const owned = !relay
  const summary = { loaded: [], dropped: [], stale: [], errors: [], untrusted: 0, envFallback: [] }
  try {
    const trusted = publisherSet(allowedPublishers)
    // `latestGrants` dedups per SCOPE (scopeId), so two grants that share a
    // credential NAME but live in different scopes — e.g. a value re-issued as a
    // fresh delegation to correct a mistyped token — both survive. Process them
    // oldest→newest by issuedAt so the NEWEST grant is the last `creds.set` and
    // wins: a corrected re-issue supersedes the stale one with no manual
    // revocation. (Ties keep prior order — harmless; identical names, one value.)
    let grants = latestGrants(await receiveGrants(own, nactorSk))
      .filter(g => (g.scopeName || '').startsWith(CREDENTIAL_PREFIX))
    if (trusted) {
      const before = grants.length
      grants = grants.filter(g => trusted.has(g.publisher))
      summary.untrusted = before - grants.length
    }
    grants.sort((a, b) => (a.issuedAt || 0) - (b.issuedAt || 0))
    for (const g of grants) {
      const name = g.scopeName.slice(CREDENTIAL_PREFIX.length)
      if (!name) { summary.errors.push('empty credential name'); continue }
      try {
        const s = await fetchScope(own, g)
        if (s.status === 'ok') {
          const value = typeof s.data === 'string' ? s.data
            : s.data?.value ?? s.data?.secret ?? s.data?.key ?? s.data?.api_key ?? null
          if (value == null) { summary.errors.push(`${name}: scope carried no value`); continue }
          const prior = creds.get(name)
          // A2 precedence: an OWNER-sourced value (the identity's own grant,
          // lent to this runtime) outranks the Nactor-addressed copy — never
          // clobber it here. If the owner grant is revoked, its entry drops and
          // this path restores supply on the next sweep (graceful fallback).
          if (prior && prior.source === 'grant-owner') { summary.loaded.push(name); continue }
          const takeover = !prior || prior.source !== 'grant'   // new, or env/put → grant
          const changed = !takeover && (prior.value !== value || prior.generation !== s.generation)
          creds.set(name, {
            type: 'secret', target: CREDENTIAL_PREFIX + name, value,
            source: 'grant', importedAt: Date.now(), generation: s.generation,
          })
          summary.loaded.push(name)
          if (takeover) onEvent({ t: 'grant-load', credential: name, generation: s.generation, when: Date.now() })
          else if (changed) onEvent({ t: 'grant-update', credential: name, generation: s.generation, when: Date.now() })
        } else {
          // 'stale' (rotated past this grant) or 'missing' → revoked. Only ever
          // drop a credential WE loaded from a grant; never a bootstrap-env one.
          const cur = creds.get(name)
          if (cur && cur.source === 'grant') {
            creds.delete(name)
            summary.dropped.push(name)
            onEvent({ t: 'grant-drop', credential: name, when: Date.now() })
          }
          summary.stale.push(name)
        }
      } catch (e) { summary.errors.push(`${name}: ${e?.message || e}`) }
    }
  } finally {
    if (owned) try { own.close() } catch {}
  }
  summary.envFallback = envFallbackNames(creds)
  if (summary.loaded.length || summary.dropped.length || summary.errors.length || summary.untrusted) {
    log(`  credential-grants: loaded [${summary.loaded.join(', ') || '—'}]`
      + (summary.dropped.length ? ` · dropped [${summary.dropped.join(', ')}]` : '')
      + (summary.untrusted ? ` · ignored ${summary.untrusted} grant(s) from non-Director publishers` : '')
      + (summary.errors.length ? ` · errors: ${summary.errors.join('; ')}` : ''))
  }
  return summary
}

// ---------------------------------------------------------------------------
// M7 — the MCP transport twin of syncCredentialGrants (nact#6).
//
// Same sweep, same CREDS semantics (source 'grant', takeover/update/drop
// events, owner-precedence, bootstrap/put isolation, env-fallback flag) — but
// the NIP-DA work happens in the nvoy-mcp service, which custodies Nactor's
// nsec as its NVOY_NSEC. This side holds NO key and speaks only the two
// conformance-pinned tools via McpGrantClient: list grants → filter
// credential:* → nvoy_scope_read each with max_age:0 (live, never the
// server's cache) → load values.
//
// Director-only trust survives the transport: nvoy_grants_list exposes each
// grant's `author_npub`, so the same allowedPublishers set (hex pubkeys)
// filters here — decode npub → hex and compare. A spoofed grant from a
// non-Director publisher is counted and ignored, exactly as on the relay
// path. (Defense in depth: the nvoy-mcp service reads grants wrapped to
// Nactor's key either way, so its key custody is a second boundary — but the
// publisher filter is what stops a *validly-addressed* spoof.)
//
// Known transport limits, deliberate and documented:
//   • nvoy_grants_list carries no issuedAt, so when TWO live scopes share a
//     credential NAME (a corrected re-issue left unrevoked), ordering is the
//     server's list order rather than oldest→newest — the Director's practice
//     of rotating the superseded scope makes this moot; a warning logs when
//     it happens.
//   • a grant the server reports 'expired' (terms) cannot be read through the
//     MCP surface (soft expiry, NIP-DA §4), so its credential drops — the
//     relay path ignores terms entirely. Stricter, and the server's contract.
//   • NVOY_SCOPE_UNAVAILABLE ('missing' with no revocation notice) is
//     ambiguous by the server's own definition (relay flake vs deletion), so
//     it is treated as a transient error: logged, never a drop. A real
//     revocation surfaces as NVOY_GRANT_REVOKED and drops.
const SEVERED = new Set(['NVOY_GRANT_REVOKED', 'NVOY_GRANT_EXPIRED', 'NVOY_GRANT_RELINQUISHED'])
const npubToHex = (npub) => {
  const s = String(npub || '').trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  try { const { type, data } = nip19.decode(s); return type === 'npub' ? data : null } catch { return null }
}

export async function syncCredentialGrantsMcp({ client, creds, allowedPublishers, log = () => {}, onEvent = () => {} }) {
  const summary = { loaded: [], dropped: [], stale: [], errors: [], untrusted: 0, envFallback: [] }
  const trusted = publisherSet(allowedPublishers)
  // A whole-list failure (service down, session refused twice) THROWS out of
  // here — the caller logs a sweep error and nothing is dropped, matching the
  // relay path's receiveGrants failure mode: transport trouble never revokes.
  let grants = (await client.listGrants())
    .filter(g => (g.scope_name || '').startsWith(CREDENTIAL_PREFIX))
  if (trusted) {
    const before = grants.length
    grants = grants.filter(g => { const hex = npubToHex(g.author_npub); return hex && trusted.has(hex) })
    summary.untrusted = before - grants.length
  }
  const seen = new Map()  // credential name → scope id, for the same-name warning
  // Names with at least one ACTIVE grant in THIS listing. A severed scope may
  // share its credential name with a live re-issue (the console's supersede
  // pattern); severance must never clobber the sibling the same sweep loads —
  // the 2026-07-21 incident: revoke-old + re-issue-new produced
  // loaded[mail-gmail] · dropped[mail-gmail] every sweep.
  const activeByName = new Map()   // name → Set of ACTIVE scope ids carrying it
  for (const g of grants.filter(g => !g.status || g.status === 'active')) {
    const n = (g.scope_name || '').slice(CREDENTIAL_PREFIX.length)
    if (!n) continue
    if (!activeByName.has(n)) activeByName.set(n, new Set())
    activeByName.get(n).add(g.d)
  }
  const hasLiveSibling = (name, exceptD) =>
    [...(activeByName.get(name) || [])].some(d => d !== exceptD)
  for (const g of grants) {
    const name = (g.scope_name || '').slice(CREDENTIAL_PREFIX.length)
    if (!name) { summary.errors.push('empty credential name'); continue }
    if (seen.has(name)) log(`  credential-grants: WARNING — two live scopes carry credential '${name}' (${seen.get(name)}, ${g.d}); no issuedAt on the MCP surface, last listed wins — rotate the superseded scope`)
    seen.set(name, g.d)
    // The server already knows a severed grant: revoked-detected /
    // relinquished / expired never dereference, so treat the status like a
    // failed fetch on the relay path — drop only what WE loaded from a grant.
    if (g.status && g.status !== 'active') {
      summary.stale.push(name)
      if (hasLiveSibling(name, g.d)) continue      // a live sibling carries this name
      const cur = creds.get(name)
      if (cur && cur.source === 'grant') {
        creds.delete(name)
        summary.dropped.push(name)
        onEvent({ t: 'grant-drop', credential: name, when: Date.now() })
      }
      continue
    }
    try {
      const s = await client.readScope(g.d, g.author_npub, { maxAge: 0 })
      const value = typeof s.data === 'string' ? s.data
        : s.data?.value ?? s.data?.secret ?? s.data?.key ?? s.data?.api_key ?? null
      if (value == null) { summary.errors.push(`${name}: scope carried no value`); continue }
      const prior = creds.get(name)
      // A2 precedence, same as the relay path: an OWNER-sourced value (the
      // identity's own grant) outranks the Nactor-addressed copy.
      if (prior && prior.source === 'grant-owner') { summary.loaded.push(name); continue }
      const takeover = !prior || prior.source !== 'grant'
      const changed = !takeover && (prior.value !== value || prior.generation !== s.v)
      creds.set(name, {
        type: 'secret', target: CREDENTIAL_PREFIX + name, value,
        source: 'grant', importedAt: Date.now(), generation: s.v,
      })
      summary.loaded.push(name)
      if (takeover) onEvent({ t: 'grant-load', credential: name, generation: s.v, when: Date.now() })
      else if (changed) onEvent({ t: 'grant-update', credential: name, generation: s.v, when: Date.now() })
    } catch (e) {
      if (e instanceof McpToolError && SEVERED.has(e.code)) {
        // Verified severance (rotation past the grant, terms expiry, or a
        // relinquishment): the credential is gone. Only drop what we loaded —
        // and never out from under a live same-name sibling in this listing.
        summary.stale.push(name)
        if (!hasLiveSibling(name, g.d)) {
          const cur = creds.get(name)
          if (cur && cur.source === 'grant') {
            creds.delete(name)
            summary.dropped.push(name)
            onEvent({ t: 'grant-drop', credential: name, when: Date.now() })
          }
        }
      } else {
        // NVOY_SCOPE_UNAVAILABLE, NVOY_NO_GRANT (list/read race), transport
        // blips: transient — keep whatever we hold (asymmetric by design).
        summary.errors.push(`${name}: ${e?.code || e?.message || e}`)
      }
    }
  }
  summary.envFallback = envFallbackNames(creds)
  if (summary.loaded.length || summary.dropped.length || summary.errors.length || summary.untrusted) {
    log(`  credential-grants: loaded [${summary.loaded.join(', ') || '—'}]`
      + (summary.dropped.length ? ` · dropped [${summary.dropped.join(', ')}]` : '')
      + (summary.untrusted ? ` · ignored ${summary.untrusted} grant(s) from non-Director publishers` : '')
      + (summary.errors.length ? ` · errors: ${summary.errors.join('; ')}` : ''))
  }
  return summary
}

// Start the boot sweep + a periodic re-sweep. Returns a stop() handle.
// The env-FALLBACK flag is logged here (boot + whenever the set changes): which
// credentials are still bootstrap-env-sourced — the honest measure of how much
// of the migration remains. Steady state logs nothing.
//
// M7 transport switch: `transport: 'mcp'` reads through the nvoy-mcp service
// (mcpUrl, or an injected mcpClient for tests) and needs NO nactor key — the
// nsec lives with nvoy-mcp. Default stays 'relay' (the direct NIP-DA reader,
// V1) until the box cutover proves the MCP path; the relay branch below is
// byte-for-byte the pre-M7 behavior.
export function startGrantReader({ relayUrls, nactorSk, creds, allowedPublishers, intervalMs = 5 * 60 * 1000, log = () => {}, onEvent = () => {}, transport = 'relay', mcpUrl, mcpClient }) {
  if (transport === 'mcp') {
    if (!mcpClient && !mcpUrl) {
      const env = envFallbackNames(creds || new Map())
      log(`  credential-grants: reader disabled (transport mcp, no NACT_MCP_URL)${env.length ? ` — ENV FALLBACK in force for [${env.join(', ')}]` : ''}`)
      return { stop() {} }
    }
    const client = mcpClient || new McpGrantClient({ url: mcpUrl })
    log(`  credential-grants: transport mcp → ${client.url || mcpUrl} (nvoy-mcp custodies the nactor key; this runtime reads with zero nostr knowledge)`)
    let lastFallback = null
    const sweep = () => syncCredentialGrantsMcp({ client, creds, allowedPublishers, log, onEvent })
      .then(s => {
        const key = s.envFallback.join(',')
        if (key === lastFallback) return
        lastFallback = key
        log(s.envFallback.length
          ? `  credential-grants: ENV FALLBACK in force for [${s.envFallback.join(', ')}] — bootstrap-env values in use until each is granted + retired (docs/migration-status-2026-07.md §5)`
          : '  credential-grants: env fallback clear — every credential is grant-sourced')
      })
      .catch(e => log(`  credential-grants: sweep error ${e?.message || e}`))
    sweep()                                   // boot read
    const t = setInterval(sweep, intervalMs)  // periodic re-read (durability + revocation pickup)
    if (t.unref) t.unref()
    return { stop() { clearInterval(t); client.close?.().catch?.(() => {}) } }
  }
  if (!nactorSk || !relayUrls?.length) {
    const env = envFallbackNames(creds || new Map())
    log(`  credential-grants: reader disabled (no nactor key / relays)${env.length ? ` — ENV FALLBACK in force for [${env.join(', ')}]` : ''}`)
    return { stop() {} }
  }
  let lastFallback = null
  const sweep = () => syncCredentialGrants({ relayUrls, nactorSk, creds, allowedPublishers, log, onEvent })
    .then(s => {
      const key = s.envFallback.join(',')
      if (key === lastFallback) return
      lastFallback = key
      log(s.envFallback.length
        ? `  credential-grants: ENV FALLBACK in force for [${s.envFallback.join(', ')}] — bootstrap-env values in use until each is granted + retired (docs/migration-status-2026-07.md §5)`
        : '  credential-grants: env fallback clear — every credential is grant-sourced')
    })
    .catch(e => log(`  credential-grants: sweep error ${e?.message || e}`))
  sweep()                                   // boot read
  const t = setInterval(sweep, intervalMs)  // periodic re-read (durability + revocation pickup)
  if (t.unref) t.unref()
  return { stop() { clearInterval(t) } }
}

// ---------------------------------------------------------------------------
// A1/A2 — grant-derived entitlements (credential sovereignty).
//
// The step beyond "Nactor reads ITS OWN grants": read EACH runtime identity's
// grants with THAT identity's key, so the broker can gate a call on whether a
// Director-signed grant actually names the caller for the requested credential.
// This is NOT a box-local ACL — the authority is the grant itself; the box only
// verifies (decrypts) it. It's how "any activated identity may use any
// credential" (blanket trust) becomes "an identity may use exactly the
// credentials granted to it." `entitlements` is a live Map<pubHex, Set<name>>.
//
// `identities` may be an array OR a function returning one — a function is
// evaluated per sweep, so identities imported at runtime (role-key scopes) are
// swept without a restart: "each runtime identity", not the boot-time set.
//
// Failure semantics, deliberately asymmetric:
//   • the RELAY READ failed (receiveGrants threw) → keep the PRIOR set. A
//     transient outage must never strip an identity of its entitlements.
//   • the read SUCCEEDED → the result is authoritative, even when EMPTY.
//     Revoking an identity's LAST grant must clear its entitlement — "no
//     grants readable" after a good read IS the revocation signal.
//   • one scope FETCH threw (network blip on a single scope) → that credential
//     keeps its prior membership. A real revocation is not a throw: it comes
//     back cleanly as 'stale'/'missing' and is simply not counted.
export async function syncIdentityEntitlements({ relay, relayUrls, identities, entitlements, creds, allowedPublishers, log = () => {}, onEvent = () => {} }) {
  const own = relay || new LiveRelay(relayUrls)
  const owned = !relay
  const summary = {}
  const ownerLoaded = []
  const ids = typeof identities === 'function' ? identities() : identities
  try {
    const trusted = publisherSet(allowedPublishers)
    for (const id of ids) {
      const prior = entitlements.get(id.pub) || new Set()
      const held = new Set()
      let readOk = false
      try {
        let grants = latestGrants(await receiveGrants(own, id.sk))
          .filter(g => (g.scopeName || '').startsWith(CREDENTIAL_PREFIX))
        if (trusted) grants = grants.filter(g => trusted.has(g.publisher))
        readOk = true
        grants.sort((a, b) => (a.issuedAt || 0) - (b.issuedAt || 0))   // newest re-issue wins the value
        for (const g of grants) {
          const name = g.scopeName.slice(CREDENTIAL_PREFIX.length)
          if (!name) continue
          try {
            const s = await fetchScope(own, g)
            if (s.status === 'ok') {
              held.add(name)
              // A2 stage 2 — the OWNER's grant supplies the VALUE. The identity
              // holds the grant; the co-resident runtime (which custodies the
              // identity's key) loads it into RAM as a capability the identity
              // LENDS it — outranking any Nactor-addressed copy, which becomes
              // revocable. Same tolerant payload keys as the delivery reader.
              if (creds) {
                const value = typeof s.data === 'string' ? s.data
                  : s.data?.value ?? s.data?.secret ?? s.data?.key ?? s.data?.api_key ?? null
                if (value != null) {
                  const prev = creds.get(name)
                  const takeover = !prev || prev.source !== 'grant-owner'
                  const changed = !takeover && (prev.value !== value || prev.generation !== s.generation || prev.owner !== id.name)
                  creds.set(name, {
                    type: 'secret', target: CREDENTIAL_PREFIX + name, value,
                    source: 'grant-owner', owner: id.name,
                    importedAt: Date.now(), generation: s.generation,
                  })
                  ownerLoaded.push(`${name}←${id.name}`)
                  if (takeover) onEvent({ t: 'grant-load', credential: name, owner: id.name, generation: s.generation, when: Date.now() })
                  else if (changed) onEvent({ t: 'grant-update', credential: name, owner: id.name, generation: s.generation, when: Date.now() })
                }
              }
            } else if (creds) {
              // Owner grant revoked/rotated: drop ONLY an entry this path set —
              // the Nactor-addressed reader (if a legacy copy still exists)
              // restores plain 'grant' supply on its next sweep.
              const cur = creds.get(name)
              if (cur && cur.source === 'grant-owner' && cur.owner === id.name) {
                creds.delete(name)
                onEvent({ t: 'grant-drop', credential: name, owner: id.name, when: Date.now() })
              }
            }
          }
          catch { if (prior.has(name)) held.add(name) }   // transient scope blip: sticky
        }
      } catch { /* relay read failed → next = prior (below) */ }
      const next = readOk || !entitlements.has(id.pub) ? held : prior
      for (const c of next) if (!prior.has(c)) onEvent({ t: 'entitlement-gain', identity: id.name, credential: c, when: Date.now() })
      for (const c of prior) if (!next.has(c)) onEvent({ t: 'entitlement-loss', identity: id.name, credential: c, when: Date.now() })
      entitlements.set(id.pub, next)
      summary[id.name] = [...next]
    }
  } finally {
    if (owned) try { own.close() } catch {}
  }
  const line = Object.entries(summary).map(([n, cs]) => `${n}:[${cs.join(',') || '—'}]`).join(' ')
  if (line) log(`  entitlements: ${line}`)
  if (ownerLoaded.length) summary['creds-from-owner'] = ownerLoaded
  return summary
}

// Boot sweep + periodic re-sweep for the entitlement map (and, when `creds` is
// passed, the A2 owner-grant value supply). Returns stop().
export function startEntitlementReader({ relayUrls, identities, entitlements, creds, allowedPublishers, intervalMs = 5 * 60 * 1000, log = () => {}, onEvent = () => {} }) {
  const idsProvided = typeof identities === 'function' || identities?.length
  if (!idsProvided || !relayUrls?.length) { log('  entitlements: reader disabled (no identities / relays)'); return { stop() {} } }
  const sweep = () => syncIdentityEntitlements({ relayUrls, identities, entitlements, creds, allowedPublishers, log, onEvent })
    .catch(e => log(`  entitlements: sweep error ${e?.message || e}`))
  sweep()
  const t = setInterval(sweep, intervalMs)
  if (t.unref) t.unref()
  return { stop() { clearInterval(t) } }
}
