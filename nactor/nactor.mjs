// Nactor — the Nact runtime. A NIP-98-gated HTTP control-plane over the Nact
// library: the on-box actor that receives config/proposals and enacts.
//
// The control-plane app (Nact) talks to this. Every /api/* request is
// authenticated with a NIP-98 event signed by a Director's key; only a
// configured Director may read the queue, enact, or edit config. The Director is
// the human decision-maker (approve or not) — distinct from Noir's AI "Director".
// Role signing keys come from the environment (SOPS-decrypted on the box) and
// never leave it.
//
// Directors live in CONFIG (config.directors — one or more npubs), so you add or
// remove them from the app without redeploying. A single BOOTSTRAP npub is read
// from the environment as the trust anchor that seeds an empty config and can
// never be locked out; the effective Director set is bootstrap ∪ config.directors.
//
//   NACT_DIRECTOR_NPUB=npub1…  # bootstrap Director (legacy: NACT_MASTER_NPUB / LUKE_MASTER_NPUB)
//   LUKE_NSEC=… NAVE_NSEC=…    # role keys (each <NAME>_NSEC becomes identity <name>)
//   LUKE_RELAYS=wss://…        # where enacted events publish
//   NACT_CONFIG=/data/nact-config.json   # directors / channels / tiers / metadata (persisted)
//   NACT_PORT=8791
//
// This is the pragmatic V1 transport (HTTP + NIP-98, the same gate Luke's
// cockpit already uses). The config-as-grant-over-Nvoy model in
// docs/architecture.md is the path we migrate to; the endpoints stay the same.
import { createServer } from 'node:http'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { getPublicKey, nip19, nip44 } from 'nostr-tools'
import { Nact } from '../src/nact.mjs'
import { kindInfo } from '../src/inspect.mjs'
import { loadSecret } from '../src/util/secret.mjs'
import { webQueueApproval } from './webqueue.mjs'
import { verifyNip98 } from './nip98.mjs'

const PORT = Number(process.env.NACT_PORT || 8791)
const RELAYS = (process.env.LUKE_RELAYS || 'wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net')
  .split(',').map(s => s.trim()).filter(Boolean)
const CONFIG_PATH = process.env.NACT_CONFIG || './nact-config.json'

function toPub(v) {
  const raw = (v || '').trim()
  if (raw.startsWith('npub1')) { try { return nip19.decode(raw).data } catch { return null } }
  if (/^[0-9a-f]{64}$/i.test(raw)) return raw.toLowerCase()
  return null
}
// The bootstrap Director: the trust anchor read from the environment once. It
// seeds an empty config and can never be locked out — the app can add co-Directors
// (for quorum) into config.directors, but this one is always authorized.
const BOOTSTRAP = toPub(process.env.NACT_DIRECTOR_NPUB || process.env.NACT_MASTER_NPUB || process.env.LUKE_MASTER_NPUB || '')

// Role identities from env: every <NAME>_NSEC → identity <name>. These are the
// bootstrap FALLBACK; the migration (docs/migration.md) replaces them with role
// keys imported at runtime as credential-scopes, held only in memory.
const IDS = {}
for (const [k, v] of Object.entries(process.env)) {
  const m = /^([A-Z][A-Z0-9]*)_NSEC$/.exec(k)
  if (m && k !== 'NACTOR_NSEC' && loadSecret(v)) IDS[m[1].toLowerCase()] = { nsec: v }
}

// Nactor's OWN keypair — the grantee. A Director encrypts credential-scopes TO
// this npub (NIP-44); Nactor decrypts with this nsec. Bootstrap it on the box
// (SOPS-sealed) via NACTOR_NSEC. Without it, Nactor can't receive credentials —
// it still runs on the env fallback, but credential import is disabled.
const NACTOR_SK = loadSecret(process.env.NACTOR_NSEC || '')
const NACTOR_PUB = NACTOR_SK ? getPublicKey(NACTOR_SK) : null
const NACTOR_NPUB = NACTOR_PUB ? nip19.npubEncode(NACTOR_PUB) : null

// In-memory credential store: name → { type, target, importedAt, value }.
// value is NEVER serialized out of the process — not to a file, not over the
// API. Role keys additionally register an in-memory signer on `nact`.
const CREDS = new Map()
const IMPORTED = new Map()   // role-key name → { nsec, importedAt } (for the identities view)

// Decrypt a credential-scope: NIP-44 ciphertext from the Director (its pubkey,
// known from the NIP-98 signature) to Nactor's key. Returns plaintext or throws.
function decryptScope(enc, directorPub) {
  if (!NACTOR_SK) throw new Error('NACTOR_NSEC not configured — credential import disabled')
  const ck = nip44.getConversationKey(NACTOR_SK, directorPub)
  return nip44.decrypt(enc, ck)
}

// The effective Director set: bootstrap ∪ config.directors (as hex pubkeys). Read
// live so app edits to config.directors take effect without a restart. Enacting
// requires being in this set, so webqueue authorizes against it, not one key.
function directorPubs() {
  const set = new Set()
  if (BOOTSTRAP) set.add(BOOTSTRAP)
  for (const d of (config?.directors || [])) { const p = toPub(d); if (p) set.add(p) }
  return set
}
const isDirector = pub => directorPubs().has(pub)

const approval = webQueueApproval({ isDirector })
const nact = new Nact({ identities: IDS, relays: RELAYS, approval })

// ---- config store (non-secret metadata the app edits) --------------------
// Config carries the Director(s) and the Nactor's own address alongside the
// channels/tiers/identity metadata — so the human decision-makers and which
// runtime this config targets are part of the desired state, not deploy-time env.
function defaultConfig() {
  const identitiesMeta = {}
  for (const k of Object.keys(IDS)) identitiesMeta[k] = { handle: `${k}@nave.pub`, signer: 'custodial', status: 'active' }
  return {
    directors: BOOTSTRAP ? [nip19.npubEncode(BOOTSTRAP)] : [],
    nactorAddress: process.env.NACT_ADDRESS || '',
    identitiesMeta,
    channels: [{ id: 'web', name: 'Nact app', kind: 'Web queue (NIP-98)', approver: 'director', covers: Object.keys(IDS), status: 'active' }],
    tiers: { 0: 'critical', 1: 'low', 3: 'critical', 5: 'critical', 6: 'low', 7: 'low', 9734: 'elevated', 10002: 'critical' },
  }
}
function loadConfig() {
  try { if (existsSync(CONFIG_PATH)) return { ...defaultConfig(), ...JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) } } catch (e) { console.warn('config load:', e.message) }
  return defaultConfig()
}
function saveConfig(c) {
  try { mkdirSync(dirname(CONFIG_PATH), { recursive: true }) } catch {}
  writeFileSync(CONFIG_PATH, JSON.stringify(c, null, 2))
}
let config = loadConfig()

// ---- http ----------------------------------------------------------------
const json = (res, code, obj) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)) }
const readBody = async req => { let s = ''; for await (const c of req) s += c; return s }

async function identitiesView() {
  const out = []
  const names = new Set([...Object.keys(IDS), ...IMPORTED.keys()])
  for (const k of names) {
    const nsec = IMPORTED.get(k)?.nsec ?? IDS[k]?.nsec
    let npub = null
    try { npub = nip19.npubEncode(getPublicKey(loadSecret(nsec))) } catch {}
    const meta = config.identitiesMeta[k] || {}
    out.push({
      key: k, handle: meta.handle || `${k}@nave.pub`, npub,
      signer: meta.signer || 'custodial', status: meta.status || 'active',
      source: IMPORTED.has(k) ? 'imported (credential-scope, in memory)' : 'env (bootstrap fallback)',
    })
  }
  return out
}

// Credentials summary — NAMES/types/targets only, never values.
function credentialsView() {
  return [...CREDS.entries()].map(([name, c]) => ({ name, type: c.type, target: c.target || null, importedAt: c.importedAt }))
}

const server = createServer(async (req, res) => {
  const path = (req.url || '/').split('?')[0]
  if (!path.startsWith('/api/')) return json(res, 404, { error: 'not found' })

  // Health is public and prints no secrets. Exposes the Nactor npub so a
  // Director knows which key to encrypt credential-scopes to.
  if (path === '/api/health' && req.method === 'GET') {
    return json(res, 200, {
      ok: true,
      identities: [...new Set([...Object.keys(IDS), ...IMPORTED.keys()])],
      relays: RELAYS.length,
      directorsConfigured: directorPubs().size,
      nactorNpub: NACTOR_NPUB,                     // the grantee address (public)
      credentials: CREDS.size,
    })
  }

  // Everything else requires NIP-98 from a configured Director.
  const bodyRaw = (req.method === 'POST' || req.method === 'PUT') ? await readBody(req) : ''
  if (!directorPubs().size) return json(res, 503, { error: 'no Director configured' })
  const pubkey = verifyNip98(req.headers['authorization'], req.method, path, bodyRaw)
  if (!pubkey) return json(res, 401, { error: 'nip-98 auth required' })
  if (!isDirector(pubkey)) return json(res, 403, { error: 'not a Director' })
  let body = {}
  if (bodyRaw) { try { body = JSON.parse(bodyRaw) } catch { return json(res, 400, { error: 'bad json' }) } }

  try {
    if (path === '/api/state' && req.method === 'GET') {
      return json(res, 200, {
        director: nip19.npubEncode(pubkey),               // the Director making this request
        directors: [...directorPubs()].map(p => nip19.npubEncode(p)),
        nactorAddress: config.nactorAddress || '',
        nactorNpub: NACTOR_NPUB,                           // grant credential-scopes to this key
        bootstrap: BOOTSTRAP ? nip19.npubEncode(BOOTSTRAP) : null,  // the anchor that can't be removed
        identities: await identitiesView(),
        credentials: credentialsView(),
        channels: config.channels,
        tiers: config.tiers,
        queue: approval.listPending().map(p => ({ ...p, tier: config.tiers[p.draft.kind] || kindInfo(p.draft.kind).risk })),
        history: approval.listHistory(),
      })
    }
    if (path === '/api/propose' && req.method === 'POST') {
      const out = await nact.propose({ identity: body.identity, event: body.event, context: body.context, replyTo: body.replyTo })
      return json(res, 200, out)
    }
    if (path === '/api/enact' && req.method === 'POST') {
      const out = await nact.enact({ id: body.id, verb: body.verb === 'ok' || body.verb === 'enacted' ? 'ok' : 'no', approver: pubkey })
      return json(res, 200, out)
    }
    if (path === '/api/config' && req.method === 'PUT') {
      // Guard against lockout: a Directors edit must keep at least one valid
      // Director (the bootstrap anchor always counts, so this only bites if
      // there's no bootstrap and the edit empties the set).
      if (Array.isArray(body.directors)) {
        const next = new Set(body.directors.map(toPub).filter(Boolean))
        if (BOOTSTRAP) next.add(BOOTSTRAP)
        if (!next.size) return json(res, 400, { error: 'refusing to remove the last Director' })
      }
      for (const key of ['directors', 'nactorAddress', 'channels', 'tiers', 'identitiesMeta']) if (body[key] !== undefined) config[key] = body[key]
      saveConfig(config)
      return json(res, 200, { ok: true, directors: [...directorPubs()].map(p => nip19.npubEncode(p)), nactorAddress: config.nactorAddress || '', channels: config.channels, tiers: config.tiers })
    }

    // Import (or revoke) a credential-scope. The Director NIP-44-encrypts the
    // secret TO Nactor's npub and PUTs { name, type, enc } (the NIP-98 signature
    // identifies the Director, so Nactor derives the shared key from it). The
    // secret is decrypted and held ONLY in memory — never written to disk, never
    // returned by the API. A role-key additionally registers an in-memory signer.
    // Revoke with { name, revoke: true }.
    if (path === '/api/credential' && req.method === 'PUT') {
      const name = String(body.name || '').trim()
      if (!name) return json(res, 400, { error: 'name required' })
      if (body.revoke) {
        CREDS.delete(name)
        if (IMPORTED.has(name)) { IMPORTED.delete(name); nact.removeIdentity(name) }
        return json(res, 200, { ok: true, revoked: name, credentials: credentialsView() })
      }
      if (!NACTOR_NPUB) return json(res, 503, { error: 'NACTOR_NSEC not configured — credential import disabled' })
      if (!body.enc) return json(res, 400, { error: 'enc (NIP-44 ciphertext to the Nactor npub) required' })
      let plaintext
      try { plaintext = decryptScope(body.enc, pubkey) } catch (e) { return json(res, 400, { error: 'decrypt failed: ' + (e?.message || 'bad ciphertext') }) }
      // plaintext may be a bare secret, or JSON { nsec | secret, handle? }.
      let secret = plaintext, extra = {}
      try { const o = JSON.parse(plaintext); if (o && typeof o === 'object') { secret = o.nsec || o.secret || plaintext; extra = o } } catch {}
      const type = String(body.type || 'secret')
      if (type === 'role-key') {
        if (!loadSecret(secret)) return json(res, 400, { error: 'role-key scope did not contain a usable nsec' })
        if (!nact.addIdentity(name, { nsec: secret })) return json(res, 400, { error: 'could not register signer' })
        IMPORTED.set(name, { nsec: secret, importedAt: Date.now() })
        if (extra.handle) { config.identitiesMeta[name] = { ...(config.identitiesMeta[name] || {}), handle: extra.handle, signer: 'custodial', status: 'active' }; saveConfig(config) }
      }
      CREDS.set(name, { type, target: body.target || null, importedAt: Date.now(), value: secret })
      return json(res, 200, { ok: true, imported: name, type, credentials: credentialsView(), identities: await identitiesView() })
    }
    return json(res, 404, { error: 'unknown endpoint' })
  } catch (e) {
    return json(res, 500, { error: e?.message || 'error' })
  }
})

server.listen(PORT, () => {
  console.log(`nactor on :${PORT} — identities: ${Object.keys(IDS).join(', ') || '(none)'} · directors: ${directorPubs().size || 'NONE'}${BOOTSTRAP ? ' (bootstrap set)' : ''} · relays: ${RELAYS.length} · nactor key: ${NACTOR_NPUB ? NACTOR_NPUB.slice(0, 16) + '…' : 'MISSING (credential import disabled)'}`)
})

export { server, nact, config }
