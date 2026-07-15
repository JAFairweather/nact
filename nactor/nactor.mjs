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
import { getPublicKey, nip19 } from 'nostr-tools'
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

// Role identities from env: every <NAME>_NSEC → identity <name>.
const IDS = {}
for (const [k, v] of Object.entries(process.env)) {
  const m = /^([A-Z][A-Z0-9]*)_NSEC$/.exec(k)
  if (m && loadSecret(v)) IDS[m[1].toLowerCase()] = { nsec: v }
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
  for (const k of Object.keys(IDS)) {
    let npub = null
    try { npub = nip19.npubEncode(getPublicKey(loadSecret(IDS[k].nsec))) } catch {}
    const meta = config.identitiesMeta[k] || {}
    out.push({ key: k, handle: meta.handle || `${k}@nave.pub`, npub, signer: meta.signer || 'custodial', status: meta.status || 'active' })
  }
  return out
}

const server = createServer(async (req, res) => {
  const path = (req.url || '/').split('?')[0]
  if (!path.startsWith('/api/')) return json(res, 404, { error: 'not found' })

  // Health is public and prints no secrets.
  if (path === '/api/health' && req.method === 'GET') {
    return json(res, 200, { ok: true, identities: Object.keys(IDS), relays: RELAYS.length, directorsConfigured: directorPubs().size })
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
        bootstrap: BOOTSTRAP ? nip19.npubEncode(BOOTSTRAP) : null,  // the anchor that can't be removed
        identities: await identitiesView(),
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
    return json(res, 404, { error: 'unknown endpoint' })
  } catch (e) {
    return json(res, 500, { error: e?.message || 'error' })
  }
})

server.listen(PORT, () => {
  console.log(`nactor on :${PORT} — identities: ${Object.keys(IDS).join(', ') || '(none)'} · directors: ${directorPubs().size || 'NONE'}${BOOTSTRAP ? ' (bootstrap set)' : ''} · relays: ${RELAYS.length}`)
})

export { server, nact, config }
