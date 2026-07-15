// Nactor — the Nact runtime. A NIP-98-gated HTTP control-plane over the Nact
// library: the on-box actor that receives config/proposals and enacts.
//
// The control-plane app (nact.nave.pub) talks to this. Every /api/* request is
// authenticated with a NIP-98 event signed by the master's key; only the master
// pubkey may read the queue, enact, or edit config. Role signing keys come from
// the environment (SOPS-decrypted on the box) and never leave it.
//
//   NACT_MASTER_NPUB=npub1…   # or LUKE_MASTER_NPUB — the only key that may act
//   LUKE_NSEC=… NAVE_NSEC=…    # role keys (each <NAME>_NSEC becomes identity <name>)
//   LUKE_RELAYS=wss://…        # where enacted events publish
//   NACT_CONFIG=/data/nact-config.json   # channels / tiers / metadata (persisted)
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
const MASTER = toPub(process.env.NACT_MASTER_NPUB || process.env.LUKE_MASTER_NPUB || '')

// Role identities from env: every <NAME>_NSEC → identity <name>.
const IDS = {}
for (const [k, v] of Object.entries(process.env)) {
  const m = /^([A-Z][A-Z0-9]*)_NSEC$/.exec(k)
  if (m && loadSecret(v)) IDS[m[1].toLowerCase()] = { nsec: v }
}

const approval = webQueueApproval({ approverPubkey: MASTER })
const nact = new Nact({ identities: IDS, relays: RELAYS, approval })

// ---- config store (non-secret metadata the app edits) --------------------
function defaultConfig() {
  const identitiesMeta = {}
  for (const k of Object.keys(IDS)) identitiesMeta[k] = { handle: `${k}@nave.pub`, signer: 'custodial', status: 'active' }
  return {
    identitiesMeta,
    channels: [{ id: 'web', name: 'Nact app', kind: 'Web queue (NIP-98)', approver: 'master', covers: Object.keys(IDS), status: 'active' }],
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
    return json(res, 200, { ok: true, identities: Object.keys(IDS), relays: RELAYS.length, masterConfigured: !!MASTER })
  }

  // Everything else requires NIP-98 from the master.
  const bodyRaw = (req.method === 'POST' || req.method === 'PUT') ? await readBody(req) : ''
  if (!MASTER) return json(res, 503, { error: 'master npub not configured' })
  const pubkey = verifyNip98(req.headers['authorization'], req.method, path, bodyRaw)
  if (!pubkey) return json(res, 401, { error: 'nip-98 auth required' })
  if (pubkey !== MASTER) return json(res, 403, { error: 'not the master key' })
  let body = {}
  if (bodyRaw) { try { body = JSON.parse(bodyRaw) } catch { return json(res, 400, { error: 'bad json' }) } }

  try {
    if (path === '/api/state' && req.method === 'GET') {
      return json(res, 200, {
        master: nip19.npubEncode(MASTER),
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
      for (const key of ['channels', 'tiers', 'identitiesMeta']) if (body[key] !== undefined) config[key] = body[key]
      saveConfig(config)
      return json(res, 200, { ok: true, channels: config.channels, tiers: config.tiers })
    }
    return json(res, 404, { error: 'unknown endpoint' })
  } catch (e) {
    return json(res, 500, { error: e?.message || 'error' })
  }
})

server.listen(PORT, () => {
  console.log(`nactor on :${PORT} — identities: ${Object.keys(IDS).join(', ') || '(none)'} · master: ${MASTER ? 'set' : 'MISSING'} · relays: ${RELAYS.length}`)
})

export { server, nact, config }
