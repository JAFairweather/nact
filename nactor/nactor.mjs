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
import { Readable } from 'node:stream'
import { timingSafeEqual } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { getPublicKey, nip19, nip44 } from 'nostr-tools'
import { Nact } from '../src/nact.mjs'
import { kindInfo } from '../src/inspect.mjs'
import { loadSecret } from '../src/util/secret.mjs'
import { webQueueApproval } from './webqueue.mjs'
import { verifyNip98 } from './nip98.mjs'
import { oauthAccessToken } from './oauth.mjs'

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

// Bootstrap provider credentials from env → CREDS at boot. This is the credential
// analog of the role-key env loop above: SOPS delivers the secret to NACTOR's
// env, Nactor loads it into memory, and the CONSUMER (e.g. luke-brain) never has
// it — it reaches the provider only by brokering through Nactor. Durable across
// restarts (re-read each boot), no Director key needed on the box, and no value
// is written back to disk or returned by the API. Add a provider by mapping its
// broker name to the env var it arrives in.
// gworkspace is an OAuth2 credential: the env var holds a JSON bundle
// {client_id, client_secret, refresh_token} from ONE Google OAuth client whose
// scopes cover both Calendar (calendar.events) and Gmail read (gmail.readonly).
// Nactor mints short-lived access tokens from it (see oauth.mjs), never the
// refresh token itself, and never returns any of it. Both the gcal and gmail
// broker providers below share this one credential.
const BOOTSTRAP_CRED_ENV = { anthropic: 'ANTHROPIC_API_KEY', telegram: 'TELEGRAM_BOT_TOKEN', google: 'GEMINI_API_KEY', gworkspace: 'GOOGLE_OAUTH_JSON' }
for (const [name, envk] of Object.entries(BOOTSTRAP_CRED_ENV)) {
  const v = (process.env[envk] || '').trim()
  if (v) CREDS.set(name, { type: 'provider-credential', target: `credential:${name}`, importedAt: Date.now(), value: v, source: 'bootstrap-env' })
}
// gworkspace fallback: assemble the OAuth bundle from three PLAIN env vars when
// GOOGLE_OAUTH_JSON isn't set. docker-compose env_file can't parse a raw JSON
// value (its braces/quotes break the parser), so this is the box-friendly path —
// three simple KEY=VALUE lines. SOPS-delivered JSON still works via the loop above.
if (!CREDS.has('gworkspace')) {
  const cid = (process.env.GOOGLE_OAUTH_CLIENT_ID || '').trim()
  const csec = (process.env.GOOGLE_OAUTH_CLIENT_SECRET || '').trim()
  const rtok = (process.env.GOOGLE_OAUTH_REFRESH_TOKEN || '').trim()
  if (cid && csec && rtok) {
    CREDS.set('gworkspace', { type: 'provider-credential', target: 'credential:gworkspace', importedAt: Date.now(),
      value: JSON.stringify({ client_id: cid, client_secret: csec, refresh_token: rtok }), source: 'bootstrap-env-parts' })
  }
}

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

// Pubkeys of on-box identities the Director has ACTIVATED (signed consent).
// The activation is what grants an identity the right to *use* brokered
// credentials — so a box service signing NIP-98 as `luke` can reach the broker,
// but only because you authorized `luke` by signature.
function activatedPubs() {
  const set = new Set()
  for (const name of Object.keys(config?.activations || {})) {
    const nsec = IMPORTED.get(name)?.nsec ?? IDS[name]?.nsec
    try { if (nsec) set.add(getPublicKey(loadSecret(nsec))) } catch {}
  }
  return set
}

// Broker providers. The caller supplies the path/method/body; Nactor pins the
// HOST and injects the secret from its in-memory credential — so the value
// never leaves Nactor, and a caller can't point the broker at an arbitrary
// host (no SSRF / open-proxy). Base URL is overridable per provider for tests
// or an egress proxy. Add a provider here to broker a new credential.
// Each provider's build(body, cred) validates the caller's request, injects the
// secret in the provider's own way, and returns { url, headers } with the host
// pinned. Anthropic puts the key in a header; Telegram puts the bot token in the
// URL path (/bot<token>/<method>). The caller never sees the secret and can't
// repoint the host. Base URL overridable per provider for tests/egress-proxy.
const BROKER_PROVIDERS = {
  anthropic: {
    credential: 'anthropic',
    build: (body, cred) => {
      const p = String(body.path || '')
      if (!p.startsWith('/v1/')) throw new Error(`path '${p}' not permitted for anthropic`)
      const base = (process.env.NACT_BROKER_BASE_ANTHROPIC || 'https://api.anthropic.com').replace(/\/$/, '')
      return { url: base + p, headers: { 'x-api-key': cred, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' } }
    },
  },
  telegram: {
    credential: 'telegram',
    build: (body, cred) => {
      const m = String(body.tgMethod || '')
      if (!/^[a-zA-Z]+$/.test(m)) throw new Error(`telegram method '${m}' not permitted`)
      const base = (process.env.NACT_BROKER_BASE_TELEGRAM || 'https://api.telegram.org').replace(/\/$/, '')
      return { url: `${base}/bot${cred}/${m}`, headers: { 'content-type': 'application/json' } }
    },
  },
  // Google Calendar — an OAuth2 provider. Unlike the static-key providers above,
  // `oauth: true` tells the broker route to first mint a short-lived access token
  // from the stored refresh-token bundle (oauth.mjs), then call build() with that
  // token. The host is pinned to googleapis.com and the caller may only reach
  // /calendar/v3/… — so a caller can't repoint egress, and never sees a token.
  gcal: {
    credential: 'gworkspace',
    oauth: true,
    build: (body, accessToken) => {
      const p = String(body.path || '')
      if (!/^\/calendar\/v3\/[A-Za-z0-9._~%\/@:+-]*$/.test(p)) throw new Error(`path '${p}' not permitted for gcal (must be /calendar/v3/…)`)
      const base = (process.env.NACT_BROKER_BASE_GCAL || 'https://www.googleapis.com').replace(/\/$/, '')
      return { url: base + p, headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' } }
    },
  },
  // Gmail (read). Same shared Google OAuth credential; the caller may only reach
  // /gmail/v1/users/me/… read endpoints. Write protection is guaranteed by the
  // gmail.readonly scope on the token (a readonly token can't send or modify),
  // and reinforced by pinning the path to the read surface here.
  gmail: {
    credential: 'gworkspace',
    oauth: true,
    build: (body, accessToken) => {
      const p = String(body.path || '')
      if (!/^\/gmail\/v1\/users\/me\/(messages|threads|labels|profile)[A-Za-z0-9._~%\/@:+?=&-]*$/.test(p)) {
        throw new Error(`path '${p}' not permitted for gmail (read-only: /gmail/v1/users/me/{messages,threads,labels,profile}…)`)
      }
      const base = (process.env.NACT_BROKER_BASE_GMAIL || 'https://gmail.googleapis.com').replace(/\/$/, '')
      return { url: base + p, headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' } }
    },
  },
}

// Egress proxy (transparent). Unlike the RPC broker above — NIP-98-gated, for
// OUR code — this serves THIRD-PARTY engines that speak a provider's native
// protocol and can't sign: e.g. OpenClaw's own model calls to Anthropic/Gemini.
// The engine points its provider base URL at /api/proxy/<provider>/… with a DUMMY
// key equal to NACT_PROXY_TOKEN; Nactor verifies that token, strips it, injects
// the REAL credential from RAM, and streams the provider's response back. The
// real key never leaves Nactor and is never returned — the env var becomes a
// scoped, revocable *grant of egress* rather than a secret the engine holds.
//
// SECURITY — INTERNAL ONLY. This route hands out credentialed egress, so it must
// never be reachable from the internet. Two hard guarantees plus one soft:
//   1. Nactor is `expose`-only (never published) — no public port.
//   2. The public Caddy vhost (nact.nave.pub) MUST refuse /api/proxy/* — the
//      only public path to Nactor is through Caddy, and it slams this door.
//   3. NACT_PROXY_TOKEN — defense-in-depth against a compromised in-network peer.
// Callers reach it directly over the nave network: http://nactor:8791/api/proxy/…
// If NACT_PROXY_TOKEN is unset, the proxy is disabled.
const PROXY_TOKEN = (process.env.NACT_PROXY_TOKEN || '').trim()
const PROXY_PROVIDERS = {
  anthropic: {
    credential: 'anthropic',
    base: (process.env.NACT_PROXY_BASE_ANTHROPIC || 'https://api.anthropic.com').replace(/\/$/, ''),
    callerToken: (req) => req.headers['x-api-key'],
    inject: (h, cred) => { h['x-api-key'] = cred; if (!h['anthropic-version']) h['anthropic-version'] = '2023-06-01' },
  },
  google: {
    credential: 'google',
    base: (process.env.NACT_PROXY_BASE_GOOGLE || 'https://generativelanguage.googleapis.com').replace(/\/$/, ''),
    callerToken: (req, u) => req.headers['x-goog-api-key'] || u.searchParams.get('key'),
    inject: (h, cred, u) => { h['x-goog-api-key'] = cred; u.searchParams.delete('key') },
  },
}
// Constant-time compare that also rejects empty/length-mismatch without leaking.
function safeEqual(a, b) {
  const x = Buffer.from(String(a ?? '')), y = Buffer.from(String(b ?? ''))
  return x.length > 0 && x.length === y.length && timingSafeEqual(x, y)
}

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
    activations: {},   // name → { by: <director npub>, at } — the Director's signed authorization to act as an on-box identity
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
      activated: (config.activations && config.activations[k]) || null,
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

  // --- Egress proxy (internal-only, token-gated) — see PROXY_PROVIDERS -------
  // BEFORE the NIP-98 gate: the callers are engines that can't sign. Auth is the
  // shared NACT_PROXY_TOKEN (presented as the provider's dummy key) plus the hard
  // guarantee that this path is unreachable from the internet (Caddy refuses
  // /api/proxy/*, Nactor isn't published). Nactor pins the host and injects the
  // real key, so a caller can't repoint egress or read the secret.
  if (path.startsWith('/api/proxy/')) {
    const seg = path.slice('/api/proxy/'.length)
    const slash = seg.indexOf('/')
    const provName = slash === -1 ? seg : seg.slice(0, slash)
    const rest = slash === -1 ? '' : seg.slice(slash)          // leading '/…'
    const prov = PROXY_PROVIDERS[provName]
    if (!prov) return json(res, 404, { error: `unknown proxy provider '${provName}'` })
    if (!PROXY_TOKEN) return json(res, 503, { error: 'egress proxy disabled (NACT_PROXY_TOKEN unset)' })
    const qs = req.url.includes('?') ? '?' + req.url.split('?').slice(1).join('?') : ''
    let url
    try { url = new URL(prov.base + rest + qs) } catch { return json(res, 400, { error: 'bad proxy path' }) }
    if (!safeEqual(prov.callerToken(req, url), PROXY_TOKEN)) return json(res, 403, { error: 'egress proxy: bad or missing token' })
    const cred = CREDS.get(prov.credential)
    if (!cred) return json(res, 503, { error: `credential '${prov.credential}' not imported` })
    // Forward the caller's headers minus hop-by-hop, host, and its dummy token.
    const fwd = {}
    for (const [k, v] of Object.entries(req.headers)) {
      const lk = k.toLowerCase()
      if (['host', 'connection', 'content-length', 'x-api-key', 'x-goog-api-key', 'authorization', 'accept-encoding'].includes(lk)) continue
      fwd[lk] = Array.isArray(v) ? v.join(', ') : v
    }
    prov.inject(fwd, cred.value, url)   // real key in; drops any ?key
    let reqBody
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const chunks = []; for await (const c of req) chunks.push(c); reqBody = Buffer.concat(chunks)
    }
    let upstream
    try {
      upstream = await fetch(url.toString(), { method: req.method, headers: fwd, body: reqBody })
    } catch (e) { return json(res, 502, { error: 'egress proxy upstream failed: ' + (e?.message || String(e)) }) }
    const outHeaders = {}
    for (const [k, v] of upstream.headers.entries()) {
      if (['content-encoding', 'content-length', 'transfer-encoding', 'connection'].includes(k.toLowerCase())) continue
      outHeaders[k] = v
    }
    res.writeHead(upstream.status, outHeaders)
    if (upstream.body) return void Readable.fromWeb(upstream.body).pipe(res)
    return void res.end()
  }

  // Everything else requires NIP-98 from a configured Director.
  const bodyRaw = (req.method === 'POST' || req.method === 'PUT') ? await readBody(req) : ''
  if (!directorPubs().size) return json(res, 503, { error: 'no Director configured' })
  const pubkey = verifyNip98(req.headers['authorization'], req.method, path, bodyRaw)
  if (!pubkey) return json(res, 401, { error: 'nip-98 auth required' })
  let body = {}
  if (bodyRaw) { try { body = JSON.parse(bodyRaw) } catch { return json(res, 400, { error: 'bad json' }) } }

  try {
    // Broker — gated by Director OR an ACTIVATED identity (not the Director-only
    // gate below). Nactor holds the credential in RAM, injects it into the pinned
    // provider host, and streams the response back. The secret value is never
    // returned. This is how a consumer USES a RAM-only credential without ever
    // seeing it. Pilot provider: anthropic (luke-brain's drafting calls).
    if (path === '/api/broker' && req.method === 'POST') {
      if (!NACTOR_NPUB) return json(res, 503, { error: 'NACTOR_NSEC not configured — broker disabled' })
      if (!isDirector(pubkey) && !activatedPubs().has(pubkey)) return json(res, 403, { error: 'caller is not a Director or an activated identity' })
      const prov = BROKER_PROVIDERS[String(body.provider || '')]
      if (!prov) return json(res, 400, { error: `unknown broker provider '${body.provider || ''}'` })
      const cred = CREDS.get(prov.credential)
      if (!cred) return json(res, 503, { error: `credential '${prov.credential}' not imported` })
      // OAuth providers mint a short-lived access token from the stored refresh
      // bundle first; static providers inject the value directly.
      let accessToken = null
      if (prov.oauth) {
        try { accessToken = await oauthAccessToken(prov.credential, cred.value) }
        catch (e) { return json(res, 502, { error: e?.message || 'oauth token error' }) }
      }
      let target
      try { target = prov.oauth ? prov.build(body, accessToken) : prov.build(body, cred.value) }
      catch (e) { return json(res, 400, { error: e?.message || 'bad broker request' }) }
      const method = String(body.method || 'POST').toUpperCase()
      const reqBody = (method === 'GET' || method === 'HEAD') ? undefined : JSON.stringify(body.body ?? {})
      let upstream
      try {
        upstream = await fetch(target.url, { method, headers: target.headers, body: reqBody })
        // An access token can be revoked/expired server-side despite our cache —
        // on a 401 from an OAuth provider, force-refresh once and retry.
        if (prov.oauth && upstream.status === 401) {
          try {
            accessToken = await oauthAccessToken(prov.credential, cred.value, { force: true })
            target = prov.build(body, accessToken)
          } catch (e) { return json(res, 502, { error: 'oauth re-auth failed: ' + (e?.message || String(e)) }) }
          upstream = await fetch(target.url, { method, headers: target.headers, body: reqBody })
        }
      } catch (e) { return json(res, 502, { error: 'broker upstream failed: ' + (e?.message || String(e)) }) }
      const text = await upstream.text().catch(() => '')
      res.writeHead(upstream.status, { 'content-type': upstream.headers.get('content-type') || 'application/json' })
      return res.end(text)
    }

    if (!isDirector(pubkey)) return json(res, 403, { error: 'not a Director' })
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

    // Activate an on-box identity — the Director SIGNS (NIP-98) an authorization
    // that Nactor may act as this custodial-on-box key. No key material is sent:
    // the box already holds the role nsec; this is the Director's consent + audit
    // record, signable from a NIP-07 extension or a NIP-46 phone signer. This is
    // the phone-friendly path for role keys (vs. issue-credential for secrets the
    // Director holds). `{name, deactivate:true}` withdraws the authorization.
    if (path === '/api/activate-identity' && req.method === 'POST') {
      const name = String(body.name || '').trim()
      if (!name) return json(res, 400, { error: 'name required' })
      const known = new Set([...Object.keys(IDS), ...IMPORTED.keys()])
      if (!known.has(name)) return json(res, 404, { error: `no such on-box identity '${name}'` })
      if (!config.activations) config.activations = {}
      if (body.deactivate) { delete config.activations[name]; saveConfig(config); return json(res, 200, { ok: true, deactivated: name, identities: await identitiesView() }) }
      config.activations[name] = { by: nip19.npubEncode(pubkey), at: Date.now() }
      saveConfig(config)
      return json(res, 200, { ok: true, activated: name, by: config.activations[name].by, identities: await identitiesView() })
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
