// mail — the first stateful-adapter connector (docs/connectors.md; nact#4, the
// docs' #36). A verb-scoped, READ-ONLY IMAP adapter: same two guarantees as the
// HTTP broker (the caller never sees the password/token; the caller can only
// read), but over a stateful IMAP session instead of an HTTP request.
//
// Shape (docs/connectors.md "The two axes"):
//   • transport `stateful-adapter` — a short-lived client per call:
//     connect → authenticate → ONE verb → logout. Hard timeout + Promise.race
//     guard (same lesson as the relay reads) so a slow server can't hang the
//     route. No long-lived session, no IDLE.
//   • auth `static-key` (app-password → IMAP LOGIN) or `oauth` (access token
//     minted from a stored refresh bundle by oauth.mjs → SASL XOAUTH2). One
//     connector, one route: the CREDENTIAL'S SHAPE selects the strategy —
//     explicit `auth` wins, else infer (`pass` ⇒ password,
//     `refresh_token`/`oauth_cred` ⇒ oauth).
//
// Credential value (inside the encrypted `mail-<account>` scope, never on disk):
//   { "auth": "password", "host": "imap.fastmail.com", "port": 993,
//     "user": "james@…", "pass": "<app-password>" }
//   { "auth": "oauth", "host": "imap.gmail.com", "port": 993,
//     "user": "james@gmail.com", "oauth_cred": "gworkspace" }
// `oauth_cred` names an OAuth bundle the broker already holds (the token then
// needs the https://mail.google.com/ IMAP scope), or the bundle rides inline
// ({ client_id, client_secret, refresh_token }).
//
// THE SECURITY CORE — the verb allow-list is the whole write-protection story:
//   list    → LIST
//   search  → EXAMINE (read-only) + UID SEARCH (+ UID FETCH of envelopes)
//   headers → UID FETCH (ENVELOPE/FLAGS/SIZE)
//   body    → UID FETCH BODY.PEEK[TEXT]   (PEEK — never sets \Seen)
// APPEND / STORE / EXPUNGE / DELETE / MOVE / COPY / CREATE / RENAME are NEVER
// IMPLEMENTED — write protection is structural (no write verb exists in this
// code), not a flag. Mailboxes open with EXAMINE (never SELECT for write) and
// every body fetch is BODY.PEEK, so a read can't even mutate flags.
//
// Egress is pinned by the CREDENTIAL: host/port/user/TLS come from the
// `mail-<account>` scope a Director issued, never from the request — a caller
// can't repoint the connection. The request contributes only verb + params,
// validated here before a socket ever opens.
//
// Never log the password, the access token, or message bodies. This module
// logs nothing (imapflow's logger is hard-disabled); the route logs
// account + verb + mailbox + counts only.

import { ImapFlow } from 'imapflow'
import { oauthAccessToken } from '../oauth.mjs'

// Errors carry an http-ish status the route maps onto the response:
// 400 caller mistake · 404 no such message · 502 upstream/auth/credential ·
// 504 timeout. Anything else defaults to 502 at the route.
export class MailError extends Error {
  constructor(message, status = 502) { super(message); this.status = status }
}

const DEFAULT_TIMEOUT_MS = 15_000     // "hard ≈15s timeout" per docs/connectors.md
const DEFAULT_BODY_MAX = 8192         // body preview cap (chars) — NACT_MAIL_BODY_MAX overrides
const DEFAULT_LIMIT = 25              // search result rows when the caller names no limit
const MAX_LIMIT = 100                 // per-call ceiling for search rows / headers uids

// ---- request validation (all of it BEFORE any socket opens) ---------------

const bad = (msg) => { throw new MailError(msg, 400) }

// Mailbox names come from the caller, so they get the protocol-injection guard:
// no CR/LF/NUL ever reaches the wire. (imapflow also encodes paths; belt+braces.)
function cleanMailbox(v) {
  if (v == null) return 'INBOX'
  if (typeof v !== 'string' || !v.length || v.length > 512 || /[\r\n\0]/.test(v)) bad('mailbox must be a plain mailbox path')
  return v
}
function cleanLimit(v) {
  if (v == null) return DEFAULT_LIMIT
  const n = Number(v)
  if (!Number.isInteger(n) || n < 1 || n > MAX_LIMIT) bad(`limit must be an integer 1..${MAX_LIMIT}`)
  return n
}
function cleanUid(v) {
  const n = Number(v)
  if (!Number.isInteger(n) || n < 1) bad(`uid '${v}' must be a positive integer`)
  return n
}
function cleanUids(v) {
  if (!Array.isArray(v) || !v.length || v.length > MAX_LIMIT) bad(`uids must be a non-empty array of at most ${MAX_LIMIT}`)
  return v.map(cleanUid)
}
const cleanStr = (k, v) => {
  if (typeof v !== 'string' || !v.length || v.length > 256 || /[\r\n\0]/.test(v)) bad(`search key '${k}' must be a short plain string`)
  return v
}
const cleanDate = (k, v) => {
  const d = new Date(v)
  if (typeof v !== 'string' || isNaN(d.getTime())) bad(`search key '${k}' must be a date string (YYYY-MM-DD)`)
  return d
}
const cleanNum = (k, v) => {
  const n = Number(v)
  if (!Number.isInteger(n) || n < 1) bad(`search key '${k}' must be a positive integer`)
  return n
}

// The search-query surface: a small allow-list of READ search terms mapped onto
// imapflow's compiler. Every IMAP SEARCH key is read-only by nature — this list
// is input hygiene (typed, bounded, no free-form protocol strings), not the
// write guard. Unknown keys are rejected, not dropped, so a caller can't
// believe a filter applied when it didn't.
function buildSearchQuery(q) {
  if (q == null) return {}                                   // {} ⇒ imapflow sends SEARCH ALL
  if (typeof q !== 'object' || Array.isArray(q)) bad('query must be an object of search terms')
  const out = {}
  for (const [k, v] of Object.entries(q)) {
    switch (k) {
      case 'since': case 'before': case 'on': out[k] = cleanDate(k, v); break
      case 'seen': case 'unseen': case 'flagged': case 'answered': case 'draft': out[k] = !!v; break
      case 'from': case 'to': case 'cc': case 'bcc': case 'subject': out[k] = cleanStr(k, v); break
      case 'text': out.body = cleanStr(k, v); break          // full-text; imapflow's key is `body`
      case 'larger': case 'smaller': out[k] = cleanNum(k, v); break
      case 'uid':
        if (!/^[0-9,:*]+$/.test(String(v))) bad(`search key 'uid' must be an IMAP uid set`)
        out.uid = String(v)
        break
      default: bad(`search key '${k}' not permitted`)
    }
  }
  return out
}

// ---- auth strategy (axis 2: chosen by the credential's VALUE) -------------

export function authStrategy(cred) {
  if (cred.auth === 'password' || cred.auth === 'oauth') return cred.auth
  if (cred.auth != null) throw new MailError(`mail credential has unknown auth '${cred.auth}'`)
  if (cred.pass) return 'password'
  if (cred.oauth_cred || cred.refresh_token) return 'oauth'
  throw new MailError('mail credential names no auth strategy (need pass, oauth_cred, or refresh_token)')
}

// Resolve the credential into imapflow auth: { user, pass } for an
// app-password, { user, accessToken } for oauth. The oauth path mints a
// short-lived token via oauth.mjs — either from a NAMED bundle the broker
// already holds (`oauth_cred`, e.g. the existing gworkspace refresh-token;
// same mint, same cache as the gcal/gmail providers) or from an inline bundle
// riding in the mail credential itself. `force` re-mints past the cache — used
// exactly once after an IMAP auth failure.
export async function resolveAuth(cred, { credName = 'mail', resolveCredential = () => null, force = false, mintToken = oauthAccessToken } = {}) {
  const user = typeof cred.user === 'string' ? cred.user.trim() : cred.user
  if (typeof user !== 'string' || !user) throw new MailError('mail credential missing user')
  const strategy = authStrategy(cred)
  if (strategy === 'password') {
    if (typeof cred.pass !== 'string' || !cred.pass.trim()) throw new MailError('mail credential missing pass')
    // Normalize paste artifacts: values arrive through a console form and a
    // relay round trip — trim edges, and collapse the interior spaces of
    // Google's app-password DISPLAY shape (four groups of four). Gmail
    // rejects the spaced form over IMAP LOGIN; a stray trailing newline is
    // equally fatal and invisible. Passwords that legitimately contain
    // interior whitespace (non-Google shapes) pass through untouched.
    let pass = cred.pass.trim()
    if (/^(?:[^\s]{4}[ ]){3}[^\s]{4}$/.test(pass)) pass = pass.replaceAll(' ', '')
    return { user, pass }
  }
  let cacheName = credName, bundle = cred
  if (cred.oauth_cred) {
    cacheName = String(cred.oauth_cred)
    bundle = resolveCredential(cacheName)
    if (bundle == null) throw new MailError(`oauth credential '${cacheName}' not imported`)
  }
  const accessToken = await mintToken(cacheName, bundle, { force })
  return { user, accessToken }
}

// ---- response shaping (what a beat needs — no raw IMAP leaks out) ---------

const addrLine = (a) => a?.name ? `${a.name} <${a.address}>` : (a?.address || null)

function shapeEnvelopeRow(msg) {
  const env = msg.envelope || {}
  return {
    uid: msg.uid,
    from: addrLine(env.from?.[0]),
    subject: env.subject ?? null,
    date: env.date instanceof Date ? env.date.toISOString() : (env.date ?? null),
    unseen: !(msg.flags instanceof Set && msg.flags.has('\\Seen')),
    size: msg.size ?? null,
  }
}

// Quoted-printable → utf8 (byte-accurate: =XX pairs become bytes, soft line
// breaks vanish).
function decodeQP(s) {
  const bytes = []
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) { bytes.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2 }
    else if (s[i] === '=' && s[i + 1] === '\n') { i += 1 }                       // soft break
    else bytes.push(s.charCodeAt(i) & 0xff)
  }
  return Buffer.from(bytes).toString('utf8')
}
function decodeTransfer(enc, body) {
  const e = (enc || '').toLowerCase()
  if (e === 'base64') { try { return Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8') } catch { return body } }
  if (e === 'quoted-printable') return decodeQP(body)
  return body
}
const looksLikeHtml = (s) => /<\s*(!doctype|html|body|div|p|br|table|span|a\s)/i.test(s)
function stripHtml(h) {
  return h
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>').replace(/&quot;/gi, '"').replace(/&#0*39;/g, "'")
    .replace(/[ \t]+/g, ' ')
}

// BODY[TEXT] of a single-part message is the bare body; of a multipart message
// it is boundaries + per-part headers + encoded parts. Extract a plain-text
// preview: first text/plain part (recursing into nested multiparts), falling
// back to stripped text/html — and NEVER an attachment or binary part.
function extractText(s, depth = 0) {
  const m = depth <= 3 && s.match(/^--\S+[ \t]*$/m)
  if (!m) return looksLikeHtml(s) ? stripHtml(s) : s
  const boundary = m[0].trim()
  const segments = s.split(new RegExp(`^${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?[ \\t]*$`, 'm')).slice(1)
  let html = null
  for (const seg of segments) {
    const split = seg.indexOf('\n\n')
    if (split === -1) continue
    const head = seg.slice(0, split), body = seg.slice(split + 2)
    const ct = (head.match(/content-type:\s*([\w/+.-]+)/i)?.[1] || 'text/plain').toLowerCase()
    const cte = head.match(/content-transfer-encoding:\s*(\S+)/i)?.[1]
    if (ct === 'text/plain') return decodeTransfer(cte, body)
    if (ct.startsWith('multipart/')) {
      const nested = extractText(body, depth + 1)
      if (nested.trim()) return nested
    }
    if (ct === 'text/html' && html == null) html = stripHtml(decodeTransfer(cte, body))
  }
  return html ?? ''
}

// Shape a fetched BODY[TEXT] section into the capped text/plain preview the
// route returns. Exported for the offline tests' MIME fixtures.
export function shapeBodyText(raw, maxChars = DEFAULT_BODY_MAX) {
  const s = (Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw ?? '')).replace(/\r\n/g, '\n')
  const text = extractText(s).replace(/\n{3,}/g, '\n\n').trim()
  const truncated = text.length > maxChars
  return { text: truncated ? text.slice(0, maxChars) : text, truncated }
}

// ---- the verbs (the ENTIRE read surface — nothing else exists) ------------

async function fetchEnvelopes(client, uids) {
  if (!uids.length) return []
  const rows = []
  for await (const msg of client.fetch(uids.join(','), { uid: true, flags: true, envelope: true, size: true }, { uid: true })) {
    rows.push(shapeEnvelopeRow(msg))
  }
  return rows.sort((a, b) => b.uid - a.uid)                  // newest first
}

const VERBS = {
  async list(client) {
    const boxes = (await client.list()) || []
    return { mailboxes: boxes.map(b => ({ path: b.path, delimiter: b.delimiter ?? null, specialUse: b.specialUse ?? null })) }
  },
  async search(client, { mailbox, query, limit }) {
    await client.mailboxOpen(mailbox, { readOnly: true })    // EXAMINE, never SELECT
    const uids = (await client.search(query, { uid: true })) || []
    const chosen = [...uids].sort((a, b) => b - a).slice(0, limit)
    return { mailbox, total: uids.length, messages: await fetchEnvelopes(client, chosen) }
  },
  async headers(client, { mailbox, uids }) {
    await client.mailboxOpen(mailbox, { readOnly: true })
    return { mailbox, messages: await fetchEnvelopes(client, uids) }
  },
  async body(client, { mailbox, uid, maxChars }) {
    await client.mailboxOpen(mailbox, { readOnly: true })
    const msg = await client.fetchOne(String(uid), { uid: true, bodyParts: ['text'] }, { uid: true })
    const part = msg ? msg.bodyParts?.get('text') : null
    if (part == null) throw new MailError(`uid ${uid} not found in '${mailbox}'`, 404)
    const { text, truncated } = shapeBodyText(part, maxChars)
    return { mailbox, uid, part: 'text', text, truncated }
  },
}
export const MAIL_VERBS = Object.keys(VERBS)

// Validate the request into per-verb params — completely, before connecting.
function validateRequest(request) {
  const verb = String(request.verb || '')
  if (!VERBS[verb]) bad(`verb '${verb}' not permitted for mail (read-only: ${MAIL_VERBS.join(', ')})`)
  const params = {}
  if (verb !== 'list') params.mailbox = cleanMailbox(request.mailbox)
  if (verb === 'search') { params.query = buildSearchQuery(request.query); params.limit = cleanLimit(request.limit) }
  if (verb === 'headers') params.uids = cleanUids(request.uids)
  if (verb === 'body') {
    params.uid = cleanUid(request.uid)
    const part = request.part == null ? 'text' : request.part
    if (part !== 'text') bad(`part '${part}' not permitted (text only — attachments are never fetched)`)
  }
  return { verb, params }
}

// ---- the adapter: one connection, one verb, one response ------------------
//
// request:   { verb, mailbox?, query?, limit?, uids?, uid?, part? } — the
//            caller's body MINUS routing fields; never a raw IMAP command.
// credValue: the `mail-<account>` credential value (JSON string or object).
// opts:      { resolveCredential? (name → value, for oauth_cred lookups),
//              timeoutMs?, maxChars?, mintToken? } — injectable for tests.
export async function runMailVerb(request, credValue, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? Number(process.env.NACT_MAIL_TIMEOUT_MS || DEFAULT_TIMEOUT_MS)
  const maxChars = opts.maxChars ?? Number(process.env.NACT_MAIL_BODY_MAX || DEFAULT_BODY_MAX)
  const { verb, params } = validateRequest(request)
  params.maxChars = maxChars

  let cred
  try { cred = typeof credValue === 'string' ? JSON.parse(credValue) : credValue } catch { throw new MailError('mail credential is not valid JSON') }
  if (!cred || typeof cred !== 'object') throw new MailError('mail credential is not an object')
  if (typeof cred.host !== 'string' || !cred.host) throw new MailError('mail credential missing host')
  const strategy = authStrategy(cred)                        // fail before any socket

  let client = null
  let abandoned = false                                      // set once the race is over — no late reconnects
  const work = (async () => {
    // Auth-failure retry, oauth only: a cached access token can be revoked or
    // expired server-side — re-mint ONCE with force:true, then give up.
    for (let attempt = 0; ; attempt++) {
      if (abandoned) throw new MailError('abandoned after timeout', 504)
      const auth = await resolveAuth(cred, { credName: opts.credName || 'mail', resolveCredential: opts.resolveCredential, force: attempt > 0, mintToken: opts.mintToken })
      client = new ImapFlow({
        host: cred.host,
        port: Number(cred.port) || 993,
        secure: cred.secure !== false,                       // TLS unless the CREDENTIAL opts out — never the request
        auth,
        logger: false,                                       // hard-off: no token/password can reach a log
        disableAutoIdle: true,                               // one verb, no session to keep alive
        connectionTimeout: timeoutMs, greetingTimeout: timeoutMs, socketTimeout: timeoutMs * 2,
      })
      try { await client.connect(); break }
      catch (e) {
        try { client.close() } catch {}
        if (e?.authenticationFailed && strategy === 'oauth' && attempt === 0) continue
        throw new MailError(`imap ${e?.authenticationFailed ? 'authentication' : 'connect'} failed: ${e?.responseText || e?.message || e}`)
      }
    }
    try {
      return await VERBS[verb](client, params)
    } finally {
      await client.logout().catch(() => { try { client.close() } catch {} })
    }
  })()
  work.catch(() => {})                                       // raced loser must not become an unhandled rejection

  let timer
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new MailError(`mail connector timed out after ${timeoutMs}ms`, 504)), timeoutMs) }),
    ])
  } finally {
    clearTimeout(timer)
    abandoned = true
    if (client) try { client.close() } catch {}              // timeout path: kill the socket, no dangling session
  }
}
