// issue-credential — the Director side of a credential-scope (Phase 1/2).
//
// Runs on the DIRECTOR's machine, never the box. It NIP-44-encrypts a secret to
// Nactor's npub (so only Nactor can open it) and either prints the scope payload
// or issues it directly over the NIP-98 gate. The Director's key derives the
// encryption conversation key AND signs the request, so Nactor can attribute it.
//
// Secrets are read from a file or stdin — NEVER argv (shell history is not a
// vault). The Director's nsec comes from DIRECTOR_NSEC in the env.
//
//   # import Luke's role key as an in-memory identity on the live Nactor:
//   DIRECTOR_NSEC=nsec1… node nactor/issue-credential.mjs \
//     --nactor <nactor-npub> --name luke --type role-key \
//     --secret-file ./luke.nsec --url https://nact.nave.pub/api
//
//   # or print the payload (no --url) to inspect / PUT by hand:
//   … --secret-file ./anthropic.key --type provider --target credential:anthropic
//
//   # revoke (no secret): --name luke --revoke --url …
//
// Reads the Nactor npub from --nactor, or from --url's /api/health.
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { finalizeEvent, getPublicKey, nip19, nip44 } from 'nostr-tools'
import { loadSecret } from '../src/util/secret.mjs'

function arg(name, def) { const i = process.argv.indexOf('--' + name); return i > 0 ? process.argv[i + 1] : def }
const has = name => process.argv.includes('--' + name)
const die = m => { console.error('error: ' + m); process.exit(1) }

const name = arg('name'); if (!name) die('--name required')
const type = arg('type', 'secret')
const target = arg('target', null)
const url = arg('url', null)          // if set, issue the signed PUT; else print payload
const revoke = has('revoke')

const dsk = loadSecret(process.env.DIRECTOR_NSEC || '')
if (!dsk) die('DIRECTOR_NSEC (nsec1… or 64-hex) must be set in the environment')

function toPub(v) {
  const raw = (v || '').trim()
  if (raw.startsWith('npub1')) return nip19.decode(raw).data
  if (/^[0-9a-f]{64}$/i.test(raw)) return raw.toLowerCase()
  return null
}

async function nactorPub() {
  const n = arg('nactor'); if (n) return toPub(n)
  if (url) {
    const h = await fetch(url.replace(/\/$/, '') + '/health').then(r => r.json())
    if (h?.nactorNpub) return toPub(h.nactorNpub)
  }
  die('provide --nactor <npub> (or --url so it can be read from /api/health)')
}

async function readSecret() {
  const f = arg('secret-file')
  if (f) return readFileSync(f, 'utf8').trim()
  if (!process.stdin.isTTY) { let s = ''; for await (const c of process.stdin) s += c; return s.trim() }
  die('provide the secret via --secret-file <path> or piped stdin (never argv)')
}

const sha256hex = s => createHash('sha256').update(s).digest('hex')
async function nip98(method, u, bodyStr) {
  const tags = [['u', u], ['method', method]]
  if (bodyStr) tags.push(['payload', sha256hex(bodyStr)])
  const ev = finalizeEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), tags, content: '' }, dsk)
  return 'Nostr ' + Buffer.from(JSON.stringify(ev)).toString('base64')
}

async function main() {
  let body
  if (revoke) {
    body = { name, revoke: true }
  } else {
    const npub = await nactorPub()
    const secret = await readSecret()
    if (!secret) die('empty secret')
    if (type === 'role-key' && !loadSecret(secret)) die('type role-key but the secret is not a usable nsec/hex')
    const ck = nip44.getConversationKey(dsk, npub)     // Director → Nactor shared key
    const enc = nip44.encrypt(secret, ck)
    body = { name, type, ...(target ? { target } : {}), enc }
  }

  if (!url) { console.log(JSON.stringify(body, null, 2)); return }

  const u = url.replace(/\/$/, '') + '/credential'
  const s = JSON.stringify(body)
  const r = await fetch(u, { method: 'PUT', headers: { authorization: await nip98('PUT', u, s), 'content-type': 'application/json' }, body: s })
  const out = await r.json().catch(() => ({}))
  if (!r.ok) die(`PUT ${r.status}: ${out.error || ''}`)
  console.log(`director ${nip19.npubEncode(getPublicKey(dsk)).slice(0, 14)}… → ${revoke ? 'revoked' : 'imported'} '${name}'` + (out.type ? ` (${out.type})` : ''))
  if (out.credentials) console.log('credentials now:', out.credentials.map(c => `${c.name}:${c.type}`).join(', ') || '(none)')
}
main().catch(e => die(e?.message || String(e)))
