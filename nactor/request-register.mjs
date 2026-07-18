// request-register — a Nave identity asks the Director to register it as a
// first-class agent. The registration half of the propose→approve pattern:
// the identity sends a plain nvoy_request_access (kind-24440 rumor, NIP-59
// gift-wrapped to the Director); it surfaces in the Nvoy console's "Pending
// access requests", and approving it adds the identity to the Director's agent
// registry. No credential, no scope — just "please list me so you can keep us
// straight". Its published kind-0 profile then gives it a name + avatar.
//
// Runs INSIDE the nactor container, which holds the role keys (LUKE_NSEC,
// NAVE_NSEC via luke.env; BRAIN_NSEC via brain.env) and relay egress. Sign as
// the identity being registered:
//   node nactor/request-register.mjs --nsec-env BRAIN_NSEC --label Brain
import { getPublicKey, nip19 } from 'nostr-tools'
import { wrapEvent } from 'nostr-tools/nip59'
import { LiveRelay } from './lib/liverelay.mjs'

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d }
const die = m => { console.error('error: ' + m); process.exit(1) }
const KIND_NVOY_MSG = 24440

const envVar = arg('nsec-env'); if (!envVar) die('--nsec-env <VAR> required (e.g. BRAIN_NSEC)')
const raw = (process.env[envVar] || '').trim(); if (!raw) die(`env ${envVar} is empty in this process`)
const toSk = s => s.startsWith('nsec') ? nip19.decode(s).data : Uint8Array.from(s.match(/../g), h => parseInt(h, 16))
const nsk = toSk(raw)
const label = arg('label', 'this identity')
const purpose = arg('purpose', `Register ${label} as a first-class Nave identity — registry only, no delegation needed.`)

const toPub = v => { const r = (v || '').trim(); if (r.startsWith('npub1')) return nip19.decode(r).data; if (/^[0-9a-f]{64}$/i.test(r)) return r.toLowerCase(); return null }
const directorPub = toPub(arg('director', process.env.NACT_DIRECTOR_NPUB || process.env.LUKE_MASTER_NPUB || ''))
if (!directorPub) die('provide --director <npub> (or set NACT_DIRECTOR_NPUB / LUKE_MASTER_NPUB)')

const relayUrls = (arg('relays', process.env.LUKE_RELAYS || 'wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net'))
  .split(',').map(s => s.trim()).filter(Boolean)

const content = { type: 'access_request', purpose }
const rumor = { kind: KIND_NVOY_MSG, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify(content), pubkey: getPublicKey(nsk) }
const wrap = wrapEvent(rumor, nsk, directorPub)

const relay = new LiveRelay(relayUrls)
try {
  const r = await relay.publish(wrap)
  console.log(`${label}: registration request → Director ${nip19.npubEncode(directorPub).slice(0, 14)}… acks ${r.acks}/${r.of}; ` +
    `from ${nip19.npubEncode(getPublicKey(nsk)).slice(0, 16)}… → approve it in the Nvoy console (Pending access requests).`)
} catch (e) { die('publish failed: ' + (e?.message || e)) }
finally { relay.close() }
