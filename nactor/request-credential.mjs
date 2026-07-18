// request-credential — the PROPOSE side of the credential migration.
//
// Nactor drafts a grant it needs and sends it to the Director as a gift-wrapped
// access request. It surfaces in the Director's Nvoy console as a pending
// approval (agents.mjs §6.2); the Director reviews, sets/confirms the value, and
// issues the credential-scope. Nactor's grant-reader then loads it from the
// relays. This is the WYSIWYS loop — the runtime proposes, you approve — the
// same way luke/nave became first-class granted identities.
//
// Wire shape (extends Nvoy's access_request, backward-compatibly — vanilla
// consoles ignore the extra fields):
//   { type:'access_request', purpose, scope_name, enc_value? }
// carried in a kind-24440 rumor, NIP-59 gift-wrapped to the Director's npub.
//
//   • Existing env credential (the box surfaces its current value):
//       --name telegram-luke --env TELEGRAM_LUKE_BOT_TOKEN
//     → enc_value = that value, NIP-44-encrypted to the Director (never logged).
//   • New credential (a plugin needs one; you'll paste the value at approval):
//       --name some-service --no-value
//
// Runs INSIDE the nactor container (it holds NACTOR_NSEC + the env + relays).
// Never prints a secret value.
import { finalizeEvent, getPublicKey, nip19, nip44 } from 'nostr-tools'
import { wrapEvent } from 'nostr-tools/nip59'
import { loadSecret } from '../src/util/secret.mjs'
import { LiveRelay } from './lib/liverelay.mjs'

const arg = (n, d) => { const i = process.argv.indexOf('--' + n); return i > 0 ? process.argv[i + 1] : d }
const has = n => process.argv.includes('--' + n)
const die = m => { console.error('error: ' + m); process.exit(1) }
const KIND_NVOY_MSG = 24440

const name = arg('name'); if (!name) die('--name <credential> required (e.g. telegram-luke)')
const scopeName = 'credential:' + name
const purpose = arg('purpose', `Runtime credential "${name}" for Luke — brokered, never held by consumers`)

const nsk = loadSecret(process.env.NACTOR_NSEC || ''); if (!nsk) die('NACTOR_NSEC not set in this process')
const npub = nip19.npubEncode(getPublicKey(nsk))

function toPub(v) {
  const raw = (v || '').trim()
  if (raw.startsWith('npub1')) return nip19.decode(raw).data
  if (/^[0-9a-f]{64}$/i.test(raw)) return raw.toLowerCase()
  return null
}
const directorPub = toPub(arg('director', process.env.NACT_DIRECTOR_NPUB || process.env.LUKE_MASTER_NPUB || ''))
if (!directorPub) die('provide --director <npub> (or set NACT_DIRECTOR_NPUB / LUKE_MASTER_NPUB)')

const relayUrls = (arg('relays', process.env.LUKE_RELAYS || 'wss://relay.damus.io,wss://nos.lol,wss://relay.primal.net'))
  .split(',').map(s => s.trim()).filter(Boolean)

// The OWNER the credential should be granted to — the identity that will HOLD it,
// which is NOT this runtime (the runtime proposes on the owner's behalf). Carried
// as owner_npub so the Director's console pre-selects the right grantee instead of
// defaulting to the requester. Omit for a self-request (runtime = owner).
let owner_npub
{
  const o = arg('owner')
  if (o) {
    const oh = toPub(o); if (!oh) die('--owner must be an npub1… or 64-char hex pubkey')
    owner_npub = nip19.npubEncode(oh)
  }
}

// The value: from --env <VAR> (existing env credential) or omitted (--no-value).
let enc_value
if (!has('no-value')) {
  const envVar = arg('env'); if (!envVar) die('give --env <VAR> (surface an existing value) or --no-value (Director will paste)')
  const value = (process.env[envVar] || '').trim(); if (!value) die(`env ${envVar} is empty`)
  const ck = nip44.getConversationKey(nsk, directorPub)   // Nactor → Director shared key
  enc_value = nip44.encrypt(value, ck)                     // only the Director can read it; never logged
}

const content = { type: 'access_request', purpose, scope_name: scopeName, ...(enc_value ? { enc_value } : {}), ...(owner_npub ? { owner_npub } : {}) }
const rumor = { kind: KIND_NVOY_MSG, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify(content), pubkey: getPublicKey(nsk) }
const wrap = wrapEvent(rumor, nsk, directorPub)

const relay = new LiveRelay(relayUrls)
try {
  const r = await relay.publish(wrap)
  console.log(`requested ${scopeName} — proposed to Director ${nip19.npubEncode(directorPub).slice(0, 14)}… ` +
    `(${enc_value ? 'existing value carried, encrypted' : 'value to be pasted at approval'}` +
    `${owner_npub ? `; grant to owner ${owner_npub.slice(0, 16)}…` : ''}); acks ${r.acks}/${r.of}`)
  console.log(`from Nactor ${npub.slice(0, 16)}… → approve it in the Nvoy console (Pending access requests).`)
} catch (e) { die('publish failed: ' + (e?.message || e)) }
finally { relay.close() }
