// Minimal NIP-98 (HTTP Auth over nostr) verifier.
// The client signs a kind-27235 event pinning the request; we verify the
// signature and that it matches this request, then return the signer's pubkey —
// the caller checks it against the authorized Director set.
import { verifyEvent } from 'nostr-tools'
import { createHash } from 'node:crypto'

const sha256hex = b => createHash('sha256').update(b).digest('hex')
const tagVal = (ev, n) => (ev.tags.find(t => t[0] === n) || [])[1]

// Returns the signer's pubkey if the token is valid for (method, path, body),
// else null. `path` is the request pathname (we compare pathnames, since the
// public URL differs from the internal one behind the reverse proxy).
export function verifyNip98(authHeader, method, path, bodyRaw, { maxAgeSec = 60 } = {}) {
  if (typeof authHeader !== 'string' || !authHeader.startsWith('Nostr ')) return null
  let ev
  try { ev = JSON.parse(Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8')) } catch { return null }
  if (!ev || ev.kind !== 27235) return null
  if (!verifyEvent(ev)) return null                                 // id + signature
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - (ev.created_at || 0)) > maxAgeSec) return null // freshness
  if ((tagVal(ev, 'method') || '').toUpperCase() !== method.toUpperCase()) return null
  let uPath
  try { uPath = new URL(tagVal(ev, 'u')).pathname } catch { return null }
  if (uPath !== path) return null
  if (bodyRaw && bodyRaw.length) {                                  // bind the body
    if (tagVal(ev, 'payload') !== sha256hex(bodyRaw)) return null
  }
  return ev.pubkey
}
