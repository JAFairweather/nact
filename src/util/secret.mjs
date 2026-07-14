// Parse a nostr secret key from either bech32 (nsec1…) or 64-char hex.
// Returns a Uint8Array sk, or null if the input isn't a usable key.
import { nip19 } from 'nostr-tools'

export function loadSecret(v) {
  const raw = (v ?? '').trim()
  if (!raw) return null
  if (raw.startsWith('nsec1')) {
    try { return nip19.decode(raw).data } catch { return null }
  }
  if (/^[0-9a-f]{64}$/i.test(raw)) {
    return Uint8Array.from(raw.match(/.{1,2}/g).map(b => parseInt(b, 16)))
  }
  return null
}
