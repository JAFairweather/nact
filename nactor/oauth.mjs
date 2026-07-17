// OAuth2 refresh-token → access-token minting for the credential broker.
//
// Static-key providers (Anthropic, Telegram) inject a secret verbatim. OAuth2
// providers (Google Calendar) can't: the long-lived secret is a refresh_token,
// and every request needs a short-lived access_token minted from it. Nactor
// holds the OAuth client_secret + refresh_token in RAM (never returned by the
// API); this module mints the access_token, caches it until just before expiry,
// and re-mints on a forced invalidation (e.g. an upstream 401). The refresh_token
// never leaves Nactor — only the access token it produces is used, in-process.
//
// Pure + injectable (now/fetchImpl) so it can be unit-tested without real Google
// credentials. See nactor-oauth.test.mjs.

const cache = new Map()   // credential name → { access_token, expiresAt }

// Test/ops hook: drop cached tokens (used by the self-test between cases).
export function _resetOAuthCache() { cache.clear() }

// Resolve a usable access token for the named OAuth credential. credJson is the
// stored credential value: JSON with { client_id, client_secret, refresh_token,
// token_uri? }. Returns a bearer-ready access_token string.
export async function oauthAccessToken(name, credJson, opts = {}) {
  const { force = false, now = Date.now(), fetchImpl = fetch } = opts
  const hit = cache.get(name)
  // Reuse a cached token until 60s before it expires (clock-skew + in-flight buffer).
  if (!force && hit && hit.expiresAt > now + 60_000) return hit.access_token

  let c
  try { c = typeof credJson === 'string' ? JSON.parse(credJson) : credJson } catch { throw new Error(`oauth credential '${name}' is not valid JSON`) }
  const client_id = c?.client_id, client_secret = c?.client_secret, refresh_token = c?.refresh_token
  const token_uri = c?.token_uri || 'https://oauth2.googleapis.com/token'
  if (!client_id || !client_secret || !refresh_token) {
    throw new Error(`oauth credential '${name}' missing client_id/client_secret/refresh_token`)
  }

  const body = new URLSearchParams({ grant_type: 'refresh_token', client_id, client_secret, refresh_token })
  let r, j
  try {
    r = await fetchImpl(token_uri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body })
    j = await r.json().catch(() => ({}))
  } catch (e) { throw new Error(`oauth refresh transport error for '${name}': ${e?.message || e}`) }
  if (!r.ok || !j.access_token) {
    throw new Error(`oauth refresh failed for '${name}': ${r.status} ${j.error || j.error_description || ''}`.trim())
  }

  const expiresAt = now + (Number(j.expires_in || 3600) * 1000)
  cache.set(name, { access_token: j.access_token, expiresAt })
  return j.access_token
}
