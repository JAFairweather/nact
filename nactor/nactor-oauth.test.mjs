// Self-test for the OAuth2 token minting (oauth.mjs). Runs with plain node, no
// network, no real Google credentials — a mock fetch stands in for the token
// endpoint.  node nactor-oauth.test.mjs
import assert from 'node:assert'
import { oauthAccessToken, _resetOAuthCache } from './oauth.mjs'

let calls = 0
const mockFetch = resp => async () => { calls++; return { ok: resp.ok !== false, status: resp.status || 200, json: async () => resp.body } }
const cred = JSON.stringify({ client_id: 'cid', client_secret: 'sec', refresh_token: 'rt' })

async function run() {
  // 1. mints a token on first use
  _resetOAuthCache(); calls = 0
  let t = await oauthAccessToken('gcal', cred, { now: 1000, fetchImpl: mockFetch({ body: { access_token: 'AT1', expires_in: 3600 } }) })
  assert.equal(t, 'AT1'); assert.equal(calls, 1, 'mints once')

  // 2. serves from cache (no second network call) while fresh
  t = await oauthAccessToken('gcal', cred, { now: 2000, fetchImpl: mockFetch({ body: { access_token: 'AT2', expires_in: 3600 } }) })
  assert.equal(t, 'AT1'); assert.equal(calls, 1, 'served from cache')

  // 3. force re-mints (used on a 401)
  t = await oauthAccessToken('gcal', cred, { now: 3000, force: true, fetchImpl: mockFetch({ body: { access_token: 'AT2', expires_in: 3600 } }) })
  assert.equal(t, 'AT2'); assert.equal(calls, 2, 'force re-mints')

  // 4. a token inside the 60s expiry buffer is re-minted
  _resetOAuthCache(); calls = 0
  await oauthAccessToken('gcal', cred, { now: 0, fetchImpl: mockFetch({ body: { access_token: 'A', expires_in: 100 } }) }) // expiresAt = 100000
  t = await oauthAccessToken('gcal', cred, { now: 41000, fetchImpl: mockFetch({ body: { access_token: 'B', expires_in: 100 } }) }) // 59s left < 60s → re-mint
  assert.equal(t, 'B', 'expiring token re-minted'); assert.equal(calls, 2)

  // 5. missing required fields → error
  _resetOAuthCache()
  await assert.rejects(oauthAccessToken('gcal', JSON.stringify({ client_id: 'x' }), { fetchImpl: mockFetch({ body: {} }) }), /missing/)

  // 6. non-JSON credential → error
  await assert.rejects(oauthAccessToken('gcal', 'not json', { fetchImpl: mockFetch({ body: {} }) }), /not valid JSON/)

  // 7. token endpoint failure surfaces the provider error
  _resetOAuthCache()
  await assert.rejects(oauthAccessToken('gcal', cred, { fetchImpl: mockFetch({ ok: false, status: 400, body: { error: 'invalid_grant' } }) }), /invalid_grant/)

  console.log('OAUTH TESTS PASS — mint, cache, force-refresh, expiry buffer, and error paths all verified')
}
run().catch(e => { console.error('OAUTH TEST FAIL:', e.message); process.exit(1) })
