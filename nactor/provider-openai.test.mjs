// Self-test for the broker's OpenAI provider. Plain node, no network, no real key.
//   node nactor/provider-openai.test.mjs
import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { openaiProvider, OPENAI_PATHS } from './provider-openai.mjs'

const CRED = 'test-credential-not-a-key'
const build = body => openaiProvider.build(body, CRED)

// 1. the credential name is the one a Director grants as `credential:openai`
assert.equal(openaiProvider.credential, 'openai')

// 2. a chat completion goes to the pinned host with the key as a bearer token, and nowhere else
let t = build({ path: '/v1/chat/completions', method: 'POST', body: { model: 'm' } })
assert.equal(t.url, 'https://api.openai.com/v1/chat/completions')
assert.deepEqual(t.headers, { authorization: `Bearer ${CRED}`, 'content-type': 'application/json' })
assert.equal(build({ path: '/v1/responses' }).url, 'https://api.openai.com/v1/responses', 'method defaults to POST')

// 3. every other path is refused: the key reaches more than text generation, the broker does not
for (const p of ['', '/v1/', '/v1/files', '/v1/images/generations', '/v1/fine_tuning/jobs', '/v1/organization/admin_api_keys',
  '/v1/chat/completions/../files', '/v1/chat/completions?x=1', '/v1/chat/completions/abc', '//evil.example/v1/chat/completions',
  '@evil.example/v1/chat/completions', 'https://evil.example/v1/chat/completions']) {
  assert.throws(() => build({ path: p }), /not permitted for openai/, `path refused: ${p}`)
}
assert.deepEqual(OPENAI_PATHS, ['/v1/chat/completions', '/v1/responses'])

// 4. only POST: no listing or deleting stored completions through the broker
for (const m of ['GET', 'DELETE', 'PUT', 'PATCH', 'get']) {
  assert.throws(() => build({ path: '/v1/chat/completions', method: m }), /method .* not permitted for openai/, `method refused: ${m}`)
}
assert.equal(build({ path: '/v1/chat/completions', method: 'post' }).url, 'https://api.openai.com/v1/chat/completions')

// 5. the caller cannot repoint the host; only the operator's env can (tests, egress proxy)
assert.equal(build({ path: '/v1/chat/completions', base: 'https://evil.example', url: 'https://evil.example' }).url, 'https://api.openai.com/v1/chat/completions')
process.env.NACT_BROKER_BASE_OPENAI = 'http://127.0.0.1:9/'
assert.equal(build({ path: '/v1/chat/completions' }).url, 'http://127.0.0.1:9/v1/chat/completions')
delete process.env.NACT_BROKER_BASE_OPENAI

// 6. the broker registers it under the name `openai`, and npm test runs this file
const nactor = readFileSync(new URL('./nactor.mjs', import.meta.url), 'utf8')
assert.match(nactor, /import \{ openaiProvider \} from '\.\/provider-openai\.mjs'/)
assert.match(nactor, /^  openai: openaiProvider,$/m)
// 7. no key can arrive by env: openai is grant-only (not in the boot-time env fallback table)
const boot = nactor.slice(nactor.indexOf('const BOOTSTRAP_CRED_ENV'), nactor.indexOf('}', nactor.indexOf('const BOOTSTRAP_CRED_ENV')))
assert.ok(boot.length > 0 && !/openai/i.test(boot), 'openai is not in BOOTSTRAP_CRED_ENV')
assert.match(readFileSync(new URL('../package.json', import.meta.url), 'utf8'), /node nactor\/provider-openai\.test\.mjs/)

console.log('provider-openai.test.mjs: all pass')
