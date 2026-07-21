// Offline test for the M7 MCP grant transport (nact#6): spawn the REAL BUILT
// nvoy-mcp server from the sibling nvoy repo — exactly as its own conformance
// suite (nvoy/test/mcp-conformance.mjs) does — and drive the new zero-nostr
// client + the reader's mcp sweep end-to-end against it:
//
//   local ws relay ← seeded Director grants ← this test (nact's own nipxx)
//   node <nvoy>/mcp/dist/server.js  (NVOY_NSEC = nactor's key, streamable HTTP)
//   McpGrantClient → syncCredentialGrantsMcp / startGrantReader(transport:mcp)
//
// Proves the M7 acceptance surface without touching the box or any live
// relay: issue → list → live read (max_age:0) → same CREDS semantics as the
// relay path (source 'grant', takeover/update audit events, bootstrap-env +
// director-put isolation, A2 owner precedence, env-fallback flag,
// Director-only trust via author_npub) → revocation by scope-key rotation →
// drop; PLUS the transport-only beats: error mapping (NVOY_* codes), the
// whole-service-down asymmetry (sweep throws, nothing dropped), session
// re-initialization across an nvoy-mcp restart, and the startGrantReader
// wiring (boot sweep + disabled guard).
//
//   node nactor/mcp-grant-client.test.mjs
//
// Needs the nvoy sibling repo BUILT (cd ../nvoy/mcp && npm install — the
// prepare script builds dist/). NVOY_REPO overrides the default ../../nvoy.

import assert from 'node:assert'
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { WebSocketServer } from 'ws'
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { publishScope, grant, rotateScope, newScopeKey } from './lib/nipxx.mjs'
import { Relay } from './lib/relay.mjs'
import { LocalRelay } from './lib/liverelay.mjs'
import { McpGrantClient, McpToolError, McpTransportError } from './mcp-grant-client.mjs'
import { syncCredentialGrantsMcp, startGrantReader } from './grant-reader.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const NVOY_ROOT = process.env.NVOY_REPO || join(here, '..', '..', 'nvoy')
const SERVER_JS = join(NVOY_ROOT, 'mcp', 'dist', 'server.js')
if (!existsSync(SERVER_JS)) {
  console.error(`✗ nvoy MCP server not built: ${SERVER_JS}`)
  console.error('  build it first:  cd <nvoy repo>/mcp && npm install   (prepare builds dist/)')
  console.error('  or point NVOY_REPO at a checkout that has mcp/dist/.')
  process.exit(1)
}
const sleep = ms => new Promise(r => setTimeout(r, ms))

// --- a real ws relay over the in-memory store (the nvoy server's transport is
// LiveRelay/SimplePool, so it needs an actual socket; we seed via the store
// directly). Same shape as nvoy/test/wsrelay.mjs, inlined so this test has no
// import into the sibling repo's test tree.
function startWsRelay() {
  const store = new Relay()
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 })
  wss.on('connection', ws => {
    ws.on('message', raw => {
      let msg; try { msg = JSON.parse(raw) } catch { return }
      const [type, ...rest] = msg
      if (type === 'EVENT') {
        const ev = rest[0]
        try { store.publish(ev); ws.send(JSON.stringify(['OK', ev.id, true, ''])) }
        catch (e) { ws.send(JSON.stringify(['OK', ev.id, false, `invalid: ${e.message}`])) }
      } else if (type === 'REQ') {
        const [subId, ...filters] = rest
        const seen = new Set()
        for (const f of filters) for (const ev of store.query(f))
          if (!seen.has(ev.id) && seen.add(ev.id)) ws.send(JSON.stringify(['EVENT', subId, ev]))
        ws.send(JSON.stringify(['EOSE', subId]))
      } else if (type === 'CLOSE') ws.send(JSON.stringify(['CLOSED', rest[0], '']))
    })
  })
  return new Promise(resolve => wss.on('listening', () => resolve({
    store,
    url: `ws://127.0.0.1:${wss.address().port}`,
    close: () => new Promise(r => { for (const c of wss.clients) c.terminate(); wss.close(r) }),
  })))
}

// --- spawn the real server binary on the streamable HTTP transport
function spawnServer(env, port = '0') {
  const child = spawn(process.execPath, [SERVER_JS], {
    env: { ...process.env, ...env, NVOY_HTTP_PORT: port },
    stdio: ['ignore', 'ignore', 'pipe'],
  })
  return new Promise((resolve, reject) => {
    let buf = ''
    const timer = setTimeout(() => reject(new Error(`nvoy server never announced: ${buf}`)), 10_000)
    child.stderr.on('data', chunk => {
      buf += chunk
      const m = buf.match(/ready on (http:\/\/[^ ]+\/mcp)/)
      if (m) { clearTimeout(timer); resolve({ child, url: m[1] }) }
    })
    child.on('exit', code => reject(new Error(`nvoy server exited ${code}: ${buf}`)))
  })
}
const stopChild = child => new Promise(r => {
  if (!child || child.exitCode !== null) return r()
  child.once('exit', r)
  child.kill('SIGTERM')
})

// ------------------------------------------------------------- seed offline
const ws = await startWsRelay()
const seedRelay = new LocalRelay(ws.store)

const dir = generateSecretKey()                  // the Director (publisher)
const dirPub = getPublicKey(dir)
const nactor = generateSecretKey()               // Nactor's identity — held by nvoy-mcp, NOT by this side
const nactorPub = getPublicKey(nactor)
const DIRECTORS = new Set([dirPub])

// credential:telegram-luke — the pilot credential
const tgScope = 'cred-tglk'
const tgKey = newScopeKey()
await publishScope(seedRelay, dir, { scopeId: tgScope, generation: 1, scopeKey: tgKey, payload: { value: '123456:AA-token' } })
await grant(seedRelay, dir, nactorPub, { scopeId: tgScope, generation: 1, scopeKey: tgKey, scopeName: 'credential:telegram-luke' })

// credential:google — will collide with an A2 owner-sourced entry
const ggScope = 'cred-gg'
const ggKey = newScopeKey()
await publishScope(seedRelay, dir, { scopeId: ggScope, generation: 1, scopeKey: ggKey, payload: { value: 'google-key-value' } })
await grant(seedRelay, dir, nactorPub, { scopeId: ggScope, generation: 1, scopeKey: ggKey, scopeName: 'credential:google' })

// non-credential namespaces — must pass through untouched (AD-8 strings, not enums)
for (const [sid, sname] of [['plain-scope', 'travel-prefs'], ['data-scope', 'data:contact-log']]) {
  const k = newScopeKey()
  await publishScope(seedRelay, dir, { scopeId: sid, generation: 1, scopeKey: k, payload: { hello: 'world' } })
  await grant(seedRelay, dir, nactorPub, { scopeId: sid, generation: 1, scopeKey: k, scopeName: sname })
}

// a spoofed credential grant from a NON-Director — newest, right name, wrong publisher
const mallory = generateSecretKey()
const evilKey = newScopeKey()
await publishScope(seedRelay, mallory, { scopeId: 'cred-evil', generation: 1, scopeKey: evilKey, payload: { value: 'EVIL-token' } })
await grant(seedRelay, mallory, nactorPub, { scopeId: 'cred-evil', generation: 1, scopeKey: evilKey, scopeName: 'credential:telegram-luke' })

// ------------------------------------------------------- spawn + drive
const serverEnv = { NVOY_NSEC: nip19.nsecEncode(nactor), NVOY_RELAYS: ws.url }
let { child, url } = await spawnServer(serverEnv)
const port = new URL(url).port
const client = new McpGrantClient({ url })

const events = []
const onEvent = e => events.push(e)
const eventTs = () => events.map(e => e.t).join(' ')
const logs = []
const log = l => logs.push(l)

try {
  // 1) the raw client: initialize + tools/call against the real server
  await client.connect()
  const grants = await client.listGrants()
  assert.equal(grants.length, 5, 'server lists all five seeded grants')
  const tg = grants.find(g => g.scope_name === 'credential:telegram-luke' && g.author_npub === nip19.npubEncode(dirPub))
  assert.ok(tg && tg.d === tgScope && tg.v === 1 && tg.status === 'active', 'grants_list carries { d, author_npub, scope_name, v, status }')
  console.log('✓ client: initialize + nvoy_grants_list against the real built server')

  const read = await client.readScope(tgScope, nip19.npubEncode(dirPub), { maxAge: 0 })
  assert.equal(read.data?.value, '123456:AA-token', 'nvoy_scope_read serves the payload under .data')
  assert.equal(read.v, 1, 'generation rides as v')
  console.log('✓ client: nvoy_scope_read (max_age:0) decrypts the credential payload')

  await assert.rejects(client.readScope('nope', nip19.npubEncode(dirPub)), e =>
    e instanceof McpToolError && e.code === 'NVOY_NO_GRANT', 'unknown scope maps to McpToolError NVOY_NO_GRANT')
  console.log('✓ client: tool errors map to McpToolError with the nvoy code')

  // 2) the reader sweep — same CREDS semantics as the relay path. Pre-existing
  // entries the sweep must never touch: bootstrap-env (the drained fallback),
  // director-put (V1 HTTP fallback), and an A2 owner-sourced value.
  const creds = new Map([
    ['anthropic', { type: 'secret', value: 'sk-boot', source: 'bootstrap-env' }],
    ['replicate', { type: 'secret', value: 'r8-put', source: 'director-put' }],
    ['google', { type: 'secret', value: 'owner-google-key', source: 'grant-owner', owner: 'luke' }],
  ])
  let s = await syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, log, onEvent })
  assert.deepEqual([...s.loaded].sort(), ['google', 'telegram-luke'], 'credential:* grants loaded; owner-held name counted')
  assert.equal(creds.get('telegram-luke').value, '123456:AA-token', 'value flowed through the MCP surface')
  assert.equal(creds.get('telegram-luke').source, 'grant', 'tagged grant-sourced')
  assert.equal(creds.get('telegram-luke').generation, 1, 'generation recorded from v')
  assert.equal(creds.get('google').value, 'owner-google-key', 'A2 precedence: owner-sourced value NOT clobbered')
  assert.equal(creds.get('google').source, 'grant-owner', 'owner tag intact')
  assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap-env cred untouched')
  assert.equal(creds.get('replicate').value, 'r8-put', 'director-put cred untouched')
  assert.equal(s.untrusted, 1, 'the spoofed non-Director grant counted and ignored')
  assert.equal(creds.size, 4, 'non-credential namespaces (bare + data:*) ignored')
  assert.deepEqual(s.envFallback, ['anthropic'], 'env-fallback flag: bootstrap-env creds only')
  assert.equal(eventTs(), 'grant-load', 'ONE grant-load audit event (owner + steady entries silent)')
  assert.ok(logs.some(l => l.includes('credential-grants: loaded [')), 'box-greppable sweep log line preserved')
  console.log('✓ reader (mcp): load + Director-only trust + isolation + A2 precedence + env flag + audit event')

  // 2b) steady-state re-sweep: no new audit events
  s = await syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, onEvent })
  assert.equal(eventTs(), 'grant-load', 'unchanged re-sweep is audit-silent')
  console.log('✓ reader (mcp): steady-state re-sweep is audit-silent')

  // 3) live update: Director republishes under the same key → next sweep sees
  // it (max_age:0 defeats the server's read cache — no subscribe needed)
  await publishScope(seedRelay, dir, { scopeId: tgScope, generation: 1, scopeKey: tgKey, payload: { value: '123456:AA-rotated-value' } })
  s = await syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, onEvent })
  assert.equal(creds.get('telegram-luke').value, '123456:AA-rotated-value', 'republish flows through on the next sweep')
  assert.equal(eventTs(), 'grant-load grant-update', 'value change emits grant-update')
  console.log('✓ reader (mcp): live update (republish, same key) + grant-update audit event')

  // 4) REVOCATION = the Director rotates the scope key with no survivors. The
  // server detects it on the live read (NVOY_GRANT_REVOKED) → the credential
  // drops; everything not grant-sourced survives.
  await rotateScope(seedRelay, dir, { scopeId: tgScope, generation: 1, payload: { value: 'secret' }, scopeName: 'credential:telegram-luke', survivors: [] })
  s = await syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, onEvent })
  assert.deepEqual(s.dropped, ['telegram-luke'], 'revoked credential dropped')
  assert.equal(creds.has('telegram-luke'), false, 'credential gone after revocation')
  assert.equal(creds.get('anthropic').value, 'sk-boot', 'bootstrap cred STILL untouched through a revoke')
  assert.equal(creds.get('replicate').value, 'r8-put', 'director-put cred STILL untouched')
  assert.equal(creds.get('google').value, 'owner-google-key', 'owner-sourced cred STILL untouched')
  assert.equal(eventTs(), 'grant-load grant-update grant-drop', 'revocation emits grant-drop')
  console.log('✓ reader (mcp): revocation (scope-key rotation) drops the credential; others safe')

  // 4b) next sweep: the server now REPORTS the severance in grants_list
  // (revoked-detected) — the non-active status path, no re-drop, no events
  s = await syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, onEvent })
  assert.deepEqual(s.dropped, [], 'nothing left to drop')
  assert.ok(s.stale.includes('telegram-luke'), 'severed grant counted stale via its listed status')
  assert.equal(eventTs(), 'grant-load grant-update grant-drop', 'no new audit events post-revocation')
  console.log('✓ reader (mcp): post-revocation status (revoked-detected) handled without re-drop')

  // 5) ASYMMETRY: the whole service going away must never strip a credential.
  await stopChild(child); child = null
  await assert.rejects(syncCredentialGrantsMcp({ client, creds, allowedPublishers: DIRECTORS, onEvent }),
    'a dead nvoy-mcp makes the sweep THROW (logged as sweep error), not drop')
  assert.equal(creds.get('google').value, 'owner-google-key', 'creds intact through the outage')
  assert.equal(creds.size, 3, 'nothing dropped by the outage')
  assert.equal(eventTs(), 'grant-load grant-update grant-drop', 'no audit events from the outage')
  console.log('✓ reader (mcp): service outage throws the sweep — nothing dropped (asymmetric by design)')

  // 6) RESTART: same port, new process, new sessions. The SAME client instance
  // must transparently re-initialize (its old mcp-session-id is dead).
  ;({ child } = await spawnServer(serverEnv, port))
  const grants2 = await client.listGrants()
  assert.equal(grants2.length, 5, 'stale session re-initialized across the server restart')
  console.log('✓ client: dead session re-initializes across an nvoy-mcp restart (sweeps survive redeploys)')

  // 7) startGrantReader wiring — transport 'mcp' boot sweep, no nactor key
  // anywhere on this side. telegram-luke is revoked by now; google (granted to
  // Nactor, no owner entry in this fresh map) must load as source 'grant'.
  const creds2 = new Map([['anthropic', { type: 'secret', value: 'sk-boot', source: 'bootstrap-env' }]])
  const rlogs = []
  const reader = startGrantReader({ transport: 'mcp', mcpUrl: url, creds: creds2, allowedPublishers: DIRECTORS, intervalMs: 3_600_000, log: l => rlogs.push(l) })
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline && creds2.get('google')?.source !== 'grant') await sleep(150)
  reader.stop()
  assert.equal(creds2.get('google')?.value, 'google-key-value', 'boot sweep loaded the credential over MCP')
  assert.equal(creds2.get('google')?.source, 'grant', 'source grant — same semantics end to end')
  assert.ok(rlogs.some(l => l.includes('credential-grants: transport mcp')), 'boot log announces the mcp transport (cutover verify greps this)')
  assert.ok(rlogs.some(l => l.includes('ENV FALLBACK in force for [anthropic]')), 'env-fallback flagging preserved in mcp mode')
  console.log('✓ startGrantReader(transport:mcp): boot sweep end-to-end, transport + env-fallback logs')

  // 7b) misconfiguration guard: transport mcp with no URL disables cleanly
  const dlogs = []
  const disabled = startGrantReader({ transport: 'mcp', creds: new Map([['x', { value: 'v', source: 'bootstrap-env' }]]), log: l => dlogs.push(l) })
  disabled.stop()
  assert.ok(dlogs.some(l => l.includes('reader disabled (transport mcp, no NACT_MCP_URL)')), 'disabled guard logs the reason + env fallback')
  console.log('✓ startGrantReader(transport:mcp): missing URL disables with the env-fallback warning')

  // 8) transport error surface sanity: a bad URL is a transport error, not a
  // tool error (so sweep-level catch logs it as a sweep error)
  const badClient = new McpGrantClient({ url: `http://127.0.0.1:${port}/nope`, timeoutMs: 3000 })
  await assert.rejects(badClient.callTool('nvoy_grants_list'), e => e instanceof McpTransportError,
    'non-MCP endpoint surfaces as McpTransportError')
  console.log('✓ client: non-MCP endpoint yields McpTransportError (sweep-level failure, never a drop)')
} finally {
  await client.close().catch(() => {})
  if (child) await stopChild(child)
  await ws.close()
}

console.log('\nMCP GRANT TRANSPORT TESTS PASS — real nvoy-mcp server, zero-nostr client,')
console.log('same CREDS semantics as the relay path (load, update, revoke-drop, isolation,')
console.log('Director-only trust, A2 precedence, env-fallback), outage asymmetry, session')
console.log('re-init across restart, and the startGrantReader mcp wiring all verified')
