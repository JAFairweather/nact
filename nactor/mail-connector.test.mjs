// Offline test for the mail connector (nactor/connectors/mail.mjs + the
// /api/connector/mail route): a loopback fake IMAP server stands in for
// imap.gmail.com — plain node, no network beyond 127.0.0.1, no real mailbox.
//   node nactor/mail-connector.test.mjs
//
// Proves the connector spec (docs/connectors.md) end to end:
//   • auth axis — app-password LOGIN and XOAUTH2 (named oauth_cred bundle),
//     strategy selected by the credential's VALUE, re-mint-once on auth failure
//   • verb axis — list / search / headers / body, shaped rows, newest-first,
//     limits, body preview extraction (multipart, QP, base64, HTML stripped)
//   • the READ-ONLY guarantee AT THE WIRE — the fake server records every
//     command of every session, and the audit asserts EXAMINE (never SELECT),
//     BODY.PEEK (never BODY[…]), and no write verb ever crossed the socket
//   • the route — NIP-98 gate, Director/activated-identity authorization,
//     credential delivery via PUT /api/credential (NIP-44), error mapping,
//     and that no response ever carries the password.

import assert from 'node:assert'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { finalizeEvent, generateSecretKey, getPublicKey, nip19, nip44 } from 'nostr-tools'
import { runMailVerb, resolveAuth, authStrategy, shapeBodyText, MAIL_VERBS } from './connectors/mail.mjs'

// ---------------------------------------------------------------------------
// A loopback fake IMAP server: just enough IMAP4rev1 for imapflow's read path.
// Dumb by design — search results are scripted, not evaluated — so every
// assertion about BEHAVIOR lives in the test, and the transcript (every line
// every client ever sent) is the read-only proof.

const unq = s => (s.startsWith('"') && s.endsWith('"')) ? s.slice(1, -1) : s
const toks = s => (s.match(/"[^"]*"|\S+/g) || []).map(unq)

class FakeImap {
  constructor({ users = {}, tokens = [], mailboxes = ['INBOX'], messages = [], searchResult = null, blackhole = null } = {}) {
    this.users = users                    // user → password accepted by LOGIN
    this.tokens = new Set(tokens)         // access tokens accepted by XOAUTH2
    this.mailboxes = mailboxes
    this.messages = messages              // [{ uid, flags[], date, subject, fromName, fromMbox, fromHost, size, text }]
    this.searchResult = searchResult      // scripted uids for UID SEARCH (default: all)
    this.blackhole = blackhole            // regex of client lines to swallow (timeout test)
    this.transcript = []                  // every client line, all sessions
    this.server = net.createServer(sock => this.session(sock))
  }
  async listen() {
    await new Promise(r => this.server.listen(0, '127.0.0.1', r))
    this.port = this.server.address().port
    return this
  }
  close() { this.server.close() }
  msgByUid(uid) { return this.messages.find(m => m.uid === uid) }
  seqOf(uid) { return [...this.messages.map(m => m.uid)].sort((a, b) => a - b).indexOf(uid) + 1 }

  session(sock) {
    const w = s => { try { sock.write(s + '\r\n') } catch {} }
    const state = { awaitingBreakerTag: null }
    w('* OK NactFakeImap ready')
    let buf = ''
    sock.on('data', d => {
      buf += d.toString('utf8')
      let i
      while ((i = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2)
        this.handle(sock, w, state, line)
      }
    })
    sock.on('error', () => {})
  }

  handle(sock, w, state, line) {
    this.transcript.push(line)
    if (this.blackhole && this.blackhole.test(line)) return          // swallow → client waits forever
    if (state.awaitingBreakerTag) {                                   // SASL error continuation
      w(`${state.awaitingBreakerTag} NO [AUTHENTICATIONFAILED] invalid token`)
      state.awaitingBreakerTag = null
      return
    }
    const m = line.match(/^(\S+)\s+([\s\S]+)$/)
    if (!m) return
    const [, tag, rest] = m
    const cmd = rest.split(' ')[0].toUpperCase()

    if (cmd === 'CAPABILITY') {
      w('* CAPABILITY IMAP4rev1 AUTH=XOAUTH2')
      return w(`${tag} OK CAPABILITY completed`)
    }
    if (cmd === 'LOGIN') {
      const [, user, pass] = toks(rest)
      if (this.users[user] === pass) return w(`${tag} OK LOGIN completed`)
      return w(`${tag} NO [AUTHENTICATIONFAILED] bad credentials`)
    }
    if (cmd === 'AUTHENTICATE') {
      const [, mech, b64] = toks(rest)
      if ((mech || '').toUpperCase() !== 'XOAUTH2') return w(`${tag} BAD unsupported mechanism`)
      const payload = Buffer.from(b64 || '', 'base64').toString('utf8')
      const pm = payload.match(/^user=([^\x01]*)\x01auth=Bearer ([^\x01]*)\x01\x01$/)
      if (pm && this.users[pm[1]] !== undefined && this.tokens.has(pm[2])) return w(`${tag} OK AUTHENTICATE completed`)
      state.awaitingBreakerTag = tag                                  // '+ <b64 err>' → client sends breaker → NO
      return w('+ ' + Buffer.from('{"status":"401"}').toString('base64'))
    }
    if (cmd === 'LIST') {
      const [, , pattern] = toks(rest)
      if (pattern === '') w('* LIST (\\Noselect) "/" ""')
      else for (const box of this.mailboxes) w(`* LIST (\\HasNoChildren) "/" "${box}"`)
      return w(`${tag} OK LIST completed`)
    }
    if (cmd === 'LSUB') {                                             // legacy subscription list — read-only, sent by imapflow list()
      for (const box of this.mailboxes) w(`* LSUB () "/" "${box}"`)
      return w(`${tag} OK LSUB completed`)
    }
    if (cmd === 'EXAMINE') {
      const [, box] = toks(rest)
      if (!this.mailboxes.includes(box)) return w(`${tag} NO no such mailbox`)
      w(`* ${this.messages.length} EXISTS`)
      w('* 0 RECENT')
      w('* OK [UIDVALIDITY 42] UIDs valid')
      w(`* OK [UIDNEXT ${Math.max(0, ...this.messages.map(x => x.uid)) + 1}] next uid`)
      w('* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)')
      return w(`${tag} OK [READ-ONLY] EXAMINE completed`)
    }
    if (/^UID\s+SEARCH/i.test(rest)) {
      const uids = this.searchResult ?? this.messages.map(x => x.uid)
      w(`* SEARCH ${uids.join(' ')}`.trimEnd())
      return w(`${tag} OK UID SEARCH completed`)
    }
    if (/^UID\s+FETCH/i.test(rest)) {
      const fm = rest.match(/^UID\s+FETCH\s+(\S+)\s+\((.+)\)$/i)
      if (!fm) return w(`${tag} BAD parse`)
      const uids = fm[1].split(',').map(Number)
      const wantBody = /BODY\.PEEK\[TEXT\]/i.test(fm[2])
      for (const uid of uids) {
        const msg = this.msgByUid(uid)
        if (!msg) continue
        if (wantBody) {
          const payload = Buffer.from(msg.text.replace(/\n/g, '\r\n'), 'utf8')
          sock.write(`* ${this.seqOf(uid)} FETCH (UID ${uid} BODY[TEXT] {${payload.length}}\r\n`)
          sock.write(payload)
          sock.write(')\r\n')
        } else {
          const from = `(${msg.fromName ? `"${msg.fromName}"` : 'NIL'} NIL "${msg.fromMbox}" "${msg.fromHost}")`
          const env = `("${msg.date}" "${msg.subject}" (${from}) NIL NIL ((NIL NIL "james" "example.com")) NIL NIL NIL "<${uid}@fake>")`
          w(`* ${this.seqOf(uid)} FETCH (UID ${uid} FLAGS (${msg.flags.join(' ')}) ENVELOPE ${env} RFC822.SIZE ${msg.size})`)
        }
      }
      return w(`${tag} OK UID FETCH completed`)
    }
    if (cmd === 'LOGOUT') {
      w('* BYE NactFakeImap out')
      w(`${tag} OK LOGOUT completed`)
      return sock.end()
    }
    if (cmd === 'NOOP') return w(`${tag} OK NOOP completed`)
    return w(`${tag} BAD command not understood`)                     // anything else fails LOUDLY
  }
}

// The mailbox fixture. uid 102's body is a QP multipart with an HTML
// alternative AND a base64 attachment — the preview must pick the plain part.
const MULTIPART_TEXT = [
  '--BOUND1',
  'Content-Type: multipart/alternative; boundary=BOUND2',
  '',
  '--BOUND2',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: quoted-printable',
  '',
  'Caf=C3=A9 plans =E2=82=AC5 =',
  'still on.',
  '--BOUND2',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body><p>Caf&eacute; plans</p></body></html>',
  '--BOUND2--',
  '--BOUND1',
  'Content-Type: application/pdf; name="a.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  'JVBERi0xLjQKJcTl8uXrp',
  '--BOUND1--',
].join('\n')

const MESSAGES = [
  { uid: 101, flags: ['\\Seen'], date: 'Sun, 19 Jul 2026 08:00:00 +0000', subject: 'Old news', fromName: 'Alice', fromMbox: 'alice', fromHost: 'example.com', size: 1200, text: 'plain old body' },
  { uid: 102, flags: [], date: 'Mon, 20 Jul 2026 09:30:00 +0000', subject: 'Multipart hello', fromName: 'Bob', fromMbox: 'bob', fromHost: 'example.com', size: 4096, text: MULTIPART_TEXT },
  { uid: 105, flags: [], date: 'Tue, 21 Jul 2026 07:15:00 +0000', subject: 'Newest', fromName: '', fromMbox: 'carol', fromHost: 'example.com', size: 900, text: 'newest body' },
]

const PASS_CRED = (fake) => ({ host: '127.0.0.1', port: fake.port, secure: false, user: 'james', pass: 'app-pass' })

async function run() {
  // -------------------------------------------------------------------------
  // A. Pure units — no server, no socket.

  // A1: auth strategy is chosen by the credential's VALUE; explicit wins.
  assert.equal(authStrategy({ pass: 'x' }), 'password')
  assert.equal(authStrategy({ oauth_cred: 'gworkspace' }), 'oauth')
  assert.equal(authStrategy({ refresh_token: 'rt' }), 'oauth')
  assert.equal(authStrategy({ auth: 'password', refresh_token: 'rt' }), 'password', 'explicit auth wins')
  assert.equal(authStrategy({ auth: 'oauth', pass: 'x' }), 'oauth', 'explicit auth wins')
  assert.throws(() => authStrategy({}), /no auth strategy/)
  assert.throws(() => authStrategy({ auth: 'kerberos' }), /unknown auth/)
  console.log('✓ auth strategy: explicit wins, else inferred (pass ⇒ password, oauth_cred/refresh_token ⇒ oauth)')

  // A2: resolveAuth — password path returns the pair; broken creds throw.
  assert.deepEqual(await resolveAuth({ user: 'u', pass: 'p' }), { user: 'u', pass: 'p' })
  await assert.rejects(resolveAuth({ pass: 'p' }), /missing user/)
  await assert.rejects(resolveAuth({ user: 'u', auth: 'password' }), /missing pass/)

  // A3: resolveAuth — oauth path. A NAMED bundle resolves through the broker's
  // store and mints under that name (shared cache with gcal/gmail); an INLINE
  // bundle mints under the mail credential's own name.
  const mintCalls = []
  const mint = (name, bundle, { force }) => { mintCalls.push({ name, bundle, force }); return 'TOK-' + name }
  let a = await resolveAuth({ user: 'u', oauth_cred: 'gworkspace' }, { credName: 'mail-james', resolveCredential: n => n === 'gworkspace' ? '{"refresh_token":"rt"}' : null, mintToken: mint })
  assert.deepEqual(a, { user: 'u', accessToken: 'TOK-gworkspace' })
  assert.deepEqual(mintCalls[0], { name: 'gworkspace', bundle: '{"refresh_token":"rt"}', force: false })
  const inline = { user: 'u', auth: 'oauth', client_id: 'c', client_secret: 's', refresh_token: 'rt' }
  a = await resolveAuth(inline, { credName: 'mail-james', mintToken: mint })
  assert.deepEqual(mintCalls[1], { name: 'mail-james', bundle: inline, force: false })
  await assert.rejects(resolveAuth({ user: 'u', oauth_cred: 'nope' }, { mintToken: mint }), /'nope' not imported/)
  console.log('✓ resolveAuth: password pair, named oauth_cred via the broker store, inline bundle, missing bundle rejected')

  // A4: body shaping — the trimmed text/plain preview.
  assert.deepEqual(shapeBodyText('just a plain body\r\nsecond line'), { text: 'just a plain body\nsecond line', truncated: false })
  const shaped = shapeBodyText(MULTIPART_TEXT)
  assert.equal(shaped.text, 'Café plans €5 still on.', 'text/plain part picked from nested multipart; QP decoded (soft break included)')
  assert.ok(!shaped.text.includes('JVBERi'), 'attachment never leaks into the preview')
  const htmlOnly = shapeBodyText('--B\nContent-Type: text/html\n\n<p>Hello&nbsp;&amp; welcome</p><script>evil()</script>\n--B--')
  assert.equal(htmlOnly.text, 'Hello & welcome', 'html-only part stripped to text')
  const b64 = shapeBodyText('--B\nContent-Type: text/plain\nContent-Transfer-Encoding: base64\n\n' + Buffer.from('decoded fine').toString('base64') + '\n--B--')
  assert.equal(b64.text, 'decoded fine', 'base64 transfer encoding decoded')
  const bare = shapeBodyText('<html><body><div>bare html message</div></body></html>')
  assert.equal(bare.text, 'bare html message', 'single-part html message stripped')
  const capped = shapeBodyText('x'.repeat(9000), 100)
  assert.deepEqual([capped.truncated, capped.text.length], [true, 100], 'preview capped with truncated flag')
  console.log('✓ body shaping: multipart → text/plain, QP + base64 decoded, HTML stripped, attachments excluded, cap + truncated')

  // A5: request validation — every write-shaped or malformed request dies
  // BEFORE a socket opens (no server is even running yet).
  const cred = { host: 'h', user: 'u', pass: 'p' }
  const status = p => p.then(() => { throw new Error('resolved') }, e => e.status)
  assert.deepEqual(MAIL_VERBS, ['list', 'search', 'headers', 'body'], 'the whole verb surface is the four read verbs')
  for (const verb of ['append', 'store', 'expunge', 'delete', 'move', 'copy', 'create', 'rename', 'send', 'x']) {
    await assert.rejects(runMailVerb({ verb }, cred), /not permitted for mail \(read-only/, `verb '${verb}' rejected`)
    assert.equal(await status(runMailVerb({ verb }, cred)), 400)
  }
  await assert.rejects(runMailVerb({ verb: 'search', mailbox: 'INBOX\r\nA1 DELETE INBOX' }, cred), /mailbox/, 'CRLF injection in mailbox rejected')
  await assert.rejects(runMailVerb({ verb: 'search', query: { deleted: true } }, cred), /not permitted/, 'unlisted search key rejected')
  await assert.rejects(runMailVerb({ verb: 'search', query: { since: 'not-a-date' } }, cred), /date/)
  await assert.rejects(runMailVerb({ verb: 'search', limit: 0 }, cred), /limit/)
  await assert.rejects(runMailVerb({ verb: 'search', limit: 101 }, cred), /limit/)
  await assert.rejects(runMailVerb({ verb: 'headers', uids: [] }, cred), /uids/)
  await assert.rejects(runMailVerb({ verb: 'headers', uids: ['abc'] }, cred), /uid/)
  await assert.rejects(runMailVerb({ verb: 'headers', uids: Array.from({ length: 101 }, (_, i) => i + 1) }, cred), /uids/)
  await assert.rejects(runMailVerb({ verb: 'body', uid: 1, part: 'html' }, cred), /part 'html' not permitted/)
  await assert.rejects(runMailVerb({ verb: 'body', uid: 1, part: '2' }, cred), /not permitted/, 'attachment part ids rejected')
  await assert.rejects(runMailVerb({ verb: 'list' }, 'not json'), /not valid JSON/)
  await assert.rejects(runMailVerb({ verb: 'list' }, '{"user":"u","pass":"p"}'), /missing host/)
  await assert.rejects(runMailVerb({ verb: 'list' }, '{"host":"h","user":"u"}'), /no auth strategy/)
  console.log('✓ validation: write verbs, protocol injection, unlisted search keys, bad limits/uids/parts, broken credentials — all 4xx before any socket')

  // -------------------------------------------------------------------------
  // B. The wire — real imapflow against the fake server.

  const fake = await new FakeImap({ users: { james: 'app-pass' }, tokens: ['TOK-GOOD'], mailboxes: ['INBOX', 'Archive'], messages: MESSAGES }).listen()

  // B1: list
  let out = await runMailVerb({ verb: 'list' }, PASS_CRED(fake), { timeoutMs: 5000 })
  assert.deepEqual(out.mailboxes.map(b => b.path), ['INBOX', 'Archive'])
  console.log('✓ list: mailboxes via LIST (app-password LOGIN)')

  // B2: search — scripted match [101,102,105]; limit 2 keeps the NEWEST two.
  out = await runMailVerb({ verb: 'search', mailbox: 'INBOX', query: { since: '2026-07-01', unseen: true }, limit: 2 }, PASS_CRED(fake), { timeoutMs: 5000 })
  assert.equal(out.total, 3, 'total reports the full match count')
  assert.deepEqual(out.messages.map(r => r.uid), [105, 102], 'limited to the newest, newest first')
  assert.deepEqual(out.messages[1], { uid: 102, from: 'Bob <bob@example.com>', subject: 'Multipart hello', date: '2026-07-20T09:30:00.000Z', unseen: true, size: 4096 }, 'rows shaped as { uid, from, subject, date, unseen, size }')
  const searchLine = fake.transcript.find(l => /UID SEARCH/i.test(l))
  assert.ok(/SINCE/i.test(searchLine) && /UNSEEN/i.test(searchLine), 'query compiled to SINCE + UNSEEN on the wire')
  console.log('✓ search: EXAMINE + UID SEARCH + envelope fetch, shaped rows, total + newest-first limit')

  // B3: headers for explicit uids
  out = await runMailVerb({ verb: 'headers', mailbox: 'INBOX', uids: [101] }, PASS_CRED(fake), { timeoutMs: 5000 })
  assert.deepEqual(out.messages.map(r => [r.uid, r.unseen, r.from]), [[101, false, 'Alice <alice@example.com>']])
  console.log('✓ headers: UID FETCH ENVELOPE/FLAGS/SIZE for explicit uids')

  // B4: body — BODY.PEEK[TEXT], shaped to the text/plain preview.
  out = await runMailVerb({ verb: 'body', mailbox: 'INBOX', uid: 102, part: 'text' }, PASS_CRED(fake), { timeoutMs: 5000 })
  assert.deepEqual(out, { mailbox: 'INBOX', uid: 102, part: 'text', text: 'Café plans €5 still on.', truncated: false })
  await assert.rejects(runMailVerb({ verb: 'body', mailbox: 'INBOX', uid: 999 }, PASS_CRED(fake), { timeoutMs: 5000 }), /999 not found/)
  console.log('✓ body: BODY.PEEK[TEXT] → trimmed text/plain preview; missing uid → not found')

  // B5: password auth failure — surfaced, and NOT retried (re-mint is oauth-only).
  const loginsBefore = fake.transcript.filter(l => / LOGIN /.test(l)).length
  await assert.rejects(runMailVerb({ verb: 'list' }, { ...PASS_CRED(fake), pass: 'WRONG' }, { timeoutMs: 5000 }), /authentication failed/)
  assert.equal(fake.transcript.filter(l => / LOGIN /.test(l)).length, loginsBefore + 1, 'exactly one LOGIN attempt for a bad password')
  console.log('✓ app-password auth failure: one attempt, clean 502-class error')

  // B6: XOAUTH2 — named oauth_cred bundle, token minted, SASL on the wire.
  const oauthCred = { auth: 'oauth', host: '127.0.0.1', port: fake.port, secure: false, user: 'james', oauth_cred: 'gworkspace' }
  const mints = []
  out = await runMailVerb({ verb: 'list' }, oauthCred, {
    timeoutMs: 5000, credName: 'mail-james',
    resolveCredential: n => n === 'gworkspace' ? '{"client_id":"c","client_secret":"s","refresh_token":"rt"}' : null,
    mintToken: (name, bundle, { force }) => { mints.push(force); return 'TOK-GOOD' },
  })
  assert.deepEqual([out.mailboxes.length, mints], [2, [false]])
  assert.ok(fake.transcript.some(l => /AUTHENTICATE XOAUTH2 /.test(l)), 'XOAUTH2 SASL line on the wire')
  console.log('✓ oauth: named bundle → minted token → AUTHENTICATE XOAUTH2')

  // B7: oauth auth failure → re-mint ONCE with force:true → success.
  mints.length = 0
  out = await runMailVerb({ verb: 'list' }, oauthCred, {
    timeoutMs: 5000, resolveCredential: () => '{"refresh_token":"rt"}',
    mintToken: (n, b, { force }) => { mints.push(force); return force ? 'TOK-GOOD' : 'TOK-STALE' },
  })
  assert.deepEqual([out.mailboxes.length, mints], [2, [false, true]], 'second mint is forced past the cache')
  console.log('✓ oauth auth failure: exactly one forced re-mint, then success')

  // B8: …and when the forced token fails too, give up (two attempts total).
  mints.length = 0
  await assert.rejects(runMailVerb({ verb: 'list' }, oauthCred, {
    timeoutMs: 5000, resolveCredential: () => '{"refresh_token":"rt"}',
    mintToken: (n, b, { force }) => { mints.push(force); return 'TOK-DEAD' },
  }), /authentication failed/)
  assert.deepEqual(mints, [false, true], 'no third attempt')
  console.log('✓ oauth auth failure twice: re-mint once, then give up')

  // B9: hard timeout — a server that swallows EXAMINE can't hang the route.
  const tarpit = await new FakeImap({ users: { james: 'app-pass' }, messages: MESSAGES, blackhole: /EXAMINE/i }).listen()
  const t0 = Date.now()
  await assert.rejects(runMailVerb({ verb: 'search', mailbox: 'INBOX' }, PASS_CRED(tarpit), { timeoutMs: 500 }), e => e.status === 504 && /timed out/.test(e.message))
  assert.ok(Date.now() - t0 < 3000, 'timeout fired on time, socket torn down')
  tarpit.close()
  console.log('✓ timeout: Promise.race guard → 504, no dangling session')

  // -------------------------------------------------------------------------
  // C. The route — nactor.mjs wired offline (loopback relays, tmp config).

  const dirSk = generateSecretKey()
  const beatSk = generateSecretKey()
  const nactorSk = generateSecretKey()
  const hex = sk => Buffer.from(sk).toString('hex')
  process.env.NACT_PORT = '0'
  process.env.NACT_CONFIG = join(mkdtempSync(join(tmpdir(), 'nact-mail-test-')), 'config.json')
  process.env.LUKE_RELAYS = 'ws://127.0.0.1:9'                        // loopback: refused instantly, swept errors are caught
  process.env.NACT_DIRECTOR_NPUB = nip19.npubEncode(getPublicKey(dirSk))
  process.env.NACTOR_NSEC = hex(nactorSk)
  process.env.MAILBEAT_NSEC = hex(beatSk)                             // → on-box identity 'mailbeat'
  delete process.env.NACT_ENFORCE_CREDENTIAL_OWNERSHIP
  delete process.env.NACT_PROXY_TOKEN
  const { server } = await import('./nactor.mjs')
  await new Promise(r => server.listening ? r() : server.once('listening', r))
  const port = server.address().port

  const nip98 = (sk, method, url, bodyStr) => 'Nostr ' + Buffer.from(JSON.stringify(finalizeEvent({
    kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '',
    tags: [['u', url], ['method', method], ...(bodyStr ? [['payload', createHash('sha256').update(bodyStr).digest('hex')]] : [])],
  }, sk))).toString('base64')
  const call = async (sk, path, bodyObj, method = 'POST') => {
    const url = `http://127.0.0.1:${port}${path}`
    const bodyStr = bodyObj ? JSON.stringify(bodyObj) : ''
    const r = await fetch(url, { method, headers: { ...(sk ? { authorization: nip98(sk, method, url, bodyStr) } : {}), 'content-type': 'application/json' }, body: bodyStr || undefined })
    return { status: r.status, body: await r.json() }
  }
  const responses = []                                                // audited for secret leakage at the end
  const track = async p => { const r = await p; responses.push(r); return r }

  // C1: the NIP-98 gate — unsigned and non-Director/non-activated callers bounce.
  let r = await track(call(null, '/api/connector/mail', { account: 'test', verb: 'list' }))
  assert.equal(r.status, 401)
  r = await track(call(generateSecretKey(), '/api/connector/mail', { account: 'test', verb: 'list' }))
  assert.equal(r.status, 403, 'a valid signature from a stranger is not authorization')
  console.log('✓ route: NIP-98 required; unknown signers 403')

  // C2: request hygiene + missing credential.
  r = await track(call(dirSk, '/api/connector/mail', { verb: 'list' }))
  assert.deepEqual([r.status, /account required/.test(r.body.error)], [400, true])
  r = await track(call(dirSk, '/api/connector/mail', { account: 'test', verb: 'list' }))
  assert.deepEqual([r.status, /mail-test' not imported/.test(r.body.error)], [503, true])
  console.log('✓ route: account validated; unissued mail-<account> credential → 503')

  // C3: credential delivery — Director PUTs the NIP-44-encrypted mail-test scope
  // (the V1 fallback path; the grant-reader path is covered by its own test).
  const health = await (await fetch(`http://127.0.0.1:${port}/api/health`)).json()
  const nactorPub = nip19.decode(health.nactorNpub).data
  const bundle = { auth: 'password', host: '127.0.0.1', port: fake.port, secure: false, user: 'james', pass: 'app-pass' }
  const enc = nip44.encrypt(JSON.stringify(bundle), nip44.getConversationKey(dirSk, nactorPub))
  r = await track(call(dirSk, '/api/credential', { name: 'mail-test', type: 'provider-credential', target: 'credential:mail-test', enc }, 'PUT'))
  assert.equal(r.status, 200)
  assert.ok(r.body.credentials.some(c => c.name === 'mail-test'), 'credential landed in CREDS (names only in the view)')

  // C4: Director calls the connector end-to-end through the fake server.
  r = await track(call(dirSk, '/api/connector/mail', { account: 'test', verb: 'search', mailbox: 'INBOX', query: { unseen: true }, limit: 1 }))
  assert.deepEqual([r.status, r.body.total, r.body.messages.length, r.body.messages[0].uid], [200, 3, 1, 105])
  console.log('✓ route: credential via PUT /api/credential (NIP-44) → Director search end-to-end')

  // C5: an ACTIVATED identity may call; the activation is the authorization.
  r = await track(call(dirSk, '/api/activate-identity', { name: 'mailbeat' }))
  assert.equal(r.status, 200)
  r = await track(call(beatSk, '/api/connector/mail', { account: 'test', verb: 'body', mailbox: 'INBOX', uid: 102 }))
  assert.deepEqual([r.status, r.body.text], [200, 'Café plans €5 still on.'])
  console.log('✓ route: activated identity authorized (same gate as the broker)')

  // C6: write verbs are 400 at the route; error mapping holds.
  r = await track(call(beatSk, '/api/connector/mail', { account: 'test', verb: 'store', mailbox: 'INBOX' }))
  assert.deepEqual([r.status, /read-only/.test(r.body.error)], [400, true])
  console.log('✓ route: write verb → 400 read-only')

  // -------------------------------------------------------------------------
  // D. The audit — the read-only guarantee AT THE WIRE, across every session
  // of the whole run (unit, wire, and route phases share the fake servers).

  const client = fake.transcript
  assert.ok(client.length > 30, 'transcript captured the full run')
  for (const line of client) {
    assert.ok(!/\b(STORE|APPEND|EXPUNGE|MOVE|COPY|CREATE|DELETE|RENAME|SETACL|SELECT)\b/i.test(line), `write/select verb on the wire: ${line}`)
  }
  assert.ok(client.some(l => /\bEXAMINE\b/i.test(l)), 'mailboxes opened via EXAMINE')
  assert.ok(client.some(l => /BODY\.PEEK\[TEXT\]/i.test(l)), 'bodies fetched via BODY.PEEK')
  assert.ok(!client.some(l => /BODY\[/i.test(l)), 'no non-PEEK body section ever requested')
  const leaked = JSON.stringify(responses)
  assert.ok(!leaked.includes('app-pass') && !leaked.includes('TOK-GOOD') && !leaked.includes(hex(nactorSk)), 'no password/token in any route response')
  console.log('✓ wire audit: EXAMINE-only, PEEK-only, zero write verbs across every session; no secret in any response')

  fake.close()
  server.close()
  console.log('\nMAIL CONNECTOR TESTS PASS — auth strategies (password + XOAUTH2 + re-mint),')
  console.log('the four read verbs, shaping, validation, timeout, the NIP-98/activation gate,')
  console.log('and the wire-level read-only audit all verified')
  process.exit(0)
}

run().catch(e => { console.error('MAIL CONNECTOR TEST FAIL:', e?.stack || e?.message || e); process.exit(1) })
