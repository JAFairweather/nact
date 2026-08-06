import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import { approvalUrl, canonicalDecision, externalActionStore } from './external-actions.mjs'

let n = 0, pass = 0
const t = (name, fn) => { n++; try { fn(); pass++; console.log(`ok - ${name}`) } catch (e) { console.error(`FAIL - ${name}\n  ${e.stack || e}`) } }
const dir = mkdtempSync(join(tmpdir(), 'nact-external-')), path = join(dir, 'actions.json')
let clock = 1_800_000_000_000
const participant = 'a'.repeat(64), proposalId = 'b'.repeat(32), fingerprint = 'c'.repeat(64)
const proposal = { version: 1, proposal_id: proposalId, instance: 'codex-jaf', fingerprint, action: 'nostr-private-reply',
  content: 'Exact reply.', recipient: 'jaf via waggle-test', context: 'Receipt-bound response', created_at_ms: clock, expires_at_ms: clock + 600_000 }
const directorSk = generateSecretKey(), director = getPublicKey(directorSk), foreignSk = generateSecretKey()
const decision = (verb = 'approve', sk = directorSk, mutate = {}) => {
  const pubkey = getPublicKey(sk), body = canonicalDecision(proposalId, fingerprint, verb)
  return finalizeEvent({ pubkey, kind: 27235, created_at: clock / 1000, content: '', tags: [
    ['u', approvalUrl(proposal.instance, proposalId)], ['method', 'POST'], ['payload', createHash('sha256').update(body).digest('hex')],
  ], ...mutate }, sk)
}
const store = externalActionStore(path, { now: () => clock })
t('activated participant can queue one inert exact proposal', () => assert.equal(store.propose(proposal, participant).state, 'pending'))
t('the durable queue survives restart', () => assert.equal(externalActionStore(path, { now: () => clock }).listPending()[0].fingerprint, fingerprint))
t('idempotent replay returns the same proposal', () => assert.equal(store.propose(proposal, participant).proposal.fingerprint, fingerprint))
t('same id with different bytes is refused', () => assert.throws(() => store.propose({ ...proposal, content: 'changed' }, participant), /reused/))
t('another participant cannot collide with the same instance proposal id', () => assert.throws(() => store.propose(proposal, '9'.repeat(64)), /another participant/))
t('foreign Director signature is refused without draining', () => {
  assert.throws(() => store.decide(participant, proposalId, decision('approve', foreignSk), [director]), /not a Director/)
  assert.equal(store.listPending().length, 1)
})
t('wrong fingerprint decision is refused', () => {
  const wrong = canonicalDecision(proposalId, 'd'.repeat(64), 'approve')
  const event = finalizeEvent({ pubkey: director, kind: 27235, created_at: clock / 1000, content: '', tags: [
    ['u', approvalUrl(proposal.instance, proposalId)], ['method', 'POST'], ['payload', createHash('sha256').update(wrong).digest('hex')],
  ] }, directorSk)
  assert.throws(() => store.decide(participant, proposalId, event, [director]), /exact proposal/)
})
t('one exact Director signature approves and is retrievable only under the participant key', () => {
  const event = decision(), row = store.decideExact(proposal.instance, proposalId, event, [director])
  assert.equal(row.state, 'approved'); assert.equal(store.result(participant, proposalId).decision.id, event.id)
  assert.throws(() => store.result('e'.repeat(64), proposalId), /not found/)
})
t('persisted decision is a signed event, not a boolean invented by Nact', () => {
  const disk = JSON.parse(readFileSync(path, 'utf8')); assert.equal(disk[0].decision.kind, 27235); assert.ok(disk[0].decision.sig)
})
t('an approved decision is single-use', () => assert.throws(() => store.decideExact(proposal.instance, proposalId, decision(), [director]), /missing or expired/))
t('expired proposal cannot be decided', () => {
  const id = 'f'.repeat(32); store.propose({ ...proposal, proposal_id: id, created_at_ms: clock, expires_at_ms: clock + 1 }, participant)
  clock += 2
  const body = canonicalDecision(id, fingerprint, 'approve')
  const event = finalizeEvent({ pubkey: director, kind: 27235, created_at: Math.floor(clock / 1000), content: '', tags: [
    ['u', approvalUrl(proposal.instance, id)], ['method', 'POST'], ['payload', createHash('sha256').update(body).digest('hex')],
  ] }, directorSk)
  assert.throws(() => store.decide(participant, id, event, [director]), /expired/)
})
t('runtime routes keep submission/retrieval participant-bound and decisions Director-signed', () => {
  const source = readFileSync(join(process.cwd(), 'nactor', 'nactor.mjs'), 'utf8')
  assert.match(source, /path === '\/api\/propose-external'[\s\S]*activatedPubs\(\)\.has\(pubkey\)[\s\S]*externalActions\.propose\(body, pubkey\)/)
  assert.match(source, /path === '\/api\/external-approval' && req\.method === 'POST'[\s\S]*externalActions\.result\(pubkey, String\(body\.proposal_id/)
  assert.match(source, /path === '\/api\/decide-external'[\s\S]*externalActions\.decideExact[\s\S]*directorPubs/)
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
