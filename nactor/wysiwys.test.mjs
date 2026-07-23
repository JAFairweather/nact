// WYSIWYS hardening P1 (nact#7), proven offline:
//   • created_at is frozen at propose — the id shown IS the id signed
//   • the fingerprint is re-verified immediately BEFORE signing — a mutated
//     queue entry is refused without the signer ever seeing it
//   • a signer that returns different bytes is refused AFTER signing
//   • every refusal lands on the approval channel's ack (→ runtime audit)
//
//   node nactor/wysiwys.test.mjs
//
// No relay, no network: a capture approval adapter, a real custodial signer
// (real getEventHash / real Schnorr), and a spy signer for the tamper case.
import assert from 'node:assert'
import { generateSecretKey, getEventHash, nip19 } from 'nostr-tools'
import { Nact } from '../src/nact.mjs'

let n = 0, pass = 0
const t = async (name, fn) => {
  n++
  try { await fn(); pass++; console.log(`ok - ${name}`) }
  catch (e) { console.error(`FAIL - ${name}\n   ${e.stack || e.message}`) }
}

const APPROVER = 'director-1'
function captureApproval() {
  const sent = [], acks = []
  return {
    sent, acks,
    async send(p) { sent.push(p); return true },
    async parseDecision(raw) { return raw },
    isApprover(a) { return a === APPROVER },
    async ack(a) { acks.push(a) },
  }
}
const nsec = nip19.nsecEncode(generateSecretKey())
const build = (approval) => new Nact({ identities: { luke: { nsec } }, relays: [], approval })

await t('created_at is frozen at propose: the fingerprint commits to the full event', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const before = Math.floor(Date.now() / 1000)
  const { fingerprint } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'hello' } })
  const p = [...nact.pending.values()][0]
  assert.ok(p.unsigned.created_at >= before, 'created_at stamped at propose')
  assert.equal(getEventHash(p.unsigned), fingerprint, 'fingerprint == hash of the frozen event')
  assert.equal(approval.sent[0].fingerprint, fingerprint, 'the human is shown the same fingerprint')
})

await t('TAMPER: a mutated queued event is refused BEFORE the signer sees it', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'what you approved' } })
  // Simulate a compromised/buggy queue: the pending bytes change after approval
  // was requested. The fingerprint (shown to the human) still matches the OLD bytes.
  const p = nact.pending.get(id)
  p.unsigned.content = 'what you did NOT approve'
  // Spy on the signer: it must never be invoked for tampered bytes — a bunker
  // signature over them would exist even if broadcast were refused.
  let signerCalled = false
  const realSign = nact.identities.luke.signer.sign.bind(nact.identities.luke.signer)
  nact.identities.luke.signer.sign = async (ev) => { signerCalled = true; return realSign(ev) }

  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER })
  assert.equal(out.enacted, false)
  assert.equal(out.why, 'pre-sign fingerprint mismatch')
  assert.equal(signerCalled, false, 'the signer must never see tampered bytes')
  const ack = approval.acks.find(a => a.id === id)
  assert.match(ack.result.error, /diverged while pending/, 'the refusal is audited via ack')
})

await t('a signer that mutates or re-stamps is refused AFTER signing (existing gate holds)', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'faithful' } })
  const realSign = nact.identities.luke.signer.sign.bind(nact.identities.luke.signer)
  nact.identities.luke.signer.sign = async (ev) => realSign({ ...ev, created_at: ev.created_at + 60 })
  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER })
  assert.equal(out.enacted, false)
  assert.equal(out.why, 'fingerprint mismatch')
  const ack = approval.acks.find(a => a.id === id)
  assert.match(ack.result.error, /diverged from approved/)
})

await t('an untampered flow still reaches broadcast (the gates admit honest bytes)', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  // No relays configured → broadcast yields zero acceptances; reaching the
  // "no relay accepted" ack proves BOTH fingerprint gates passed.
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'honest' } })
  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER })
  assert.equal(out.why, 'broadcast failed', 'refused only at broadcast, not at either gate')
  const ack = approval.acks.find(a => a.id === id)
  assert.match(ack.result.error, /no relay accepted/)
})

await t('a non-approver cannot enact, tampered or not', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'x' } })
  const out = await nact.enact({ id, verb: 'ok', approver: 'impostor' })
  assert.equal(out.enacted, false)
  assert.equal(out.why, 'not authorized')
  assert.ok(nact.pending.has(id), 'an unauthorized attempt does not drain the queue entry')
})

// ---- P3: critical kinds cannot be one-tap approved -------------------------
await t('a CRITICAL kind refuses a one-tap enact (no confirm) and stays pending', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  // kind 0 = profile edit = critical (see inspect.mjs).
  const { id, risk } = await nact.propose({ identity: 'luke', event: { kind: 0, content: '{"name":"x"}' } })
  assert.equal(risk, 'critical')
  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER })   // one tap, no confirm
  assert.equal(out.enacted, false)
  assert.equal(out.why, 'needs confirmation')
  assert.equal(out.needsConfirm, true)
  assert.ok(nact.pending.has(id), 'the proposal survives so a confirmed retry works')
  const ack = approval.acks.find(a => a.id === id)
  assert.match(ack.result.error, /critical action — confirm explicitly/)
})

await t('a CRITICAL kind enacts WITH an explicit confirm', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 3, content: '' } })   // contact-list replace
  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER, confirm: true })
  // No relays configured → reaches broadcast (the confirm gate passed).
  assert.equal(out.why, 'broadcast failed')
  assert.match(approval.acks.find(a => a.id === id).result.error, /no relay accepted/)
  assert.equal(nact.pending.has(id), false, 'a confirmed enact drains the proposal')
})

await t('a LOW-risk kind is unaffected — one tap still enacts', async () => {
  const approval = captureApproval()
  const nact = build(approval)
  const { id } = await nact.propose({ identity: 'luke', event: { kind: 1, content: 'a note' } })
  const out = await nact.enact({ id, verb: 'ok', approver: APPROVER })   // no confirm needed
  assert.equal(out.why, 'broadcast failed')   // passed the gates, only the (absent) relays failed
})

console.log(`\n${pass}/${n} passed`)
process.exit(pass === n ? 0 : 1)
