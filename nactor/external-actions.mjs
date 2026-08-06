// Durable external-actuator approval queue (AD-12).
// Nact approves exact bytes owned by another runtime; it never receives that runtime's signer.

import { createHash } from 'node:crypto'
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { getEventHash, verifyEvent } from 'nostr-tools'

const HEX32 = /^[0-9a-f]{32}$/
const HEX64 = /^[0-9a-f]{64}$/
const INSTANCE = /^[a-z0-9][a-z0-9._-]{1,63}$/i
const fail = (message, status = 400) => { const error = new Error(message); error.status = status; throw error }
const canonicalDecision = (proposalId, fingerprint, verb) => JSON.stringify({ proposal_id: proposalId, fingerprint, verb })
const approvalUrl = (instance, proposalId) => `nvoy://outbound/${encodeURIComponent(instance)}/${proposalId}`

function exactTagMap(tags) {
  if (!Array.isArray(tags) || tags.length !== 3 || tags.some(tag => !Array.isArray(tag) || tag.length !== 2 || typeof tag[0] !== 'string' || typeof tag[1] !== 'string')) fail('decision tag schema is not closed')
  const out = new Map()
  for (const tag of tags) {
    if (out.has(tag[0]) || !['u', 'method', 'payload'].includes(tag[0])) fail('decision tag schema is not closed')
    out.set(tag[0], tag[1])
  }
  return out
}

export function verifyExternalDecision(event, proposal, { directors, nowMs = Date.now(), maxAgeMs = 5 * 60 * 1000 } = {}) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) fail('signed decision is missing')
  const keys = Object.keys(event).sort(), expected = ['content', 'created_at', 'id', 'kind', 'pubkey', 'sig', 'tags']
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) fail('decision event schema is not closed')
  if (!Array.isArray(directors) || !directors.includes(event.pubkey)) fail('decision signer is not a Director', 403)
  if (event.kind !== 27235 || event.content !== '' || !Number.isInteger(event.created_at)) fail('decision event shape is invalid')
  const age = nowMs - event.created_at * 1000
  if (age < -30_000 || age > maxAgeMs) fail('decision is stale or future-dated')
  const tags = exactTagMap(event.tags)
  const verbs = ['approve', 'reject']
  const matchingVerb = verbs.find(verb => tags.get('payload') === createHash('sha256').update(canonicalDecision(proposal.proposal_id, proposal.fingerprint, verb)).digest('hex'))
  if (!matchingVerb || tags.get('u') !== approvalUrl(proposal.instance, proposal.proposal_id) || tags.get('method') !== 'POST') fail('decision does not bind the exact proposal')
  if (event.id !== getEventHash(event) || !verifyEvent(JSON.parse(JSON.stringify(event)))) fail('decision signature is invalid')
  return Object.freeze({ verb: matchingVerb, event: JSON.parse(JSON.stringify(event)) })
}

export function externalActionStore(path, { now = () => Date.now() } = {}) {
  const records = new Map()
  if (existsSync(path)) {
    const st = lstatSync(path)
    if (!st.isFile() || st.isSymbolicLink()) fail('external action store must be a regular file', 500)
    let rows
    try { rows = JSON.parse(readFileSync(path, 'utf8')) } catch { fail('external action store is invalid', 500) }
    if (!Array.isArray(rows)) fail('external action store is invalid', 500)
    for (const row of rows) if (row?.key && row?.proposal) records.set(row.key, row)
  }
  const persist = () => {
    mkdirSync(dirname(path), { recursive: true })
    const tmp = `${path}.${process.pid}.tmp`
    writeFileSync(tmp, JSON.stringify([...records.values()]), { mode: 0o600 })
    const file = openSync(tmp, 'r'); try { fsyncSync(file) } finally { closeSync(file) }
    renameSync(tmp, path)
    const parent = openSync(dirname(path), 'r'); try { fsyncSync(parent) } finally { closeSync(parent) }
  }
  const keyFor = (participant, id) => `${participant}:${id}`
  const normalize = (input, participant) => {
    const allowed = ['version', 'proposal_id', 'instance', 'fingerprint', 'action', 'content', 'recipient', 'context', 'created_at_ms', 'expires_at_ms']
    if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !allowed.includes(key)) ||
        input.version !== 1 || !HEX32.test(String(input.proposal_id || '')) || !INSTANCE.test(String(input.instance || '')) ||
        !HEX64.test(String(input.fingerprint || '')) || input.action !== 'nostr-private-reply' ||
        typeof input.content !== 'string' || !input.content.trim() || Buffer.byteLength(input.content) > 4000 ||
        typeof input.recipient !== 'string' || input.recipient.length > 160 || typeof input.context !== 'string' || input.context.length > 1000 ||
        !Number.isFinite(input.created_at_ms) || !Number.isFinite(input.expires_at_ms)) fail('external proposal shape is invalid')
    const t = now()
    if (input.created_at_ms > t + 30_000 || input.created_at_ms < t - 5 * 60_000 || input.expires_at_ms <= t || input.expires_at_ms > t + 15 * 60_000) fail('external proposal timing is invalid')
    return Object.freeze({ ...input, participant, approval_url: approvalUrl(input.instance, input.proposal_id) })
  }
  return {
    propose(input, participant) {
      if (!HEX64.test(String(participant || ''))) fail('participant is invalid', 403)
      const proposal = normalize(input, participant), key = keyFor(participant, proposal.proposal_id)
      const collision = [...records.values()].find(row => row.proposal.instance === proposal.instance && row.proposal.proposal_id === proposal.proposal_id && row.key !== key)
      if (collision) fail('instance proposal id belongs to another participant', 409)
      const prior = records.get(key)
      if (prior) {
        if (JSON.stringify(prior.proposal) !== JSON.stringify(proposal)) fail('proposal id was reused with different bytes', 409)
        return prior
      }
      const row = { key, proposal, state: 'pending', decision: null, updated_at_ms: now() }
      records.set(key, row); persist(); return row
    },
    listPending() {
      const t = now()
      return [...records.values()].filter(row => row.state === 'pending' && row.proposal.expires_at_ms > t).map(row => row.proposal)
    },
    decide(participant, proposalId, event, directors) {
      const row = records.get(keyFor(participant, proposalId))
      if (!row || row.state !== 'pending' || row.proposal.expires_at_ms <= now()) fail('proposal is missing or expired', 404)
      const decision = verifyExternalDecision(event, row.proposal, { directors, nowMs: now() })
      row.state = decision.verb === 'approve' ? 'approved' : 'rejected'
      row.decision = decision.event; row.updated_at_ms = now(); persist(); return row
    },
    decideExact(instance, proposalId, event, directors) {
      const matches = [...records.values()].filter(row => row.proposal.instance === instance && row.proposal.proposal_id === proposalId)
      if (matches.length !== 1) fail('proposal is missing or ambiguous', 404)
      return this.decide(matches[0].proposal.participant, proposalId, event, directors)
    },
    result(participant, proposalId) {
      const row = records.get(keyFor(participant, proposalId))
      if (!row) fail('proposal is not found', 404)
      return { state: row.state, proposal_id: proposalId, fingerprint: row.proposal.fingerprint, decision: row.decision }
    },
  }
}

export { approvalUrl, canonicalDecision }
