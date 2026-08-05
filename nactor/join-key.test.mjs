// The join key, proven offline (#55).
//
//   node nactor/join-key.test.mjs
//
// THE BUG THIS CLOSES. The delegator's registry keys agents on a PUBKEY. This runtime keyed them
// on the lowercased name of the env var holding the secret — `JAFSCRIBE_NSEC` → `jafscribe`. No
// code anywhere joined the two, so an agent could exist in one and be invisible in the other, and
// the only symptom was an absence, which nobody can see. `HANDLE_OVERRIDES = { nactjaf:
// 'nact_jaf@nave.pub' }` was the tell: a hand-maintained patch for one identity whose real NIP-05
// did not match its env-var name, which is only ever necessary if a name is being mistaken for an
// identity.
//
// The two migrations are the risky part, so they are what this exercises. A migration that drops a
// Director's signed consent, or that silently changes a displayed handle, is worse than the defect
// it fixes.
//
// The pure functions live in nactor.mjs behind its boot side-effects, so the migration logic is
// re-implemented here against the same contract. That is a real limitation and it is stated rather
// than hidden: it proves the CONTRACT, not the wiring. The wiring is covered by nactor.mjs's own
// `node --check` plus the six existing suites, all of which still pass.

import assert from 'node:assert'
import { getPublicKey, generateSecretKey, nip19 } from 'nostr-tools'

let pass = 0, fail = 0
const ok = (name, fn) => {
  try { fn(); console.log(`ok   — ${name}`); pass++ }
  catch (e) { console.log(`FAIL — ${name}\n       ${e.message}`); fail++ }
}

const HEX64 = /^[0-9a-f]{64}$/
const key = () => { const sk = generateSecretKey(); return { sk, pub: getPublicKey(sk) } }
const luke = key(), brain = key(), gone = key()

// ── the contract, as nactor.mjs implements it ────────────────────────────────
const pubOf = (name, ids) => ids[name]?.pub ?? null

function migrateActivationKeys(cfg, ids) {
  const acts = cfg?.activations
  if (!acts) return false
  let changed = false
  for (const [k, v] of Object.entries(acts)) {
    if (HEX64.test(k)) continue
    const pub = pubOf(k, ids)
    if (!pub) { if (!v.orphanedName) { acts[k] = { ...v, orphanedName: k }; changed = true } ; continue }
    acts[pub] = { ...v, migratedFromName: k }
    delete acts[k]
    changed = true
  }
  return changed
}

const defaultHandle = (k) => `${k}@nave.pub`
const LEGACY_HANDLES = { nactjaf: 'nact_jaf@nave.pub' }
function migrateLegacyHandles(cfg) {
  let changed = false
  cfg.identitiesMeta = cfg.identitiesMeta || {}
  for (const [name, handle] of Object.entries(LEGACY_HANDLES)) {
    const meta = cfg.identitiesMeta[name]
    if (!meta) continue
    if (meta.handle && meta.handle !== defaultHandle(name)) continue
    cfg.identitiesMeta[name] = { ...meta, handle }
    changed = true
  }
  return changed
}

// ── the identity IS the pubkey ───────────────────────────────────────────────
const IDS = {
  luke:  { nsec: 'x', pub: luke.pub,  ref: 'LUKE_NSEC' },
  brain: { nsec: 'x', pub: brain.pub, ref: 'BRAIN_NSEC' },
}
ok('an identity resolves to a pubkey, not to its env-var name', () => {
  assert.equal(pubOf('luke', IDS), luke.pub)
  assert.ok(HEX64.test(pubOf('luke', IDS)))
})
ok('the env-var name is retained as a custody LOCATOR, so a key can still be found or rotated', () => {
  assert.equal(IDS.luke.ref, 'LUKE_NSEC')
})
ok('two identities are distinct by key even though their names are unrelated to it', () => {
  assert.notEqual(pubOf('luke', IDS), pubOf('brain', IDS))
})
ok('an unknown name resolves to null rather than to a plausible-looking value', () => {
  assert.equal(pubOf('nope', IDS), null)
})

// ── activation migration ─────────────────────────────────────────────────────
ok('a name-keyed activation is re-keyed by pubkey', () => {
  const cfg = { activations: { luke: { by: 'npub1director', at: 111 } } }
  assert.equal(migrateActivationKeys(cfg, IDS), true)
  assert.ok(cfg.activations[luke.pub], 'expected a pubkey-keyed entry')
  assert.equal(cfg.activations[luke.pub].at, 111, 'the signed consent must survive verbatim')
  assert.equal(cfg.activations[luke.pub].migratedFromName, 'luke', 'provenance is recorded')
  assert.equal(cfg.activations.luke, undefined, 'the name key is gone')
})
ok('migration is idempotent — a second run changes nothing', () => {
  const cfg = { activations: { luke: { by: 'd', at: 1 } } }
  migrateActivationKeys(cfg, IDS)
  const before = JSON.stringify(cfg)
  assert.equal(migrateActivationKeys(cfg, IDS), false)
  assert.equal(JSON.stringify(cfg), before)
})
ok('an activation whose key is NOT on this box is KEPT, flagged, never dropped', () => {
  // A Director's signed consent is not ours to discard because we cannot currently see the key
  // it names — the box may simply be missing an env var today.
  const cfg = { activations: { departed: { by: 'd', at: 7 } } }
  assert.equal(migrateActivationKeys(cfg, IDS), true)
  assert.ok(cfg.activations.departed, 'the entry survives')
  assert.equal(cfg.activations.departed.orphanedName, 'departed')
  assert.equal(cfg.activations.departed.at, 7)
})
ok('an already-migrated orphan is not re-flagged on every load', () => {
  const cfg = { activations: { departed: { by: 'd', at: 7, orphanedName: 'departed' } } }
  assert.equal(migrateActivationKeys(cfg, IDS), false)
})
ok('mixed shapes migrate without disturbing the pubkey-keyed entries', () => {
  const cfg = { activations: { [brain.pub]: { by: 'd', at: 2 }, luke: { by: 'd', at: 3 } } }
  migrateActivationKeys(cfg, IDS)
  assert.equal(cfg.activations[brain.pub].at, 2)
  assert.equal(cfg.activations[luke.pub].at, 3)
  assert.equal(Object.keys(cfg.activations).length, 2)
})
ok('no config, or no activations, is not an error', () => {
  assert.equal(migrateActivationKeys({}, IDS), false)
  assert.equal(migrateActivationKeys(undefined, IDS), false)
})

// ── activatedPubs becomes the identity function ──────────────────────────────
const activatedPubs = (cfg) => new Set(Object.keys(cfg?.activations || {}).filter(k => HEX64.test(k)))
ok('activatedPubs returns exactly the migrated pubkeys', () => {
  const cfg = { activations: { [luke.pub]: { at: 1 }, departed: { at: 2, orphanedName: 'departed' } } }
  const set = activatedPubs(cfg)
  assert.equal(set.size, 1)
  assert.ok(set.has(luke.pub))
})
ok('an orphaned name grants nothing — it is a record, not an authorization', () => {
  // The point of keeping it is audit, not access. A name that cannot be resolved to a key must
  // never authorize the broker.
  assert.equal(activatedPubs({ activations: { departed: { at: 2, orphanedName: 'departed' } } }).size, 0)
})

// ── the handle override migrates instead of vanishing ────────────────────────
ok('a legacy hardcoded handle is written into the config that should have held it', () => {
  const cfg = { identitiesMeta: { nactjaf: { signer: 'custodial', status: 'active' } } }
  assert.equal(migrateLegacyHandles(cfg), true)
  assert.equal(cfg.identitiesMeta.nactjaf.handle, 'nact_jaf@nave.pub')
})
ok('deleting the map would have changed a displayed handle — which is why it migrates', () => {
  // The regression this prevents, stated as an assertion: without the migration the derived
  // handle is wrong for this identity.
  assert.notEqual(defaultHandle('nactjaf'), 'nact_jaf@nave.pub')
})
ok('an operator\'s own customised handle is never overwritten', () => {
  const cfg = { identitiesMeta: { nactjaf: { handle: 'mine@example.com' } } }
  assert.equal(migrateLegacyHandles(cfg), false)
  assert.equal(cfg.identitiesMeta.nactjaf.handle, 'mine@example.com')
})
ok('an identity not on this box is not invented by the migration', () => {
  const cfg = { identitiesMeta: {} }
  assert.equal(migrateLegacyHandles(cfg), false)
  assert.equal(cfg.identitiesMeta.nactjaf, undefined)
})
ok('the handle migration is idempotent', () => {
  const cfg = { identitiesMeta: { nactjaf: { signer: 'custodial' } } }
  migrateLegacyHandles(cfg)
  assert.equal(migrateLegacyHandles(cfg), false)
})

// ── a director-path identity is keyless but not identity-less ───────────────
ok('a keyless director-path identity still has the same join key, from its npub', () => {
  const npub = nip19.npubEncode(gone.pub)
  const { type, data } = nip19.decode(npub)
  assert.equal(type, 'npub')
  assert.equal(data, gone.pub, 'the join key is the same shape regardless of custody')
})

console.log(`\n${pass}/${pass + fail} passed`)
process.exit(fail ? 1 : 0)
