// registry-reader.mjs — read the delegator's projected agent roster, or admit that you could not.
//
// WHY A RUNTIME NEEDS THIS AT ALL. The roster is `nvoy_agents` on the Director's kind-10440,
// NIP-44-encrypted to himself. This box holds no key of his, so it is STRUCTURALLY unable to read it.
// That is the whole reason an agent could exist in Nvoy and be invisible here, with an absence as the
// only symptom — and an absence is the one defect nobody can see.
//
// nvoy publishes the roster as a scoped dataset (`data:agents/registry`) and grants this runtime read.
// Then the two sets can be joined on the pubkey, which nact#57 made the join key on both sides.
//
// THE ONE RULE THIS FILE EXISTS TO ENFORCE: `agents: null` and `agents: []` are DIFFERENT ANSWERS and
// must never collapse. Null means nobody asked, or nobody answered — the honest report is "not
// verified". An empty array means the Director's registry really is empty, which makes every on-box
// key a real divergence. A reader that returned `[]` on failure would turn "I could not check" into
// "Nvoy does not know this key", which is the original bug wearing a fix's clothing.
//
// So every failure path here returns null WITH a reason, and the reason is surfaced to the console.

export const REGISTRY_SCOPE = 'data:agents/registry'
export const REGISTRY_MAX_VERSION = 1

const HEX64 = /^[0-9a-f]{64}$/

/**
 * Pull the projection through the MCP grant client.
 *
 * @param client       the nvoy MCP client (readScope(d, authorNpub, {maxAge}))
 * @param grants       the grants this runtime holds, as grant-reader sees them:
 *                     [{ d, author_npub, ... }]
 * @returns { agents: string[]|null, generatedAt, generation, why }
 */
export async function readRegistry({ client, grants = [], log = () => {} } = {}) {
  const no = (why) => ({ agents: null, generatedAt: null, generation: null, why })

  if (!client) return no('no MCP client — this runtime has no path to the delegator\'s scopes')
  const g = (Array.isArray(grants) ? grants : []).find(x => x && x.d === REGISTRY_SCOPE)
  if (!g) {
    return no(`no grant on ${REGISTRY_SCOPE} — the Director has not granted this runtime read on the `
      + 'roster, so whether Nvoy knows a given key cannot be checked from here')
  }

  let res
  // maxAge 0: read it LIVE. A cached roster would let a revoked agent keep reading as registered,
  // which is the same class of staleness the Ledger's hard-expiry banner warns about.
  try { res = await client.readScope(REGISTRY_SCOPE, g.author_npub, { maxAge: 0 }) }
  catch (e) { return no(`could not read ${REGISTRY_SCOPE}: ${e?.message || e}`) }

  const payload = res?.data ?? res
  if (!payload || typeof payload !== 'object') return no('the registry scope held no readable payload')

  // Refuse a shape this build does not know rather than guessing at it. A future field could change
  // what a row MEANS, and a roster misread is worse than a roster unread.
  const v = Number(payload.v)
  if (!Number.isFinite(v) || v > REGISTRY_MAX_VERSION) {
    return no(`registry projection is v${payload.v}; this runtime understands up to v${REGISTRY_MAX_VERSION}. `
      + 'Refusing to guess at a shape it does not know.')
  }

  const rows = Array.isArray(payload.agents) ? payload.agents : []
  const agents = []
  let dropped = 0
  for (const r of rows) {
    const pub = typeof r?.pub === 'string' ? r.pub.toLowerCase() : null
    if (pub && HEX64.test(pub)) agents.push(pub); else dropped++
  }
  if (dropped) log(`registry: ${dropped} projected row(s) were not a valid pubkey and were not counted`)

  return {
    agents,                                     // possibly [] — an ANSWER, not a failure
    generatedAt: Number.isFinite(payload.generated_at) ? payload.generated_at : null,
    generation: Number.isFinite(res?.generation) ? res.generation : null,
    dropped,
    why: null,
  }
}

/**
 * The shape `/api/state` exposes. Kept here so the console and the runtime agree on one contract
 * rather than two descriptions of it.
 *
 * `stale` is reported, never hidden: the projection is a COPY, so a consumer that rendered it as live
 * would let a roster from last week look like the roster now.
 */
export function registryView(read, { now = 0, staleAfterSeconds = 24 * 3600 } = {}) {
  const r = read || {}
  const age = (r.generatedAt && now) ? now - r.generatedAt : null
  return {
    agents: Array.isArray(r.agents) ? r.agents : null,
    generatedAt: r.generatedAt ?? null,
    generation: r.generation ?? null,
    dropped: r.dropped ?? 0,
    ageSeconds: age,
    stale: age !== null ? age > staleAfterSeconds : null,
    why: r.why ?? null,
  }
}
