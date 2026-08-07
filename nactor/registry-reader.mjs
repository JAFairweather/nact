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
 * NAME VS ID, AND WHY THIS IS NOT A COSMETIC DISTINCTION. A grant carries both: `scope_name` is what
 * the scope IS (`data:agents/registry`), and `d` is the scope ID it lives under on the relay. They are
 * deliberately different values. nvoy publishes every scope under an OPAQUE `d` — its own rule, in
 * `console/nvoygrant.mjs`: "semantic names in `d` tags leak disclosure structure" — because a relay
 * that sees `d: data:agents/registry` on a Director's 30440 learns that this pubkey maintains an agent
 * roster and, from the generation churn, how often it changes. The contents stay encrypted; the fact
 * of it would not. `scope_name` travels inside the gift-wrapped grant, so only the grantee sees it,
 * which is the whole point of putting it there.
 *
 * This reader previously matched `x.d === REGISTRY_SCOPE` and then read BY THAT NAME. Both were wrong
 * in the same direction: it could only ever have found a projection published under a semantic `d` —
 * that is, one that had already leaked. Its sibling `grant-reader.mjs` had it right all along
 * (`client.readScope(g.d, …)`). So: match on the name, read by the id. Refusing to match on `d` is a
 * feature, not strictness — the shape it would accept is the shape that must not exist.
 *
 * @param client       the nvoy MCP client (readScope(d, authorNpub, {maxAge}))
 * @param grants       the grants this runtime holds, as grant-reader sees them:
 *                     [{ d, scope_name, author_npub, status, ... }]
 * @returns { agents: string[]|null, generatedAt, generation, why }
 */
export async function readRegistry({ client, grants = [], log = () => {} } = {}) {
  const no = (why) => ({ agents: null, generatedAt: null, generation: null, why })

  if (!client) return no('no MCP client — this runtime has no path to the delegator\'s scopes')

  const held = (Array.isArray(grants) ? grants : []).filter(x => x && x.scope_name === REGISTRY_SCOPE)
  if (!held.length) {
    return no(`no grant on ${REGISTRY_SCOPE} — the Director has not granted this runtime read on the `
      + 'roster, so whether Nvoy knows a given key cannot be checked from here')
  }

  // A revoked grant is not a missing one, and the two must not print the same sentence: "never granted"
  // sends you to Nvoy to grant it, "revoked" tells you it was taken away. Rotation-based revocation
  // leaves the old row visible to the grantee, so this case is reachable in normal operation.
  const g = held.find(x => x.status === 'active') ?? null
  if (!g) {
    const states = [...new Set(held.map(x => x.status || 'unknown'))].join(', ')
    return no(`the grant on ${REGISTRY_SCOPE} is ${states}, not active — this runtime held read on the `
      + 'roster and no longer does, which is not the same as never having been granted it')
  }
  if (typeof g.d !== 'string' || !g.d) {
    return no(`the grant on ${REGISTRY_SCOPE} carries no scope id, so there is nothing to dereference`)
  }

  let res
  // maxAge 0: read it LIVE. A cached roster would let a revoked agent keep reading as registered,
  // which is the same class of staleness the Ledger's hard-expiry banner warns about.
  try { res = await client.readScope(g.d, g.author_npub, { maxAge: 0 }) }
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
