// endpoint-advert — AD-2: address the runtime by its identity, not a URL.
//
// The sovereign end-state points clients at *who* the runtime is (its npub /
// nactor@nave.pub), not *where* it's hosted. On boot the Nactor publishes,
// under its OWN key, two replaceable events so a client can discover HOW to
// reach it from WHO it is:
//
//   • kind 10002 (NIP-65 relay list) — the relays it reads/writes on, so a
//     client that only knows the npub can find where to talk to it.
//   • kind 31990 (NIP-89 handler advertisement) — names the HTTP service
//     endpoint (the NIP-98-gated API) as a `web` target, with a short
//     self-description in content.
//
// Both are replaceable (10002 is replaceable; 31990 is addressable via its `d`
// tag), so moving the box is just republishing — no client reconfig, the same
// decoupling as email. Nothing here is secret: the endpoint and relay list are
// public by design. Failures are non-fatal — a runtime that can't advertise
// still serves; it just isn't yet discoverable by identity.
import { finalizeEvent } from 'nostr-tools'
import { LiveRelay } from './lib/liverelay.mjs'

export function buildEndpointEvents({ nactorSk, relayUrls, endpoint, now }) {
  const relayTags = relayUrls.map(u => ['r', u])
  const relayList = finalizeEvent(
    { kind: 10002, created_at: now, tags: relayTags, content: '' }, nactorSk)
  const handler = finalizeEvent({
    kind: 31990, created_at: now,
    tags: [
      ['d', 'nactor'],                                 // stable identifier → addressable/replaceable
      ...(endpoint ? [['web', endpoint, 'nactor']] : []),
      ...relayTags,
    ],
    content: JSON.stringify({
      name: 'Nave Nactor',
      about: 'Per-box credential broker + control-plane runtime. The NIP-98-gated ' +
        'API lives at the web endpoint; discover transport from this identity, ' +
        'not a hard-coded URL. Moving the box republishes this event.',
      ...(endpoint ? { web: endpoint } : {}),
    }),
  }, nactorSk)
  return { relayList, handler }
}

export async function publishEndpointAdvert({ nactorSk, relayUrls, endpoint, now, log = () => {} }) {
  if (!nactorSk || !relayUrls?.length) { log('  endpoint-advert: disabled (no key / relays)'); return }
  const { relayList, handler } = buildEndpointEvents({ nactorSk, relayUrls, endpoint, now })
  const relay = new LiveRelay(relayUrls)
  try {
    const a = await relay.publish(relayList)
    const b = await relay.publish(handler)
    log(`  endpoint-advert: relay-list 10002 (${a.acks}/${a.of}) + handler 31990 (${b.acks}/${b.of})` +
      `${endpoint ? ` → ${endpoint}` : ' (no endpoint configured — relays only)'}`)
  } catch (e) {
    log(`  endpoint-advert: publish failed ${e?.message || e}`)
  } finally { try { relay.close() } catch {} }
}
