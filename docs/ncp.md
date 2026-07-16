# NCP — the Nostr Context Protocol (concept)

**Status: concept, with v0 already running.** The perceive-side sibling to Nact
and Nops, on the same spine. The transparent egress proxy in Nactor
(`/api/proxy/<provider>/…`) is NCP's first organ — so unlike Nops, this one isn't
purely on paper; it's a seed already breathing.

## One line

**Give a runtime exactly the data and credentialed egress a nostr identity has
been granted — mediated, never handed over.** MCP gives a model *context* from a
vendor's connectors; NCP gives a runtime *context* from the **nostr grant
graph**, scoped to an identity and revocable by rotation. The runtime *uses* what
it's been granted; it never *holds* it.

## The core invariant — serve the capability, not the secret

Every face of NCP obeys one rule: **Nactor mediates the *use* of a granted thing
so the runtime never holds the thing itself.** That single rule dissolves the
tension between "serve credentials to the engine" and "never vend keys" — because
what's served is the *capability*, injected at the edge, not the material. The
engine gets to *call Anthropic*; it never gets the Anthropic key. It gets to
*read a granted document*; it never gets custody of the grant.

This is the same discipline as the rest of the Nave: the signature is the
authorization, the rotation is the revocation — here applied to what a runtime is
allowed to *perceive and spend*.

## Where it sits — the missing quadrant

```
              perceive (data-in)        act (actions-out)
  protocol    Scoped Data Grants        Scoped Action Approvals
  ↳ instances Nvoy, Nvelope, …          Nact (social) · Nops (server ops)
  runtime     NCP  ← this               Nactor
```

We built **Nactor** — the runtime interface for the *act* side (propose → approve
→ enact). There has never been a runtime interface for the ***perceive*** side.
NCP is that: the data-in mirror of Nactor. It's the door a runtime walks through
to see and spend exactly what its identity was granted — no more.

## We already built v0 — the egress organ

Nactor's egress proxy is NCP's first working piece. A third-party engine
(OpenClaw) points its provider base URL at `http://nactor:8791/api/proxy/anthropic`
with a dummy key; Nactor verifies the gate, injects the **real** credential from
RAM, pins the host (no SSRF / open-proxy), and streams the provider's response
back. The key never leaves Nactor and is never returned. That is already
"serve a credential off a grant," done under the invariant.

It's deliberately internal-only: Nactor is never published, the public Caddy
vhost refuses `/api/proxy/*`, and a token is the defense-in-depth gate.

## The growth path — one core, three organs

1. **Egress (built).** Inject a provider credential and forward. Serves granted
   *spend* (LLM inference, an API call) without the key ever landing in the engine.
2. **Identity gate (next, small).** Swap the single shared token for **per-identity
   resolution**: the caller's token resolves to an activated identity, and Nactor
   injects *that identity's* scoped credential. Now it's literally "bound to a
   nostr identity, serving what that identity was granted." One engine can then
   use **Luke's** credentials when Luke is operating through it and a **different**
   identity's when someone else is — attributable, least-privilege, revocable per
   operator. (Nactor already has `activations` to build this on.)
3. **Data read-path (the reach, genuinely new).** Resolve NIP-DA **data** grants —
   a contact set granted through Nontact, a document through Nvelope, a feed
   through Nvoy — and serve them as **readable resources**. This is resolve-and-read,
   not forward-and-inject, so it's real new mechanics, not a config flip. It turns
   NCP from "granted egress" into "granted *data*" — the whole perceive side.

Same core, same invariant, wider reach each step.

## Faces, not products — where MCP fits

NCP is one core with several **doorways**, chosen by what the consumer speaks:

- **HTTP transparent proxy** — for engines that speak a provider's native protocol
  and can't be modified (OpenClaw's model calls). *Built.*
- **NIP-98 RPC** — for our own code that can sign (the existing `/api/broker`).
- **MCP server** — for MCP-native clients, exposing granted **data as MCP
  resources** and brokered calls as tools.

MCP is just a doorway. The novelty isn't the protocol — it's that the **source of
context is the nostr grant graph**. A generic MCP server connects to Drive or
Slack; NCP connects to *"everything this npub was granted,"* identity-scoped and
revocable. The grant graph is the substrate no one else has.

## The boundary (security)

- **Never vend a raw secret.** Data grants → served as resources. Infra keys
  (Anthropic/Gemini) → **injected egress only**, never handed over.
- **Host-pinned.** A caller can't repoint egress at an arbitrary host (no
  open-proxy / SSRF).
- **Internal-only for the egress face.** Unreachable from the internet by
  construction (not published + Caddy refuses the path), token gate on top.
- **Per-identity scope = attribution + least privilege + revocability.** Rotate an
  identity's grant and its access through the engine dies, without touching others.

## The honest read

The egress organ is real and shipping — it unblocks getting OpenClaw's engine keys
out of plaintext today. The identity gate is a small, natural evolution of it. The
data read-path is a genuine build (grant resolution + a resolve-and-read surface),
and the MCP-native framing is optional polish on top. So NCP is a **sibling
product** to Nact and Nops — weightier than plumbing — but it's the one whose
foundation is already laid. It's the perceive-side runtime the ecosystem was
missing, and we found it by building the proxy and realizing what it was.

## If it were built out

- Nactor gains **per-identity** credential/grant resolution (activation → scope).
- A **data-grant resolver** turns NIP-DA grants into readable resources.
- An optional **MCP server front** exposes those resources + brokered tools to
  MCP-native runtimes.
- Effectively: **Nactor as the perceive-side mediator**, growing egress →
  identity → data — the mirror of the act-side runtime we already run.
