// NIP-46 remote signer — the sovereign path. nact holds a *connection* to a
// bunker (nsecbunker, a phone signer like Amber, an nsec.app instance), not a
// key. Every sign() is a round-trip that the bunker authorizes; the secret
// never leaves the user's device. Pair this with nact's human approval and
// you get two independent gates: the approver taps "enact", and the bunker
// signs — both must be the sovereign to produce a valid event.
//
// Give it a bunker connection string:
//   bunker://<remote-signer-pubkey>?relay=wss://…&secret=…
// nact generates an ephemeral client key per process unless you pass one
// (clientSecret) so a bunker can remember the pairing across restarts.
import { generateSecretKey } from 'nostr-tools'
import { BunkerSigner, parseBunkerInput } from 'nostr-tools/nip46'
import { loadSecret } from '../util/secret.mjs'

export function nip46Signer(bunkerUri, { clientSecret } = {}) {
  const local = (clientSecret && loadSecret(clientSecret)) || generateSecretKey()
  let signer = null
  let pk = null

  async function ready() {
    if (signer) return signer
    const pointer = await parseBunkerInput(bunkerUri)
    if (!pointer) throw new Error('nip46Signer: not a valid bunker:// URI')
    signer = new BunkerSigner(local, pointer)
    await signer.connect()
    pk = await signer.getPublicKey()
    return signer
  }

  return {
    kind: 'nip46',
    async publicKey() { await ready(); return pk },
    // BunkerSigner.signEvent takes an unsigned template and returns the fully
    // signed event — the bunker fills pubkey, id, and sig.
    async sign(unsigned) { await ready(); return signer.signEvent(unsigned) },
    async close() { try { await signer?.close?.() } catch { /* best effort */ } },
  }
}
