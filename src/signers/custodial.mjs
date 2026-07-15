// Custodial signer — the nsec lives on this host. This is the pragmatic
// path for a role key (luke@, nave@) you've explicitly decided to let a
// server hold, ideally SOPS-encrypted at rest and decrypted only in memory.
// It is NOT the path for your sovereign identity; use the NIP-46 signer for
// anything whose key must never touch a server.
import { finalizeEvent, getPublicKey } from 'nostr-tools'
import { loadSecret } from '../util/secret.mjs'

export function custodialSigner(nsec) {
  const sk = loadSecret(nsec)
  if (!sk) throw new Error('custodialSigner: no usable nsec (want nsec1… or 64-char hex)')
  const pk = getPublicKey(sk)
  return {
    kind: 'custodial',
    async publicKey() { return pk },
    // finalizeEvent stamps pubkey/id/sig from sk; a pubkey on the template
    // is ignored, so this is safe for the shared unsigned shape Nact builds.
    async sign(unsigned) { return finalizeEvent(unsigned, sk) },
    async close() {},
  }
}
