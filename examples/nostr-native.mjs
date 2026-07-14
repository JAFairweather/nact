// The fully nostr-native wiring: no Telegram, no custodial key.
//
//   • proposals are delivered to YOUR npub as NIP-59 gift-wrapped DMs;
//   • you approve from any NIP-17 client by replying "ok <id>";
//   • the identity signs via a NIP-46 bunker, so its key stays on your phone.
//
// There's no HTTP server here — the whole approval channel is nostr relays.
// Run with:
//   NACT_CHANNEL_NSEC=nsec1…   # a throwaway carrier key (can't enact anything)
//   MY_NPUB=npub1…             # the only npub allowed to enact
//   MY_BUNKER_URI=bunker://…   # your remote signer connection string
//   RELAYS=wss://relay.damus.io,wss://nos.lol
//
// This is illustrative — your real proposer (LLM + signals + voice) calls
// nact.propose() on whatever schedule you like.

import { Nact } from '../src/nact.mjs'
import { nostrDmApproval } from '../src/adapters/nostr-dm.mjs'

const relays = (process.env.RELAYS || 'wss://relay.damus.io,wss://nos.lol').split(',')

const approval = nostrDmApproval({
  channelNsec: process.env.NACT_CHANNEL_NSEC, // low-value; only carries approval DMs
  approver: process.env.MY_NPUB,              // only this npub may enact
  relays,
})

const nact = new Nact({
  identities: {
    // NIP-46: the key lives in your bunker (phone), never on this host.
    me: { bunker: process.env.MY_BUNKER_URI },
  },
  relays,
  approval,
})

// Receive the approver's wrapped replies and route them to enact.
const sub = approval.listen(wrap => nact.handleCallback(wrap))
console.log(`nact nostr-native · channel ${approval.channelNpub.slice(0, 20)}… · relays: ${relays.length}`)
console.log('proposals go to your DMs; reply "ok <id>" in any NIP-17 client to enact.')

// Fire one proposal so you can watch the loop. Your real proposer replaces this.
await nact.propose({
  identity: 'me',
  event: { kind: 1, content: 'hello, sovereignly — signed on my phone, broadcast by an agent.' },
  context: 'nostr-native demo — enact from your DM client',
})

// Keep the process alive to listen for your reply.
process.on('SIGINT', () => { sub.close(); approval.close(); process.exit(0) })
