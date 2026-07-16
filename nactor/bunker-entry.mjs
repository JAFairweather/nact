// Entry for the browser bundle used by the Nact app's Connect flow (NIP-46).
// Build: npm run build:bunker  →  assets/vendor/nostr-tools-bunker.mjs
// Self-contained so app.html stays a static file. Exposes what the Connect
// flow needs for both NIP-46 directions, plus nip44/nip04 so we can run a
// lenient nostrconnect handshake (some signers reply result:"ack" / NIP-04).
export { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46'
export { SimplePool } from 'nostr-tools/pool'
export { generateSecretKey, getPublicKey, nip19, nip44 } from 'nostr-tools'
export * as nip04 from 'nostr-tools/nip04'
