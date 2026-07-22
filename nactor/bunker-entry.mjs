// Entry for the browser bundle used by the Nact app's Connect flow (NIP-46).
// Also the import target for the app's importmap: `nostr-tools`,
// `nostr-tools/pool` and `nostr-tools/nip46` all resolve HERE, so the vendored
// nave-connect runs unmodified against one local file — no CDN in the control
// plane's sign-in path.
// Build: npm run build:bunker  →  assets/vendor/nostr-tools-bunker.mjs
// Self-contained so app.html stays a static file. Exposes what the Connect
// flow needs for both NIP-46 directions, plus nip44/nip04 so we can run a
// lenient nostrconnect handshake (some signers reply result:"ack" / NIP-04).
export { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46'
export { SimplePool } from 'nostr-tools/pool'
export { generateSecretKey, getPublicKey, finalizeEvent, nip19, nip44 } from 'nostr-tools'
export * as nip04 from 'nostr-tools/nip04'
