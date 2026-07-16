// Entry for the browser bundle used by the Nact app's Connect flow (NIP-46).
// Build: npm run build:bunker  →  assets/vendor/nostr-tools-bunker.mjs
// Bundled so app.html stays a self-contained static file (no CDN, no build at
// serve time). Exposes just what the Connect flow needs — both NIP-46
// directions: nostrconnect:// (app-generated, paste into nsec.app "Connect
// app") and bunker:// (signer-generated, paste into Nact).
export { BunkerSigner, parseBunkerInput, createNostrConnectURI } from 'nostr-tools/nip46'
export { SimplePool } from 'nostr-tools/pool'
export { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
