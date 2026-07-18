# Nmail — Nactor's IMAP protocol adapter (design)

Directed by James 2026-07-17: move the Gmail app-specific password from on-disk
custody (mail/app-passwd read by himalaya's auth.cmd) into Nactor RAM, like
every other brokered credential — via a protocol adapter rather than an RPC.

## Shape
- Nactor listens on the nave network only (e.g. nactor:1143, expose-only).
- Consumers (himalaya in the engine, himalaya in beat containers) point their
  IMAP host at the adapter and present NACT_PROXY_TOKEN as the password —
  the same dummy-credential pattern as the existing /api/proxy egress route.
- The adapter verifies the dummy, swaps the LOGIN to the real app password
  (bootstrap env → RAM, never on disk), opens TLS to imap.gmail.com:993, and
  pipes bytes thereafter.

## The differentiator: verb-scoped grants, enforced at the protocol
Before the authenticated pipe goes transparent, the adapter filters commands:
- ALLOW: CAPABILITY NOOP LOGOUT LOGIN SELECT EXAMINE LIST LSUB STATUS FETCH
  SEARCH UID-FETCH UID-SEARCH IDLE
- ALLOW APPEND only when the target folder matches /Drafts/i
- DENY: STORE EXPUNGE MOVE COPY CREATE DELETE RENAME SETACL — read+draft-only
  stops being client-config politeness and becomes an enforced grant no
  consumer, skill, or prompt injection can exceed.
This composes with the existing guarantee (no SMTP configured anywhere) for
defense in depth: cannot send, cannot destroy, can read and draft.

## Nact model
An imap credential-scope: Director-granted to Nactor, host-pinned
(imap.gmail.com), verb-scoped (read+draft), revocable (drop from env / revoke
the app password at Google). Candidate for the public Nave pattern library —
verb-scoped mail grants are not something the OpenClaw frontier has.

## Migration
1. Ship adapter in nactor (net.createServer + tls.connect; no new deps).
2. TELEGRAM-style bootstrap: GMAIL_APP_PASSWORD in nactor.env → CREDS.
3. Repoint both himalaya config.tomls at the adapter w/ dummy password.
4. Delete mail/app-passwd from disk; keep the Google-side revocation note.
5. Regression: mail-setup.sh live check via the adapter; blocked-verb test
   (STORE must fail) becomes part of the suite.
