# Nmail — verb-scoped IMAP read adapter in Nactor (#36)

**Status:** design, build-ready. Blocked on one thing only: a Director-issued
`imap` app-password credential + the target IMAP host, so the code can be
verified against a real server. The design below is what to build the moment
that lands; nothing here changes the running box.

Companion: `credential-consumption-policy.md` (why this is broker, not
grant-to-app), `credential-sovereignty.md` (the grant model).

---

## Why it isn't just another broker provider

Every provider in `BROKER_PROVIDERS` today is **HTTP**: `build(body, cred) →
{ url, headers }`, the broker route pins the host and verb-scopes the path, and
the credential never leaves the box (Anthropic, Telegram, Gmail/GCal over
googleapis). IMAP is **not HTTP** — it's a stateful TCP session (CONNECT →
LOGIN → SELECT → SEARCH/FETCH → LOGOUT). So Nmail can't be a `build()` provider;
it needs its **own route** and a short-lived IMAP client, while keeping the same
two guarantees: (1) the caller never sees the password, (2) the caller can only
do **read** verbs.

## Consumption mode: broker (not grant-to-app)

Per the hybrid policy (AD-6): the consumer here is an **on-box** agent (Luke's
morning/inbox beat), and the content (mail metadata) is handled by a Nave agent,
not an off-box/ZK party. Both tests say **broker** — the Nactor holds the
app-password in RAM and makes the IMAP connection on the caller's behalf. The
authority is still the grant (`credential:imap`), issued to the owning identity;
the box only decrypts and uses it.

## Credential shape

- Scope name: `credential:imap` (or `imap-<account>` if multiple mailboxes,
  matching the `telegram-<agent>` convention).
- Value (JSON, carried inside the encrypted scope, never on disk):
  ```json
  { "host": "imap.fastmail.com", "port": 993, "user": "james@…", "pass": "<app-password>" }
  ```
  A dedicated **app-password** (Fastmail/Gmail app-password), never the real
  account password — revocable independently, and read-only if the provider
  supports scoped app-passwords.
- Loaded by the existing `grant-reader` into `CREDS` (RAM), same as every other
  credential. Newest-wins already applies.

## The route: `POST /api/nmail` (NIP-98 gated)

Same gate as `/api/broker` — a Director/agent NIP-98 signature, and (when
`NACT_ENFORCE_CREDENTIAL_OWNERSHIP`) the caller must hold a grant for `imap`.
Body is a **verb + params**, never a raw IMAP command:

```json
{ "verb": "search", "mailbox": "INBOX", "query": { "since": "2026-07-01", "unseen": true }, "limit": 25 }
{ "verb": "list" }                                   // list mailboxes
{ "verb": "headers", "mailbox": "INBOX", "uids": [1234, 1235] }
{ "verb": "body", "mailbox": "INBOX", "uid": 1234, "part": "text" }   // text/plain preferred
```

### Verb allow-list — READ ONLY (the security core)

| verb      | IMAP ops                         | allowed |
|-----------|----------------------------------|---------|
| `list`    | LIST                             | ✅ |
| `search`  | SELECT (read-only) + UID SEARCH  | ✅ |
| `headers` | UID FETCH (ENVELOPE/FLAGS/SIZE)  | ✅ |
| `body`    | UID FETCH BODY.PEEK[TEXT]        | ✅ (PEEK = doesn't set \Seen) |
| —         | APPEND / STORE / EXPUNGE / DELETE / MOVE / COPY / CREATE / RENAME | ❌ never implemented |

The adapter **only ever issues** the read commands above. Reinforce with:
`imap.select(mailbox, { readOnly: true })` (EXAMINE, not SELECT), and
`BODY.PEEK` so a fetch never mutates flags. There is no code path that writes —
write protection is *structural* (no write verb exists), not a flag we could
forget, mirroring how the Gmail provider is pinned to the read surface.

## Implementation sketch

- **Dependency:** `imapflow` (maintained, promise-based, TLS by default). Add to
  `nactor/package.json` + the nactor Dockerfile layer. Keep it out of any
  browser bundle — it's server-only.
- **Per-call client, not a pool:** connect → EXAMINE → do the one verb → LOGOUT,
  with a hard timeout (≈15s) and `Promise.race` guard so a slow server can't
  hang the route (same lesson as the relay reads). No long-lived IMAP session.
- **Never log the password or full bodies.** Log verb + mailbox + counts only.
- **Shape the response** to what a beat needs: for `search`/`headers`, return
  `[{ uid, from, subject, date, unseen, size }]`; for `body`, a trimmed
  text/plain preview (cap length). Strip HTML; never return attachments inline.
- **Egress pinning:** the host comes from the *credential*, not the request body,
  so a caller can't repoint the connection — same principle as the host-pinned
  HTTP providers.

## Consumer

Luke's morning beat (and, once this exists, an on-demand "what's in my inbox"
ask) calls `/api/nmail` with a NIP-98 signature as `luke`. It gets read-only
mail metadata to summarize — matching the existing draft-only email posture
(#34, himalaya IMAP, no SMTP): **read + draft, never auto-send.**

## Build checklist (once the credential exists)

1. Director issues `credential:imap` to the owning identity (Nvoy → paste the
   app-password bundle → Issue), granted **also** to the Nactor so the broker
   holds the value.
2. Add `imapflow` to `nactor/package.json` + Dockerfile.
3. Implement `nactor/nmail.mjs`: `runVerb({ verb, ...params }, cred)` with the
   allow-list above; unit-test the verb guard + response shaping against a mock.
4. Wire `POST /api/nmail` in `nactor.mjs` behind `verifyNip98` + the ownership
   gate; resolve `CREDS.get('imap')`.
5. Verify against the real server (list → search unseen → fetch one body),
   confirm no flags mutate (BODY.PEEK), confirm write verbs are absent.
6. Point Luke's inbox summary at it; keep it draft-only.
