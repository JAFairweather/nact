# Nactor connectors — the pattern (and the mail connector, #36)

A **connector** is how a Nactor lets an agent *use* a third‑party account
(read mail, list a calendar, call an API) **without ever handing the agent the
secret**. It's not a product and it doesn't get a brand — "Nmail" was
over‑naming a single connector. This doc defines the pattern once, then
specs the first non‑HTTP connector (mail) as an instance of it.

Companions: `credential-consumption-policy.md` (broker vs grant‑to‑app, AD‑6),
`credential-sovereignty.md` (the grant model).

---

## The two axes

Every connector is one cell in a 2×N grid. The axes are **orthogonal** — pick a
transport and an auth strategy independently.

### Axis 1 — transport (how the call is shaped)

- **`http-build` (stateless).** A `build(body, secretOrToken) → { url, headers }`
  provider. The caller supplies path/method/body; Nactor **pins the host** and
  allow‑lists the path/verb, injects the secret its own way, and returns the
  request for the broker route to execute. This is every provider in
  `BROKER_PROVIDERS` today (Anthropic, `telegram-*`, `gcal`, `gmail`).
- **`stateful-adapter` (session).** For protocols that aren't request/response
  HTTP — IMAP, CalDAV, SFTP. Can't be a `build()` provider; needs its **own
  route** and a short‑lived client: `connect → authenticate → one verb → close`,
  hard timeout + `Promise.race` guard, no long‑lived session. **Mail is the
  first of these.**

### Axis 2 — auth (how the secret becomes credentials)

- **`static-key`.** Inject a long‑lived secret verbatim: an API key (Anthropic),
  a bot token (Telegram), or an **app‑password** (IMAP `LOGIN`).
- **`oauth`.** The stored secret is a `refresh_token` bundle; every call needs a
  freshly‑minted short‑lived **access token**. `oauth.mjs :: oauthAccessToken()`
  mints + caches it (re‑mints on a forced 401). The token is used as a **Bearer**
  header (HTTP transports) *or* as an **XOAUTH2 SASL** string (IMAP). Same minter,
  same refresh‑token bundle — only the place the token lands differs.

The mail connector James asked for is therefore:
**`stateful-adapter` × { `app-password` | `oauth` }** — one adapter, two ways in.

### Invariants every connector keeps

1. The **caller never sees the secret** (key, token, or password).
2. The caller can only do **allow‑listed verbs** — write protection is
   *structural* (no write verb exists in the code), not a flag.
3. **Egress is pinned by the credential**, never by the request body — a caller
   can't repoint the host/mailbox.
4. Consumption mode follows AD‑6 (broker for on‑box Nave agents; grant‑to‑app
   for off‑box/ZK parties). Authority is always the grant.

---

## The mail connector (`connector: mail`) — replaces "Nmail"

A verb‑scoped, **read‑only** IMAP adapter. Same two guarantees as the HTTP
broker (caller never sees the password/token; caller can only read), but over a
stateful IMAP session instead of an HTTP request.

### Credential shape — auth is chosen by the value, not a second endpoint

One connector, one route; the **credential's shape selects the auth strategy**.
Scope name `mail-<account>` (e.g. `mail-james-fastmail`, `mail-james-gmail`) —
matching the `telegram-<agent>` convention. Value JSON (inside the encrypted
scope, never on disk):

**App‑password (static‑key):**
```json
{ "auth": "password", "host": "imap.fastmail.com", "port": 993,
  "user": "james@…", "pass": "<app-password>" }
```
A dedicated app‑password (Fastmail/Gmail), never the real account password —
independently revocable.

**OAuth (XOAUTH2):**
```json
{ "auth": "oauth", "host": "imap.gmail.com", "port": 993,
  "user": "james@gmail.com", "oauth_cred": "gworkspace" }
```
`oauth_cred` names an OAuth bundle the broker already holds (reuse the existing
`gworkspace` refresh‑token — no new secret), or inline
`{ client_id, client_secret, refresh_token }`. The adapter mints an access token
via `oauthAccessToken(oauth_cred, …)` and authenticates IMAP with **SASL
XOAUTH2** (needs the Gmail/Google `https://mail.google.com/` IMAP scope on that
token).

**Strategy selection:** explicit `auth` wins; else infer (`pass` ⇒ `password`,
`refresh_token`/`oauth_cred` ⇒ `oauth`). Everything above the handshake — the
verbs, the response shaping, the egress pinning — is identical for both. Adding
Outlook later is just another `mail-<account>` credential (its own host + either
auth), zero code change.

### Route: `POST /api/connector/mail` (NIP‑98 gated)

Same gate as `/api/broker`: a Director/agent NIP‑98 signature, and (under
`NACT_ENFORCE_CREDENTIAL_OWNERSHIP`) the caller must hold a grant for the
`mail-<account>` scope. Body is **verb + params**, never a raw IMAP command:

```json
{ "account": "james-fastmail", "verb": "search", "mailbox": "INBOX",
  "query": { "since": "2026-07-01", "unseen": true }, "limit": 25 }
{ "account": "james-fastmail", "verb": "list" }
{ "account": "james-fastmail", "verb": "headers", "mailbox": "INBOX", "uids": [1234] }
{ "account": "james-fastmail", "verb": "body", "mailbox": "INBOX", "uid": 1234, "part": "text" }
```

`account` selects which `mail-<account>` credential to use; the host/user/auth all
come from that credential.

### Verb allow‑list — READ ONLY (the security core)

| verb      | IMAP ops                         | allowed |
|-----------|----------------------------------|---------|
| `list`    | LIST                             | ✅ |
| `search`  | EXAMINE (read‑only) + UID SEARCH | ✅ |
| `headers` | UID FETCH (ENVELOPE/FLAGS/SIZE)  | ✅ |
| `body`    | UID FETCH BODY.PEEK[TEXT]        | ✅ (PEEK = doesn't set \Seen) |
| —         | APPEND / STORE / EXPUNGE / DELETE / MOVE / COPY / CREATE / RENAME | ❌ never implemented |

The adapter **only ever issues** the read commands above. Reinforced by
`EXAMINE` (never `SELECT` for write) and `BODY.PEEK` so a fetch never mutates
flags. No code path writes — write protection is structural, mirroring how the
Gmail HTTP provider is pinned to its read surface + a `gmail.readonly` token.

## Implementation sketch

- **Dependency:** `imapflow` (maintained, promise‑based, TLS by default; supports
  both `auth: { user, pass }` and `auth: { user, accessToken }`). Add to
  `nactor/package.json` + the nactor Dockerfile layer. Server‑only.
- **`nactor/connectors/mail.mjs`:**
  - `resolveAuth(cred)` → `{ user, pass }` or, for oauth, `{ user, accessToken }`
    via `oauthAccessToken(cred.oauth_cred || cred, { force })`. On an IMAP auth
    failure with an oauth cred, re‑mint once with `force:true`, then give up.
  - `runVerb({ verb, ...params }, cred)` implements the allow‑list; connects,
    `EXAMINE`s the mailbox, runs the one verb, `LOGOUT`s. Hard ≈15s timeout +
    `Promise.race` guard (same lesson as the relay reads) so a slow server can't
    hang the route.
  - **Never log** the password, access token, or full bodies. Log
    `account + verb + mailbox + counts` only.
  - **Shape the response** to what a beat needs: `search`/`headers` →
    `[{ uid, from, subject, date, unseen, size }]`; `body` → trimmed text/plain
    preview (cap length, strip HTML, never inline attachments).
- **Wire `POST /api/connector/mail`** in `nactor.mjs` behind `verifyNip98` + the
  ownership gate; resolve `CREDS.get('mail-' + account)`.
- **Egress pinning:** host + mailbox come from the *credential* / verb params
  against the allow‑list, not from a free‑form request — a caller can't repoint
  the connection.

## Consumer

Luke's morning beat (and an on‑demand "what's in my inbox" ask) calls
`/api/connector/mail` with a NIP‑98 signature as `luke`, gets read‑only mail
metadata to summarize — matching the existing draft‑only posture (#34, IMAP read,
no SMTP): **read + draft, never auto‑send.**

## Build checklist (once a credential exists)

1. Director issues a `mail-<account>` credential to the owning identity (Nvoy →
   paste the app‑password bundle **or** point at the `gworkspace` oauth cred →
   Issue), granted **also** to the Nactor so the broker holds the value.
2. Add `imapflow` to `nactor/package.json` + Dockerfile.
3. Implement `nactor/connectors/mail.mjs` (`resolveAuth` + `runVerb` + allow‑list);
   unit‑test the verb guard, the auth‑strategy selection, and response shaping
   against a mock (both a `password` and an `oauth` credential).
4. Wire `POST /api/connector/mail` behind `verifyNip98` + ownership gate.
5. Verify against a real server on **both** paths — an app‑password mailbox and a
   Gmail XOAUTH2 mailbox (list → search unseen → fetch one body); confirm no flags
   mutate (BODY.PEEK) and that write verbs are absent.
6. Point Luke's inbox summary at it; keep it draft‑only.

## Why this is the right shape

- **No new brand, no new subsystem** — the mail connector is one cell in a grid
  the Nactor already implements; the OAuth minter and the NIP‑98 gate are reused
  verbatim.
- **Both auth models by construction** — app‑password and OAuth are the two
  values of Axis 2; the adapter above the handshake doesn't care which.
- **The next connector is cheap** — CalDAV, SFTP, or an Outlook mailbox slot in
  as a transport/auth pair with no rethink.
