# Google Workspace channel — Calendar + Gmail (read), brokered through Nactor

Calendar and Gmail are both **Google OAuth2**. Nactor holds ONE Google OAuth
credential (client secret + refresh token) in RAM, mints short-lived access
tokens from it (`oauth.mjs`), and injects them per request. Luke reaches the
calendar and inbox by **brokering** — he never holds a Google credential, and
email is **read-only** (the `gmail.readonly` scope can't send or modify).

## What's built (done, autonomous)
- `oauth.mjs` — refresh_token → access_token, cached until 60s before expiry,
  force-refreshed on an upstream 401. Unit-tested (`nactor-oauth.test.mjs`).
- Broker providers in `nactor.mjs`, both sharing the `gworkspace` credential:
  - **`gcal`** — host pinned to `googleapis.com`, only `/calendar/v3/…`.
  - **`gmail`** — host pinned to `gmail.googleapis.com`, only
    `/gmail/v1/users/me/{messages,threads,labels,profile}…` (read surface).
- Bootstrap credential `gworkspace` ← env `GOOGLE_OAUTH_JSON`.

## What's left (needs you — one interactive Google step, once for both)
1. **Google Cloud** → new project → enable **Google Calendar API** and **Gmail API**.
2. Create an **OAuth client** (Desktop app is simplest). Note `client_id` + `client_secret`.
3. Run the consent flow **once** requesting BOTH scopes:
   - `https://www.googleapis.com/auth/calendar.events`
   - `https://www.googleapis.com/auth/gmail.readonly`
   to obtain a single **refresh_token** (OAuth Playground works, or a one-shot
   local script). This is the only interactive step.
4. On the box, add to Nactor's box-local env (`nactor.env`, SOPS-sealed — never a repo):
   ```
   GOOGLE_OAUTH_JSON={"client_id":"…","client_secret":"…","refresh_token":"…"}
   ```
   Recreate Nactor; it loads `gworkspace` into RAM at boot (health `credentials` count goes up).
5. Consumer side (I build this next): a Luke workspace script that signs NIP-98 as
   an **activated** identity and calls the broker, e.g.:
   ```
   POST http://nactor:8791/api/broker
   # calendar
   { "provider":"gcal",  "method":"GET", "path":"/calendar/v3/calendars/primary/events?timeMin=…&maxResults=10" }
   # gmail (read)
   { "provider":"gmail", "method":"GET", "path":"/gmail/v1/users/me/messages?q=is:unread&maxResults=10" }
   ```
   Nactor mints the token, calls Google, streams the result back.

## Read-only guarantee for email
Two layers: the **scope** (`gmail.readonly`) means the token itself cannot send
or modify anything; and Nactor **pins the path** to the read surface. Even a
buggy or hostile caller can't turn this into send access.
