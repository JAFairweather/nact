# Calendar channel — Google Calendar, brokered through Nactor

Google Calendar is an **OAuth2** provider, so Nactor mints a short-lived access
token from a long-lived refresh token on each call (see `oauth.mjs`). The
refresh token + client secret live **only in Nactor** (RAM, from SOPS-sealed
env) and are never returned by the API — Luke reaches the calendar by brokering,
exactly like Anthropic/Telegram, and never holds a Google credential.

## What's built (done, autonomous)
- `oauth.mjs` — refresh_token → access_token, cached until 60s before expiry,
  force-refreshed on an upstream 401. Unit-tested in `nactor-oauth.test.mjs`.
- `gcal` broker provider in `nactor.mjs` — pins the host to `googleapis.com`,
  permits only `/calendar/v3/…` paths, injects `Authorization: Bearer <token>`.
- Bootstrap credential `gcal` ← env `GCAL_OAUTH_JSON`.

## What's left (needs you — one interactive Google step)
1. **Google Cloud** → new project → enable the **Google Calendar API**.
2. Create an **OAuth client** (Desktop app is simplest). Note the `client_id` +
   `client_secret`.
3. Run the consent flow **once** for scope `https://www.googleapis.com/auth/calendar.events`
   to obtain a **refresh_token** (e.g. the OAuth Playground, or a one-shot local
   script). This is the only interactive step.
4. On the box, add to Nactor's box-local env (`nactor.env`, SOPS-sealed — never a repo):
   ```
   GCAL_OAUTH_JSON={"client_id":"…","client_secret":"…","refresh_token":"…"}
   ```
   Recreate Nactor; it loads `gcal` into RAM at boot.
5. The consumer side (later): a Luke workspace script that signs NIP-98 as an
   **activated** identity and POSTs:
   ```
   POST http://nactor:8791/api/broker
   { "provider":"gcal", "method":"GET",
     "path":"/calendar/v3/calendars/primary/events?timeMin=…&maxResults=10" }
   ```
   Nactor mints the token, calls Google, and streams the result back — Luke never
   sees a Google credential.

## Test it end-to-end without Google (optional)
Point the provider + token endpoint at a local mock:
`NACT_BROKER_BASE_GCAL=http://localhost:PORT` and a `token_uri` in the cred JSON
that returns `{access_token, expires_in}` — the broker will inject the Bearer and
call your mock `/calendar/v3/…`.
