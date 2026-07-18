// migrate-env — Phase 0 of the secrets.env → Nact/Nactor migration.
//
// Reads a dotenv file (the box's secrets.env) and classifies every key per
// docs/migration.md, emitting a migration PLAN:
//   • config     — public desired-state (directors, identities, operational),
//                  WITH values (npubs/relays/models are not secret);
//   • secrets    — the credential-scopes to issue, by key NAME + class only,
//                  NEVER a value;
//   • runtime    — deploy-time env that stays put (ports, flags);
//   • unknown    — anything the rules don't cover, so the table stays honest.
//
// It never prints a secret value, so the output is safe to read, diff, commit.
//
//   node nactor/migrate-env.mjs path/to/secrets.env            # JSON plan
//   node nactor/migrate-env.mjs path/to/secrets.env --summary  # human table
//
// Classes (see docs/migration.md): role-key(A) provider-credential(B)
// infra-secret(C) identity(D→config) operational(E→config) runtime(F).

import { readFileSync } from 'node:fs'

// Exact-name rules take precedence; PATTERNS below catch anything new.
const RULES = {
  // A — role signing keys → an identity; the nsec is imported once (never rotated)
  LUKE_NSEC:               ['role-key', 'identity:luke'],
  NAVE_NSEC:               ['role-key', 'identity:nave'],
  NOIR_DIRECTOR_NSEC:      ['role-key', 'identity:noir-director'],
  NACT_CHANNEL_NSEC:       ['role-key', 'channel:carrier'],
  // B — provider credentials → credential-scopes
  ANTHROPIC_API_KEY:       ['provider-credential', 'credential:anthropic'],
  REPLICATE_API_TOKEN:     ['provider-credential', 'credential:replicate'],
  TELEGRAM_BOT_TOKEN:      ['provider-credential', 'channel:telegram/bot-token'],
  // C — infra secrets → credential-scopes (or SOPS-only if never remote-rotated)
  TELEGRAM_WEBHOOK_SECRET: ['infra-secret', 'channel:telegram/webhook-secret'],
  PROPOSE_TOKEN:           ['infra-secret', 'bridge:propose-token'],
  GATE_SECRET:             ['infra-secret', 'session:gate-secret'],
  OPENCLAW_GATEWAY_TOKEN:  ['infra-secret', 'cockpit:gateway-token'],
  OPENCLAW_GATEWAY_PASSWORD:['infra-secret', 'cockpit:gateway-password'],  // internal-client auth (2026-07)
  MY_BUNKER_URI:           ['infra-secret', 'signer:bunker-uri'],   // may embed a secret
  // B — agent-era additions (2026-07): the gworkspace OAuth trio is ONE
  // credential-scope; the two Telegram bots and Gmail IMAP are their own.
  BRAIN_NSEC:              ['role-key', 'identity:brain'],
  NACTOR_NSEC:             ['bootstrap', 'runtime-key'],   // stays on box (sanctioned)
  TELEGRAM_LUKE_BOT_TOKEN: ['provider-credential', 'channel:telegram-luke/bot-token'],
  GOOGLE_OAUTH_CLIENT_ID:  ['provider-credential', 'credential:gworkspace'],
  GOOGLE_OAUTH_CLIENT_SECRET:['provider-credential', 'credential:gworkspace'],
  GOOGLE_OAUTH_REFRESH_TOKEN:['provider-credential', 'credential:gworkspace'],
  GOOGLE_OAUTH_JSON:       ['provider-credential', 'credential:gworkspace'],
  GMAIL_APP_PASSWORD:      ['provider-credential', 'credential:gmail-imap'],
  // D — identities / addresses (public) → config
  LUKE_MASTER_NPUB:        ['identity', 'director'],
  NACT_MASTER_NPUB:        ['identity', 'director'],
  NACT_DIRECTOR_NPUB:      ['identity', 'director'],
  MY_NPUB:                 ['identity', 'director'],
  MASTER_NIP05:            ['identity', 'director:nip05'],
  TELEGRAM_APPROVER_ID:    ['identity', 'channel:telegram/approver'],
  GMAIL_ADDRESS:           ['identity', 'channel:gmail/address'],   // an email, public-ish
  BRAIN_NPUB:              ['identity', 'director-or-identity'],
  // E — operational config (non-secret values are emitted)
  LUKE_RELAYS:             ['operational', 'relays'],
  NOIR_RELAYS:             ['operational', 'relays'],
  RELAYS:                  ['operational', 'relays'],
  DRAFT_MODEL:             ['operational', 'model'],
  NOIR_MODEL:              ['operational', 'model'],
  NOIR_IMAGE_MODEL:        ['operational', 'model'],
  NOIR_RATE_LIMIT:         ['operational', 'guardrail'],
  NOIR_DAILY_CAP:          ['operational', 'guardrail'],
  NOIR_ALLOWED_ORIGINS:    ['operational', 'guardrail'],
  MAX_POSTS:               ['operational', 'guardrail'],
  SINCE_HOURS:             ['operational', 'guardrail'],
  GATE_SESSION_TTL:        ['operational', 'guardrail'],
  NOIR_HOUSE_FILE:         ['operational', 'path'],
  NOIR_SCENES:             ['operational', 'flag'],
  SUBSTACK_FEED:           ['operational', 'feed'],
  NAVE_REPOS:              ['operational', 'feed'],
  GITHUB_OWNER:            ['operational', 'feed'],
  PROPOSE_URL:             ['operational', 'endpoint'],
  NACT_ADDRESS:            ['operational', 'nactor-address'],
  NACT_BROKER_URL:         ['operational', 'endpoint'],
  CAL_TZ:                  ['operational', 'flag'],
  LUKE_MANDATE:            ['operational', 'label'],
  LUKE_NAME:               ['operational', 'label'],
  ACME_EMAIL:              ['operational', 'acme'],
  // F — pure runtime (stays deploy-time env)
  LUKE_PORT:               ['runtime', 'port'],
  NOIR_GM_PORT:            ['runtime', 'port'],
  NACT_PORT:               ['runtime', 'port'],
  NACT_CONFIG:             ['runtime', 'path'],
  WS_NO_BUFFER_UTIL:       ['runtime', 'flag'],
  WS_NO_UTF_8_VALIDATE:    ['runtime', 'flag'],
  TZ:                      ['runtime', 'flag'],
}

// Fallback patterns for keys not named above — conservative: an unknown
// *_TOKEN/_KEY/_SECRET is treated as a secret, never leaked.
const PATTERNS = [
  [/_NSEC$/,                         ['role-key', 'identity:?']],
  [/_NPUB$/,                         ['identity', 'director-or-identity']],
  [/_RELAYS?$/,                      ['operational', 'relays']],
  [/_MODEL$/,                        ['operational', 'model']],
  [/_PORT$/,                         ['runtime', 'port']],
  [/(_TOKEN|_KEY|_SECRET|_PASSWORD)$/, ['infra-secret', 'unknown-secret']],
]

const SECRET_CLASSES = new Set(['role-key', 'provider-credential', 'infra-secret'])

function classify(key) {
  if (RULES[key]) return RULES[key]
  for (const [re, res] of PATTERNS) if (re.test(key)) return res
  return null
}

// Minimal dotenv parse: KEY=VALUE, ignores comments/blank, strips quotes.
function parseDotenv(text) {
  const out = {}
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    const eq = line.indexOf('=')
    if (eq < 0) continue
    const key = line.slice(0, eq).trim().replace(/^export\s+/, '')
    let val = line.slice(eq + 1).trim()
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1)
    }
    out[key] = val
  }
  return out
}

export function planMigration(env) {
  const config = { directors: [], identities: {}, operational: {} }
  const secrets = []
  const runtime = []
  const unknown = []
  const identityFor = { LUKE_NSEC: 'luke', NAVE_NSEC: 'nave', NOIR_DIRECTOR_NSEC: 'noir-director', NACT_CHANNEL_NSEC: 'channel-carrier' }

  for (const [key, value] of Object.entries(env)) {
    const set = value !== undefined && value !== ''
    const rule = classify(key)
    if (!rule) { unknown.push(key); continue }
    const [cls, target] = rule

    if (SECRET_CLASSES.has(cls)) {
      // NEVER emit the value — only the fact it exists + where it goes.
      secrets.push({ key, class: cls, target, present: set })
      if (cls === 'role-key' && identityFor[key]) {
        config.identities[identityFor[key]] = { signer: 'custodial', import: key, status: set ? 'to-import' : 'missing' }
      }
      continue
    }
    if (cls === 'identity') {
      if (target === 'director' && set) config.directors.push({ from: key, npub: value })
      else config.operational[key] = set ? value : null   // nip05, approver id, etc. (public)
      continue
    }
    if (cls === 'operational') { config.operational[key] = set ? value : null; continue }
    if (cls === 'runtime') { runtime.push(key); continue }
  }

  // Dedup directors by npub (LUKE_MASTER_NPUB / NACT_DIRECTOR_NPUB are the same key).
  const seen = new Set()
  config.directors = config.directors.filter(d => !seen.has(d.npub) && seen.add(d.npub))

  return {
    summary: {
      identities: Object.keys(config.identities).length,
      directors: config.directors.length,
      secrets: secrets.length,
      operational: Object.keys(config.operational).length,
      runtime: runtime.length,
      unknown: unknown.length,
    },
    config, secrets, runtime, unknown,
  }
}

function renderSummary(plan) {
  const L = []
  L.push('Migration plan (no secret values shown)\n')
  L.push(`identities to import : ${Object.entries(plan.config.identities).map(([k, v]) => `${k}(${v.status})`).join(', ') || '—'}`)
  L.push(`directors            : ${plan.config.directors.map(d => d.npub.slice(0, 14) + '…').join(', ') || '—'}`)
  L.push(`credential-scopes    : ${plan.secrets.map(s => `${s.key}→${s.target}${s.present ? '' : '(unset)'}`).join('\n                       ') || '—'}`)
  L.push(`operational config   : ${Object.keys(plan.config.operational).join(', ') || '—'}`)
  L.push(`runtime (stays env)  : ${plan.runtime.join(', ') || '—'}`)
  L.push(`UNKNOWN (rules gap)  : ${plan.unknown.join(', ') || '—'}`)
  return L.join('\n')
}

// CLI
const path = process.argv[2]
if (path && !path.startsWith('--')) {
  const env = parseDotenv(readFileSync(path, 'utf8'))
  const plan = planMigration(env)
  if (process.argv.includes('--summary')) console.log(renderSummary(plan))
  else console.log(JSON.stringify(plan, null, 2))
} else if (path) {
  console.error('usage: node nactor/migrate-env.mjs <dotenv-file> [--summary]')
  process.exit(2)
}
