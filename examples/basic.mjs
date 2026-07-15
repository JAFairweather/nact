// A minimal Nact wiring: an HTTP server that (a) lets your proposer submit an
// action and (b) receives the Telegram approval callback. Run with the env
// vars from the quickstart set. This is illustrative — your real proposer
// (LLM + signals) calls nact.propose() however it likes.

import { createServer } from 'node:http'
import { Nact } from '../src/nact.mjs'
import { telegramApproval } from '../src/adapters/telegram.mjs'

const approval = telegramApproval({
  botToken: process.env.TELEGRAM_BOT_TOKEN,
  approverId: process.env.TELEGRAM_APPROVER_ID,
  webhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET,
})

const nact = new Nact({
  identities: {
    nave: { nsec: process.env.NAVE_NSEC },
    luke: { nsec: process.env.LUKE_NSEC },
  },
  relays: (process.env.RELAYS || 'wss://relay.damus.io,wss://nos.lol').split(','),
  approval,
})

const readBody = async req => { let s = ''; for await (const c of req) s += c; return s }

createServer(async (req, res) => {
  const url = (req.url || '/').split('?')[0]

  // Your proposer POSTs an action here (guard this with your own auth).
  if (req.method === 'POST' && url === '/propose') {
    const d = JSON.parse(await readBody(req))
    const out = await nact.propose({ identity: d.identity, event: d.event, context: d.context, replyTo: d.replyTo })
    return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out))
  }

  // Telegram calls this when the human taps a button.
  if (req.method === 'POST' && url === '/telegram/webhook') {
    if (!approval.verifyWebhook(req.headers)) return res.writeHead(401).end()
    const raw = await readBody(req)
    res.writeHead(200).end()                 // ack Telegram fast
    await nact.handleCallback(raw)           // then sign + broadcast if approved
    return
  }

  res.writeHead(404).end()
}).listen(8790, () => console.log(`nact example on :8790 — identities: ${nact.identityNames().join(', ')}`))
