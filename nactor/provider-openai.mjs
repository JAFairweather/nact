// provider-openai.mjs: the broker's OpenAI provider (one entry of BROKER_PROVIDERS in nactor.mjs).
//
// Narrower than the anthropic entry on purpose. An OpenAI key reaches far more than text generation (files,
// fine-tuning, images, key and project admin on some key types), and the caller picks the path and the method. So
// the broker forwards only text-generation calls, POST only, to the pinned host. A consumer that needs another
// endpoint adds it here, in review, not in its request.
//
// Its own module so the rule can be tested without starting the broker (provider-openai.test.mjs).
export const OPENAI_PATHS = ['/v1/chat/completions', '/v1/responses']

export const openaiProvider = {
  credential: 'openai',
  build: (body, cred) => {
    const p = String(body.path || '')
    if (!OPENAI_PATHS.includes(p)) throw new Error(`path '${p}' not permitted for openai`)
    const m = String(body.method || 'POST').toUpperCase()
    if (m !== 'POST') throw new Error(`method '${m}' not permitted for openai`)
    const base = (process.env.NACT_BROKER_BASE_OPENAI || 'https://api.openai.com').replace(/\/$/, '')
    return { url: base + p, headers: { authorization: `Bearer ${cred}`, 'content-type': 'application/json' } }
  },
}
