// mcp-grant-client — a minimal MCP-over-streamable-HTTP client for reading
// Nactor's credential grants from the nvoy-mcp service (M7, nact#6).
//
// ZERO NOSTR KNOWLEDGE by design: this module speaks JSON-RPC over HTTP and
// knows two tool names — `nvoy_grants_list` and `nvoy_scope_read` — the same
// conformance-pinned pair warm.contact consumes (nvoy/test/mcp-conformance.mjs
// is authoritative for their shapes: payload under `.data`, `max_age: 0` =
// live fetch, errors carry `code`). No keys, no relays, no crypto, no
// nostr-tools import. The nvoy-mcp service holds Nactor's nsec and does all
// of that; Nactor just asks.
//
// NO SDK dependency, deliberately: the client needs exactly two verbs
// (initialize + tools/call) of the Streamable HTTP transport, and the
// @modelcontextprotocol/sdk client would add a dependency tree to the runtime
// image for what is ~200 lines of protocol. The transport details below are
// pinned against the SDK SERVER the nvoy repo actually runs
// (@modelcontextprotocol/sdk ^1.29 StreamableHTTPServerTransport):
//   • POST /mcp with `accept: application/json, text/event-stream` (406
//     without BOTH) and `content-type: application/json` (415 otherwise).
//   • The response to a request is an SSE stream (`text/event-stream`) that
//     carries the JSON-RPC response as `data:` events and closes when the
//     response is complete; a plain `application/json` body is also honored
//     (servers configured with enableJsonResponse).
//   • initialize returns an `mcp-session-id` response header; every later
//     request must send it back, plus `mcp-protocol-version` (the version the
//     server negotiated in the initialize result).
//   • Notifications POST → 202 with no body.
//   • DELETE /mcp with the session header terminates the session.
//   • A dead/unknown session answers 400/404 — the client transparently
//     re-initializes ONCE and retries, so an nvoy-mcp restart between sweeps
//     never wedges the reader.
//
// Auth: the server exposes no token gate (verified against nvoy/mcp/src — the
// HTTP listener authenticates nothing). The trust boundary is NETWORK
// ISOLATION: nvoy-mcp is expose-only on the private compose network, never
// published, never routed by Caddy. Anything that can reach it is already
// inside the box's trust perimeter (see the nave.pub deploy notes for M7).

const JSONRPC = '2.0'

/** A tool call that returned isError — carries the nvoy error `code`. */
export class McpToolError extends Error {
  constructor(payload, toolName) {
    super(`${toolName}: ${payload?.code || 'TOOL_ERROR'}${payload?.message ? ` — ${payload.message}` : ''}`)
    this.name = 'McpToolError'
    this.code = payload?.code || 'TOOL_ERROR'
    this.payload = payload
  }
}

/** Transport/protocol failure (HTTP status, JSON-RPC error, bad frame). */
export class McpTransportError extends Error {
  constructor(message, { status } = {}) {
    super(message)
    this.name = 'McpTransportError'
    this.status = status
  }
}

// Parse an SSE body: `data:` lines per event, events separated by blank
// lines. Returns every JSON-parseable data payload, in order.
function parseSse(text) {
  const out = []
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block.split(/\r?\n/)
      .filter(l => l.startsWith('data:'))
      .map(l => l.slice(5).trimStart())
      .join('\n')
    if (!data) continue
    try { out.push(JSON.parse(data)) } catch { /* keep-alives / non-JSON */ }
  }
  return out
}

export class McpGrantClient {
  #url; #timeoutMs; #clientInfo
  #session = null          // mcp-session-id, once initialized
  #protocolVersion = null  // what the server negotiated
  #nextId = 1              // JSON-RPC request ids must be strings or INTEGERS

  constructor({ url, timeoutMs = 30_000, clientInfo } = {}) {
    if (!url) throw new Error('McpGrantClient: url required (e.g. http://nvoy-mcp:8799/mcp)')
    this.#url = url
    this.#timeoutMs = timeoutMs
    this.#clientInfo = clientInfo || { name: 'nact-grant-reader', version: '0.1.0' }
  }

  get url() { return this.#url }

  async #post(body, { expectResponse = true } = {}) {
    const headers = {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    }
    if (this.#session) headers['mcp-session-id'] = this.#session
    if (this.#protocolVersion) headers['mcp-protocol-version'] = this.#protocolVersion
    const ctl = new AbortController()
    const t = setTimeout(() => ctl.abort(), this.#timeoutMs)
    let res
    try {
      res = await fetch(this.#url, { method: 'POST', headers, body: JSON.stringify(body), signal: ctl.signal })
      if (!res.ok) {
        const text = await res.text().catch(() => '')
        throw new McpTransportError(`MCP endpoint answered ${res.status}: ${text.slice(0, 200)}`, { status: res.status })
      }
      const sid = res.headers.get('mcp-session-id')
      if (sid) this.#session = sid
      if (!expectResponse) { await res.text().catch(() => {}); return null }
      const ctype = res.headers.get('content-type') || ''
      const text = await res.text()
      const messages = ctype.includes('text/event-stream') ? parseSse(text)
        : text ? [JSON.parse(text)] : []
      const reply = messages.find(m => m && m.id === body.id)
      if (!reply) throw new McpTransportError(`no JSON-RPC response for id ${body.id} in ${ctype || 'empty body'}`)
      if (reply.error) throw new McpTransportError(`JSON-RPC error ${reply.error.code}: ${reply.error.message}`)
      return reply.result
    } catch (e) {
      if (e?.name === 'AbortError') throw new McpTransportError(`MCP request timed out after ${this.#timeoutMs}ms`)
      throw e
    } finally {
      clearTimeout(t)
    }
  }

  /** Initialize (or re-initialize) the MCP session. Idempotent. */
  async connect() {
    if (this.#session) return
    const result = await this.#post({
      jsonrpc: JSONRPC, id: this.#nextId++, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: this.#clientInfo },
    })
    this.#protocolVersion = result?.protocolVersion || '2025-06-18'
    // Spec lifecycle: acknowledge before the first tools/call. 202, no body.
    await this.#post({ jsonrpc: JSONRPC, method: 'notifications/initialized' }, { expectResponse: false })
  }

  /**
   * Call a tool and return its parsed JSON payload (the text content).
   * A dead session (server restarted between sweeps) is re-initialized once.
   * Throws McpToolError (with `.code`) when the tool answered isError.
   */
  async callTool(name, args = {}) {
    await this.connect()
    let result
    try {
      result = await this.#toolsCall(name, args)
    } catch (e) {
      const gone = e instanceof McpTransportError && (e.status === 400 || e.status === 404)
      if (!gone) throw e
      this.#session = null            // session died with the old server process
      await this.connect()
      result = await this.#toolsCall(name, args)
    }
    const text = result?.content?.find?.(c => c.type === 'text')?.text
    if (text === undefined) throw new McpTransportError(`tool ${name} returned no text content`)
    let payload
    try { payload = JSON.parse(text) } catch { throw new McpTransportError(`tool ${name} returned non-JSON text`) }
    if (result.isError) throw new McpToolError(payload, name)
    return payload
  }

  #toolsCall(name, args) {
    return this.#post({
      jsonrpc: JSONRPC, id: this.#nextId++, method: 'tools/call',
      params: { name, arguments: args },
    })
  }

  /** The held grants, as nvoy_grants_list reports them:
   *  [{ d, author_npub, scope_name, purpose, expires_at, terms, v, status, … }] */
  async listGrants() {
    const payload = await this.callTool('nvoy_grants_list')
    return Array.isArray(payload?.grants) ? payload.grants : []
  }

  /** Dereference one scope. maxAge 0 forces a fresh relay fetch (live read).
   *  Returns { data, v, fetched_at, terms, … } — payload under `.data`. */
  async readScope(d, authorNpub, { maxAge } = {}) {
    const args = { d, author_npub: authorNpub }
    if (maxAge !== undefined) args.max_age = maxAge
    return this.callTool('nvoy_scope_read', args)
  }

  /** Terminate the session (best-effort DELETE); safe to call repeatedly. */
  async close() {
    if (!this.#session) return
    const headers = { 'mcp-session-id': this.#session }
    if (this.#protocolVersion) headers['mcp-protocol-version'] = this.#protocolVersion
    this.#session = null
    try { await fetch(this.#url, { method: 'DELETE', headers }) } catch { /* server already gone */ }
  }
}
