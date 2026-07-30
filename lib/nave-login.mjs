// vendored from JAFairweather/nave.pub components @ 9fd4a61 — do not edit; npm run sync-login
// Source of truth: nave.pub/components/nave-login.mjs — copy in, do not edit.
// The shared Nave sign-in card — the common login surface every app draws from,
// so a bespoke gate never drifts again. Pairs with nave-connect (the signer
// logic) and nave-titlebar (the signed-in cluster); this is the signed-OUT
// panel. No imports, no build step: apps vendor this file next to their
// vendored nave-connect and call
//
//   renderLogin(el, {
//     appName, tagline, sealSvg,        // header identity (sealSvg: trusted literal)
//     blurb,                            // one line under the title
//     primaryLabel,                     // the big button ("Sign in", "Sign in with Alby")
//     signerNote,                       // "works with any NIP-07 signer — Alby · nos2x · Amber"
//     bunkerPlaceholder, bunkerNote,    // the remote-signer row
//     advancedLabel,                    // optional "use a local key" link
//     onExtension,                      // () => sign in via a NIP-07 browser extension
//     onBunker,                         // (uri) => connect a bunker:// string
//     onNostrConnect,                   // () => pair a remote signer (generates a link)
//     onLocal,                          // () => optional advanced/local-key path
//     hasExtension,                     // bool — show the extension button (default: !!window.nostr)
//   })
//   setLoginStatus(el, msg, kind)       // 'info' | 'error' | '' — live status under the card
//
// The app owns the signer (nave-connect); this component owns the surface and
// the layout. Buttons render only when their callback is given. Theme with a
// single token: set --accent on `el` (or an ancestor) — gold for the control
// plane, purple for the app family, anything for a new app. Token-driven CSS
// with dark-canonical fallbacks, so it looks right with or without a token
// sheet. Keep in lock-step with components/nave-login.html.

const STYLE_ID = 'nave-login-style'

const CSS = `
  .nave-login { max-width: 560px; margin: 40px auto; padding: 0 18px;
    font-family: var(--sans, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif);
    color: var(--text, #f4efe4); }
  .nave-login .nl-card {
    border: 1px solid var(--line, #2a2317); border-radius: 14px;
    background: linear-gradient(180deg, color-mix(in srgb, var(--panel, #14100a) 70%, var(--bg, #0b0906)), var(--bg, #0b0906));
    padding: 26px 24px 22px; }
  .nave-login .nl-head { display: flex; align-items: center; gap: 13px; margin-bottom: 12px; }
  .nave-login .nl-seal { width: 40px; height: 40px; flex: none; color: var(--accent, #c39a56); }
  .nave-login .nl-seal:empty { display: none; }
  .nave-login .nl-seal svg { width: 100%; height: 100%; display: block; }
  .nave-login .nl-title { margin: 0; font-size: 20px; font-weight: 650; letter-spacing: -0.01em; color: var(--text, #f4efe4); }
  .nave-login .nl-tag { margin: 1px 0 0; font-size: 12.5px; color: var(--dim, #9c927f);
    font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace); letter-spacing: 0.04em; }
  .nave-login .nl-blurb { color: var(--dim, #9c927f); font-size: 14px; margin: 4px 0 18px; }
  .nave-login .nl-primary {
    width: 100%; font-size: 15px; font-weight: 700; letter-spacing: 0.02em;
    padding: 14px 16px; border-radius: 10px; cursor: pointer;
    border: 1px solid var(--accent, #c39a56); background: var(--accent, #c39a56); color: var(--on-accent, #0b0906);
    transition: filter .15s, transform .05s; }
  .nave-login .nl-primary:hover { filter: brightness(1.07); }
  .nave-login .nl-primary:active { transform: translateY(1px); }
  .nave-login .nl-note { text-align: center; font-size: 12.5px; color: var(--faint, #6f6555); margin: 9px 0 0; }
  .nave-login .nl-row { display: flex; gap: 8px; margin-top: 16px; }
  .nave-login .nl-input {
    flex: 1; min-width: 0; background: var(--bg2, #0d0a06); border: 1px solid var(--line2, #3a3020);
    border-radius: 9px; padding: 11px 12px; color: var(--text, #f4efe4);
    font-family: var(--mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace); font-size: 12px; }
  .nave-login .nl-input:focus { outline: none; border-color: color-mix(in srgb, var(--accent, #c39a56) 60%, transparent); }
  .nave-login .nl-connect {
    flex: none; font-size: 13px; font-weight: 600; padding: 0 16px; border-radius: 9px; cursor: pointer;
    border: 1px solid var(--accent, #c39a56); background: none; color: var(--accent, #c39a56); }
  .nave-login .nl-connect:hover { background: color-mix(in srgb, var(--accent, #c39a56) 14%, transparent); }
  .nave-login .nl-subnote { font-size: 12px; color: var(--faint, #6f6555); margin: 7px 2px 0; }
  .nave-login .nl-alt { margin-top: 14px; text-align: center; }
  .nave-login .nl-link { background: none; border: none; cursor: pointer; font: inherit;
    color: var(--accent, #c39a56); font-size: 13px; padding: 4px; }
  .nave-login .nl-link:hover { color: var(--text, #f4efe4); }
  .nave-login .nl-sep { display: flex; align-items: center; gap: 10px; margin: 16px 0 4px; color: var(--faint, #6f6555); font-size: 11px; }
  .nave-login .nl-sep::before, .nave-login .nl-sep::after { content: ""; flex: 1; height: 1px; background: var(--line, #2a2317); }
  .nave-login .nl-status { min-height: 18px; margin-top: 12px; font-size: 13px; white-space: pre-wrap;
    color: var(--dim, #9c927f); }
  .nave-login .nl-status[data-kind="error"] { color: var(--crit, #d1705f); }
  .nave-login .nl-key { font-size: 12px; color: var(--faint, #6f6555); text-align: center; margin-top: 16px; }
`

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])) }

function ensureStyle(doc) {
  if (doc.getElementById(STYLE_ID)) return
  const s = doc.createElement('style'); s.id = STYLE_ID; s.textContent = CSS; doc.head.appendChild(s)
}

export function renderLogin(el, opts = {}) {
  if (!el) return
  ensureStyle(el.ownerDocument || document)
  const o = { hasExtension: (typeof window !== 'undefined' && !!window.nostr), ...opts }
  const wrap = el.querySelector ? el : el
  wrap.classList.add('nave-login')

  const showExt = typeof o.onExtension === 'function' && o.hasExtension !== false
  const showBunker = typeof o.onBunker === 'function'
  const showNC = typeof o.onNostrConnect === 'function'
  const showLocal = typeof o.onLocal === 'function'

  wrap.innerHTML = `
    <div class="nl-card">
      <div class="nl-head">
        <div class="nl-seal">${o.sealSvg || ''}</div>
        <div>
          <h3 class="nl-title">${esc(o.appName || 'Sign in')}</h3>
          ${o.tagline ? `<p class="nl-tag">${esc(o.tagline)}</p>` : ''}
        </div>
      </div>
      ${o.blurb ? `<p class="nl-blurb">${esc(o.blurb)}</p>` : ''}
      ${showExt ? `<button class="nl-primary" data-nl="ext">${esc(o.primaryLabel || 'Sign in with your extension')}</button>
        ${o.signerNote ? `<p class="nl-note">${esc(o.signerNote)}</p>` : ''}` : ''}
      ${showNC ? `${showExt ? '<div class="nl-sep">or</div>' : ''}
        <button class="nl-primary" data-nl="nc" ${showExt ? 'style="background:none;color:var(--accent,#c39a56)"' : ''}>${esc(o.nostrConnectLabel || 'Connect a remote signer')}</button>` : ''}
      ${showBunker ? `<div class="nl-row">
          <input class="nl-input" data-nl="bunker-uri" placeholder="${esc(o.bunkerPlaceholder || 'bunker://… from your remote signer')}">
          <button class="nl-connect" data-nl="bunker-go">Connect</button>
        </div>
        ${o.bunkerNote ? `<p class="nl-subnote">${esc(o.bunkerNote)}</p>` : ''}` : ''}
      ${showLocal ? `<div class="nl-alt"><button class="nl-link" data-nl="local">${esc(o.advancedLabel || 'Advanced: use a local key in this tab')}</button></div>` : ''}
      <div class="nl-status" data-nl="status"></div>
      ${o.keyNote !== false ? `<p class="nl-key">${esc(o.keyNote || 'Your key never enters this page.')}</p>` : ''}
    </div>`

  const q = sel => wrap.querySelector(sel)
  q('[data-nl="ext"]')?.addEventListener('click', () => o.onExtension())
  q('[data-nl="nc"]')?.addEventListener('click', () => o.onNostrConnect())
  q('[data-nl="local"]')?.addEventListener('click', () => o.onLocal())
  const uri = q('[data-nl="bunker-uri"]')
  const go = () => { const v = (uri?.value || '').trim(); if (v) o.onBunker(v) }
  q('[data-nl="bunker-go"]')?.addEventListener('click', go)
  uri?.addEventListener('keydown', e => { if (e.key === 'Enter') go() })
  return wrap
}

// Live status under the card (errors, "generating link…", "approve in your
// signer…") without a re-render — mirrors updateTitlebar's in-place update.
export function setLoginStatus(el, msg = '', kind = 'info') {
  const s = el?.querySelector?.('[data-nl="status"]')
  if (!s) return
  s.textContent = msg || ''
  if (kind === 'error') s.setAttribute('data-kind', 'error'); else s.removeAttribute('data-kind')
}
