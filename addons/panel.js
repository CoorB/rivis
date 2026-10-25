/* Product-neutral panel — injected into mitmweb by proxy_panel.py.
 * A self-contained drawer (shadow DOM, so mitmweb's CSS and ours never collide), modelled on
 * FRTMProxy / Proxyman: This call · Compose · Map Local · Breakpoints · Network (incl. TLS decryption list) ·
 * Scripts · Rules, "Copy as …" code generation, plus a pop-up
 * editor that opens by itself when a call pauses at a breakpoint (Continue / Skip / Abort).
 * Talks only to /proxy/api/* with mitmweb's own XSRF scheme (cookie _mitmproxy_xsrf → X-XSRFToken).
 */
(() => {
  if (window.__proxyPanel) return;
  window.__proxyPanel = true;
  const drawerW = () => Math.round(Math.min(460, Math.max(380, window.innerWidth * 0.32)));   // laptop screens keep more room for the list

  const xsrf = () => (document.cookie.match(/(?:^|;\s*)_mitmproxy_xsrf=([^;]+)/) || [])[1] || "";
  // A request that never answers must end in a message, never in silence (and must give its connection back: a browser
  // allows 6 per host, and hung requests that are only abandoned, not aborted, starve every later click).
  // Normal ops get 15 s; these legitimately take longer (a whole capture saved / loaded / exported, an update, a device set-up).
  const SLOW_OPS = new Set(["sess_har", "sess_save", "sess_load", "coll_replay", "coll_import", "update_check", "update_install", "device_setup", "browser_open"]);
  const NORMAL_MS = 15000, SLOW_MS = 120000;
  const product = () => (state && state.product) || {};
  const noAnswer = (what, secs, post) => {
    const cli = product().cli || "rivis";
    return new Error(`${product().name || "Rivis"} did not answer within ${secs} s${what ? " (" + what + ")" : ""} — the proxy may be busy or stuck. ` +
      `Run \`${cli} status\` in Terminal; if that hangs too, run \`${cli} restart\`.${post ? " The action may still have been applied." : ""}`);
  };
  const fetchT = async (url, opts, ms, what) => {
    const ac = new AbortController(), t = setTimeout(() => ac.abort(), ms);
    try { return await fetch(url, { ...opts, signal: ac.signal }); }
    catch (e) {
      if (ac.signal.aborted) throw noAnswer(what, Math.round(ms / 1000), opts && opts.method && opts.method !== "GET");
      throw e;
    }
    finally { clearTimeout(t); }
  };
  const api = async (op, body, ms) => {
    const opts = body === undefined
      ? { credentials: "same-origin" }
      : { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(body) };
    const r = await fetchT("./proxy/api/" + op, opts, ms || (SLOW_OPS.has(op) ? SLOW_MS : NORMAL_MS), OP_NAMES[op] || op);
    let j = {};
    try { j = await r.json(); } catch (e) { j = { error: "HTTP " + r.status }; }
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    return j;
  };
  const OP_NAMES = { mock: "Map Local", maplocal_add: "Map Local", bp_add: "Breakpoint", bp_update: "Breakpoint", bp_delete: "Breakpoint",
    retry: "Repeat", retry_get: "Edit & Repeat", focus_host: "Show only this host", tls_host: "TLS decryption", tls_set: "TLS decryption",
    tls_update: "TLS decryption", view: "view filter", source: "source filter", delete: "delete", sess_save: "session save", sess_load: "session load",
    sess_har: "HAR export", client_cert_add: "client certificate", client_cert_rm: "client certificate", lan_allow: "allow device", lan_rm: "remove device", lan_dismiss: "ignore device", compose_send: "Compose send", codegen: "Copy as code", export: "Copy", update_install: "update" };
  const selectedFlow = () => {   // mitmweb keeps the selection in the hash: #/flows/<id>/<tab>
    const p = location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
    return p[0] === "flows" && p[1] ? p[1] : null;
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const emptyState = (icon, title, hint) =>
    `<div class="empty">${ico(icon)}<b>${esc(title)}</b><span class="sub">${hint}</span></div>`;
  const info = (t) => `<span class="info" tabindex="0" role="img" aria-label="${esc(t)}" title="${esc(t)}">ⓘ</span>`;
  const hostPath = (u) => { try { const x = new URL(u); return [x.host, x.pathname + x.search]; } catch (e) { return ["", u]; } };
  // a rule's match regex → readable "host/path" for lists
  const pretty = (r) => {
    if (r.note && r.note.startsWith("from ")) { const u = r.note.split(" ").pop(); const [h, p] = hostPath(u); return h + p; }
    if (r.note && r.note.startsWith("manual: ")) return r.note.slice(8);
    if (r.label) return r.label;
    return String(r.match || "").replace(/^\^https\?:\/\//, "").replace(/\(:\\d\+\)\?/, "").replace(/\(\\\?\|\$\)$/, "")
      .replace(/\\([.\-\/])/g, "$1").replace(/\[\^\/:\]\*/g, "*").replace(/\.\*/g, "*");
  };

  // one icon family: 24px grid, 1.7 stroke, round caps — inline so the tool works offline
  const ICONS = {
    mark: '<path d="M8 19V5h5a3.5 3.5 0 0 1 0 7H8"/><path d="M13 12l4.5 7"/>',
    call: '<path d="M5 3l14 8-6.2 1.8L10 19z"/>',
    compose: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
    map: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5"/><path d="M10 14h6M13 11l3 3-3 3"/>',
    bp: '<circle cx="12" cy="12" r="9"/><path d="M10 9v6M14 9v6"/>',
    net: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/>',
    coll: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
    cmp: '<path d="M4 5h7v14H4zM13 5h7v14h-7z"/>',
    sess: '<path d="M5 4h11l3 3v13H5z"/><path d="M8 4v5h7V4M8 20v-6h8v6"/>',
    scripts: '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 6l-3 12"/>',
    rules: '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    gear: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10M14 5v4M6 15v4"/>',
    help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1.1.9-1.1 1.7M12 17h.01"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6L7 7M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4"/>',
    moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>',
    auto: '<circle cx="12" cy="12" r="8"/><path d="M12 4v16" /><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7"/>',
    lock: '<path d="M6 11h12v9H6z"/><path d="M9 11V8a3 3 0 0 1 6 0v3"/>',
    warn: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17h.01"/>',
    pause: '<path d="M9 6v12M15 6v12"/>',
    phone: '<path d="M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M11 18h2"/>',
    inbox: '<path d="M4 13l2-8h12l2 8"/><path d="M4 13v6h16v-6h-5l-1 2h-4l-1-2z"/>',
    retry: '<path d="M4 12a8 8 0 1 0 3-6.2"/><path d="M4 4v5h5"/>',
    note: '<path d="M5 4h14v12l-4 4H5z"/><path d="M15 20v-4h4M8 9h8M8 13h4"/>',
    wifi: '<path d="M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01"/>',
    down: '<path d="M4 6l8 11 8-11"/>',
    sliders: '<path d="M4 12h4M16 12h4M8 8v8M16 8v8"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    back: '<path d="M15 5l-7 7 7 7"/>',
    unlock: '<path d="M6 11h12v9H6z"/><path d="M9 11V8a3 3 0 0 1 5.8-1"/>',
    search: '<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/>',
    trash: '<path d="M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13M10 11v6M14 11v6"/>',
  };
  const ico = (n, cls = "") => `<svg class="i ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[n] || ""}</svg>`;
  const LS = {   // remembered per browser; wrapped because localStorage throws in some private windows
    get: (k, d) => { try { const v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } },
  };
  const DOC = document.documentElement;
  const columnStyle = document.createElement("style");
  columnStyle.textContent = '.flow-table table[data-rivis-hide-path="1"] .col-path, .flow-table table[data-rivis-hide-timestamp="1"] .col-timestamp { display: none; }';
  document.head.appendChild(columnStyle);      // column visibility is functional even when the optional skin is off

  const host = document.createElement("div");
  host.id = "proxy-panel-host";
  document.body.appendChild(host);
  const root = host.attachShadow({ mode: "open" });
  // mitmweb has single-key shortcuts on window (d = delete, a = resume, r = replay…) and swallows
  // keys it thinks are shortcuts. It cannot see that focus is in OUR text boxes (shadow DOM), so
  // keep every key press inside the panel from ever reaching its window handler.
  ["keydown", "keypress", "keyup"].forEach((t) => host.addEventListener(t, (e) => e.stopPropagation()));
  root.innerHTML = `
  <link rel="stylesheet" href="./proxy/theme.css">
  <style>
    :host { all: initial; }
    * { box-sizing: border-box; font-family: var(--rv-font); }
    button, input, select, textarea { font: inherit; }
    svg.i { width: 16px; height: 16px; flex: none; fill: none; stroke: currentColor; stroke-width: 1.7; stroke-linecap: round; stroke-linejoin: round; }
    svg.i.sm { width: 14px; height: 14px; }
    ::selection { background: color-mix(in srgb, var(--rv-accent) 30%, transparent); }
    * { scrollbar-width: thin; scrollbar-color: var(--rv-border-strong) transparent; }
    :focus-visible { outline: 2px solid var(--rv-focus); outline-offset: 1px; }

    /* launcher */
    /* the tools button lives in the toolbar row (placeBars sets --fab-top): a floating button used to cover the time column of the last rows */
    .fab { position: fixed; top: var(--fab-top, 46px); right: calc(var(--open-w, 0px) + 12px); z-index: 11; display: flex; align-items: center; gap: 7px; height: 32px; background: var(--rv-accent); color: var(--rv-accent-fg);
           border: 0; border-radius: var(--rv-r-pill); padding: 0 13px 0 5px; font-weight: 600; font-size: 12.5px; cursor: pointer; box-shadow: var(--rv-shadow-1);
           transition: transform var(--rv-dur) var(--rv-ease), background var(--rv-dur) var(--rv-ease), box-shadow var(--rv-dur) var(--rv-ease), right var(--rv-dur) var(--rv-ease); }
    .fab:hover { background: var(--rv-accent-hover); transform: translateY(-1px); }
    .fab:active { transform: none; }
    .fab .mark { width: 22px; height: 22px; border-radius: 50%; background: var(--rv-accent-fg); color: var(--rv-accent); display: grid; place-items: center; }
    .fab .mark svg { width: 15px; height: 15px; stroke-width: 2.2; }
    .fab .dot { width: 8px; height: 8px; border-radius: 50%; background: #ffd166; box-shadow: 0 0 0 2px color-mix(in srgb, #ffd166 35%, transparent); }
    .fab.paused { background: var(--rv-warn); color: var(--rv-warn-fg); }
    .fab.paused .mark { color: var(--rv-warn); }
    .fab.paused .dot { background: #fff; animation: pulse 1.2s ease-in-out infinite; }
    @keyframes pulse { 50% { opacity: .35; } }

    /* brand bar over mitmweb's header (product + project label, theme, help) */
    .brand.mini #bname, .brand.mini #bproj, .brand.mini .sep { display: none; }   /* narrow window: the mark only, so the search box keeps its room */
    .brand { position: fixed; top: 4px; right: 12px; z-index: 11; display: flex; align-items: center; gap: 4px; height: 32px; padding: 0 4px 0 10px;
             background: var(--rv-surface); border: 1px solid var(--rv-border); border-radius: var(--rv-r-pill); box-shadow: var(--rv-shadow-1); color: var(--rv-text); font-size: 12.5px; transition: right var(--rv-dur) var(--rv-ease); }
    .brand .mark { width: 18px; height: 18px; border-radius: 6px; background: var(--rv-accent); color: var(--rv-accent-fg); display: grid; place-items: center; margin-right: 4px; }
    .brand .mark svg { width: 12px; height: 12px; stroke-width: 2.4; }
    .brand b { font-weight: 700; letter-spacing: .01em; }
    .brand .proj { color: var(--rv-text-2); max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding-right: 6px; }
    .brand .proj::before { content: "/"; margin-right: 6px; color: var(--rv-text-3); }
    .ib { border: 0; background: transparent; color: var(--rv-text-2); width: 26px; height: 26px; border-radius: var(--rv-r-pill); display: grid; place-items: center; cursor: pointer;
          transition: background var(--rv-dur) var(--rv-ease), color var(--rv-dur) var(--rv-ease); }
    .ib:hover { background: var(--rv-surface-2); color: var(--rv-text); }
    .ib.on { background: var(--rv-accent-soft); color: var(--rv-accent-text); }


    /* always-visible search: sits in mitmweb's top row after the tabs, wired to mitmweb's own filter (see "Search bar" below) */
    .sbar { position: fixed; z-index: 11; top: 5px; left: var(--sb-left, 360px); width: var(--sb-w, 300px); height: 30px; display: flex; align-items: center; gap: 4px; }
    :host([data-skin="off"]) .sbar, :host([data-skin="off"]) .fstrip, :host(:not([data-sbar])) .sbar, :host(:not([data-sbar])) .fstrip { display: none; }
    .sbox { flex: 1; min-width: 0; height: 30px; display: flex; align-items: center; gap: 6px; padding: 0 4px 0 10px; background: var(--rv-surface); border: 1px solid var(--rv-control); border-radius: var(--rv-r-pill); color: var(--rv-text-3);
            transition: border-color var(--rv-dur) var(--rv-ease), box-shadow var(--rv-dur) var(--rv-ease); }
    .sbox:focus-within { border-color: var(--rv-accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--rv-accent) 22%, transparent); color: var(--rv-accent-text); }
    .sbox.bad { border-color: var(--rv-danger); }
    .sbox.bad:focus-within { box-shadow: 0 0 0 3px color-mix(in srgb, var(--rv-danger) 22%, transparent); }
    .sbox input#sq { flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; box-shadow: none; padding: 0; min-height: 0; height: 26px; font: 12.5px var(--rv-mono); color: var(--rv-text); border-radius: 0; }
    .sbox input#sq::placeholder { font-family: var(--rv-font); }
    .sbox kbd { font-size: 10.5px; padding: 0 5px; border-bottom-width: 1px; color: var(--rv-text-3); }
    .sbox:focus-within kbd, .sbox.has kbd, :host([data-tight]) .sbox kbd { display: none; }
    .sbox .ib { width: 22px; height: 22px; flex: none; }
    .sbox .ib[hidden], .sbox kbd[hidden] { display: none; }
    .spop { position: fixed; z-index: 12; top: 42px; left: var(--sb-left, 360px); width: max(var(--sb-w, 300px), 340px); background: var(--rv-surface); border: 1px solid var(--rv-border); border-radius: var(--rv-r-lg); box-shadow: var(--rv-shadow-2);
            padding: 10px 12px; display: none; font-size: 12px; color: var(--rv-text-2); }
    .spop.open { display: block; animation: pop var(--rv-dur) var(--rv-ease); }
    .spop.err { border-color: var(--rv-danger); color: var(--rv-danger); background: var(--rv-surface); }
    .spop h5 { margin: 0 0 6px; font-size: 10.5px; letter-spacing: .07em; text-transform: uppercase; color: var(--rv-text-3); }
    .spop button.ex { display: flex; width: 100%; align-items: baseline; gap: 10px; border: 0; background: none; padding: 3px 4px; border-radius: var(--rv-r-sm); cursor: pointer; text-align: left; color: var(--rv-text-2); font-size: 12px; }
    .spop button.ex:hover { background: var(--rv-accent-soft); color: var(--rv-accent-text); }
    .spop button.ex code { background: transparent; padding: 0; min-width: 112px; color: var(--rv-text); font-size: 12px; }
    .fstrip { position: fixed; z-index: 2; left: 0; right: var(--open-w, 0px); top: var(--hb, 80px); height: 28px; display: flex; align-items: center; gap: 6px; padding: 0 12px; background: var(--rv-surface-2); border-bottom: 1px solid var(--rv-border); font-size: 12px; color: var(--rv-text-2); overflow: hidden; white-space: nowrap; transition: right var(--rv-dur) var(--rv-ease); }
    .fstrip .fchip { display: inline-flex; align-items: center; gap: 4px; height: 20px; padding: 0 4px 0 9px; border-radius: var(--rv-r-pill); background: var(--rv-accent-soft); color: var(--rv-accent-text); font-weight: 600; max-width: 260px; }
    .fstrip .fchip span { overflow: hidden; text-overflow: ellipsis; }
    .fstrip .fchip button { border: 0; background: none; color: inherit; width: 16px; height: 16px; border-radius: 50%; padding: 0; display: grid; place-items: center; cursor: pointer; flex: none; }
    .fstrip .fchip button:hover { background: color-mix(in srgb, var(--rv-accent) 22%, transparent); }
    .fstrip .cnt2 { margin-left: auto; font-variant-numeric: tabular-nums; }
    .fstrip .lnk { font-size: 12px; }
    .fstrip .saved { border: 1px solid var(--rv-border-strong); border-radius: var(--rv-r-pill); background: var(--rv-surface); color: var(--rv-text); white-space: nowrap; cursor: pointer; padding: 2px 7px; }
    .fstrip .saved.on { background: var(--rv-accent-soft); color: var(--rv-accent-text); }
    .fstrip .savedmenu { display: inline-flex; gap: 3px; }
    .fstrip .savedmenu button { border: 0; background: transparent; color: var(--rv-accent-text); cursor: pointer; font-size: 11px; }
    :host([data-sbrow]) .fstrip { padding-left: calc(var(--sb-w, 200px) + 16px); }
    :host([data-sbrow]) .sbar, :host([data-sbrow]) .sbox { height: 26px; }
    :host([data-sbrow]) .sbox input#sq { height: 22px; }


    /* right-click menu on a call */
    .cmenu { position: fixed; z-index: 2147483004; min-width: 232px; display: none; padding: 4px; background: var(--rv-surface); color: var(--rv-text); border: 1px solid var(--rv-border); border-radius: var(--rv-r-lg); box-shadow: var(--rv-shadow-3); font-size: 12.5px; }
    .cmenu.open { display: block; animation: pop var(--rv-dur) var(--rv-ease); }
    .cmenu button { display: flex; align-items: center; gap: 9px; width: 100%; padding: 6px 10px; border: 0; background: none; border-radius: var(--rv-r-md); color: inherit; text-align: left; cursor: pointer; }
    .cmenu button:hover, .cmenu button:focus-visible { background: var(--rv-accent-soft); color: var(--rv-accent-text); outline: none; }
    .cmenu button:disabled { opacity: .4; pointer-events: none; }
    .cmenu button.d:hover, .cmenu button.d:focus-visible { background: var(--rv-danger-soft); color: var(--rv-danger); }
    .cmenu button kbd { margin-left: auto; font-size: 10.5px; }
    .cmenu hr { border: 0; border-top: 1px solid var(--rv-border); margin: 4px 2px; }
    .cmenu .hd { padding: 4px 10px 6px; color: var(--rv-text-3); font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* drawer */
    .drawer { container: rvdrawer / inline-size; position: fixed; top: 0; right: 0; height: 100vh; width: var(--drawer-w, 460px); max-width: 100vw; z-index: 2147483001; background: var(--rv-surface); color: var(--rv-text);
              border-left: 1px solid var(--rv-border); box-shadow: var(--rv-shadow-2); display: none; flex-direction: column; font-size: 13px; }
    .drawer.open { display: flex; animation: slide var(--rv-dur) var(--rv-ease); }
    @keyframes slide { from { transform: translateX(18px); opacity: .4; } }
    header { display: flex; align-items: center; gap: 8px; padding: 10px 12px 10px 14px; border-bottom: 1px solid var(--rv-border); }
    header .mark { width: 22px; height: 22px; border-radius: 7px; background: var(--rv-accent); color: var(--rv-accent-fg); display: grid; place-items: center; flex: none; }
    header .mark svg { width: 14px; height: 14px; stroke-width: 2.2; }
    header b { font-size: 14px; flex: 1; font-weight: 650; min-width: 40px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    header b small { font-weight: 500; color: var(--rv-text-2); font-size: 13px; }
    .x { border: 0; background: transparent; font-size: 20px; line-height: 1; cursor: pointer; color: var(--rv-text-2); width: 26px; height: 26px; border-radius: var(--rv-r-md); }
    .x:hover { background: var(--rv-surface-2); color: var(--rv-text); }
    nav { display: grid; grid-template-columns: repeat(6, 1fr); gap: 2px; padding: 6px 8px 0; border-bottom: 1px solid var(--rv-border); background: var(--rv-surface); }   /* 6 + 5: every tab visible, even widths */
    nav::-webkit-scrollbar { display: none; }
    @container rvdrawer (max-width: 430px) { nav { grid-template-columns: repeat(4, 1fr); } }
    nav button { position: relative; display: flex; flex-direction: column; align-items: center; gap: 3px; border: 0; background: none; padding: 7px 2px 7px; cursor: pointer; font-size: 11.5px; font-weight: 500; color: var(--rv-text-2);
                 border-bottom: 2px solid transparent; border-radius: var(--rv-r-md) var(--rv-r-md) 0 0; white-space: nowrap; min-width: 0; transition: color var(--rv-dur) var(--rv-ease), background var(--rv-dur) var(--rv-ease); }
    nav button svg.i { width: 17px; height: 17px; }
    nav button:hover { color: var(--rv-text); background: var(--rv-surface-2); }
    nav button.on { color: var(--rv-accent-text); border-bottom-color: var(--rv-accent); font-weight: 600; }
    label.pj { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--rv-text-3); min-width: 0; flex: 0 1 auto; }
    label.pj select { min-width: 58px; width: 100%; }
    /* two menus (Show, Source) share a ~380 px header with the close button: drop their words before anything overflows */
    @container rvdrawer (max-width: 430px) { label.pj .pjt { display: none; } }
    .info { color: var(--rv-text-3); cursor: help; font-size: 11px; }
    nav .cnt:empty { display: none; }
    nav .cnt { position: absolute; top: 3px; right: calc(50% - 24px); background: var(--rv-accent-soft); color: var(--rv-accent-text); border-radius: var(--rv-r-pill); padding: 0 6px; font-size: 10.5px; font-weight: 700; line-height: 16px; font-variant-numeric: tabular-nums; }
    nav .cnt.err { background: var(--rv-danger-soft); color: var(--rv-danger); }
    main { flex: 1; overflow: auto; padding: 14px; }
    h4 { margin: 18px 0 7px; font-size: 10.5px; text-transform: uppercase; letter-spacing: .07em; color: var(--rv-text-3); font-weight: 700; display: flex; align-items: center; gap: 8px; }
    h4::after { content: ""; flex: 1; height: 1px; background: var(--rv-border); }
    h4:first-child { margin-top: 2px; }
    .call .u { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }   /* a 3,000-char URL must not push the actions off screen */
    .call { background: var(--rv-surface-2); border: 1px solid var(--rv-border); border-radius: var(--rv-r-md); padding: 9px 11px; word-break: break-all; font-family: var(--rv-mono); font-size: 12px; line-height: 1.5; }
    .call .sub { font-family: var(--rv-font); }
    .m { font-weight: 700; margin-right: 8px; color: var(--rv-accent-text); font-size: 11px; letter-spacing: .03em; }
    .btns { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; align-items: center; }

    /* controls */
    button.b { display: inline-flex; align-items: center; gap: 6px; border: 1px solid var(--rv-border-strong); background: var(--rv-surface); border-radius: var(--rv-r-md); padding: 5px 11px; min-height: 28px;
               cursor: pointer; font-size: 12.5px; font-weight: 500; color: var(--rv-text); box-shadow: var(--rv-shadow-1);
               transition: background var(--rv-dur) var(--rv-ease), border-color var(--rv-dur) var(--rv-ease), transform var(--rv-dur) var(--rv-ease); }
    button.b:hover { background: var(--rv-accent-soft); border-color: var(--rv-accent); color: var(--rv-accent-text); }
    button.b:active { transform: translateY(1px); }
    button.b:disabled { opacity: .45; cursor: default; pointer-events: none; }
    button.p { background: var(--rv-accent); color: var(--rv-accent-fg); border-color: var(--rv-accent); box-shadow: none; font-weight: 600; }
    button.p:hover { background: var(--rv-accent-hover); border-color: var(--rv-accent-hover); color: var(--rv-accent-fg); }
    button.d { color: var(--rv-danger); }
    button.d:hover { background: var(--rv-danger-soft); border-color: var(--rv-danger); color: var(--rv-danger); }
    button.warn { background: var(--rv-warn); color: var(--rv-warn-fg); border-color: var(--rv-warn); }
    button.warn:hover { background: var(--rv-warn); filter: brightness(.92); color: var(--rv-warn-fg); }
    .row { display: flex; align-items: center; gap: 8px; padding: 8px 2px; border-bottom: 1px solid var(--rv-border); }
    .row .n { flex: 1; min-width: 0; }
    .row .n div { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tag { font-size: 10px; font-weight: 700; letter-spacing: .03em; padding: 1px 7px; border-radius: var(--rv-r-pill); background: var(--rv-accent-soft); color: var(--rv-accent-text); margin-left: 4px; }
    .tag.err { background: var(--rv-danger-soft); color: var(--rv-danger); }
    .chip { font-size: 12px; padding: 3px 10px; border-radius: var(--rv-r-pill); border: 1px solid var(--rv-border-strong); background: var(--rv-surface); cursor: pointer; color: var(--rv-text-2); user-select: none;
            transition: background var(--rv-dur) var(--rv-ease), color var(--rv-dur) var(--rv-ease); }
    .chip:hover { border-color: var(--rv-accent); color: var(--rv-accent-text); }
    .chip.on { background: var(--rv-accent); color: var(--rv-accent-fg); border-color: var(--rv-accent); }
    .sub { color: var(--rv-text-3); font-size: 11.5px; line-height: 1.45; }
    .muted { color: var(--rv-text-3); }
    .sw { position: relative; width: 34px; height: 20px; flex: none; }
    .sw input { opacity: 0; width: 100%; height: 100%; position: absolute; margin: 0; cursor: pointer; z-index: 1; }
    .sw span { position: absolute; inset: 0; background: var(--rv-text-3); border-radius: 10px; transition: background var(--rv-dur) var(--rv-ease); }   /* off track >= 3:1 against the surface (WCAG 1.4.11) */
    .sw span:before { content: ""; position: absolute; width: 16px; height: 16px; left: 2px; top: 2px; background: var(--rv-surface); border-radius: 50%; box-shadow: var(--rv-shadow-1); transition: transform var(--rv-dur) var(--rv-ease); }
    .sw input:checked + span { background: var(--rv-accent); }
    .sw input:checked + span:before { background: var(--rv-accent-fg); }
    .sw input:checked + span:before { transform: translateX(14px); }
    .sw input:focus-visible + span { outline: 2px solid var(--rv-focus); outline-offset: 2px; }
    select, input[type=number], input[type=text], input:not([type]), input[type=search] { border: 1px solid var(--rv-control); border-radius: var(--rv-r-md); padding: 5px 8px; min-height: 28px; font-size: 12.5px; background: var(--rv-surface); color: var(--rv-text);
            transition: border-color var(--rv-dur) var(--rv-ease), box-shadow var(--rv-dur) var(--rv-ease); }
    select:focus, input:focus, textarea:focus { outline: none; border-color: var(--rv-accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--rv-accent) 22%, transparent); }
    input::placeholder, textarea::placeholder { color: var(--rv-text-3); opacity: 1; }
    input[type=checkbox] { accent-color: var(--rv-accent); }
    input.grow { flex: 1; min-width: 0; }
    #project { max-width: 120px; min-height: 26px; font-size: 12px; }
    #source { max-width: 112px; min-height: 26px; font-size: 12px; }
    #source option.unset { color: var(--rv-text-3); font-style: italic; }
    textarea { width: 100%; min-height: 260px; height: calc(100vh - 420px); font-family: var(--rv-mono); font-size: 12px; line-height: 1.55; border: 1px solid var(--rv-control); border-radius: var(--rv-r-md);
               padding: 10px; resize: vertical; background: var(--rv-surface-2); color: var(--rv-text); tab-size: 2; }
    textarea[readonly] { opacity: .75; }
    .hrow input, .krow input[type=text], td input { font-family: var(--rv-mono); }
    .lostbar { position: fixed; bottom: 34px; left: 50%; transform: translateX(-50%); z-index: 2147483004; display: none; max-width: min(720px, 92vw);
               background: var(--rv-danger, #b42318); color: #fff; padding: 8px 14px; border-radius: var(--rv-r-md); font-size: 13px; box-shadow: var(--rv-shadow-2, 0 4px 14px rgba(0,0,0,.25)); }
    .lostbar.open { display: block; }
    .lostbar.info { background: var(--rv-text); color: var(--rv-surface); bottom: 78px; }
    .lostbar.info .b { margin-left: 8px; }
    .lostbar.info .lnk { color: inherit; text-decoration: underline; margin-left: 8px; }
    .updnotes { white-space: pre-wrap; font-size: 12.5px; margin: 6px 0 0; max-height: 240px; overflow: auto; }
    .devcode { font: 600 20px/1.2 var(--rv-mono); letter-spacing: 2px; margin: 4px 0 6px; }
    .lostbar code { background: rgba(255,255,255,.18); color: #fff; padding: 0 4px; border-radius: 3px; white-space: nowrap; }
    .toast { position: fixed; left: 50%; transform: translateX(-50%); bottom: 26px; z-index: 2147483003; background: var(--rv-text); color: var(--rv-surface); padding: 9px 16px; border-radius: var(--rv-r-md);
             font-size: 12.5px; font-weight: 500; display: none; align-items: center; gap: 12px; max-width: 80vw; box-shadow: var(--rv-shadow-2); animation: toast var(--rv-dur) var(--rv-ease); }
    .toast.err { background: var(--rv-danger); color: var(--rv-danger-fg); }
    .toast button { border: 1px solid currentColor; border-radius: var(--rv-r-pill); padding: 4px 9px; background: transparent; color: inherit; font-weight: 700; white-space: nowrap; cursor: pointer; }
    @keyframes toast { from { opacity: 0; transform: translate(-50%, 8px); } }
    .card { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--rv-border); border-radius: var(--rv-r-lg); padding: 10px 12px; margin-bottom: 8px; cursor: pointer; background: var(--rv-surface);
            transition: border-color var(--rv-dur) var(--rv-ease), background var(--rv-dur) var(--rv-ease), box-shadow var(--rv-dur) var(--rv-ease); }
    .card:hover { border-color: var(--rv-accent); box-shadow: var(--rv-shadow-1); }
    .card.on { border-color: var(--rv-accent); background: var(--rv-accent-soft); }
    .card .ic { width: 24px; height: 24px; display: grid; place-items: center; color: var(--rv-accent-text); flex: none; }
    .card .t { font-weight: 600; }
    .card .ok { margin-left: auto; color: var(--rv-accent-text); display: grid; place-items: center; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 8px; }
    .grid label { font-size: 11.5px; color: var(--rv-text-2); display: flex; flex-direction: column; gap: 4px; }
    .seg { display: inline-flex; gap: 2px; margin: 8px 0 8px; padding: 3px; background: var(--rv-surface-2); border: 1px solid var(--rv-border); border-radius: var(--rv-r-md); }
    .seg button { border: 0; background: transparent; padding: 4px 12px; cursor: pointer; font-size: 12.5px; font-weight: 500; color: var(--rv-text-2); border-radius: calc(var(--rv-r-md) - 2px);
                  transition: background var(--rv-dur) var(--rv-ease), color var(--rv-dur) var(--rv-ease); }
    .seg button:hover { color: var(--rv-text); background: var(--rv-surface-3); }
    .seg button.on { background: var(--rv-surface); color: var(--rv-accent-text); font-weight: 600; box-shadow: var(--rv-shadow-1), inset 0 0 0 1px var(--rv-border); }
    .hrow { display: flex; gap: 4px; margin-bottom: 4px; }
    .hrow input { flex: 1; min-width: 0; font-size: 11.5px; }
    .hrow input:first-child { flex: 0 0 38%; }
    .krow { display: flex; gap: 4px; margin-bottom: 4px; align-items: center; }
    .krow input[type=text] { flex: 1; min-width: 0; font-size: 11.5px; }
    .krow input[type=checkbox] { flex: none; }
    .chip span[data-tlsrm] { margin-left: 4px; cursor: pointer; opacity: .7; }
    .empty { display: flex; flex-direction: column; align-items: center; gap: 6px; text-align: center; padding: 28px 18px; color: var(--rv-text-3); border: 1px dashed var(--rv-border-strong); border-radius: var(--rv-r-lg); background: var(--rv-surface-2); }
    .empty svg.i { width: 26px; height: 26px; color: var(--rv-text-3); }
    .empty b { color: var(--rv-text); font-size: 13px; }
    .set { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--rv-border); }
    .set > div:first-child { flex: 1; } .set b { font-weight: 600; display: block; }

    button.b.sm { min-height: 24px; padding: 2px 9px; font-size: 12px; box-shadow: none; background: transparent; }
    button.b.sm.d { background: transparent; }
    .call .dim { color: var(--rv-text-3); }
    .call .m { display: inline-block; font-size: 10.5px; padding: 0 7px; line-height: 18px; border-radius: var(--rv-r-pill); background: var(--rv-accent-soft); color: var(--rv-accent-text); margin-right: 8px; vertical-align: 1px; }
    .call .lnk { font-size: 11.5px; padding: 0 2px; }
    .lnk:hover { text-decoration: underline; }
    .info { display: inline-block; padding: 0 2px; border-radius: var(--rv-r-sm); }
    .info:hover, .info:focus-visible { color: var(--rv-accent-text); }
    .btns > .seg { margin: 0; }
    input[type=file] { font-size: 12px; color: var(--rv-text-2); max-width: 100%; }
    input[type=file]::file-selector-button { font: inherit; font-weight: 500; border: 1px solid var(--rv-border-strong); background: var(--rv-surface); color: var(--rv-text); border-radius: var(--rv-r-md); padding: 4px 10px; margin-right: 8px; cursor: pointer; }
    input[type=file]::file-selector-button:hover { background: var(--rv-accent-soft); border-color: var(--rv-accent); color: var(--rv-accent-text); }
    .chip { font-family: inherit; }

    /* paused-call sheet / dialogs */
    .pause { position: fixed; inset: 0; z-index: 2147483002; background: var(--rv-overlay); display: none; align-items: center; justify-content: center; backdrop-filter: blur(2px); }
    .pause.open { display: flex; }
    .sheet { background: var(--rv-surface); color: var(--rv-text); width: min(860px, 94vw); max-height: 92vh; display: flex; flex-direction: column; border-radius: 14px; box-shadow: var(--rv-shadow-3);
             border: 1px solid var(--rv-border); overflow: hidden; animation: pop var(--rv-dur) var(--rv-ease); }
    @keyframes pop { from { transform: translateY(8px) scale(.985); opacity: 0; } }
    .sheet header { background: var(--rv-surface-2); }
    .sheet header.paused { background: var(--rv-warn-soft); border-color: color-mix(in srgb, var(--rv-warn) 40%, transparent); }
    .sheet header.paused b { color: var(--rv-warn); }
    .sheet header.retry { background: var(--rv-accent-soft); }
    .sheet main { padding: 14px 16px; }
    .sheet footer { display: flex; gap: 8px; justify-content: flex-end; padding: 10px 16px; border-top: 1px solid var(--rv-border); align-items: center; background: var(--rv-surface-2); }
    .sheet textarea { height: 38vh; }
    .sheet textarea.nobody { height: 120px; min-height: 120px; }
    .banner { background: var(--rv-warn-soft); color: var(--rv-warn); border: 1px solid color-mix(in srgb, var(--rv-warn) 35%, transparent); border-radius: var(--rv-r-md); padding: 8px 11px; display: flex; align-items: center; gap: 8px; }
    .banner.bad { background: var(--rv-danger-soft); color: var(--rv-danger); border-color: color-mix(in srgb, var(--rv-danger) 35%, transparent); }
    .banner .sub { color: inherit; opacity: .85; }
    .row .n div.rule-hits { white-space: normal; overflow: visible; }
    .rule-hits.warn, .ruletest .warn { color: var(--rv-warn); }
    .ruletest { border: 1px solid var(--rv-border, #8884); border-radius: var(--rv-r-md); padding: 6px 9px; margin: 6px 0 10px; }
    .ruletest .fires { color: var(--rv-accent-text); }
    table.diff { width: 100%; border-collapse: collapse; font-size: 11.5px; table-layout: fixed; }
    table.diff td, table.diff th { border-bottom: 1px solid var(--rv-border); padding: 5px 6px; vertical-align: top; word-break: break-all; text-align: left; }
    table.diff th { color: var(--rv-text-3); font-weight: 600; }
    table.diff td.k { font-family: var(--rv-mono); color: var(--rv-text-2); }
    td.a { background: var(--rv-danger-soft); } td.b { background: var(--rv-ok-soft); }
    .rec { color: var(--rv-danger); font-weight: 700; }
    pre.code { white-space: pre-wrap; word-break: break-word; background: var(--rv-surface-2); border: 1px solid var(--rv-border); border-radius: var(--rv-r-md); padding: 9px 11px; font: 11.5px/1.55 var(--rv-mono); max-height: 280px; overflow: auto; margin: 6px 0; }
    .jk { color: var(--rv-accent-text); } .js { color: var(--rv-ok); } .jn { color: var(--rv-info); } .jb { color: var(--rv-t-composed); }
    .errbox { background: var(--rv-danger-soft); color: var(--rv-danger); border: 1px solid color-mix(in srgb, var(--rv-danger) 35%, transparent); border-radius: var(--rv-r-md); padding: 8px 10px; margin-top: 8px; }
    .errbox pre.code { color: var(--rv-danger); }
    kbd { font: 600 11px var(--rv-mono); background: var(--rv-surface); border: 1px solid var(--rv-border-strong); border-bottom-width: 2px; border-radius: 5px; padding: 1px 6px; color: var(--rv-text-2); white-space: nowrap; }
    .map { width: 100%; border-collapse: collapse; font-size: 12.5px; }
    .map th { text-align: left; font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase; color: var(--rv-text-3); padding: 4px 8px; }
    .map td { padding: 7px 8px; border-top: 1px solid var(--rv-border); vertical-align: top; }
    .map td:first-child { color: var(--rv-text-2); width: 36%; }
    .map td.go { width: 64px; white-space: nowrap; text-align: right; }
    .map .lnk, .lnk { border: 0; background: none; padding: 2px 4px; border-radius: var(--rv-r-sm); color: var(--rv-accent-text); cursor: pointer; font-weight: 600; font-size: 12.5px; }
    .map .lnk:hover { text-decoration: underline; background: var(--rv-accent-soft); }
    code.cmd { display: block; font: 12px/1.5 var(--rv-mono); background: var(--rv-surface); border: 1px solid var(--rv-border); border-radius: var(--rv-r-md); padding: 6px 10px; margin: 4px 0; text-align: left; user-select: all; color: var(--rv-text); }

    /* floating cards over mitmweb: welcome + empty list */
    .wscrim { position: fixed; inset: 0; z-index: 2147483001; background: var(--rv-overlay); display: none; }
    .welcome.open + .wscrim { display: block; }
    .welcome { position: fixed; left: calc((100vw - var(--open-w, 0px)) / 2); top: 50%; transform: translate(-50%, -50%); z-index: 2147483002; width: min(700px, calc(100vw - var(--open-w, 0px) - 32px)); max-height: min(88vh, 760px); overflow: auto;
               background: var(--rv-surface); border: 1px solid var(--rv-border); border-radius: 14px;
               box-shadow: var(--rv-shadow-3); padding: 18px 20px; display: none; animation: pop var(--rv-dur) var(--rv-ease); }
    .welcome.open { display: flex; flex-direction: column; overflow: hidden; }
    .welcome .wbody { overflow: auto; min-height: 0; flex: 1; margin: 0 -6px; padding: 0 6px; }
    .welcome .wfoot { margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--rv-border); flex: none; }
    .welcome h3 { margin: 0 0 4px; font-size: 16px; display: flex; align-items: center; gap: 10px; }
    .welcome h3 .mark { width: 26px; height: 26px; border-radius: 8px; background: var(--rv-accent); color: var(--rv-accent-fg); display: grid; place-items: center; }
    .welcome h3 .mark svg { width: 16px; height: 16px; stroke-width: 2.2; }
    .welcome p { margin: 6px 0 12px; color: var(--rv-text-2); line-height: 1.5; }
    #askdlg { width: min(480px, calc(100vw - var(--open-w, 0px) - 32px)); }
    #askdlg input { width: 100%; box-sizing: border-box; margin: 4px 0 2px; }
    .emptylist { position: fixed; z-index: 1; left: 0; top: calc(var(--hb, 80px) + 30px + var(--strip-h, 0px)); width: calc(100vw - var(--open-w, 0px)); bottom: 30px; pointer-events: none; display: none; align-items: center; justify-content: center; padding: 16px; overflow: hidden; }   /* placed over the call list by placeEmptyList() */
    .emptylist.open { display: flex; }
    .emptylist .box { pointer-events: auto; width: min(660px, 100%); text-align: center; padding: 8px 12px; }
    .emptylist .glyph { width: 52px; height: 52px; margin: 0 auto 12px; border-radius: 16px; background: var(--rv-accent-soft); color: var(--rv-accent-text); display: grid; place-items: center; }
    .emptylist .glyph svg.i { width: 26px; height: 26px; }
    .emptylist h3 { margin: 0 0 6px; font-size: 17px; font-weight: 650; color: var(--rv-text); }
    .emptylist .lede { color: var(--rv-text-2); font-size: 13px; line-height: 1.5; max-width: 460px; margin: 0 auto; }
    .emptylist .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 18px; text-align: left; }
    .emptylist .opt { background: var(--rv-surface); border: 1px solid var(--rv-border); border-radius: var(--rv-r-lg); padding: 12px 14px; box-shadow: var(--rv-shadow-1); }
    .emptylist h5 { margin: 0 0 8px; font-size: 12.5px; letter-spacing: 0; text-transform: none; color: var(--rv-text); display: flex; align-items: center; gap: 6px; font-weight: 650; }
    .emptylist h5 svg.i { color: var(--rv-accent-text); }
    .emptylist code.cmd { cursor: copy; font-size: 12px; padding: 7px 9px; margin: 0 0 6px; white-space: nowrap; overflow-x: auto; }
    .emptylist code.cmd:hover { border-color: var(--rv-accent); }
    .emptylist .btns { justify-content: center; margin-top: 14px; }
    .emptylist .foot { margin-top: 16px; color: var(--rv-text-3); font-size: 11.5px; }
    @media (max-width: 760px) { .emptylist .cols { grid-template-columns: 1fr; } }
    .reddot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--rv-danger); margin-right: 6px; animation: pulse 1.4s ease-in-out infinite; }
    .errtext { color: var(--rv-danger); }
    .sub svg.i, .banner svg.i, p svg.i, b svg.i, h3 svg.i, h5 svg.i { vertical-align: -3px; margin-right: 3px; }
    .banner button { margin-left: auto; }
    code { font-family: var(--rv-mono); font-size: 11.5px; background: var(--rv-surface-2); border-radius: 4px; padding: 1px 5px; }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0ms !important; transition-duration: 0ms !important; } }
  </style>
  <button class="fab" id="fab" aria-label="Tools: Map Local, breakpoints, network conditions, scripts" title="Tools — Map Local, breakpoints, network conditions, scripts (Alt+Shift+P)"><span class="mark">${ico("sliders")}</span><span id="fablabel">Tools</span><span class="dot" id="fabdot" style="display:none"></span></button>
  <div class="brand" id="brand"><span class="mark">${ico("mark")}</span><b id="bname">Rivis</b><span class="proj" id="bproj"></span>
    <button class="ib" id="btheme" title="Theme">${ico("auto")}</button><button class="ib" id="bhelp" title="Help, shortcuts and settings  (?)">${ico("help")}</button></div>
  <div class="sbar" id="sbar"><div class="sbox" id="sbox">${ico("search", "sm")}<input id="sq" type="text" placeholder="Filter: host, path or ~filter" aria-label="Filter calls: host or part of a URL, or a ~filter expression" spellcheck="false" autocomplete="off" autocapitalize="off">
      <button class="ib" id="sclear" hidden aria-label="Clear filter" title="Clear filter (Esc)">${ico("x", "sm")}</button><button class="ib" id="ssave" aria-label="Save filter" title="Save filter">☆</button><kbd>${/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "") ? "⌘F" : "Ctrl F"}</kbd></div>
    <button class="ib" id="strash" aria-label="Clear all calls" title="Clear all calls from the list">${ico("trash")}</button></div>
  <div class="spop" id="spop" role="status"></div>
  <div class="fstrip" id="fstrip"></div>
  <div class="cmenu" id="cmenu" role="menu" aria-label="Call actions"></div>
  <div class="drawer" id="drawer">
    <header><span class="mark">${ico("mark")}</span><b id="ptitle">Tools</b><label class="pj" title="Choose which project's calls the list shows"><span class="pjt">Show</span><select id="project" aria-label="Project shown in the call list"></select></label><label class="pj" title="Show the calls of one device, or of one app on it"><span class="pjt">Source</span><select id="source" aria-label="Device or app shown in the call list"></select></label><button class="ib" id="gear" title="Settings and help">${ico("gear")}</button><button class="x" id="close" title="Close" aria-label="Close">×</button></header>
    <nav>
      <button data-t="call" class="on">${ico("call", "sm")}This call</button>
      <button data-t="compose">${ico("compose", "sm")}Compose</button>
      <button data-t="map">${ico("map", "sm")}Map Local<span class="cnt" id="c-map"></span></button>
      <button data-t="bp">${ico("bp", "sm")}Breakpoints<span class="cnt" id="c-bp"></span></button>
      <button data-t="net">${ico("net", "sm")}Network</button>
      <button data-t="dev">${ico("phone", "sm")}Devices<span class="cnt" id="c-dev"></span></button>
      <button data-t="coll">${ico("coll", "sm")}Collections<span class="cnt" id="c-coll"></span></button>
      <button data-t="cmp">${ico("cmp", "sm")}Compare</button>
      <button data-t="sess">${ico("sess", "sm")}Sessions</button>
      <button data-t="scripts">${ico("scripts", "sm")}Scripts<span class="cnt" id="c-scripts"></span></button>
      <button data-t="rules">${ico("rules", "sm")}Rules<span class="cnt" id="c-rules"></span></button>
    </nav>
    <main id="main"></main>
  </div>
  <div class="pause" id="pause"><div class="sheet" id="sheet"></div></div>
  <div class="pause" id="help"><div class="sheet" id="hsheet"></div></div>
  <div class="welcome" id="welcome" role="dialog" aria-label="Coming from Proxyman?"></div><div class="wscrim" id="wscrim"></div>
  <div class="welcome" id="opendlg" role="alertdialog" aria-label="Open a file"></div><div class="wscrim" id="opscrim"></div>
  <div class="welcome" id="askdlg" role="alertdialog" aria-label="Question"></div><div class="wscrim" id="askscrim"></div>
  <div class="emptylist" id="emptylist"></div>
  <div class="toast" id="toast"></div>
  <div class="lostbar" id="lostbar" role="alert"></div>
  <div class="lostbar" id="proxybar" role="alert"></div>
  <div class="lostbar info" id="updatebar" role="status"></div>`;

  const $ = (id) => root.getElementById(id);
  let tab = "call", state = null, editing = null, pausedOpen = null, dismissed = new Set(), sheetDirty = () => false, drawerTypingDirty = false;
  // ── keyboard focus for what the panel opens (R6B-01/02/04/06) ──
  // A sheet, editor or the drawer opened from the keyboard left focus on mitmweb's list (or on <body>), so Tab never
  // reached it and the next "r" replayed the selected call. Whatever opens now takes focus, Tab cycles inside it,
  // Esc does what its close button / backdrop does, and focus goes back to where it was (or, when that element was
  // redrawn meanwhile, to the element with the same id).
  const FOCUSABLE = "button:not([disabled]), a[href], input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";
  const focusables = (box) => [...box.querySelectorAll(FOCUSABLE)].filter((el) => el.getClientRects().length > 0);
  const deepActive = () => { let a = document.activeElement; while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement; return a; };
  const returnTo = {};                       // surface → element (or {id} of a panel element that gets redrawn)
  const noteReturn = (key, from) => {
    const a = from ? { id: from } : deepActive(), box = key === "editor" ? $("drawer") : $(key);
    if (!returnTo[key] && a && a !== document.body && !(a.nodeType && box && box.contains(a))) returnTo[key] = a;
  };
  const focusInto = (box, prefer) => { const el = (prefer && box.querySelector(prefer)) || focusables(box)[0]; if (el) el.focus(); return el; };
  const giveBack = (key) => {
    const r = returnTo[key]; returnTo[key] = null;
    let el = r && r.nodeType ? r : null;
    if (el && !(el.isConnected && el.getClientRects().length)) el = null;
    const id = r && (r.nodeType ? r.getRootNode() === root && r.id : r.id);
    if (!el && id && $(id) && $(id).getClientRects().length) el = $(id);
    if (!el && $("drawer").classList.contains("open")) el = root.querySelector("nav button.on");
    // R6-04: a closed drawer cannot return keyboard shortcuts to a button inside this host.
    if (key === "drawer" && !$("drawer").classList.contains("open") && el && root.contains(el)) el = null;
    if (el) el.focus(); else if (key === "drawer" && !$("drawer").classList.contains("open")) {
      const row = document.querySelector(".flow-table tbody tr.selected, .flow-table tbody tr.active");
      if (row) { row.tabIndex = -1; row.focus({ preventScroll: true }); }
      else { document.body.tabIndex = -1; document.body.focus({ preventScroll: true }); }
    }
  };
  const openSheet = (id, prefer, auto = false) => { noteReturn(id); $(id).classList.add("open");
    // R6-01: a polled pause must leave a live typing target alone; Tab can still enter the sheet.
    const a = deepActive(), typing = a && (/^(INPUT|TEXTAREA)$/.test(a.tagName) || a.isContentEditable);
    if (!(auto && typing) && !$(id).contains(root.activeElement)) focusInto($(id).querySelector(".sheet") || $(id), prefer);
  };
  const closeSheet = (id) => { const was = $(id).classList.contains("open"); $(id).classList.remove("open"); if (was) giveBack(id); else returnTo[id] = null; };
  const topSheet = () => ["askdlg", "help", "pause", "welcome", "opendlg"].map($).find((x) => x.classList.contains("open")) || null;
  const trapTab = (e, box) => {      // Tab / Shift+Tab move through box's controls only, wrapping at either end
    const list = focusables(box); if (!list.length) return;
    const i = list.indexOf(deepActive()), n = list.length;
    e.preventDefault(); e.stopPropagation();
    list[i < 0 ? (e.shiftKey ? n - 1 : 0) : (i + (e.shiftKey ? n - 1 : 1)) % n].focus();
  };
  let viewers = { tokens:[], graphql_ops:[], graphql_error_ids:[], complete:false };
  const toast = (msg, err, action, sticky) => {
    toast._working = null;
    const t = $("toast"); t.innerHTML = `<span>${esc(msg)}</span>${action ? `<button type="button">${esc(action.label)}</button>` : ""}`;
    t.className = "toast" + (err ? " err" : ""); t.style.display = "flex";
    if (action) t.querySelector("button").onclick = () => { t.style.display = "none"; action.run(); };
    clearTimeout(toast._t);
    if (!sticky) toast._t = setTimeout(() => (t.style.display = "none"), action ? 8000 : err ? (msg.length > 80 ? 12000 : 5000) : 2500);
  };
  // "Working…": shown when an action is still waiting after a moment, so a slow answer is visible; whatever result follows replaces it
  const working = (what) => {
    const mark = {}, timer = setTimeout(() => { toast(`Working… ${what}`, false, null, true); toast._working = mark; }, 250);
    return () => { clearTimeout(timer); if (toast._working === mark) { toast._working = null; clearTimeout(toast._t); $("toast").style.display = "none"; } };
  };
  // R9-05: mitmweb's File → Open posts to /flows/dump and ignores the answer. The server now refuses a file it cannot
  // read with a 400 and a readable reason (keeping the current calls); show that reason instead of nothing.
  // F1: File → Open used to replace the whole live capture without asking. With calls captured, ask first: keep them and add
  // the file's (the default; the server marks them imported), replace them, or cancel. The server keeps by default too.
  let openAsk = null;                       // resolves the open question: "keep" | "replace" | null (cancelled)
  const askOpenMode = async () => {
    let n = Number((state && state.flow_count) || 0);
    try { n = Number((await api("state", undefined, 4000)).flow_count || 0); } catch (e) { /* the polled count will do */ }
    if (!n) return "keep";                  // nothing captured: nothing to lose, nothing to ask
    return new Promise((resolve) => {
      const done = (mode) => { openAsk = null; closeSheet("opendlg"); resolve(mode); };
      openAsk = () => done(null);
      $("opendlg").innerHTML = `
        <h3>Open this file?</h3>
        <div class="wbody"><p>You have <b>${n} captured call${n === 1 ? "" : "s"}</b>. <b>Keep</b> them and add the file's calls (marked <i>imported</i>),
          or <b>replace</b> them: replacing loses all ${n} call${n === 1 ? "" : "s"} unless you saved a session first.</p></div>
        <div class="btns wfoot" style="justify-content:flex-end"><button class="b" id="od-cancel">Cancel</button>
          <button class="b" id="od-replace">Replace (lose ${n})</button><button class="b p" id="od-keep">Keep my calls and add the file's</button></div>`;
      openSheet("opendlg", "#od-keep");
      $("od-keep").onclick = () => done("keep");
      $("od-replace").onclick = () => done("replace");
      $("od-cancel").onclick = () => done(null);
    });
  };
  $("opscrim").onclick = () => { if (openAsk) openAsk(); };
  // Pilot 2026-10-21 ("the delete/clear button doesn't work"): once someone ticks the browser's "Prevent this page from
  // creating additional dialogs", confirm() and prompt() answer "no" at once without showing anything, so Clear and
  // Delete looked dead. Every question is asked inside the panel instead. ask() resolves true/false; with
  // opts.input (the starting text) it resolves the typed text, or null when cancelled; with opts.choices
  // ([[value, label, "p"|"d"|""], …], the last one focused) it resolves the chosen value, or null for Cancel.
  let askDone = null;
  const ask = (message, opts = {}) => new Promise((resolve) => {
    if (askDone) askDone(null);                               // one question at a time: a new one cancels the old
    const field = opts.input !== undefined;
    const done = (v) => { askDone = null; closeSheet("askdlg"); resolve(field || opts.choices ? v : v === true); };
    askDone = done;
    const [head, ...rest] = String(message).split("\n\n");
    $("askdlg").innerHTML = `<h3>${esc(head)}</h3>
      ${rest.length ? `<div class="wbody">${rest.map((x) => `<p>${esc(x).replace(/\n/g, "<br>")}</p>`).join("")}</div>` : ""}
      ${field ? (opts.multiline ? `<textarea id="ask-in" rows="8" spellcheck="false" aria-label="${esc(head)}"></textarea>` : `<input type="text" id="ask-in" spellcheck="false" aria-label="${esc(head)}">`) : ""}
      <div class="btns wfoot" style="justify-content:flex-end"><button class="b" id="ask-no">${esc(opts.no || "Cancel")}</button>
        ${opts.choices ? opts.choices.map(([v, label, cls], i) => `<button class="b ${cls || ""}" data-ask="${i}"${i === opts.choices.length - 1 ? ' id="ask-yes"' : ""}>${esc(label)}</button>`).join("")
          : `<button class="b ${opts.danger ? "d" : "p"}" id="ask-yes">${esc(opts.yes || "OK")}</button>`}</div>`;
    if (field) $("ask-in").value = opts.input || "";
    openSheet("askdlg", field ? "#ask-in" : "#ask-yes");
    if (opts.choices) $("askdlg").querySelectorAll("[data-ask]").forEach((b) => (b.onclick = () => { askDone = null; closeSheet("askdlg"); resolve(opts.choices[b.dataset.ask][0]); }));
    else $("ask-yes").onclick = () => done(field ? $("ask-in").value : true);
    $("ask-no").onclick = () => done(null);
    if (field && !opts.multiline) $("ask-in").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); $("ask-yes").click(); } };
  });
  $("askscrim").onclick = () => { if (askDone) askDone(null); };
  if (window.fetch && !window.fetch._rivisOpen) {
    const origFetch = window.fetch;
    const wrapped = function (input, init) {
      let url = "", method = "GET";
      try {
        url = typeof input === "string" ? input : (input && input.url) || "";
        method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
      } catch (e) { /* never break mitmweb's own request */ }
      if (method === "POST" && /\/flows\/dump(?:[?#]|$)/.test(url) && typeof input === "string" && !/[?&]mode=/.test(url)) {
        return askOpenMode().then((mode) => {
          if (!mode) return new Response("", { status: 200 });          // cancelled: nothing opened, nothing lost
          const args = Array.prototype.slice.call(arguments);
          args[0] = url + (url.indexOf("?") < 0 ? "?" : "&") + "mode=" + mode;
          return reportOpen(origFetch.apply(this, args));
        });
      }
      const p = origFetch.apply(this, arguments);
      return method === "POST" && /\/flows\/dump(?:[?#]|$)/.test(url) ? reportOpen(p) : p;
    };
    const reportOpen = (p) => {
      try {
        p.then((r) => {
          if (r.ok) {
            r.clone().json().then((j) => { if (j && j.added !== undefined) toast(`Added ${j.added} call${j.added === 1 ? "" : "s"} from the file (marked imported). Your ${j.kept} captured call${j.kept === 1 ? " was" : "s were"} kept.`); }, () => {});
            return;
          }
          r.clone().text().then((t) => toast((t || "").trim() || `Could not open the file (HTTP ${r.status}). Your current calls were kept.`, true),
                                () => toast(`Could not open the file (HTTP ${r.status}).`, true));
        }, () => {});
      } catch (e) { /* never break mitmweb's own request */ }
      return p;
    };
    wrapped._rivisOpen = true;
    window.fetch = wrapped;
  }
  // ── sources (proxy_source.py): which device / app sent a call. Keys are "<kind>|<device>|<app id>"; a key ending in
  // "|" is a whole device. mitmweb's flow JSON has no metadata, so rows map through client_conn.id → key.
  const KIND_NAME = { ios: "iOS Simulator", android: "Android emulator", phone: "Phone or tablet (Wi-Fi)", browser: "Web browser", mac: "This Mac", unknown: "Unknown" };
  const sourceRows = () => (state && state.sources && state.sources.list) || [];
  const sourceOfFlow = (f) => {
    const key = f && f.client_conn && state && state.sources && state.sources.by_conn[f.client_conn.id];
    return key ? sourceRows().find((r) => r.key === key) || null : null;
  };
  const deviceKey = (r) => r.kind + "|" + r.device + "|";
  const deviceName = (r) => r.device || KIND_NAME[r.kind] || r.kind;
  const sourceName = (sel) => {             // the chip / toast text for a selection
    if (!sel) return "";
    const row = sourceRows().find((r) => r.key === sel || deviceKey(r) === sel);
    const [kind, device] = sel.split("|");
    if (sel.endsWith("|")) return (row ? deviceName(row) : device || KIND_NAME[kind] || kind) + " (all apps)";
    return row ? (row.app || deviceName(row)) + (row.app && row.device ? " on " + row.device : "") : sel.split("|").slice(2).join("|");
  };
  const tilde = (p) => { const h = state && state.home; return h && p && (p === h || String(p).startsWith(h + "/")) ? "~" + String(p).slice(h.length) : p; };
  const busy = new Set();
  // the control in the open tab that has the keyboard, as a selector that finds it again after a redraw (or null)
  const focusKey = () => {
    const f = root.activeElement;
    if (!f || !f.closest || !f.closest("#main")) return null;
    return f.id ? "#" + CSS.escape(f.id)
      : [...f.attributes].filter((a) => a.name.startsWith("data-")).map((a) => `[${a.name}="${CSS.escape(a.value)}"]`).join("") || null;
  };
  const refocus = (sel) => { if (!sel) return; const el = $("main").querySelector(sel); if (el && root.activeElement !== el) el.focus({ preventScroll: true }); };
  const run = async (op, body, ok) => {
    const key = op + JSON.stringify(body || {});
    const again = focusKey();       // a change redraws its tab: the keyboard stays on the same control (a second Space works)
    const what = OP_NAMES[op] || op.replace(/_/g, " ");
    if (busy.has(key)) { toast(`Still waiting for the previous ${what}… (${product().name || "Rivis"} has not answered yet)`, true); return; }
    busy.add(key);
    const done = working(what);
    try { const r = await api(op, body); if (r.state) state = r.state; done(); if (ok) toast(typeof ok === "function" ? ok(r) : ok); Promise.resolve(render()).then(() => refocus(again)); return r; }
    catch (e) { toast(e.message, true); }
    finally { done(); busy.delete(key); }
  };
  const breakpointOn = (flowId) => {
    const repeatId = flowId || selectedFlow();
    toast("Breakpoint on — it pauses the NEXT matching call. Trigger it in the app, or Repeat it now.", false, {
      label: "Repeat now",
      run: () => repeatId ? run("retry", { flow_id: repeatId, edits: {} }, "Repeated — the new call is in the list (newest first)")
        : toast("Select a call in the list first", true),
    });
  };
  const sw = (id, on, extra = "") => `<label class="sw"><input type="checkbox" ${id} ${on ? "checked" : ""} ${extra}><span></span></label>`;

  // headers editor: rows of [name, value]
  const headersHTML = (rows, idp) => `<div id="${idp}">${(rows || []).map(([k, v]) =>
      `<div class="hrow"><input type="text" value="${esc(k)}" placeholder="Header"><input type="text" value="${esc(v)}" placeholder="Value"><button class="b d" data-hdel aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")}</div>
    <button class="b" data-hadd="${idp}">+ Add header</button>`;
  const wireHeaders = (scope) => {
    scope.querySelectorAll("[data-hdel]").forEach((b) => (b.onclick = () => b.parentElement.remove()));
    scope.querySelectorAll("[data-hadd]").forEach((b) => (b.onclick = () => {
      const box = root.getElementById(b.dataset.hadd);
      const d = document.createElement("div"); d.className = "hrow";
      d.innerHTML = `<input type="text" placeholder="Header"><input type="text" placeholder="Value"><button class="b d" data-hdel aria-label="Remove">${ico("x", "sm")}</button>`;
      box.appendChild(d); d.querySelector("[data-hdel]").onclick = () => d.remove(); d.querySelector("input").focus();
    }));
  };
  const readHeaders = (idp) => [...root.getElementById(idp).querySelectorAll(".hrow")]
    .map((r) => [...r.querySelectorAll("input")].map((i) => i.value)).filter(([k]) => k.trim());
  const jsonCheck = (ta, out) => { try { JSON.parse(ta.value); out.textContent = ta.value.trim() ? "Valid JSON" : ""; return true; } catch (x) { out.textContent = ta.value.trim() ? "Not JSON — sent as plain text" : ""; out.title = x.message; return !ta.value.trim(); } };

  // F2: the call list is fetched incrementally (only what is new or changed since the last answer, plus the ids that left the
  // list), with a full download when there is no cursor yet, the proxy says so (list cleared or rebuilt) and every
  // FULL_RESYNC_MS as a safety net for a change that sent no signal. One poll at a time, 10 s deadline, as before.
  const flowCache = { at: 0, byId: new Map(), pending: null, epoch: null, cursor: 0, fullAt: 0 };
  const FULL_RESYNC_MS = Number(LS.get("rivis-flow-resync-ms", "")) || 30000;
  async function refreshFlows() {
    if (!flowCache.pending) {
      const full = flowCache.epoch === null || Date.now() - flowCache.fullAt >= FULL_RESYNC_MS;
      const q = full ? "" : `?epoch=${encodeURIComponent(flowCache.epoch)}&cursor=${flowCache.cursor}`;
      flowCache.pending = fetchT("./proxy/api/flows_since" + q, { credentials: "same-origin" }, 10000, "call list")
        .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); }).then((d) => {
          if (d.full) { flowCache.byId = new Map(); flowCache.fullAt = Date.now(); }
          d.flows.forEach((f) => flowCache.byId.set(f.id, f));
          d.removed.forEach((id) => flowCache.byId.delete(id));
          flowCache.epoch = d.epoch; flowCache.cursor = d.cursor; flowCache.at = Date.now();
        }).finally(() => { flowCache.pending = null; });
    }
    await flowCache.pending;
  }
  async function flowsById(id, strict) {
    try {
      const fresh = Date.now() - flowCache.at < 800;
      if (fresh && flowCache.byId.has(id)) return flowCache.byId.get(id);
      await refreshFlows();
      return flowCache.byId.get(id) || null;
    }
    catch (e) { if (strict) throw e; return null; }
  }
  async function builtinContent(id, side, views) {
    for (const view of views) {
      try {
        // R6-06: the decoded protobuf view must include every byte, including beyond the normal UI clip.
        const r = await fetchT(`./flows/${id}/${side}/content/${encodeURIComponent(view)}.json?full=1`, { credentials:"same-origin" }, NORMAL_MS, "call body");
        if (r.ok) return await r.json();
      } catch (e) { /* use the panel-side schema-less fallback */ }
    }
    return null;
  }

  let renderSeq = 0, editorCheckT = 0;
  let pollState = null;                   // poll()'s state request while it is in flight: render() shares it
  async function render() {
    const seq = ++renderSeq;
    clearTimeout(editorCheckT);  // R6-05: any redraw detaches the old editor and its JSON result node.
    if (!state) state = await (pollState || api("state")).catch(() => null);   // share a poll already asking, never a second request
    if (seq !== renderSeq) return;
    if (!state) { $("main").innerHTML = '<p class="muted">Cannot reach the panel API.</p>'; return; }
    openTabSig = tabSig(state);              // B15: what this tab now shows; the poll redraws only when it changes
    badges();
    root.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
    const m = $("main");
    if (editing) return editing.kind === "script" ? renderScriptEditor(m) : editing.kind === "rule" ? renderRuleForm(m) : renderEditor(m);
    if (tab === "call") return renderCall(m, seq);
    if (tab === "compose") return renderCompose(m);
    if (tab === "map") return renderMap(m);
    if (tab === "bp") return renderBp(m);
    if (tab === "net") return renderNet(m);
    if (tab === "dev") return renderDev(m);
    if (tab === "coll") return renderColl(m);
    if (tab === "cmp") return renderCmp(m, seq);
    if (tab === "sess") return renderSess(m);
    if (tab === "scripts") return renderScripts(m);
    return renderRules(m);
  }
  function badges() {
    const maps = state.rules.filter((r) => r.action === "map_local");
    const on = (xs) => xs.filter((x) => x.enabled !== false).length;
    $("c-map").textContent = on(maps) || ""; $("c-bp").textContent = on(state.breakpoints) || "";
    const skipped = state.skipped_rules || [];
    $("c-rules").textContent = skipped.length ? `! ${skipped.length}` : (on(state.rules) || "");
    $("c-rules").classList.toggle("err", skipped.length > 0);
    const cl = state.collections || { items: [] };
    $("c-coll").textContent = cl.recording ? "REC" : (cl.items.filter((x) => x.replay).length || "");
    $("c-coll").classList.toggle("err", !!cl.recording);
    const scriptErrors = Object.keys((state.script_status || {}).errors || {}).length;
    $("c-scripts").textContent = scriptErrors ? `! ${scriptErrors}` : (on(state.scripts || []) || "");
    $("c-scripts").classList.toggle("err", scriptErrors > 0);
    const active = on(state.rules) || on(state.breakpoints) || state.throttle !== "off" || Number(state.loss || 0) > 0 || !!state.no_cache;
    $("fabdot").style.display = active ? "inline-block" : "none";
    $("fab").classList.toggle("paused", state.paused.length > 0);
    const label = state.project.label || state.view_project;
    const product = state.product.name || "Proxy";
    $("ptitle").textContent = product;
    $("bname").textContent = product; $("bproj").textContent = label;
    document.title = product + " · " + label;
    const options = `<option value="__all" ${state.project_only ? "" : "selected"}>All traffic</option>` +
      state.projects.filter((p) => p.id !== "default").map((p) => `<option value="${esc(p.id)}" ${state.project_only && p.id === state.view_project ? "selected" : ""}>${esc(p.label || p.id)} only</option>`).join("");
    if ($("project").innerHTML !== options) $("project").innerHTML = options;
    sourceOptions();
    $("fablabel").textContent = state.paused.length ? `${state.paused.length} paused` : "Tools";
    $("fab").title = active ? "Tools — rules, breakpoints or network conditions are switched on (Alt+Shift+P)" : "Tools — Map Local, breakpoints, network conditions, scripts (Alt+Shift+P)";
  }

  function sourceOptions(force) {
    // grouped by device: "All apps on <device>" first, then each app, with call counts. Not rebuilt while the native
    // dropdown is open (a rebuild closes it). Rebuilt eagerly on mousedown/focus/keydown — before the dropdown appears —
    // so new sources always show. The old activeElement guard blocked rebuilds whenever the <select> had focus, which in
    // Chromium persists after the dropdown closes, so sources arriving while the menu was focused never appeared.
    const sel = $("source"); if (!force && sel._rvDropOpen) return;
    const groups = new Map();
    for (const r of sourceRows()) { const k = deviceKey(r); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
    const cur = (state && state.source) || "";
    let found = !cur, html = `<option value="" ${cur ? "" : "selected"}>All sources</option>`;
    for (const [k, rows] of groups) {
      const n = rows.reduce((a, r) => a + r.count, 0), first = rows[0];
      const opt = (v, t) => { if (v === cur) found = true; return `<option value="${esc(v)}" ${v === cur ? "selected" : ""}>${esc(t)}</option>`; };
      html += `<optgroup label="${esc(deviceName(first) + " · " + (KIND_NAME[first.kind] || first.kind))}">` + opt(k, `All of ${deviceName(first)} (${n})`) +
        rows.filter((r) => r.app).map((r) => opt(r.key, `${r.app} (${r.count})`)).join("") + `</optgroup>`;
    }
    if (!found) html += `<option value="${esc(cur)}" selected>${esc(sourceName(cur))} (no calls)</option>`;
    // running emulators / booted simulators that are not set up and sent nothing yet: a pointer to Tools → Devices.
    // Uses only the Devices result already fetched (tab or badge poll); never starts a device check of its own.
    if (dev && !dev.error && !dev.pending) {
      const seen = new Set(sourceRows().map((r) => String(r.device || "").toLowerCase()));
      const unset = [...(dev.ios || []), ...(dev.android || [])].filter((d) => !d.ready && !seen.has(String(d.name || "").toLowerCase()) && !seen.has(String(d.id || "").toLowerCase()));
      if (unset.length) html += `<optgroup label="Not set up">` + unset.map((d) => `<option value="__devices" class="unset">${esc(d.name)} — not set up (Tools → Devices)</option>`).join("") + `</optgroup>`;
    }
    if (sel.innerHTML !== html) sel.innerHTML = html;
    sel.title = cur ? "Showing only " + sourceName(cur) : "Every device and app";
  }

  // ───────────── This call ─────────────
  async function renderCall(m, seq) {
    const id = selectedFlow();
    if (id && !m.querySelector(".call")) m.innerHTML = '<p class="muted">Loading this call…</p>';   // never a blank tab while it loads
    const f = id ? await flowsById(id) : null;
    if (seq !== renderSeq) return;
    if (f && f.type === "tcp") {       // a host that is not decrypted: only the tunnel is visible
      const conn = f.server_conn || {}, hostName = conn.sni || (f.client_conn || {}).sni || (conn.address || [""])[0] || "", portNo = (conn.address || [])[1];
      const tunnelTarget = hostName && portNo && !String(hostName).endsWith(":" + portNo) ? hostName + ":" + portNo : hostName;
      m.innerHTML = `<div class="call"><span class="m">HOST ONLY</span>${esc(tunnelTarget)}
          <div class="sub">${ico("lock", "sm")} Not decrypted — you can see the host, but not the URL, headers or body</div></div>
        ${tlsQuickHTML(tunnelTarget)}`;
      wireTlsQuick(f.id, tunnelTarget);
      return;
    }
    if (!f || f.type !== "http") {
      m.innerHTML = emptyState("call", "No call selected", "Click a row in the list. Everything for that call — Map Local, Breakpoint, Copy as cURL, Edit &amp; Repeat — is on this tab.");
      return;
    }
    const r = f.request, s = f.response;
    // like the proxy: the breakpoint's pattern on the URL (CLI-made breakpoints carry no label)
    const urlOf = (r.scheme || "https") + "://" + r.pretty_host + ((r.port && ![80, 443].includes(r.port)) ? ":" + r.port : "") + r.path;
    const bpHits = (b) => { if (b.label) return b.label === r.pretty_host + r.path.split("?")[0];
      try { return new RegExp(b.match).test(urlOf); } catch (e) { return false; } };
    const bpFor = state.breakpoints.find((b) => bpHits(b) && (!b.method || b.method === r.method));
    let viewer = null;
    try { viewer = await api("viewer", { flow_id: f.id }); } catch (e) { /* call tools still work */ }
    if (viewer && viewer.grpc) {
      const views = viewer.grpc.content_type === "protobuf" ? ["Protocol Buffer", "gRPC/Protocol Buffer"] : ["gRPC/Protocol Buffer", "Protocol Buffer"];
      const decoded = await Promise.all([builtinContent(f.id, "request", views), s ? builtinContent(f.id, "response", views) : null]);
      viewer.grpc.builtin_request = decoded[0]; viewer.grpc.builtin_response = decoded[1];
    }
    if (seq !== renderSeq) return;
    const focused = state.focus_host === r.pretty_host, src = sourceOfFlow(f), srcOn = src && state.source === src.key;
    const srcLine = src ? `<div class="sub" id="srcline">From <b>${esc(src.app || deviceName(src))}</b>${src.app ? " on " + esc(deviceName(src)) : ""}${deviceName(src) === (KIND_NAME[src.kind] || src.kind) ? "" : " · " + esc(KIND_NAME[src.kind] || src.kind)}${src.id && src.id !== src.app ? ` · <code>${esc(src.id)}</code>` : ""} · <button class="lnk" id="srconly">${srcOn ? "Showing only this source — show all" : "Show only this " + (src.app ? "app" : "device")}</button></div>` : "";
    m.innerHTML = `
      <div class="call"><span class="m">${esc(r.method)}</span><span class="u" title="${esc(r.pretty_host + r.path)}"><span class="dim">${esc(r.pretty_host)}</span>${esc(r.path)}</span>
        <div class="sub">${s ? "→ " + s.status_code : "no response yet"} · <button class="lnk" id="focus">${focused ? "Showing only this host — show all" : "Show only this host"}</button></div>${srcLine}</div>
      <h4>Map Local ${info("Saves this response and serves it instead of the server's. You can edit its body, status and headers.")}</h4>
      <div class="btns" style="margin-top:0"><button class="b p" id="mock">Map Local this call…</button>${s ? "" : '<span class="sub">no response yet — starts from 200 {}</span>'}</div>
      <h4>Breakpoint ${info("Pause calls to this endpoint so you can edit them. Request = before it reaches the server; Response = before the app gets it.")}</h4>
      <div class="btns" style="margin-top:0"><span class="sub">Pause at</span>
        <div class="seg" style="margin:0"><button data-ph="request" class="${bpFor && bpFor.request ? "on" : ""}" aria-pressed="${!!(bpFor && bpFor.request)}">Request</button><button data-ph="response" class="${bpFor && bpFor.response ? "on" : ""}" aria-pressed="${!!(bpFor && bpFor.response)}">Response</button></div>
        <span class="sub">${bpFor ? "on for this endpoint" : "off"}</span></div>
      <h4>Edit &amp; repeat</h4>
      <div class="btns" style="margin-top:0"><button class="b" id="retry">Edit &amp; Repeat…</button>
        <button class="b" id="compose">Compose from this call</button>
        <button class="b" id="cmpA">Compare: set as A</button></div>
      <h4>Copy</h4>
      <div class="btns" style="margin-top:0"><button class="b" id="curl">Copy cURL</button><button class="b" id="curlurl">Copy URL</button></div>
      ${copyAsHTML("ca")}
      <h4>Simulate a failure ${info("Adds a rule for this endpoint (same method and path, any query). Turn it off in the Rules tab.")}</h4>
      <div class="btns" style="margin-top:0">
        <select id="code" aria-label="Status code">${[500, 503, 504, 401, 403, 404, 400, 429].map((c) => `<option>${c}</option>`).join("")}</select>
        <button class="b" id="force">Force status</button>
        <button class="b" id="block">Block (network error)</button></div>
      <div class="btns"><span class="sub">Delay by</span><input type="number" id="ms" value="8000" step="1000" style="width:84px" aria-label="Delay in milliseconds"><span class="sub">ms</span>
        <button class="b" id="delay">Delay this endpoint</button></div>
      ${tlsQuickHTML(r.pretty_host)}
      ${viewerHTML(viewer)}${viewerListsHTML()}`;
    $("mock").onclick = async () => {
      const res = await run("mock", { flow_id: f.id, draft: true }, mockToast);
      if (res) openEditor(res.name, "mock");
    };
    root.querySelectorAll("[data-ph]").forEach((c) => (c.onclick = async () => {
      const want = { request: !!(bpFor && bpFor.request), response: !!(bpFor && bpFor.response) };
      want[c.dataset.ph] = !want[c.dataset.ph];
      if (!want.request && !want.response) return bpFor && run("bp_delete", { name: bpFor.name }, "Breakpoint removed");
      const added = await run("bp_add", { flow_id: f.id, ...want });
      if (added && want[c.dataset.ph]) breakpointOn(f.id);
    }));
    $("retry").onclick = () => openRetry(f.id);
    $("compose").onclick = async () => {
      const res = await run("compose_get", { flow_id: f.id });
      if (!res) return;
      loadDraft(res.spec, ""); tab = "compose"; render();
    };
    wireCopyAs("ca", () => ({ flow_id: f.id }));
    wireTlsQuick(f.id, r.pretty_host);
    $("curl").onclick = () => copyExport(f.id, "curl");
    $("curlurl").onclick = () => copyExport(f.id, "url");
    $("cmpA").onclick = () => { cmpA = { id: f.id, label: r.method + " " + r.pretty_host + r.path }; tab = "cmp"; toast("Now select another call — Compare tab"); render(); };
    $("focus").onclick = () => run("focus_host", { host: state.focus_host === r.pretty_host ? null : r.pretty_host }, state.focus_host === r.pretty_host ? "Showing all hosts" : "Showing only " + r.pretty_host);
    if (src) $("srconly").onclick = () => setSource(srcOn ? null : (src.app ? src.key : deviceKey(src)));
    $("force").onclick = () => run("quick", { flow_id: f.id, kind: "status", status: $("code").value }, (x) => "Rule '" + x.name + "' is on — see the Rules tab");
    $("block").onclick = () => run("quick", { flow_id: f.id, kind: "block" }, (x) => "Rule '" + x.name + "' is on — see the Rules tab");
    $("delay").onclick = () => run("quick", { flow_id: f.id, kind: "delay", ms: $("ms").value }, (x) => "Rule '" + x.name + "' is on — see the Rules tab");
    m.querySelectorAll("[data-copy-json]").forEach((b) => (b.onclick = () => navigator.clipboard.writeText(decodeURIComponent(b.dataset.copyJson)).then(() => toast("Copied decoded JSON"))));
    m.querySelectorAll("[data-gql]").forEach((b) => (b.onclick = () => run("graphql_filter", { name: b.dataset.gql === state.graphql_operation ? null : b.dataset.gql }, b.dataset.gql === state.graphql_operation ? "GraphQL filter cleared" : "Showing " + b.dataset.gql)));
  }

  // Colour JSON we own (viewers). Keys, strings, numbers, true/false/null. Escapes as it goes.
  function colorJSON(src) {
    const text = String(src ?? "");
    let i = 0, out = "";
    const push = (cls, s) => { out += cls ? `<span class="${cls}">${esc(s)}</span>` : esc(s); };
    while (i < text.length) {
      const c = text[i];
      if (c === '"') {
        let j = i + 1, escaped = false;
        while (j < text.length) {
          const ch = text[j];
          if (escaped) escaped = false;
          else if (ch === "\\") escaped = true;
          else if (ch === '"') { j++; break; }
          j++;
        }
        let k = j;
        while (k < text.length && /\s/.test(text[k])) k++;
        push(text[k] === ":" ? "jk" : "js", text.slice(i, j));
        i = j;
        continue;
      }
      if ((c === "-" || (c >= "0" && c <= "9")) && (i === 0 || /[\s,:[{]/.test(text[i - 1]))) {
        const m = text.slice(i).match(/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/);
        if (m) { push("jn", m[0]); i += m[0].length; continue; }
      }
      const word = text.startsWith("false", i) ? "false" : text.startsWith("true", i) ? "true" : text.startsWith("null", i) ? "null" : "";
      if (word && (i + word.length === text.length || /[\s,\]}]/.test(text[i + word.length]))) { push("jb", word); i += word.length; continue; }
      push("", c);
      i++;
    }
    return out;
  }
  function jpretty(value) { return colorJSON(JSON.stringify(value, null, 2)); }
  function gqlPretty(query) {
    let out = "", indent = 0, string = false, escapeNext = false, space = false;
    const pad = () => "  ".repeat(indent);
    for (const ch of String(query || "")) {
      if (string) {
        out += ch;
        if (escapeNext) escapeNext = false; else if (ch === "\\") escapeNext = true; else if (ch === '"') string = false;
        continue;
      }
      if (ch === '"') { if (space && out && !out.endsWith("\n")) out += " "; space = false; string = true; out += ch; continue; }
      if (/\s/.test(ch)) { space = true; continue; }
      if (ch === "{") { out = out.trimEnd() + " {\n"; indent++; out += pad(); space = false; continue; }
      if (ch === "}") { indent = Math.max(0, indent - 1); out = out.trimEnd() + "\n" + pad() + "}"; space = true; continue; }
      if (space && out && !out.endsWith("\n") && !out.endsWith("(") && !",:)".includes(ch)) out += " ";
      out += ch; space = false;
    }
    return out.trim();
  }
  function viewerHTML(v) {
    if (!v) return "";
    let out = "";
    if (v.tokens && v.tokens.length) out += `<h4>JWT (${v.tokens.length})</h4>` + v.tokens.map((t) => {
      const times = Object.entries(t.times || {}).map(([k, x]) => `${k}: ${x.local}${x.relative ? " · " + x.relative : ""}`).join("<br>");
      return `<div class="call"><b>${esc(t.where)}</b> · alg ${esc(t.alg || "—")} · kid ${esc(t.kid || "—")}<div class="sub">signature not verified<br>${times}</div>
        <div class="btns"><button class="b" data-copy-json="${encodeURIComponent(JSON.stringify(t.header, null, 2))}">Copy header JSON</button><button class="b" data-copy-json="${encodeURIComponent(JSON.stringify(t.payload, null, 2))}">Copy payload JSON</button></div>
        <pre class="code">Header\n${jpretty(t.header)}\n\nPayload\n${jpretty(t.payload)}</pre></div>`;
    }).join("");
    if (v.graphql && v.graphql.length) out += `<h4>GraphQL</h4>` + v.graphql.map((g) => `<div class="call"><b>${esc(g.type)} ${esc(g.name)}</b><pre class="code">${esc(gqlPretty(g.query))}</pre><b>Variables</b><pre class="code">${jpretty(g.variables)}</pre></div>`).join("") +
      (v.graphql_response ? `<b>Response data</b><pre class="code">${jpretty(v.graphql_response.data)}</pre>${v.graphql_response.errors && v.graphql_response.errors.length ? `<div class="errbox"><b>ERR · GraphQL errors (HTTP status may still be 200)</b><pre class="code">${jpretty(v.graphql_response.errors)}</pre></div>` : ""}` : "");
    if (v.grpc) {
      const content = (builtin, fallback) => {
        if (!builtin) return jpretty(fallback);
        if (Array.isArray(builtin)) return esc(builtin.map((x) => x.text || JSON.stringify(x, null, 2)).join("\n\n"));
        return esc(typeof builtin.text === "string" ? builtin.text : JSON.stringify(builtin.text ?? builtin, null, 2));
      };
      out += `<h4>gRPC / protobuf</h4><div class="call"><b>${esc(v.grpc.service)}/${esc(v.grpc.method)}</b><div class="sub">grpc-status ${esc(v.grpc.status ?? "—")} · ${esc(v.grpc.message || "")}<br>${v.grpc.builtin_request || v.grpc.builtin_response ? "mitmproxy built-in content view" : esc(v.grpc.decoder + " · built-in view unavailable, using fallback")}</div><b>Request</b><pre class="code">${content(v.grpc.builtin_request, v.grpc.request || {error:v.grpc.request_error})}</pre><b>Response</b><pre class="code">${content(v.grpc.builtin_response, v.grpc.response || {error:v.grpc.response_error})}</pre></div>`;
    }
    return out;
  }
  function viewerListsHTML() {
    const v = viewers;
    let out = `<h4>Tokens seen this session (${v.tokens.length})</h4>` + (v.tokens.length ? v.tokens.map((t) => `<div class="row"><div class="n"><div><b>${esc(t.sub || "(no sub)")}</b> <span class="tag">${esc(t.alg || "JWT")}</span></div><div class="sub">iat ${esc(t.iat ?? "—")} · first: ${esc(t.method)} ${esc(t.url)}</div></div></div>`).join("") : '<p class="muted">No JWTs seen.</p>');
    out += `<h4>GraphQL operations</h4>` + (v.graphql_ops.length ? v.graphql_ops.map((g) => `<button class="chip ${state.graphql_operation === g.name ? "on" : ""}" data-gql="${esc(g.name)}">${esc(g.name)} · ${g.count}${g.errors ? " · ERR " + g.errors : ""}</button>`).join(" ") : '<p class="muted">No GraphQL operations seen.</p>');
    return out;
  }

  // ───────────── Map Local manager ─────────────
  function renderMap(m) {
    const maps = state.rules.map((r, i) => [r, i]).filter(([r]) => r.action === "map_local");
    m.innerHTML = `
      <h4>New Map Local rule</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="mh" class="grow" placeholder="Host (or paste a full URL)">
        <input type="text" id="mp" class="grow" placeholder="Path" value="/"></div>
      <div class="btns"><select id="mm"><option value="">ANY</option>${["GET", "POST", "PUT", "PATCH", "DELETE"].map((x) => `<option>${x}</option>`).join("")}</select>
        status <input type="number" id="ms2" value="200" style="width:70px">
        <button class="b p" id="madd">Add rule</button></div>
      <div class="sub">Wildcards: * and ? in host or path. Faster: select a call and use “Map Local this call”.</div>
      <h4>Rules (${maps.length})</h4>
      ${maps.length ? maps.map(([r, i]) => `
        <div class="row">${sw(`data-i="${i}"`, r.enabled !== false)}
          <div class="n"><div><b>${esc(pretty(r))}</b></div>
            <div class="sub">${esc(r.method || "ANY")} · status ${esc(((r.variants || []).find((v) => v.name === r.active) || {}).status || r.status || 200)} · ${esc(r.name)}${r.active ? " · active: " + esc(r.active) : ""}</div></div>
          <button class="b" data-edit="${i}">Edit</button><button class="b d" data-del="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")
      : emptyState("map", "No Map Local rules yet", "Select a call and use <b>Map Local this call</b>, or add one above with a host and path. <b>*</b> and <b>?</b> are wildcards.")}`;
    let pastedQuery = false;
    const split = () => { const v = $("mh").value.trim(); if (/^https?:\/\//.test(v)) { const [h, p] = hostPath(v); $("mh").value = h; $("mp").value = p; pastedQuery = p.includes("?"); } };
    $("mh").onchange = split;
    $("madd").onclick = async () => {
      split();
      const path = $("mp").value;
      const res = await run("maplocal_add", { host: $("mh").value, path, method: $("mm").value, status: $("ms2").value,
        literal_query: pastedQuery || /\?[^#]*=/.test(path) }, (x) => "Map Local '" + x.name + (x.existing ? "' already exists" : "' added"));
      if (res) openEditor(res.name, "madd");
    };
    wireRuleRows(m);
  }

  // ───────────── Breakpoints manager ─────────────
  function renderBp(m) {
    const bps = state.breakpoints;
    m.innerHTML = `
      ${state.paused.length ? `<div class="banner">${ico("pause", "sm")} ${state.paused.length} call(s) paused <button class="b warn" id="showp">Open</button></div>` : ""}
      <h4>New breakpoint</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="bh" class="grow" placeholder="Host (or paste a full URL)">
        <input type="text" id="bpth" class="grow" placeholder="Path" value="/*"></div>
      <div class="btns"><select id="bm" aria-label="Method"><option value="">ANY</option>${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option>${x}</option>`).join("")}</select>
        <span class="sub">Pause at</span>
        <div class="seg" style="margin:0"><button class="on" data-nph="request" aria-pressed="true">Request</button><button class="on" data-nph="response" aria-pressed="true">Response</button></div></div>
      <div class="btns"><button class="b" id="bsel">Use selected call</button><button class="b p" id="badd">Add breakpoint</button>
        ${info("Request = pause before it reaches the server. Response = pause before the app gets it.")}</div>
      <h4>Breakpoints (${bps.length})</h4>
      ${bps.length ? bps.map((b, i) => `
        <div class="row">${sw(`data-bi="${i}"`, b.enabled !== false)}
          <div class="n"><div><b>${esc(pretty(b))}</b></div><div class="sub">${esc(b.method || "Any HTTP method")}</div></div>
          <button class="chip ${b.request ? "on" : ""}" data-bph="${i}:request" aria-pressed="${!!b.request}" title="Pause at request">Req</button>
          <button class="chip ${b.response ? "on" : ""}" data-bph="${i}:response" aria-pressed="${!!b.response}" title="Pause at response">Resp</button>
          <button class="b d" data-bdel="${i}" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")
      : emptyState("bp", "No breakpoints", "Add one above, or open a call and turn on <b>Request</b> or <b>Response</b>. A match pauses and this sheet opens on its own.")}`;
    root.querySelectorAll("[data-nph]").forEach((c) => (c.onclick = () => { c.classList.toggle("on"); c.setAttribute("aria-pressed", c.classList.contains("on")); }));
    const ph = (p) => root.querySelector(`[data-nph=${p}]`).classList.contains("on");
    const split = () => { const v = $("bh").value.trim(); if (/^https?:\/\//.test(v)) { const [h, p] = hostPath(v); $("bh").value = h; $("bpth").value = p; } };
    $("bh").onchange = split;
    $("bsel").onclick = async () => {
      const f = selectedFlow() && await flowsById(selectedFlow());
      if (!f) return toast("Select a call in the list first", true);
      $("bh").value = f.request.pretty_host; $("bpth").value = f.request.path.split("?")[0]; $("bm").value = f.request.method;
    };
    $("badd").onclick = async () => { split(); const added = await run("bp_add", { host: $("bh").value, path: $("bpth").value, method: $("bm").value, request: ph("request"), response: ph("response") }); if (added) breakpointOn(); };
    root.querySelectorAll("[data-bi]").forEach((c) => (c.onchange = async () => {
      const updated = await run("bp_update", { name: bps[c.dataset.bi].name, enabled: c.checked }, c.checked ? null : "Breakpoint off");
      if (updated && c.checked) breakpointOn();
    }));
    root.querySelectorAll("[data-bph]").forEach((c) => (c.onclick = async () => {
      const [i, p] = c.dataset.bph.split(":"); const b = bps[i];
      const next = { request: b.request, response: b.response }; next[p] = !next[p];
      if (!next.request && !next.response) return toast("Keep Request or Response on — or delete the breakpoint", true);
      const updated = await run("bp_update", { name: b.name, ...next });
      if (updated && next[p]) breakpointOn();
    }));
    root.querySelectorAll("[data-bdel]").forEach((b) => (b.onclick = () => run("bp_delete", { name: bps[b.dataset.bdel].name }, "Breakpoint removed")));
    $("showp") && ($("showp").onclick = () => { dismissed.clear(); openPaused(state.paused[0].id); });
  }

  // ───────────── Network: traffic profiles ─────────────
  function renderNet(m) {
    const icons = { off: "net", "3g-urban": "wifi", "lte-congested": "down", "high-latency-vpn": "lock", "packet-loss-8": "warn", manual: "sliders" };
    const desc = (p) => p.desc || `${p.latency_ms}ms ±${p.jitter_ms}ms latency · ↓${p.down_kbps}kbps / ↑${p.up_kbps}kbps · ${p.loss_pct}% packet loss`;
    const cur = state.throttle || "off";
    const extraLoss = Number(state.loss || 0);
    const known = state.profiles.some((p) => p.id === cur);
    const mn = state.manual;
    m.innerHTML = `
      <h4>Traffic profiles</h4>
      <div class="row" style="border:0;padding:0 0 8px;flex-wrap:wrap"><label class="sub" for="tm" style="white-space:nowrap">Only slow URLs matching the pattern (regex)</label>
        <input type="text" id="tm" class="grow" value="${esc(state.throttle_match)}" placeholder="e.g. neo\\.sa — empty = every call" title="A regular expression searched for in the URL, e.g. neo\\.sa (plain text such as neo.sa also works; . matches any character). Empty slows down every call."></div>
      <div class="sub" style="margin:-2px 0 10px">${cur === "off" && !extraLoss ? "Pick a profile — it only slows calls whose URL matches the pattern above." : `<b>On</b> for ${state.throttle_match ? "URLs matching <code>" + esc(state.throttle_match) + "</code>" : "every call"}.${extraLoss ? ` <b>Packet loss is active: ${esc(extraLoss)}%</b>.` : ""}`}</div>
      ${state.profiles.map((p) => `
        <div class="card ${p.id === cur ? "on" : ""}" data-prof="${p.id}"><div class="ic">${ico(icons[p.id] || "net")}</div>
          <div><div class="t">${esc(p.name)}</div><div class="sub">${esc(desc(p))}</div></div>${p.id === cur ? `<div class="ok">${ico("check")}</div>` : ""}</div>`).join("")}
      ${!known ? `<div class="sub">Current: ${esc(cur)} (set from the command line)</div>` : ""}
      <div id="manual" style="${cur === "manual" ? "" : "display:none"}">
        <div class="grid">
          <label>Latency ms<input type="number" data-mk="latency_ms" value="${esc(mn.latency_ms)}"></label>
          <label>Jitter ms<input type="number" data-mk="jitter_ms" value="${esc(mn.jitter_ms)}"></label>
          <label>Download kbps (0 = unlimited)<input type="number" data-mk="down_kbps" value="${esc(mn.down_kbps)}"></label>
          <label>Upload kbps (0 = unlimited)<input type="number" data-mk="up_kbps" value="${esc(mn.up_kbps)}"></label>
          <label>Packet loss %<input type="number" step="0.5" data-mk="loss_pct" value="${esc(mn.loss_pct)}"></label>
          <label>Extra response delay ms<input type="number" data-mk="response_delay_ms" value="${esc(mn.response_delay_ms)}"></label>
        </div>
        <div class="btns"><button class="b p" id="mapply">Apply manual profile</button></div>
      </div>
      <h4>Caching</h4>
      <div class="row">${sw('id="nocache" aria-describedby="nocache-d"', state.no_cache)}<div class="n"><label for="nocache">No caching</label> <div class="sub" id="nocache-d">Strips If-None-Match / If-Modified-Since from requests and marks responses no-store, so the app always gets fresh content (never an empty 304). Map Local answers are left as they are</div></div></div>
      ${tlsSectionHTML()}
      ${clientCertsHTML()}
      <h4>What the list shows</h4>
      <div class="row">${sw('id="project-filter"', state.project_only)}<div class="n">Only ${esc(state.project.label)} calls <div class="sub">Hides other apps' traffic. Also in the “Show” menu above</div></div></div>
      <div class="row">${sw('id="dns"', state.show_dns)}<div class="n">Show background lookups (DNS) <div class="sub">Off = only web calls are listed</div></div></div>
      <div class="row"><div class="n">Appearance <div class="sub">Theme and compact rows live in Settings (this browser only)</div></div><button class="b" id="openset">${ico("gear", "sm")}Settings</button></div>`;
    wireTlsSection();
    wireClientCerts();
    root.querySelectorAll("[data-prof]").forEach((c) => (c.onclick = () => {
      if (c.dataset.prof === "manual") { $("manual").style.display = ""; root.querySelectorAll("[data-prof]").forEach((x) => x.classList.toggle("on", x === c)); return; }
      run("profile", { id: c.dataset.prof, match: $("tm").value }, "Network: " + c.querySelector(".t").textContent);
    }));
    $("mapply").onclick = () => {
      const manual = {}; root.querySelectorAll("[data-mk]").forEach((i) => (manual[i.dataset.mk] = Number(i.value || 0)));
      run("profile", { id: "manual", manual, match: $("tm").value }, "Network: manual profile");
    };
    $("tm").onchange = () => run("profile", { match: $("tm").value }, "Applies to: " + ($("tm").value || "all calls"));
    $("nocache").onchange = () => run("nocache", { on: $("nocache").checked }, "No caching " + ($("nocache").checked ? "on" : "off"));
    $("project-filter").onchange = () => run("view", { project: state.view_project, project_only: $("project-filter").checked, show_dns: false }, "Call list updated");
    $("dns").onchange = () => run("view", { project_only: false, show_dns: $("dns").checked }, "Call list updated");
    $("openset").onclick = () => openHelp("settings");
  }

  // ───────────── Devices (Proxyman's Certificate → Simulator / Emulator menu) ─────────────
  // Status is polled while the tab is open (and every 30 s for the badge); "Set up" runs the CLI's own command as a
  // background job and streams its output here. Google Play emulators get the same consent text as the terminal.
  let dev = null, devConsent = null, devTimer = null, devStarting = null;   // devStarting: clicked, job not reported yet (R3-DEV-01)
  let devUrl = "";                                                          // the web-app URL typed in the Web browser row
  const devRefresh = async () => {
    try { dev = await api("devices", {}); } catch (e) { dev = { error: e.message }; }
    const notReady = dev && !dev.error ? [...(dev.ios || []), ...(dev.android || [])].filter((d) => !d.ready).length : 0;
    const c = $("c-dev"); if (c) { c.textContent = notReady ? `! ${notReady}` : ""; c.classList.toggle("err", notReady > 0); }
    const typing = root.activeElement && root.activeElement.id === "dburl";   // a poll must not wipe the URL being typed
    if (tab === "dev" && !editing && !typing) renderDev($("main"));
    if (state) sourceOptions();
  };
  const devLoop = () => { clearTimeout(devTimer); devLoop.fast = tab === "dev"; devTimer = setTimeout(async () => { await devRefresh(); devLoop(); },
    tab === "dev" ? ((dev && dev.pending) ? 600 : (dev && dev.job && dev.job.running) ? 1500 : 4000) : 30000); };
  function renderDev(m) {
    if (!devLoop.fast) { devLoop.fast = true; devLoop(); }          // entering the tab: poll every few seconds
    if (!dev || dev.pending) { m.innerHTML = '<p class="muted">Looking for simulators and emulators…</p>'; if (!dev) devRefresh(); return; }
    if (dev.error) { m.innerHTML = `<p class="muted">${esc(dev.error)}</p>`; return; }
    const job = dev.job, running = !!(job && job.running);
    const bj = dev.browser_job;                                     // the last "Open a browser": its CLI output (or error)
    if (running || (job && devStarting && job.started * 1000 >= devStarting.at - 2000)) devStarting = null;  // the server has it now
    const busy = running || !!devStarting;
    const mine = (platform, id) => (running && job.platform === platform && (job.target === "all" || job.target === id))
      || (devStarting && devStarting.platform === platform && (devStarting.target === "all" || devStarting.target === id));
    const row = (platform, d) => {
      const settingUp = !d.ready && mine(platform, d.id);
      const failedHere = !settingUp && job && job.rc !== null && job.rc !== 0 && job.error &&
        job.platform === platform && (job.target === "all" || job.target === d.id);
      const detail = settingUp ? (job && job.step ? job.step : "Setting up…")
        : failedHere ? job.error
        : platform === "ios" ? (d.ready ? "Trusts the Rivis certificate" : "Certificate not trusted yet")
        : !d.ca_ok ? (d.play ? "Google Play image — certificate not installed yet" : "Certificate not installed yet")
        : !d.proxy_ok ? "Certificate OK — proxy not pointing at Rivis" : "Certificate and proxy set";
      // the system store (apps that trust only system certificates): Google APIs images via adb root, put back after a
      // restart while Rivis runs; Google Play images on the one-click restart, for that boot only
      const sys = platform !== "android" || !d.ca_ok || settingUp ? ""
        : d.system_ok ? `<div class="sub" data-sysstate="${esc(d.id)}">System store: on${d.play ? " (until its next normal restart)" : ""}</div>`
        : `<div class="sub" data-sysstate="${esc(d.id)}" title="Apps that trust only system certificates (most release builds) do not see Rivis without it. It does not bypass certificate pinning.">${d.system_wanted ? "System store: gone after a restart" + (d.play ? "" : " — coming back") : "System store: off"}</div>`
          + (d.system_wanted && !d.play ? "" : `<button class="lnk" data-dsetup="android" data-system="1" data-id="${esc(d.id)}" data-name="${esc(d.name)}" data-play="${d.play ? 1 : ""}" ${busy ? "disabled" : ""}>${d.system_wanted ? "Add it again" : "Add to system store"}</button>`);
      return `<div class="row"><div class="n">${esc(d.name)} <span class="sub">${esc(d.os)}</span><div class="sub"${failedHere ? ' role="alert"' : ''}>${esc(detail)}</div>${sys}</div>
        ${d.ready ? `<span class="ok" title="Ready">${ico("check")}</span>`
          : settingUp ? `<button class="b" disabled aria-busy="true">${esc(job && job.step ? job.step : "Setting up…")}</button>`
          : `<button class="b p" data-dsetup="${platform}" data-id="${esc(d.id)}" data-name="${esc(d.name)}" data-play="${d.play && !d.ca_ok ? 1 : ""}" ${busy ? "disabled" : ""}>Set up</button>`}</div>`;
    };
    const section = (platform, title, list, none) => {
      if (list === null) return `<h4>${title}</h4><div class="sub">${none}</div>`;
      const todo = list.filter((d) => !d.ready).length;
      return `<h4>${title}${todo > 1 ? ` <button class="lnk" data-dsetup="${platform}" data-id="all" data-name="all" data-play="${list.some((d) => d.play && !d.ca_ok) ? 1 : ""}" ${busy ? "disabled" : ""}>Set up all ${todo}</button>` : ""}</h4>` +
        (list.length ? list.map((d) => row(platform, d)).join("") : `<div class="sub">${platform === "ios" ? "No simulator is booted. Start one from Xcode or Simulator.app — it shows up here." : "No emulator is running. Start one from Android Studio's Device Manager — it shows up here."}</div>`);
    };
    const consent = devConsent ? `
      <div class="card on" style="cursor:default;display:block">
        <b>${devConsent.system ? "System store for" : "One-time setup for"} ${esc(devConsent.name === "all" ? "these Google Play emulators" : devConsent.name)}</b>
        <div class="sub" style="margin:6px 0">${dev.magisk ? `Google Play images refuse adb root, so Rivis installs its certificate the way Proxyman does:
          Magisk (official release, checksum verified) patches a temporary copy of the ramdisk and the emulator restarts once
          with it, where a one-shot service copies the certificate. About a minute; the window closes and reopens. It stays on
          that temporary boot until its next normal start (or <code>rivis android off</code>). Nothing else gets root, and the
          SDK image and AVD settings are not changed.${devConsent.system ? ` The system store copy lasts for that boot only: after the
          emulator's next normal start, add it again.` : ""}`
          : devConsent.system ? `Google Play images refuse adb root, and the system store needs Rivis's one-click setup (Magisk), which this
          copy does not have: install Rivis from the release zip, or use a Google APIs emulator (no Play Store), where it is a direct copy.`
          : `Google Play images refuse adb root. This copy of Rivis has no Magisk, so it will drive the emulator's Settings screens
          to install the certificate instead — up to four minutes; hands off the emulator while it runs.`}
          Use test emulators only (no personal Google account).</div>
        <div class="btns"><button class="b p" id="dyes">Continue</button><button class="b" id="dno">Cancel</button></div>
      </div>` : "";
    const log = job && !devStarting ? `<h4>${running ? "Setting up" : job.rc === 0 ? "Done" : "Failed"} — ${esc(job.label)}</h4>
      <pre class="devlog" style="max-height:220px;overflow:auto;font-size:11.5px;white-space:pre-wrap;margin:0">${esc(job.lines.join("\n")) || "starting…"}</pre>` : "";
    m.innerHTML = `
      <div class="sub" style="margin-bottom:8px">Rivis sets up each simulator or emulator once: its certificate, and for Android the proxy. Like Proxyman's Certificate menu — one click per device.</div>
      ${consent}${log}
      ${section("ios", "iOS Simulators", dev.ios, esc(dev.ios_error || "Xcode command-line tools are not installed (xcrun simctl)."))}
      ${section("android", "Android emulators", dev.android, "adb was not found. Install Android Studio (SDK platform-tools) to use emulators.")}
      <div class="sub" style="margin-top:10px">Same from a terminal: <code>rivis setup</code>.</div>
      ${lanSectionHTML()}
      <h4>Web browser</h4>
      <div class="sub">For web apps: a separate browser window with its own profile, pointed at Rivis. Your normal browser, the Mac's proxy settings and the keychain are not touched.</div>
      ${(dev.browsers || []).length ? `<div class="btns"><input type="text" id="dburl" class="grow" value="${esc(devUrl)}" placeholder="Web app URL (optional), e.g. https://app.example.com" aria-label="Web app URL" spellcheck="false" autocomplete="off">
        ${dev.browsers.map((b) => `<button class="b p" data-dbrowser="${esc(b.id)}">Open ${esc(b.name)}</button>`).join("")}</div>
        ${bj ? `<pre class="devlog" style="font-size:11.5px;white-space:pre-wrap;margin:6px 0 0"${bj.rc ? ' role="alert"' : ""}>${esc(bj.running ? "Opening…" : (bj.rc ? "Could not open: " : "") + bj.lines.join("\n"))}</pre>` : ""}
        <div class="sub">Same from a terminal: <code>rivis browser [URL]</code>.</div>`
        : `<div class="sub">No Chrome, Edge, Chromium or Brave found in Applications (Firefox is not supported yet).</div>`}`;
    wireLanSection(m);
    const url = $("dburl");
    if (url) url.oninput = () => { devUrl = url.value; };
    m.querySelectorAll("[data-dbrowser]").forEach((b) => (b.onclick = () =>
      run("browser_open", { browser: b.dataset.dbrowser, url: devUrl.trim() }, `Opening ${b.textContent.replace(/^Open /, "")}…`)
        .then(() => setTimeout(devRefresh, 1500))));
    const start = (b, consentGiven) => {
      devStarting = { platform: b.dataset.dsetup, target: b.dataset.id, at: Date.now() }; devConsent = null; renderDev(m);
      return run("device_setup", { platform: b.dataset.dsetup, target: b.dataset.id, name: b.dataset.name, consent: consentGiven, system: !!b.dataset.system },
        "Setup started").then((ok) => { if (!ok) devStarting = null; devRefresh(); devLoop(); });
    };
    m.querySelectorAll("[data-dsetup]").forEach((b) => (b.onclick = () => {
      if (b.dataset.dsetup === "android" && b.dataset.play) { devConsent = { b, name: b.dataset.name, system: !!b.dataset.system }; renderDev(m); return; }
      start(b, false);
    }));
    if (devConsent) {
      $("dyes").onclick = () => start(devConsent.b, true);
      $("dno").onclick = () => { devConsent = null; renderDev(m); };
    }
  }
  devLoop();
  // Phones and tablets on the Wi-Fi (`rivis start --lan`): who may use the proxy, who is waiting, and how to set one up.
  function lanSectionHTML() {
    const lan = (state && state.lan) || { on: false, devices: [], pending: [], addresses: [], setup_urls: [], qr: [] };
    const cli = esc(product().cli || "rivis");
    if (!lan.on) return `<h4 id="lansec">Phones and tablets (Wi-Fi)</h4>
      <div class="sub">Off. To capture a real phone or tablet on this Wi-Fi, restart with <code>${cli} stop</code>, then <code>${cli} start --lan</code>.
        Each device must then be allowed here; every other device on the network is refused.</div>`;
    const ago = (t) => { const s = Math.max(0, Math.round(Date.now() / 1000 - t)); return s < 60 ? s + " s ago" : Math.round(s / 60) + " min ago"; };
    const [ip, port] = (lan.addresses[0] || ":").split(":");
    return `<h4 id="lansec">Phones and tablets (Wi-Fi)</h4>
      <div class="lanbox" style="display:flex;gap:14px;align-items:flex-start;flex-wrap:wrap">
        ${lan.qr[0] ? `<div class="lanqr" style="background:#fff;border-radius:8px;line-height:0;width:148px">${lan.qr[0].replace(/width="\d+" height="\d+"/, 'width="148" height="148"')}</div>` : ""}
        <div class="n" style="min-width:220px;flex:1">
          <div><b>1.</b> On the phone, scan the code with the camera (or open <code>${esc(lan.setup_urls[0] || "")}</code>) for the steps and the certificate.</div>
          <div style="margin-top:6px"><b>2.</b> Set its Wi-Fi proxy to manual: server <code id="lanip">${esc(ip)}</code>, port <code id="lanport">${esc(port)}</code>.</div>
          <div style="margin-top:6px"><b>3.</b> Allow it below when it shows up.</div>
          ${lan.addresses.length > 1 ? `<div class="sub" style="margin-top:6px">This Mac is on several networks: also ${lan.addresses.slice(1).map((a) => `<code>${esc(a)}</code>`).join(", ")}</div>` : ""}
        </div></div>
      ${lan.pending.length ? `<div class="sub" style="margin-top:8px"><b>Waiting to be allowed</b> — refused until you allow them</div>` +
        lan.pending.map((d) => `<div class="row" data-lanwait="${esc(d.ip)}"><div class="n">${esc(d.name)} <code>${esc(d.ip)}</code>
          <div class="sub">${esc(d.mac || "MAC unknown")} · ${esc(d.count)} call${d.count === 1 ? "" : "s"} refused · last ${esc(ago(d.last))}${d.ua ? " · " + esc(d.ua.slice(0, 90)) : ""}</div></div>
          <button class="b p" data-lanallow="${esc(d.ip)}" data-name="${esc(d.name)}">Allow</button><button class="b" data-landismiss="${esc(d.ip)}">Ignore</button></div>`).join("") : ""}
      <div class="sub" style="margin-top:8px"><b>Allowed</b></div>
      ${lan.devices.length ? lan.devices.map((d) => `<div class="row" data-lanok="${esc(d.ip)}"><div class="n">${esc(d.name)} <code>${esc(d.ip)}</code>
          <div class="sub">${esc(d.mac || "MAC unknown")} · Its calls show as “${esc(d.name)}” (Source menu: Phone or tablet)</div></div>
          <button class="b" data-lanrename="${esc(d.ip)}" data-name="${esc(d.name)}">Rename</button>
          <button class="b d" data-lanrm="${esc(d.ip)}" data-name="${esc(d.name)}" aria-label="Remove ${esc(d.name)}">${ico("x", "sm")}</button></div>`).join("")
        : '<div class="sub">None yet.</div>'}
      <div class="sub" style="margin-top:6px">Same from a terminal: <code>${cli} lan</code>, <code>${cli} lan allow IP [NAME]</code>, <code>${cli} lan rm IP</code>.</div>`;
  }
  function wireLanSection(m) {
    m.querySelectorAll("[data-lanallow]").forEach((b) => (b.onclick = () =>
      run("lan_allow", { ip: b.dataset.lanallow, name: b.dataset.name }, (x) => "Allowed " + x.device.name + " (" + x.device.ip + ")").then(devRefresh)));
    m.querySelectorAll("[data-landismiss]").forEach((b) => (b.onclick = () => run("lan_dismiss", { ip: b.dataset.landismiss }).then(devRefresh)));
    m.querySelectorAll("[data-lanrename]").forEach((b) => (b.onclick = async () => {
      const name = await ask("Name for " + b.dataset.lanrename + "\n\nShown on its calls; up to 40 characters.", { input: b.dataset.name, yes: "Rename" });
      if (name && name.trim()) run("lan_allow", { ip: b.dataset.lanrename, name: name.trim() }, "Renamed to " + name.trim()).then(devRefresh);
    }));
    m.querySelectorAll("[data-lanrm]").forEach((b) => (b.onclick = async () => {
      if (await ask("Remove " + b.dataset.name + " (" + b.dataset.lanrm + ")?\n\nIts calls are refused from now on.", { yes: "Remove", danger: true }))
        run("lan_rm", { ip: b.dataset.lanrm }, "Removed " + b.dataset.name).then(devRefresh);
    }));
  }

  // ───────────── Copy URL / cURL ─────────────
  async function copyExport(id, fmt) {
    const mask = maskOn();
    const r = await run("export", { flow_id: id, fmt, mask });
    if (!r) return;
    try { await navigator.clipboard.writeText(r.text); toast(fmt === "url" ? "URL copied" : "cURL copied" + (mask ? " (secrets masked)" : " — contains secrets!")); }
    catch (e) { ask("Copy this text", { input: r.text, yes: "Done", no: "Close" }); }
  }

  // ───────────── Collections (record → replay) ─────────────
  let collOpen = null, collEntries = null;
  function renderColl(m) {
    const c = state.collections;
    m.innerHTML = `
      <h4>Record</h4>
      ${c.recording
        ? `<div class="call"><span class="rec"><i class="reddot"></i>Recording</span> into <b>${esc(c.recording)}</b> — use the app now.
             <div class="btns"><button class="b warn" id="cstop">Stop recording</button></div></div>`
        : `<div class="btns" style="margin-top:0"><input type="text" id="cname" class="grow" placeholder="Collection name, e.g. cards-journey-sit">
             <button class="b p" id="crec">Start recording</button></div>
           <div class="btns">Record calls matching <input type="text" id="cmatch" class="grow" value="${esc(c.record_match)}"></div>`}
      <h4>Replay</h4>
      <div class="row">${sw('id="cstrict"', c.strict)}<div class="n">Strict replay <div class="sub">Calls matching <code>${esc(c.record_match || ".")}</code> that are not in a replayed collection get a 404. ${c.record_match && c.record_match !== "." ? "Other calls still go to the real server." : "That is every call."}</div></div></div>
      <div class="btns">Strict replay match <input type="text" id="smatch" class="grow" value="${esc(c.record_match)}"><button class="b" id="savematch">Save match</button></div>
      <h4>Collections (${c.items.length})</h4>
      ${c.items.length ? c.items.map((x, i) => `
        <div class="row">${sw(`data-ci="${i}"`, x.replay, c.recording === x.name ? "disabled" : "")}
          <div class="n"><div><b>${esc(x.name)}</b>${c.recording === x.name ? ' <span class="rec"><i class="reddot"></i>REC</span>' : ""}</div>
            <div class="sub">${esc(Number(x.count) || 0)} calls${x.created ? " · " + new Date(x.created * 1000).toLocaleString() : ""}${x.replay ? " · replaying" : ""}</div></div>
          <button class="b" data-cview="${i}">${collOpen === x.name ? "Hide" : "Calls"}</button>
          <button class="b" data-cexp="${i}">HAR</button><button class="b d" data-cdel="${i}" aria-label="Remove">${ico("x", "sm")}</button></div>
        ${collOpen === x.name ? `<div id="centries" class="sub">loading…</div>` : ""}`).join("")
      : emptyState("coll", "No collections yet", "Name a journey above and <b>Start recording</b>, use the app, then stop. Switch a collection on to replay those responses as mocks.")}
      <h4>Import</h4>
      <div class="btns" style="margin-top:0"><input type="file" id="chf" accept=".har,application/json" aria-label="HAR file">
        <input type="text" id="chn" placeholder="name" style="width:120px"><button class="b" id="cimp">Import HAR</button></div>
      ${harSecretsBox("chsec")}
      <p class="sub">Stored in ${esc(state.project_state)}/collections · recordings stay on this machine (no Git sync).</p>`;
    $("crec") && ($("crec").onclick = () => run("coll_record", { name: $("cname").value, record_match: $("cmatch").value }, "Recording into " + $("cname").value));
    $("cstop") && ($("cstop").onclick = () => run("coll_stop", {}, "Recording stopped"));
    $("cstrict").onchange = () => run("coll_strict", { strict: $("cstrict").checked }, $("cstrict").checked ? "Strict replay on" : "Strict replay off");
    $("savematch").onclick = () => run("coll_match", { record_match: $("smatch").value }, "Replay match saved");
    m.querySelectorAll("[data-ci]").forEach((cb) => (cb.onchange = () => run("coll_replay", { name: c.items[cb.dataset.ci].name, enabled: cb.checked }, cb.checked ? "Replaying " + c.items[cb.dataset.ci].name : "Replay off")));
    m.querySelectorAll("[data-cdel]").forEach((b) => (b.onclick = async () => { const n = c.items[b.dataset.cdel].name; if (await ask("Delete collection '" + n + "'?", { yes: "Delete", danger: true })) { if (collOpen === n) collOpen = null; run("coll_delete", { name: n }, "Deleted " + n); } }));
    m.querySelectorAll("[data-cexp]").forEach((b) => (b.onclick = () => downloadHar("coll_export", c.items[b.dataset.cexp].name, "chsec")));
    m.querySelectorAll("[data-cview]").forEach((b) => (b.onclick = () => { const n = c.items[b.dataset.cview].name; collOpen = collOpen === n ? null : n; render(); }));
    $("cimp").onclick = async () => {
      const file = $("chf").files[0];
      if (!file) return toast("Choose a .har file first", true);
      let har; try { har = JSON.parse(await file.text()); } catch (e) { return toast("Not a valid HAR (JSON) file", true); }
      const name = $("chn").value.trim() || file.name.replace(/\.har$|\.json$/i, "").replace(/[^A-Za-z0-9._-]/g, "-");
      const overwrite = c.items.some((x) => x.name === name);
      if (overwrite && !await ask("A collection named '" + name + "' already exists. Replace it?\n\nIts recorded calls will be lost.", { yes: "Replace", danger: true })) return;
      run("coll_import", { name, har, overwrite }, (x) => "Imported " + x.count + " calls into " + name + (x.skipped_count ? " — left out " + x.skipped_count + " (failed calls / WebSocket upgrades)" : ""));
    };
    if (collOpen) api("coll_entries", { name: collOpen }).then((r) => {
      const box = $("centries"); if (!box) return;
      box.innerHTML = r.entries.length ? r.entries.map((e) => `<div class="row" style="padding:4px 0"><div class="n"><div>${esc(e.method)} ${esc(e.host)}${esc(e.path)}${e.query ? "?" + esc(e.query) : ""}</div></div>
        <span class="tag">${esc(e.status)}</span><button class="b d" data-edel="${e.i}" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") : "empty";
      box.querySelectorAll("[data-edel]").forEach((b) => (b.onclick = () => run("coll_entry_delete", { name: collOpen, i: b.dataset.edel }, "Removed")));
    }).catch((e) => toast(e.message, true));
  }

  // ───────────── Compare two calls ─────────────
  let cmpA = null, cmpResult = null;
  async function renderCmp(m, seq) {
    const id = selectedFlow();
    const f = id ? await flowsById(id) : null;
    if (seq !== renderSeq) return;
    const lab = (x) => x ? `${esc(x.method)} ${esc(x.url || x.label)}${x.status ? " → " + x.status : ""}` : "";
    m.innerHTML = `
      <h4>Compare two calls</h4>
      <div class="sub" style="margin-bottom:6px">1 · Select a call and set it as <b>A</b>. 2 · Select another call and compare.</div>
      <div class="call"><span class="m">A</span>${cmpA ? esc(cmpA.label) : '<span class="muted">not set yet</span>'}</div>
      <div class="call" style="margin-top:6px"><span class="m">B</span>${f ? esc(f.request.method + " " + f.request.pretty_host + f.request.path) : '<span class="muted">select a call in the list</span>'}</div>
      <div class="btns"><button class="b" id="seta" ${f ? "" : "disabled"}>Set selected as A</button>
        <button class="b p" id="docmp" ${cmpA && f && f.id !== cmpA.id ? "" : "disabled"}>Compare A with B</button></div>
      <div id="cmpout"></div>`;
    $("seta").onclick = () => { cmpA = { id: f.id, label: f.request.method + " " + f.request.pretty_host + f.request.path }; cmpResult = null; render(); };
    $("docmp").onclick = async () => { const r = await run("diff", { a: cmpA.id, b: f.id }); if (r) { cmpResult = r; drawCmp(); } };
    if (cmpResult) drawCmp();
    function drawCmp() {
      const r = cmpResult, out = $("cmpout"); if (!out) return;
      const tbl = (rows, kind) => rows.length ? `<table class="diff"><tr><th style="width:34%">${kind === "text" ? "" : "field"}</th><th>A</th><th>B</th></tr>${rows.map(([k, a, b]) =>
          kind === "text" ? `<tr><td class="k">${k === "-" ? "only A" : "only B"}</td><td class="${k === "-" ? "a" : ""}">${k === "-" ? esc(a) : ""}</td><td class="${k === "+" ? "b" : ""}">${k === "+" ? esc(a) : ""}</td></tr>`
                          : `<tr><td class="k">${esc(k)}</td><td class="a">${esc(a)}</td><td class="b">${esc(b)}</td></tr>`).join("")}</table>`
        : '<div class="sub">identical</div>';
      out.innerHTML = `
        <h4>Summary</h4><table class="diff"><tr><td class="k">A</td><td colspan="2">${lab(r.a)}</td></tr><tr><td class="k">B</td><td colspan="2">${lab(r.b)}</td></tr></table>
        <h4>Response body (${r.resp_body.rows.length} differences)</h4>${tbl(r.resp_body.rows, r.resp_body.kind)}
        <h4>Response headers</h4>${tbl(r.resp_headers)}
        <h4>Request body</h4>${tbl(r.req_body.rows, r.req_body.kind)}
        <h4>Request headers</h4>${tbl(r.req_headers)}`;
    }
  }

  // ───────────── HAR download (secrets redacted unless ticked for this one export; never remembered) ─────────────
  const harSecretsBox = (id) => `<div class="btns"><label class="sub"><input type="checkbox" id="${id}"> Include secrets in the next HAR
    ${info("By default a HAR export replaces Authorization, cookies, API keys, JWTs and fields such as password, otp, pin and token with <redacted>. Tick this only for an export that stays on this machine; it resets after each download.")}</label></div>`;
  async function downloadHar(op, name, boxId) {
    const box = $(boxId), withSecrets = !!(box && box.checked);
    if (withSecrets && !await ask("Export with secrets?\n\nThis HAR will contain tokens, cookies and passwords in clear text.\n\nKeep it on this machine — never attach it to a ticket or chat.", { yes: "Export with secrets", danger: true })) return;
    const r = await run(op, { name, include_secrets: withSecrets });
    if (!r) return;
    if (box) box.checked = false;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(r.har, null, 2)], { type: "application/json" }));
    a.download = r.filename; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    toast(r.redacted ? "HAR saved to Downloads (secrets redacted)" : "HAR saved to Downloads — contains secrets!", !r.redacted);
  }

  // ───────────── Sessions: save / reload whole captures ─────────────
  function renderSess(m) {
    const ss = state.sessions || [];
    m.innerHTML = `
      <h4>Save the current capture</h4>
      <div class="btns" style="margin-top:0"><input type="text" id="sn" class="grow" placeholder="Session name, e.g. ticket-1234-repro"></div>
      <div class="btns"><input type="text" id="snote" class="grow" placeholder="Note (optional): what this capture shows"></div>
      <div class="btns"><label class="sub"><input type="checkbox" id="svis"> Only calls visible with the current filter</label>
        <button class="b p" id="ssave">Save session</button></div>
      <h4>Saved sessions (${ss.length})</h4>
      ${ss.length ? ss.map((x, i) => `
        <div class="row" style="align-items:flex-start"><div class="n"><div><b>${esc(x.name)}</b></div>
            <div class="sub">${esc(Number(x.count) || 0)} calls · ${new Date(x.created * 1000).toLocaleString()}${x.hosts && x.hosts.length ? " · " + esc(x.hosts.slice(0, 3).join(", ")) : ""}</div>
            <div class="sub" data-note="${i}" title="click to edit" style="cursor:text;white-space:normal">${x.note ? ico("note", "sm") + " " + esc(x.note) : "<i>add a note…</i>"}</div></div>
          <button class="b" data-sload="${i}">Open</button><button class="b" data-shar="${i}">HAR</button><button class="b d" data-sdel="${i}" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")
      : emptyState("sess", "No saved sessions yet", "Name the capture above and <b>Save session</b>. Open brings it back into the list; HAR exports it.")}
      ${harSecretsBox("shsec")}
      <p class="sub">Stored in ${esc(state.project_state)}/sessions ${info("Open adds the saved calls to the list (you can choose to replace it first). Per-call notes and bookmarks: use the Comment tab and the Mark button on a call — they are saved with the session.")}</p>`;
    $("ssave").onclick = async () => {
      const name = $("sn").value.trim(), overwrite = ss.some((x) => x.name === name);
      if (overwrite && !await ask("A session named '" + name + "' already exists. Replace it?\n\nThe earlier capture will be lost.", { yes: "Replace", danger: true })) return;
      run("sess_save", { name, note: $("snote").value, visible_only: $("svis").checked,
        search_filter: $("svis").checked ? storeSearch() : "", overwrite }, (x) => "Saved " + x.count + " calls"); // R7A-05: mitmweb's search is separate from its view
    };
    m.querySelectorAll("[data-sload]").forEach((b) => (b.onclick = async () => {
      const x = ss[b.dataset.sload];
      // R8D-17: say exactly what each button does; Cancel always means "do nothing"
      const how = await ask("Open session '" + x.name + "'?\n\nReplace the calls in the list with this session's, or add its calls to them.",
                            { choices: [["add", "Add to the list", ""], ["replace", "Replace the list", "p"]] });
      if (!how) return;
      const replace = how === "replace";
      run("sess_load", { name: x.name, replace }, (r) => "Opened " + r.count + " calls");
    }));
    m.querySelectorAll("[data-sdel]").forEach((b) => (b.onclick = async () => { const x = ss[b.dataset.sdel]; if (await ask("Delete session '" + x.name + "'?", { yes: "Delete", danger: true })) run("sess_delete", { name: x.name }, "Deleted"); }));
    m.querySelectorAll("[data-note]").forEach((d) => (d.onclick = async () => {
      const x = ss[d.dataset.note]; const note = await ask("Note for " + x.name, { input: x.note || "", yes: "Save note" });
      if (note !== null) run("sess_note", { name: x.name, note }, "Note saved");
    }));
    m.querySelectorAll("[data-shar]").forEach((b) => (b.onclick = () => downloadHar("sess_har", ss[b.dataset.shar].name, "shsec")));
  }

  // ───────────── Per-project scripts ─────────────
  function renderScripts(m) {
    const scripts = state.scripts || [], status = state.script_status || {};
    const errorHTML = (error) => error ? `<br><span class="tag err">ERROR</span>
      <span class="errtext">${esc(error.message || error)}${error.time ? " · " + esc(error.time) : ""}</span>
      ${error.traceback ? `<pre class="code errtext">${esc(error.traceback)}</pre>` : ""}` : "";
    m.innerHTML = `${status.node_message ? `<div class="errbox">${esc(status.node_message)}. Python scripts still work.</div>` : ""}
      <h4>New script</h4>
      <div class="btns" style="margin-top:0"><input id="sn" type="text" class="grow" placeholder="Script name" aria-label="Script name">
        <select id="sl"><option value="js">JavaScript</option><option value="py">Python</option></select></div>
      <div class="btns"><select id="stpl" aria-label="Template"><option value="header">Request header</option><option value="json">JSON response field</option><option value="mock">Local mock</option><option value="latency">Endpoint latency</option><option value="token">Log token refresh</option></select>
        <select id="smethod" aria-label="Method"><option value="">Any method</option>${["GET","POST","PUT","PATCH","DELETE"].map((x) => `<option>${x}</option>`).join("")}</select></div>
      <div class="btns"><label class="sub" for="smatch" style="white-space:nowrap">Run on URLs like</label><input id="smatch" type="text" class="grow" value="." placeholder="URL pattern" title="A pattern matched against the URL (a regular expression). A single dot matches every call.">
        <button class="b p" id="snew">New</button></div>
      <p class="sub">Rules run first, then scripts. Scripts are trusted code with your user rights — not a sandbox. ${info("Python and JavaScript scripts run with your user rights. The Node VM omits process, require and network helpers to prevent accidents, but it is NOT a security boundary.")}</p>
      <h4>Scripts (${scripts.length})</h4>${scripts.length ? scripts.map((s, i) => `<div class="row">${sw(`data-si="${i}"`, s.enabled !== false)}
        <div class="n"><div><b>${esc(s.name)}</b><span class="tag">${esc(s.lang)}</span></div><div class="sub">${esc(s.method || "ANY")} · ${esc(s.match || ".")} · ${esc(tilde(s.file))}${s.exists ? "" : " · FILE MISSING"}${errorHTML(status.errors && status.errors[s.file])}</div></div>
        <button class="b" data-sedit="${i}">Edit</button><button class="b d" data-sdelete="${i}" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") : emptyState("scripts", "No scripts yet", "Pick a template above and click <b>New</b>. Rules run first; enabled scripts run after them, in filename order.")}`;
    $("snew").onclick = async () => {
      const r = await run("script_new", { name: $("sn").value, lang: $("sl").value, template: $("stpl").value, match: $("smatch").value, method: $("smethod").value }, (x) => "Created " + x.file);
      if (r) openScript(r.file);
    };
    m.querySelectorAll("input[data-si]").forEach((c) => (c.onchange = () => run("script_toggle", { file: scripts[c.dataset.si].file, enabled: c.checked }, c.checked ? "Script on" : "Script off")));
    m.querySelectorAll("[data-sedit]").forEach((b) => (b.onclick = () => openScript(scripts[b.dataset.sedit].file)));
    m.querySelectorAll("[data-sdelete]").forEach((b) => (b.onclick = async () => { const s = scripts[b.dataset.sdelete]; if (await ask("Delete script '" + s.name + "' and its source file?", { yes: "Delete", danger: true })) run("script_delete", { file: s.file }, "Deleted " + s.file); }));
  }

  async function openScript(file) {
    try { const r = await api("script_get", { file }); editing = { kind:"script", from: tab, ...r }; render(); }
    catch (e) { toast(e.message, true); }
  }
  function renderScriptEditor(m) {
    const e = editing, s = e.script;
    m.innerHTML = `<div class="btns" style="margin-top:0"><button class="b" id="sback">${ico("back", "sm")}Back</button><b style="flex:1">${esc(tilde(s.file))}</b></div>
      <div class="btns"><input id="sematch" type="text" class="grow" value="${esc(s.match || ".")}" placeholder="URL pattern"><select id="semethod"><option value="">ANY</option>${["GET","POST","PUT","PATCH","DELETE"].map((x) => `<option ${s.method === x ? "selected" : ""}>${x}</option>`).join("")}</select></div>
      <textarea id="sebody" spellcheck="false">${esc(e.content)}</textarea><div class="btns"><button class="b p" id="sesave">Save</button><span class="sub">${esc(tilde(e.file))}</span></div>`;
    $("sback").onclick = () => { editing = null; render(); };
    $("sesave").onclick = async () => {
      const r = await run("script_put", { file:s.file, match:$("sematch").value, method:$("semethod").value, content:$("sebody").value }, (x) => x.syntax_error ? "Saved, but it has a syntax error — " + x.syntax_error : "Script saved — hot reloads within 1 s");
      if (r) { editing = null; tab = e.from || "scripts"; drawerTypingDirty = false; render(); }
    };
  }

  // ───────────── Theme, skin switch and list tagging (restyles mitmweb's own table) ─────────────
  // The skin itself is /proxy/theme.css (see its "mitmweb DOM contract").  Here: the switches, plus the
  // data-* attributes the CSS needs because CSS cannot read cell text.  Only attributes on mitmweb's own
  // <td>/<tr> — never their children, React owns those (HANDOVER §6 #15).
  const skinOn = () => LS.get("rivis-skin", LS.get("proxy-restyle", "on")) !== "off";
  const themeMode = () => { const v = LS.get("rivis-theme", "system"); return v === "light" || v === "dark" ? v : "system"; };
  const compactOn = () => LS.get("rivis-compact", "off") === "on";
  const syncHost = () => ["data-theme", "data-density", "data-skin"].forEach((a) => { const v = DOC.getAttribute(a); if (v) host.setAttribute(a, v); else host.removeAttribute(a); });
  const THEME_ICON = { system: "auto", light: "sun", dark: "moon" };
  function applyTheme(mode) {
    LS.set("rivis-theme", mode);
    if (mode === "light" || mode === "dark") DOC.setAttribute("data-theme", mode); else DOC.removeAttribute("data-theme");
    syncHost();
    $("btheme").innerHTML = ico(THEME_ICON[mode]); $("btheme").title = "Theme: " + mode + " (click to change)";
  }
  function applyDensity(on) {
    LS.set("rivis-compact", on ? "on" : "off");
    if (on) DOC.setAttribute("data-density", "compact"); else DOC.removeAttribute("data-density");
    syncHost(); window.dispatchEvent(new Event("resize"));
  }
  function setSkin(on) {
    LS.set("rivis-skin", on ? "on" : "off");
    const link = document.getElementById("rivis-theme");
    const min = document.getElementById("rivis-min");
    if (on) {
      DOC.removeAttribute("data-skin"); min && min.remove();
      if (!link) { const l = document.createElement("link"); l.rel = "stylesheet"; l.href = "./proxy/theme.css"; l.id = "rivis-theme"; document.head.appendChild(l); }
    } else {
      DOC.setAttribute("data-skin", "off"); link && link.remove();
      if (!min) {   // stock mitmweb, plus the one functional marker: host-only TLS tunnel rows
        const st = document.createElement("style"); st.id = "rivis-min";
        st.textContent = `.flow-table tbody tr[data-tunnel="1"] td { opacity:.7; font-style:italic; }
          .flow-table tbody tr[data-tunnel="1"] td.col-path::after { content:" not decrypted"; font-style:normal; font-size:10px; }`;
        document.head.appendChild(st);
      }
    }
    syncHost();
  }
  setSkin(skinOn()); applyTheme(themeMode()); applyDensity(compactOn());
  // R10-04/06/07: a call that failed (TLS, refused, cut short) kept a blank or green status and "…" for ever. Always
  // on, skin or not: the failed marker is information, not decoration.
  if (!document.getElementById("rivis-fail")) {
    const st = document.createElement("style"); st.id = "rivis-fail";
    st.textContent = `.flow-table tbody td.col-status[data-failed] { color: #d93025 !important; font-weight: 600; }
      :root[data-skin="off"] .flow-table tbody td.col-status[data-failed="1"]::before { content: "failed"; }
      :root[data-skin="off"] .flow-table tbody td.col-status[data-failed="cut"]::after { content: " \\2715"; }
      .flow-table tbody td.col-time[data-failed] { font-size: 0 !important; }
      .flow-table tbody td.col-time[data-failed]::after { content: "failed"; font-size: 12px; color: #d93025; }`;
    document.head.appendChild(st);
  }

  // mitmweb's row components receive the flow as a prop; reading it from the React fiber (read-only) is exact even when the list is
  // virtualised, sorted or filtered — unlike guessing by row index (the first <tr> is a spacer).
  let fiberKey = null;
  function flowOf(el) {
    if (!fiberKey) fiberKey = Object.keys(el).find((k) => k.startsWith("__reactFiber$")) || "";
    let f = fiberKey && el[fiberKey];
    for (let n = 0; f && n < 8; n++, f = f.return) { const p = f.memoizedProps; if (p && p.flow && p.flow.id) return p.flow; }
    return null;
  }
  const TAG_TEXT = { mock: "MOCK", rule: "RULE", script: "SCRIPT", composed: "COMPOSED", repeat: "REPEAT" };
  function tagsOf(comment) {
    const out = new Set(), mockNames = new Set(((state && state.rules) || []).filter((r) => r.action === "map_local").map((r) => r.name));
    for (const part of String(comment || "").split(" | ")) {
      if (part.startsWith("mock:")) out.add("mock");
      else if (part.startsWith("rule:")) out.add(mockNames.has(part.slice(5).split(" ")[0]) ? "mock" : "rule");
      else if (part.startsWith("script:")) out.add("script");
      else if (part === "composed" || part.startsWith("edit & retry")) out.add("composed");
      else if (part.startsWith("repeat of")) out.add("repeat");
    }
    return out;
  }
  const setAttr = (el, k, v) => { if (v === null) { if (el.hasAttribute(k)) el.removeAttribute(k); } else if (el.getAttribute(k) !== v) el.setAttribute(k, v); };
  function tagCells() {
    tagRows();
    const line = document.querySelector(".flow-detail section.response .first-line");   // status line colour in the details pane
    if (line) { const m = line.textContent.match(/\b([1-5])\d\d\b/); setAttr(line, "data-s", m ? m[1] : null); }
    paintURLs();
    paintJSONBody();
    syncBodyFind();
    footerLabels();
  }
  // Attributes only (never children), so it is cheap and does not re-trigger the row observer below.
  // R10-04/06/07: an HTTP call that ended in an error: "1" no response at all, "cut" a response that broke off.
  const failOf = (flow) => flow && flow.type === "http" && flow.error && !flow.websocket ? (flow.response ? "cut" : "1") : null;
  function tagRows() {
    // host-only tunnel rows (not decrypted): attribute on the <tr> only (the path cell of a TCP flow reads "client ↔ server")
    document.querySelectorAll(".flow-table tbody tr").forEach((tr) => {
      const cell = tr.querySelector("td.col-path");
      const tunnel = cell && cell.textContent.includes(" ↔ ") ? "1" : "0";
      if (tr.dataset.tunnel !== tunnel) tr.dataset.tunnel = tunnel;
      const flow = cell && flowOf(cell), fail = failOf(flow), why = fail ? "Failed: " + (flow.error.msg || "error") : null;
      for (const sel of ["td.col-status", "td.col-time"]) {
        const td = tr.querySelector(sel);
        if (td) { setAttr(td, "data-failed", fail); if (sel === "td.col-time") setAttr(td, "title", why); }
      }
      setAttr(tr, "data-failed", fail);
    });
    if (!skinOn()) return;
    const errors = new Set(viewers.graphql_error_ids || []);
    document.querySelectorAll(".flow-table tbody tr").forEach((tr) => {
      const path = tr.querySelector("td.col-path");
      if (!path) return;                                   // spacer rows
      const method = tr.querySelector("td.col-method"), status = tr.querySelector("td.col-status");
      if (method) setAttr(method, "data-m", method.textContent.trim());
      const fail = failOf(flowOf(path));
      if (status) { const t = status.textContent.trim(); setAttr(status, "data-code", fail ? (t && fail === "cut" ? t + " \u2715" : "failed") : (t || "—")); setAttr(status, "data-s", /^\d/.test(t) ? t.charAt(0) : "x"); }
      const txt = path.textContent, at = txt.indexOf("://"), cut = at < 0 ? -1 : txt.indexOf("/", at + 3);
      const scheme = txt.match(/^\s*(https?):\/\//i);
      setAttr(tr, "data-rv-scheme", scheme ? scheme[1].toLowerCase() : null);
      const hl = String(cut < 0 ? txt.length : cut);
      if (path.style.getPropertyValue("--hl") !== hl) path.style.setProperty("--hl", hl);
      const flow = flowOf(path);
      const tags = flow ? tagsOf(flow.comment) : new Set();
      const top = ["mock", "rule", "script", "composed", "repeat"].find((t) => tags.has(t));
      const icon = tr.querySelector("td.col-icon");
      setAttr(path, "data-tag", top || null);
      setAttr(path, "data-tag-text", top ? TAG_TEXT[top] + (tags.size > 1 ? " +" + (tags.size - 1) : "") : null);
      setAttr(path, "title", top ? flow.comment : null);
      if (icon) {                                          // narrow list: the same tag as a one-letter glyph in the type-icon column
        setAttr(icon, "data-tag", top || null);
        setAttr(icon, "data-tag-glyph", top ? (top === "repeat" ? "↻" : TAG_TEXT[top][0]) : null);
        setAttr(icon, "title", top ? TAG_TEXT[top] + " — " + flow.comment : (tr.dataset.tunnel === "1" ? "TLS tunnel — not decrypted (add the host to the decrypt list in Network)" : null));
      }
      const src = flow && sourceOfFlow(flow);        // the sending app (or device) as a chip at the right of the path
      setAttr(path, "data-src", src ? (src.app || deviceName(src)) : null);
      if (status) { const g = flow && (errors.has(flow.id) || String(flow.comment || "").split(" | ").includes("graphql:error")); setAttr(status, "data-gql-error", g ? "1" : "0"); setAttr(status, "title", g ? "GraphQL: the response body contains errors" : (fail ? "Failed: " + (flow.error.msg || "error") : null)); }
    });
  }
  // mitmweb's status-bar badges are developer jargon ("regular@8094", "ssl_insecure"). Relabel through attributes + CSS; the React text stays.
  // mitmweb calls a request/response pair a "flow"; this tool says "call" everywhere
  const TAB_NAMES = { "Flow List": "Calls", Flow: "Selected call" };
  const PLACEHOLDERS = { Highlight: "Highlight calls matching…", Intercept: "Pause calls matching…" };
  function relabelChrome() {
    document.querySelectorAll("#container > header nav a").forEach((a) => { const n = TAB_NAMES[a.textContent.trim()]; setAttr(a, "data-rv", n || null); });
    document.querySelectorAll("#container > header .filter-input input").forEach((i) => { const ph = i.getAttribute("placeholder"); if (PLACEHOLDERS[ph]) { i.setAttribute("placeholder", PLACEHOLDERS[ph]); i.setAttribute("aria-label", ph); i.title = ph === "Intercept" ? "A filter such as ~u /pay — matching calls stop and wait until you press Resume (or use Breakpoints in the Tools drawer)" : "A filter such as ~u /pay or ~c 500 — matching calls are highlighted"; } });
  }
  function footerLabels() {
    relabelChrome();
    document.querySelectorAll("footer .label").forEach((el) => {
      const t = el.textContent.trim(); let m;
      if (/^Intercept:/.test(t)) { setAttr(el, "data-rv", "Breakpoints on — matching calls pause"); setAttr(el, "title", t); setAttr(el, "data-rv-tone", "warn"); return; }
      if (/^stream:/i.test(t)) {
        const size = String(state && state.stream_large_bodies || "").trim().match(/^(\d+(?:\.\d+)?)\s*([kmgt]?)(?:b)?$/i);
        const readable = size ? `${size[1]} ${size[2] ? size[2].toUpperCase() + "B" : "bytes"}` : "configured size";
        setAttr(el, "data-rv", `Stream bodies above ${readable}`);
        return;
      }
      if ((m = t.match(/^(\d+) of (\d+) flows? selected$/))) {
        const kept = state && state.retention && state.retention.limit && state.retention.trimmed ? ` · ${state.retention.trimmed} older calls trimmed (keeps up to ${state.retention.limit}; trims oldest in batches)` : "";   // R4A-02: low-water batches may leave fewer than the cap
        setAttr(el, "data-rv", (m[1] === "0" ? `${m[2]} call${m[2] === "1" ? "" : "s"}` : `${m[1]} selected · ${m[2]} calls`) + kept); return;
      }
      if ((m = t.match(/^(?:regular|local|transparent|socks5|upstream|reverse)[^@]*@(?:.*:)?(\d+)$/))) {
        setAttr(el, "data-rv", `Proxy 127.0.0.1:${m[1]}` + (state && state.project.label ? ` · ${state.project.label}` : ""));
        setAttr(el, "title", "Point the device or simulator at this address (the tool prints the exact setup commands)");
      } else if (t === "ssl_insecure") {
        setAttr(el, "data-rv", "Server certificates not checked");
        setAttr(el, "title", "ssl_insecure is on: upstream (server) certificates are not checked. Fine for internal test environments.");
        setAttr(el, "data-rv-tone", "warn");
      }
    });
  }
  // Flow-list URLs: scheme + host muted, path in full colour, query muted. Ranges over React's text node (never replaced).
  function paintURLs() {
    const names = ["rv-url-scheme", "rv-url-host", "rv-url-query"];
    if (!window.Highlight || !window.CSS || !CSS.highlights) return;
    if (!skinOn()) { names.forEach((n) => CSS.highlights.delete(n)); return; }
    const buckets = { "rv-url-scheme": [], "rv-url-host": [], "rv-url-query": [] };
    const add = (node, a, b, name) => { if (a >= b) return; const r = document.createRange(); r.setStart(node, a); r.setEnd(node, b); buckets[name].push(r); };
    document.querySelectorAll(".flow-table tbody td.col-path").forEach((cell) => {
      const node = Array.from(cell.childNodes).find((n) => n.nodeType === Node.TEXT_NODE && n.nodeValue.includes("://"));
      if (!node) return;
      const t = node.nodeValue, at = t.indexOf("://");
      const cut = t.indexOf("/", at + 3), end = cut < 0 ? t.length : cut, q = cut < 0 ? -1 : t.indexOf("?", cut);
      add(node, 0, at + 3, "rv-url-scheme");
      // CSS shifts an https:// scheme out of view (https is the norm); plain http:// stays visible next to the amber strip
      if (/^https:/i.test(t)) { const sch = String(at + 3); if (cell.style.getPropertyValue("--sch") !== sch) cell.style.setProperty("--sch", sch); }
      else if (cell.style.getPropertyValue("--sch")) cell.style.removeProperty("--sch");
      // a narrow list (13" laptop + tools drawer) shifts the host out too, or every row reads "http://127…"; the full URL is the tooltip
      const hst = String(end); if (cell.style.getPropertyValue("--hst") !== hst) cell.style.setProperty("--hst", hst);
      if (cell.title !== t) cell.title = t;
      add(node, at + 3, end, "rv-url-host");
      if (q >= 0) add(node, q, t.length, "rv-url-query");
    });
    names.forEach((n) => { if (buckets[n].length) CSS.highlights.set(n, new Highlight(...buckets[n])); else CSS.highlights.delete(n); });
  }
  // mitmweb's JSON view is plain text (no token spans). Colour it with ranges over those text nodes.
  function paintJSONBody() {
    const names = ["rv-key", "rv-str", "rv-num", "rv-lit"];
    const clear = () => { if (window.CSS && CSS.highlights) names.forEach((n) => CSS.highlights.delete(n)); };
    if (!skinOn() || !window.Highlight || !window.CSS || !CSS.highlights) { clear(); return; }
    const pre = document.querySelector(".flow-detail .contentview pre");
    const label = (document.querySelector(".contentview .controls h5") || {}).textContent || "";
    const buckets = { key: [], str: [], num: [], lit: [] };
    if (pre && /json/i.test(label)) {
      const nodes = [];
      const walker = document.createTreeWalker(pre, NodeFilter.SHOW_TEXT);
      let full = "", node;
      while ((node = walker.nextNode())) { nodes.push({ node, start: full.length }); full += node.nodeValue; }
      const take = (a, b, kind) => {
        for (let n = 0; n < nodes.length && a < b; n++) {
          const start = nodes[n].start;
          const end = n + 1 < nodes.length ? nodes[n + 1].start : full.length;
          const from = Math.max(a, start), to = Math.min(b, end);
          if (from >= to) continue;
          const range = document.createRange();
          range.setStart(nodes[n].node, from - start);
          range.setEnd(nodes[n].node, to - start);
          buckets[kind].push(range);
        }
      };
      let i = 0;
      while (i < full.length) {
        const c = full[i];
        if (c === '"') {
          let j = i + 1, escaped = false;
          while (j < full.length) {
            const ch = full[j];
            if (escaped) escaped = false;
            else if (ch === "\\") escaped = true;
            else if (ch === '"') { j++; break; }
            j++;
          }
          let k = j;
          while (k < full.length && /\s/.test(full[k])) k++;
          take(i, j, full[k] === ":" ? "key" : "str");
          i = j;
          continue;
        }
        if ((c === "-" || (c >= "0" && c <= "9")) && (i === 0 || /[\s,:[{]/.test(full[i - 1]))) {
          const m = full.slice(i).match(/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/);
          if (m) { take(i, i + m[0].length, "num"); i += m[0].length; continue; }
        }
        const word = full.startsWith("false", i) ? "false" : full.startsWith("true", i) ? "true" : full.startsWith("null", i) ? "null" : "";
        if (word && (i + word.length === full.length || /[\s,\]}]/.test(full[i + word.length]))) { take(i, i + word.length, "lit"); i += word.length; continue; }
        i++;
      }
    }
    const cssName = { key: "rv-key", str: "rv-str", num: "rv-num", lit: "rv-lit" };
    Object.entries(buckets).forEach(([kind, ranges]) => {
      if (ranges.length) CSS.highlights.set(cssName[kind], new Highlight(...ranges));
      else CSS.highlights.delete(cssName[kind]);
    });
  }
  // Body tools live beside React's <pre>; ranges paint text without changing the content view it owns.
  let bodyQuery = "", bodyTree = LS.get("rivis-body-tree", "0") === "1", bodyPre = null, bodyText = "", bodyMode = "", bodyMatches = [], bodyAt = -1;
  const bodyHighlight = () => { if (window.CSS && CSS.highlights) { CSS.highlights.delete("rv-find"); CSS.highlights.delete("rv-find-now"); } };
  function bodyRanges(el, query) {
    if (!query || !window.Highlight || !window.CSS || !CSS.highlights) return [];
    const nodes = [], walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, { acceptNode: (n) =>
      n.parentElement.closest(".rv-tree-copy") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT });
    let full = "", node;
    while ((node = walker.nextNode())) { nodes.push({ node, start: full.length }); full += node.nodeValue; }
    const hits = [], lower = full.toLowerCase(), needle = query.toLowerCase();
    for (let at = lower.indexOf(needle); at >= 0; at = lower.indexOf(needle, at + Math.max(1, needle.length))) {
      const end = at + needle.length, first = nodes.findLast ? nodes.findLast((n) => n.start <= at) : nodes.filter((n) => n.start <= at).pop();
      const last = nodes.findLast ? nodes.findLast((n) => n.start < end) : nodes.filter((n) => n.start < end).pop();
      if (!first || !last) continue;
      const range = document.createRange(); range.setStart(first.node, at - first.start); range.setEnd(last.node, end - last.start);
      hits.push(range);
    }
    return hits;
  }
  function bodyShowMatch() {
    bodyHighlight();
    const view = document.querySelector(".flow-detail .contentview"), counter = view && view.querySelector(".rv-find-count");
    if (counter) counter.textContent = bodyQuery ? `${bodyMatches.length ? bodyAt + 1 : 0} of ${bodyMatches.length}` : "";
    if (!bodyMatches.length || !window.Highlight || !window.CSS || !CSS.highlights) return;
    CSS.highlights.set("rv-find", new Highlight(...bodyMatches));
    CSS.highlights.set("rv-find-now", new Highlight(bodyMatches[bodyAt]));
    const range = bodyMatches[bodyAt], parent = range.startContainer.parentElement;
    if (parent) {
      for (let p = parent.closest("details"); p; p = p.parentElement && p.parentElement.closest("details")) p.open = true;
      parent.scrollIntoView({ block: "center", inline: "nearest" });
    }
  }
  function bodySearch(reset = true) {
    const view = document.querySelector(".flow-detail .contentview"), pre = view && view.querySelector("pre"), tree = view && view.querySelector(".rv-tree");
    bodyMatches = []; bodyHighlight();
    if (!view || !pre || !bodyQuery) { bodyAt = -1; bodyShowMatch(); return; }
    if (bodyTree && tree && !tree.hidden && tree.dataset.ready === "1") bodyTreeOpen(tree, bodyQuery);
    bodyMatches = bodyRanges(bodyTree && tree && !tree.hidden && tree.dataset.ready === "1" ? tree : pre, bodyQuery);
    if (bodyTree && tree && tree.dataset.ready === "1") bodyMatches.forEach((range) => {
      for (let p = range.startContainer.parentElement.closest("details"); p; p = p.parentElement && p.parentElement.closest("details")) p.open = true;
    });
    bodyAt = bodyMatches.length ? (reset ? 0 : Math.min(Math.max(bodyAt, 0), bodyMatches.length - 1)) : -1;
    bodyShowMatch();
  }
  function bodyStep(by) { if (!bodyMatches.length) return; bodyAt = (bodyAt + by + bodyMatches.length) % bodyMatches.length; bodyShowMatch(); }
  const bodyPath = (base, key, array) => array ? `${base}[${key}]` : /^[A-Za-z_$][\w$]*$/.test(key) ? `${base}.${key}` : `${base}[${JSON.stringify(key)}]`;
  function bodyTreeNode(value, key, path, array, depth) {
    const branch = value !== null && typeof value === "object", kind = Array.isArray(value) ? "array" : "object";
    const el = document.createElement(branch ? "details" : "div"); el.className = "rv-tree-node"; el.dataset.path = path;
    if (branch && depth < 2 && Object.keys(value).length <= 100) el.open = true;     // a big array starts folded
    const row = document.createElement(branch ? "summary" : "div"); row.className = "rv-tree-row";
    if (key !== null) { const k = document.createElement("span"); k.className = "rv-tree-key"; k.textContent = array ? String(key) : key; row.appendChild(k); }
    const val = document.createElement("span"); val.className = branch ? "rv-tree-count" : value === null || typeof value === "boolean" ? "rv-tree-lit" : typeof value === "number" ? "rv-tree-num" : "rv-tree-str";
    val.textContent = branch ? `${Array.isArray(value) ? "[" : "{"}${Object.keys(value).length}${Array.isArray(value) ? "]" : "}"}` : JSON.stringify(value);
    row.appendChild(val);
    for (const label of ["Copy path", "Copy JSON"]) {
      const b = document.createElement("button"); b.type = "button"; b.className = "rv-tree-copy"; b.title = label; b.setAttribute("aria-label", `${label} ${path}`); b.textContent = label === "Copy path" ? "$" : "{}";
      b.onclick = (e) => { e.stopPropagation(); e.preventDefault(); navigator.clipboard.writeText(label === "Copy path" ? path : JSON.stringify(value)).then(() => toast(label === "Copy path" ? "Path copied" : "JSON copied"), () => toast("Could not copy")); };
      row.appendChild(b);
    }
    el.appendChild(row);
    // children are built when their branch first opens: a 2 MB body as a full tree was a million elements and froze the page
    // …and 200 at a time, behind a "Show N more" row (searching builds only as far as a match)
    const entries = branch ? Object.entries(value) : [];
    let done = 0, more = null;
    const lone = new Map();                                      // items past `done` built alone, for a search match
    const make = (i) => { const [child, item] = entries[i], n = bodyTreeNode(item, child, bodyPath(path, child, kind === "array"), kind === "array", depth + 1); n._rvIndex = i; return n; };
    const build = (upTo = done + 200) => {
      const end = Math.min(entries.length, Math.max(upTo, done + 1)), frag = document.createDocumentFragment();
      for (; done < end; done++) frag.appendChild(lone.get(done) || make(done));
      for (const i of [...lone.keys()]) if (i < done) lone.delete(i);
      if (more) more.remove();
      const after = [...lone.keys()].sort((a, b) => a - b)[0];
      if (after === undefined) el.appendChild(frag); else el.insertBefore(frag, lone.get(after));
      el.dataset.built = "1";
      if (done < entries.length) {
        more = document.createElement("button"); more.type = "button"; more.className = "rv-tree-more";
        more.textContent = `Show ${Math.min(200, entries.length - done)} more of ${entries.length - done}`;
        more.onclick = (e) => { e.preventDefault(); build(); bodySearch(false); };
        const first = [...lone.keys()].sort((a, b) => a - b)[0];
        el.insertBefore(more, first === undefined ? null : lone.get(first));      // right after the items built in a row
      }
    };
    el._rvEntries = entries; el._rvArray = kind === "array";
    el._rvOne = (i) => {                                          // build just item i (a search hit far down a big array)
      if (i < done || lone.has(i)) return;
      const n = make(i), next = [...lone.keys()].filter((j) => j > i).sort((a, b) => a - b)[0];
      lone.set(i, n); el.insertBefore(n, next === undefined ? more : lone.get(next));
    };
    if (branch) {                                                 // small folded branches near the top are built anyway: search and copy reach them
      el._rvBuild = build;
      if (el.open || (depth <= 3 && entries.length <= 20)) build();
      el.addEventListener("toggle", () => { if (el.open && !el.dataset.built) build(); });
    }
    return el;
  }
  // Tree search looks in the parsed body, then opens (and builds) only the branches that hold a match.
  function bodyTreeOpen(tree, query) {
    const needle = query.toLowerCase(), want = new Set(), root = tree.firstElementChild;
    if (!root || root._rvData === undefined) return;
    const walk = (value, path, array) => {
      if (want.size >= 200) return;                              // opens the first 200 matches: enough to read, quick on 2 MB
      if (value === null || typeof value !== "object") return;
      Object.entries(value).forEach(([k, v]) => {
        const p = bodyPath(path, k, array), leaf = v === null || typeof v !== "object";
        if (k.toLowerCase().includes(needle) || (leaf && JSON.stringify(v).toLowerCase().includes(needle))) want.add(p);
        if (!leaf) walk(v, p, Array.isArray(v));
      });
    };
    walk(root._rvData, "$", Array.isArray(root._rvData));
    want.forEach((p) => {
      let el = root;
      const under = (c) => c.classList.contains("rv-tree-node") && (p === c.dataset.path || p.startsWith(c.dataset.path + ".") || p.startsWith(c.dataset.path + "["));
      while (el && el.dataset.path !== p) {
        let next = null;
        if (el.tagName === "DETAILS" && el._rvBuild) {
          if (!el.dataset.built) el._rvBuild();
          next = [...el.children].find(under);
          if (!next) {                                            // past what is built: build as far as this child
            const holds = (cp) => p === cp || p.startsWith(cp + ".") || p.startsWith(cp + "[");
            const i = el._rvEntries.findIndex(([k]) => holds(bodyPath(el.dataset.path, k, el._rvArray)));
            if (i >= 0) { el._rvOne(i); next = [...el.children].find(under); }
          }
          el.open = true;
        }
        el = next;
      }
    });
  }
  function syncBodyFind() {
    const view = document.querySelector(".flow-detail .contentview"), controls = view && view.querySelector(":scope > .controls"), pre = view && view.querySelector("pre");
    if (!view || !controls || !pre) { bodyPre = null; bodyHighlight(); return; }
    let tools = controls.querySelector(":scope > .rv-body-tools");
    if (!tools) {
      tools = document.createElement("span"); tools.className = "rv-body-tools";
      tools.innerHTML = '<input class="rv-body-find" type="search" placeholder="Find in body" aria-label="Find in body"><span class="rv-find-count" aria-live="polite"></span><button type="button" class="rv-find-prev" title="Previous match" aria-label="Previous match">▲</button><button type="button" class="rv-find-next" title="Next match" aria-label="Next match">▼</button><button type="button" class="rv-tree-toggle" aria-pressed="false">Tree</button>';
      controls.appendChild(tools);
      const field = tools.querySelector("input"); field.value = bodyQuery;
      let typed = 0;
      field.oninput = () => { bodyQuery = field.value; clearTimeout(typed); typed = setTimeout(bodySearch, 150); };
      field.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); bodyStep(e.shiftKey ? -1 : 1); } else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); field.value = bodyQuery = ""; bodySearch(); } };
      tools.querySelector(".rv-find-prev").onclick = () => bodyStep(-1);
      tools.querySelector(".rv-find-next").onclick = () => bodyStep(1);
      tools.querySelector(".rv-tree-toggle").onclick = () => { bodyTree = !bodyTree; LS.set("rivis-body-tree", bodyTree ? "1" : "0"); syncBodyFind(); };
    }
    // two ways a body is only partly on screen: Rivis clips one over VIEW_SOURCE_LIMIT ("showing first …"), and mitmweb
    // draws a long one a screenful at a time behind "Show more". The tree reads the whole body from the proxy instead.
    const label = (controls.querySelector("h5") || {}).textContent || "", json = /json/i.test(label), clipped = /showing first/i.test(label);
    const more = [...view.querySelectorAll("button")].some((b) => /show more/i.test(b.textContent));
    const toggle = tools.querySelector(".rv-tree-toggle"); toggle.hidden = !json; toggle.setAttribute("aria-pressed", String(bodyTree));
    let note = view.querySelector(":scope > .rv-body-note");
    if (!note) { note = document.createElement("div"); note.className = "rv-body-note"; controls.after(note); }
    const partial = clipped || (more && !(json && bodyTree));
    note.textContent = !partial ? "" : json ? "Searching the shown part — Tree searches the whole body." : "Searching the shown part — show the full body to search all.";
    note.hidden = !partial;
    let tree = view.querySelector(":scope > .rv-tree");
    if (!tree) { tree = document.createElement("div"); tree.className = "rv-tree"; pre.after(tree); }
    const side = (location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] || "").toLowerCase(), id = selectedFlow();
    const src = id && /^(request|response)$/.test(side) ? `./flows/${encodeURIComponent(id)}/${side}/content.data` : "";
    const content = pre.textContent, mode = `${src}/${json}/${clipped}/${bodyTree}`, changed = pre !== bodyPre || content !== bodyText || bodyMode !== mode;
    if (!changed) return;
    const fresh = bodyMode !== mode;
    bodyPre = pre; bodyText = content; bodyMode = mode;
    if (!fresh && tree.dataset.ready === "1") { pre.hidden = true; bodySearch(false); return; }   // "Show more" grew the <pre>: the tree has it all
    tree.replaceChildren(); tree.dataset.ready = "0";
    tree.hidden = !json || !bodyTree; pre.hidden = false;
    if (json && bodyTree) {
      if (clipped) tree.textContent = "Tree is available for JSON up to 2 MB. Use the text view for this body.";
      else if (!src) tree.textContent = "This body cannot be shown as a tree.";
      else {
        tree.textContent = "Loading the tree…";
        fetchT(src, { credentials: "same-origin" }, NORMAL_MS, "body").then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); }).then((text) => {
          if (bodyMode !== mode || !tree.isConnected) return;               // another call or tab since
          tree.replaceChildren();
          if (new Blob([text]).size > 2 * 1024 * 1024) { tree.textContent = "Tree is available for JSON up to 2 MB. Use the text view for this body."; return; }
          try { const data = JSON.parse(text), top = bodyTreeNode(data, null, "$", false, 0); top._rvData = data; tree.appendChild(top); tree.dataset.ready = "1"; }
          catch (e) { tree.textContent = "This body cannot be parsed as JSON."; return; }
          pre.hidden = true; bodySearch();
        }).catch((e) => { if (bodyMode === mode) tree.textContent = "Could not load the body for the tree: " + e.message; });
      }
    }
    pre.hidden = tree.dataset.ready === "1";
    bodySearch();
  }
  // list width buckets for theme.css: narrow (< 520px) drops size; wide (> 640px) shows the word chips
  const sizeBuckets = () => {
    const t = document.querySelector(".flow-table"); if (!t) return;
    const w = t.getBoundingClientRect().width;
    if (w) { setAttr(DOC, "data-narrow", w < 520 ? "1" : null); setAttr(DOC, "data-wide", w > 640 ? "1" : null); setAttr(DOC, "data-midlist", w < 760 ? "1" : null); }
  };
  const columnBuiltins = ["path", "method", "status", "size", "time", "timestamp", "duration", "content_type", "source_app", "comment"];
  const columnNames = { path: "Path", method: "Method", status: "Status", size: "Size", time: "Time",
    timestamp: "Start time", duration: "Duration", content_type: "Content type", source_app: "Source app", comment: "Comment" };
  let columns = ["path", "method", "status", "size", "time", "timestamp"];
  const columnLabel = (id) => columnNames[id] || id.replace(/^request:/, "Request: ").replace(/^response:/, "Response: ");
  const columnValue = (id, flow) => {
    if (!flow) return "";
    const req = flow.request || {}, res = flow.response || {};
    if (id === "duration") {
      const end = res.timestamp_end || req.timestamp_end, start = req.timestamp_start;
      return end && start ? `${Math.round((end - start) * 1000)} ms` : "";
    }
    if (id === "source_app") { const src = sourceOfFlow(flow); return src ? (src.app || deviceName(src)) : ""; }
    const header = id === "content_type" ? "content-type" : id.split(":").slice(1).join(":").toLowerCase();
    const message = id === "content_type" || id.startsWith("response:") ? res : req;
    const pairs = message.headers || [];
    if (Array.isArray(pairs)) return (pairs.find((p) => String(p[0]).toLowerCase() === header) || [null, ""])[1];
    return Object.entries(pairs).find(([k]) => k.toLowerCase() === header)?.[1] || "";
  };
  const customColumn = (id) => !["path", "method", "status", "size", "time", "timestamp", "comment"].includes(id);
  let columnBusy = false;
  function syncColumns() {
    if (columnBusy) return;
    const table = document.querySelector(".flow-table table"), head = table && table.querySelector("thead tr");
    if (!head) return;
    columnBusy = true;
    try {
      // path and start time stay in mitmweb's list when unchecked (the newest-first sort clicks "Start time"): hidden, not removed
      table.dataset.rivisHidePath = columns.includes("path") ? "0" : "1";
      table.dataset.rivisHideTimestamp = columns.includes("timestamp") ? "0" : "1";
      const order = ["tls", "icon", ...columns, "path", "timestamp", "quickactions"].filter((id, i, a) => a.indexOf(id) === i);
      const syncRow = (row, isHead) => {
        const tag = isHead ? "th" : "td", cells = [...row.children].filter((c) => c.tagName === tag.toUpperCase());
        if (!cells.some((c) => c.classList.contains("col-path"))) return;
        for (const old of cells.filter((c) => c.dataset.rvColumn && !columns.includes(c.dataset.rvColumn))) old.remove();
        const flow = isHead ? null : flowOf(row);
        for (const id of columns.filter(customColumn)) {
          let cell = [...row.children].find((c) => c.dataset.rvColumn === id);
          if (!cell) { cell = document.createElement(tag); cell.dataset.rvColumn = id; cell.className = "col-rivis-extra"; row.appendChild(cell); }
          const value = isHead ? columnLabel(id) : columnValue(id, flow);
          if (cell.textContent !== String(value || "")) cell.textContent = value || "";
          if (!isHead) cell.title = String(value || "");
        }
        const desired = order.map((id) => [...row.children].find((c) => c.dataset.rvColumn === id || c.classList.contains("col-" + id))).filter(Boolean);
        desired.forEach((cell, i) => { if (row.children[i] !== cell) row.insertBefore(cell, row.children[i] || null); });
      };
      syncRow(head, true);
      table.querySelectorAll("tbody tr").forEach((row) => syncRow(row, false));
      const last = head.querySelector("th.col-quickactions") || head.lastElementChild;
      if (last && !last.querySelector("#rivis-columns")) {
        const b = document.createElement("button"); b.id = "rivis-columns"; b.type = "button"; b.textContent = "+";
        b.title = "Customize columns"; b.setAttribute("aria-label", "Customize columns");
        b.onclick = (e) => { e.stopPropagation(); chooseColumns(); };
        last.appendChild(b);
      }
    } finally { columnBusy = false; }
  }
  async function chooseColumns() {
    const action = await ask("Customize columns", { choices: [["toggle", "Show or hide"], ["move", "Reorder"], ["header", "Add header"]] });
    if (!action) return;
    let next = columns.slice();
    if (action === "header") {
      const side = await ask("Which headers?", { choices: [["request", "Request"], ["response", "Response"]] });
      if (!side) return;
      const name = await ask("Header name", { input: "x-request-id", yes: "Add" });
      if (name === null) return;
      const id = side + ":" + name.trim().toLowerCase();
      if (!/^[a-z0-9!#$%&'*+.^_`|~-]{1,100}$/.test(name.trim()) || next.includes(id)) { toast("Enter a unique HTTP header name", true); return; }
      next.push(id);
    } else {
      const items = action === "toggle" ? [...columnBuiltins, ...next.filter((x) => !columnBuiltins.includes(x))] : next;
      const id = await ask(action === "toggle" ? "Show or hide a column" : "Move a column", { choices: items.map((x) =>
        [x, `${next.includes(x) ? "✓ " : ""}${columnLabel(x)}`]) });
      if (!id) return;
      if (action === "toggle") next = next.includes(id) ? next.filter((x) => x !== id) : [...next, id];
      else {
        const way = await ask("Move " + columnLabel(id), { choices: [["left", "Earlier"], ["right", "Later"]] });
        const i = next.indexOf(id), j = i + (way === "left" ? -1 : 1);
        if (!way || j < 0 || j >= next.length) return;
        [next[i], next[j]] = [next[j], next[i]];
      }
    }
    try { const r = await api("columns_set", { columns: next }); columns = r.columns; syncColumns(); }
    catch (e) { toast(e.message, true); }
  }
  window.addEventListener("resize", () => { sizeBuckets(); placeBars(); });
  // Rows the virtual list builds while scrolling must never paint unstyled (raw https:// URLs, no badges): style them
  // right here, before the browser paints. This used to be a 60 ms debounce, which never fired while rows kept changing
  // (scrolling, live traffic), so rows stayed raw until the next poll. The heavier rest runs at most once per frame.
  let restQueued = 0;
  new MutationObserver(() => {
    tagRows();
    if (!restQueued) restQueued = requestAnimationFrame(() => { restQueued = 0; tagCells(); syncColumns(); sizeBuckets(); placeBars(); });
  }).observe(document.body, { childList: true, subtree: true, characterData: true });


  // ───────────── Search bar: always visible, drives mitmweb's own list filter ─────────────
  // mitmweb keeps the filter in its redux store (ui.filter.search) and sends it to the server, which evaluates it.
  // Its own Search box only exists on the "Flow List" tab (it vanishes as soon as a call is selected), so this bar
  // finds the store through the React root (read-only fiber walk, like flowOf) and dispatches the same action the
  // stock box does.  An INVALID filter makes the server close the websocket, so every filter is checked with the
  // server's own parser first (op filter_check). Plain words match URLs or TCP destinations (host-only tunnels).
  const reFilter = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\/g, "\\\\").replace(/'/g, "\\'");   // regex-escape, then the filter parser's own un-escaping (HANDOVER §6 #3)
  const isExpr = (t) => t === "~" || /(^|[\s(!&|])~([A-Za-z]+(\s|$)|[(])/.test(t) ||   // R7A-03: bare ~ is an incomplete filter; R2A-13: embedded ~ is URL text
     /^[!(]/.test(t) || /\s[&|]\s/.test(t);
  const toFilter = (text) => {
    const t = text.trim();
    if (!t) return "";
    if (isExpr(t)) return t;
    // a 3-digit status code (500, 404…) also matches the response status — what a tester typing "500" means
    return t.split(/\s+/).map((w) => /^[1-5]\d\d$/.test(w) ? "( ~u '" + w + "' | ~c " + w + " )" : "( ~u '" + reFilter(w) + "' | ( ~tcp & ~dst '" + reFilter(w) + "' ) )").join(" & ");
  };
  let storeRef = null;
  const mwStore = () => {
    if (storeRef) return storeRef;
    const root = document.getElementById("mitmproxy"), key = root && Object.keys(root).find((k) => k.startsWith("__reactContainer$"));
    if (!key) return null;
    const stack = [root[key]];
    for (let n = 0; stack.length && n < 800; n++) {
      const f = stack.pop(); if (!f) continue;
      const pr = f.memoizedProps;
      if (pr && pr.store && typeof pr.store.getState === "function" && typeof pr.store.dispatch === "function") { storeRef = pr.store; return storeRef; }
      if (f.sibling) stack.push(f.sibling);
      if (f.child) stack.push(f.child);
    }
    return null;
  };
  const storeSearch = () => { const st = mwStore(); try { return (st && st.getState().ui.filter.search) || ""; } catch (e) { return ""; } };
  const checked = new Map();                 // filter text → {ok, error}
  let sbSeq = 0, lastSent = "", lastTyped = "";
  const sq = () => $("sq");
  function spop(html, err) { const p = $("spop"); p.innerHTML = html || ""; p.classList.toggle("open", !!html); p.classList.toggle("err", !!err); }
  function examplesHTML() {
    const ex = [["~m POST", "only POST calls"], ["~c 500", "status 500"], ["~q", "no response yet"], ["~u /api & ~m GET", "combine with  &  |  !"], ["~b token", "body contains a word"], ["~h x-request-id", "a header contains…"]];
    return `<h5>Type a host or part of a URL</h5><div class="sub" style="margin-bottom:8px">e.g. <code>postman-echo</code> or <code>/v2/cards</code> — it filters as you type. For more, use a <code>~</code> filter:</div>` +
      ex.map(([c, d]) => `<button class="ex" data-ex="${esc(c)}"><code>${esc(c)}</code><span>${esc(d)}</span></button>`).join("");
  }
  async function commitSearch(raw) {
    const seq = ++sbSeq, text = raw.trim(), f = toFilter(text), st = mwStore();
    if (!st) { toast("Can't reach mitmweb's filter (version changed?). Use the Search box on the Calls tab.", true); return; }
    let res = f ? checked.get(f) : { ok: true };
    if (!res) {
      try { const r = await api("filter_check", { filter: f }); res = { ok: r.ok !== false, error: r.error }; }
      catch (e) { res = { ok: false, error: e.message }; }
      checked.set(f, res);
      if (checked.size > 200) checked.delete(checked.keys().next().value);
    }
    if (seq !== sbSeq) return;                      // a newer keystroke is already in flight
    $("sbox").classList.toggle("bad", !res.ok);
    if (!res.ok) { spop(`Not a valid filter yet — the list keeps the last good one. Plain words always work; for a <code>~</code> filter, see <button class="lnk" data-ex-help>the examples</button>.`, true); $("spop").title = res.error || ""; return; }
    spop(document.activeElement === host && !text ? examplesHTML() : "");
    if (f !== lastSent) { lastSent = f; st.dispatch({ type: "ui/filters/setFilter", payload: f }); }
    drawStrip();
  }
  let sqTimer = null;
  let savedMenu = -1;
  const savedRows = () => (state && state.saved_filters) || [];
  const applySaved = (i) => {
    const row = savedRows()[i]; if (!row) return;
    const input = sq(); input.value = input.value.trim() === row.filter ? "" : row.filter;
    sbSync(); clearTimeout(sqTimer); commitSearch(input.value); drawStrip();
  };
  const saveFilter = async () => {
    const value = sq().value.trim(); if (!value) return toast("Type a filter first", true);
    try {
      const valid = await api("filter_check", { filter: toFilter(value) });
      if (!valid.ok) return toast(valid.error || "Invalid filter", true);
      const name = await ask("Name this filter\n\nUp to 40 letters, digits, spaces or . _ -", { input: value.slice(0, 40), yes: "Save" });
      if (!name) return;
      const r = await api("filters_save", { name, filter: value }); state.saved_filters = r.filters; savedMenu = -1; drawStrip(); toast("Filter saved");
    } catch (e) { toast(e.message, true); }
  };
  const sbSync = () => {
    const v = sq().value; $("sclear").hidden = !v; $("sbox").classList.toggle("has", !!v);
  };
  function wireSearch() {
    const input = sq();
    $("ssave").onclick = saveFilter;
    input.addEventListener("input", () => {
      sbSync(); lastTyped = input.value; clearTimeout(sqTimer);
      if (!input.value.trim()) { spop(examplesHTML()); }
      sqTimer = setTimeout(() => commitSearch(input.value), 150);
    });
    input.addEventListener("focus", () => { if (!input.value.trim() && !$("sbox").classList.contains("bad")) spop(examplesHTML()); input.select(); });
    input.addEventListener("blur", () => setTimeout(() => { if (root.activeElement !== input && !$("spop").matches(":hover")) spop(""); }, 120));
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { clearTimeout(sqTimer); commitSearch(input.value); }
      else if (e.key === "Escape") { e.preventDefault(); if (input.value) { input.value = ""; sbSync(); clearTimeout(sqTimer); commitSearch(""); spop(examplesHTML()); } else { input.blur(); spop(""); } }
    });
    $("sclear").onclick = () => { input.value = ""; sbSync(); commitSearch(""); input.focus(); };
    $("spop").onmousedown = (e) => e.preventDefault();      // keep focus in the box while clicking an example
    $("spop").onclick = (e) => {
      if (e.target.closest("[data-ex-help]")) { spop(examplesHTML()); return; }
      const b = e.target.closest("[data-ex]"); if (!b) return;
      input.value = b.dataset.ex + " "; sbSync(); input.focus(); commitSearch(input.value);
    };
    $("strash").onclick = async () => {
      const n = (mwStore() && mwStore().getState().flows.list.length) || 0;
      if (!n) return toast("The list is already empty");
      if (!await ask(`Clear all ${n} calls from the list?\n\nSaved sessions, rules and scripts are not affected.`, { yes: "Clear all", danger: true })) return;
      try { const r = await fetchT("./clear", { method: "POST", credentials: "same-origin", headers: { "X-XSRFToken": xsrf() } }, NORMAL_MS, "clear"); if (!r.ok) throw new Error("HTTP " + r.status); toast("List cleared"); }
      catch (err) { toast("Could not clear the list: " + err.message, true); }
    };
  }
  const focusSearch = () => { const i = sq(); i.focus(); i.select(); };
  // mitmweb (or the URL ?s=…) changed the filter behind our back → show it, unless the user is typing
  function pullSearch() {
    const st = mwStore(); if (!st) return;
    const cur = storeSearch();
    if (cur === lastSent) return;
    lastSent = cur;
    if (root.activeElement !== sq()) { sq().value = cur; lastTyped = cur; sbSync(); $("sbox").classList.remove("bad"); }
    drawStrip();
  }
  // chips for everything that hides calls, so "my call vanished" has a visible answer (and a one-click undo)
  function drawStrip() {
    const el = $("fstrip"), st = mwStore();
    const saved = savedRows();
    const chips = [];
    if (state) {
      const label = (state.project && state.project.label) || state.view_project;
      if (state.project_only) chips.push(["project", `Only ${label} calls`]);
      if (state.focus_host) chips.push(["host", `Only ${state.focus_host}`]);
      if (state.graphql_operation) chips.push(["gql", `GraphQL: ${state.graphql_operation}`]);
      if (state.source) chips.push(["source", `Only ${sourceName(state.source)}`]);
    }
    const searching = !!(st && storeSearch());
    let counts = "";
    if (st) { try { const f = st.getState().flows; counts = searching ? `${f.view.length} of ${f.list.length} calls match` : ""; } catch (e) { /* cosmetic */ } }
    const sig = JSON.stringify([chips, searching, counts, saved, savedMenu, storeSearch()]);
    const show = chips.length > 0 || searching || saved.length > 0 || host.hasAttribute("data-sbrow");   // R6B-05: the strip carries the filter box
    if (drawStrip._sig !== sig) {
      drawStrip._sig = sig;
      el.innerHTML = (chips.length ? `<span>Showing</span>` : "") + chips.map(([k, t]) => `<span class="fchip"><span title="${esc(t)}">${esc(t)}</span><button data-un="${k}" aria-label="Show everything again: ${esc(t)}" title="Remove this limit">${ico("x", "sm")}</button></span>`).join("") +
        saved.map((row, i) => `<span><button class="saved ${sq().value.trim() === row.filter ? "on" : ""}" data-saved="${i}" title="Alt+${i + 1}: ${esc(row.filter)}">${esc(row.name)}</button><button class="lnk" data-smenu="${i}" aria-label="Options for ${esc(row.name)}">⋯</button>${savedMenu === i ? `<span class="savedmenu"><button data-sact="rename" data-si="${i}">Rename</button><button data-sact="delete" data-si="${i}">Delete</button><button data-sact="left" data-si="${i}" ${i ? "" : "disabled"}>←</button><button data-sact="right" data-si="${i}" ${i < saved.length - 1 ? "" : "disabled"}>→</button></span>` : ""}</span>`).join("") +
        (counts ? `<span class="cnt2">${esc(counts)} · <button class="lnk" data-un="search">Clear filter</button></span>` : "");
      el.querySelectorAll("[data-saved]").forEach((b) => (b.onclick = () => applySaved(Number(b.dataset.saved))));
      el.querySelectorAll("[data-smenu]").forEach((b) => (b.onclick = () => { const i = Number(b.dataset.smenu); savedMenu = savedMenu === i ? -1 : i; drawStrip(); }));
      el.querySelectorAll("[data-sact]").forEach((b) => (b.onclick = async () => {
        const i = Number(b.dataset.si), row = savedRows()[i], act = b.dataset.sact; if (!row) return;
        try {
          let r;
          if (act === "rename") { const name = await ask("Rename filter", { input: row.name, yes: "Rename" }); if (!name || name === row.name) return; r = await api("filters_save", { old: row.name, name }); }
          else if (act === "delete") { if (!await ask("Delete saved filter '" + row.name + "'?", { yes: "Delete", danger: true })) return; r = await api("filters_delete", { name: row.name }); }
          else { const names = savedRows().map((x) => x.name), j = act === "left" ? i - 1 : i + 1; [names[i], names[j]] = [names[j], names[i]]; r = await api("filters_order", { names }); }
          state.saved_filters = r.filters; savedMenu = -1; drawStrip();
        } catch (e) { toast(e.message, true); }
      }));
      el.querySelectorAll("[data-un]").forEach((b) => (b.onclick = () => {
        const k = b.dataset.un;
        if (k === "search") { sq().value = ""; sbSync(); commitSearch(""); }
        else if (k === "host") run("focus_host", { host: null }, "Showing all hosts");
        else if (k === "gql") run("graphql_filter", { name: null }, "GraphQL filter cleared");
        else if (k === "source") setSource(null);
        else run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic");
      }));
    }
    if (DOC.getAttribute("data-fstrip") !== (show ? "1" : null) && (show || DOC.hasAttribute("data-fstrip"))) { setAttr(DOC, "data-fstrip", show ? "1" : null); window.dispatchEvent(new Event("resize")); }
    el.style.display = show ? "" : "none";
    host.style.setProperty("--strip-h", show ? "28px" : "0px");
  }
  // fixed bars follow mitmweb's header: left edge after the tabs, right edge before the brand pill
  const SB_MIN = 200;          // the filter bar (box + clear-list button) never gets narrower than this
  function placeBars() {
    const hdr = document.querySelector("#container > header");
    const ready = !!hdr && !!mwStore();
    if (host.hasAttribute("data-sbar") !== ready) { if (ready) host.setAttribute("data-sbar", ""); else host.removeAttribute("data-sbar"); setAttr(DOC, "data-sbar", ready ? "1" : null); }
    if (!ready) return;
    if (!placeBars._sub) { placeBars._sub = true; mwStore().subscribe(() => { clearTimeout(placeBars._t); placeBars._t = setTimeout(() => { pullSearch(); drawStrip(); try { drawEmptyList(); } catch (e) { /* cosmetic */ } }, 80); }); }
    const nav = hdr.querySelector("nav"), nr = nav.getBoundingClientRect();
    const hb = Math.round(hdr.getBoundingClientRect().bottom);
    // the brand pill slides when the drawer opens; use where it will end up, not where it is mid-transition
    const brand = $("brand"), openW = parseFloat(host.style.getPropertyValue("--open-w")) || 0;
    const links0 = [...nav.querySelectorAll("a")], last0 = links0[links0.length - 1];   // the search box starts after the last menu
    const left0 = Math.round((last0.dataset.rv === "Selected call" ? last0.getBoundingClientRect().right : last0.getBoundingClientRect().right + 112) + 16);
    brand.classList.remove("mini");                                     // measure the full pill first
    if (window.innerWidth - openW - 12 - brand.offsetWidth - left0 - 12 - 34 < 220) brand.classList.add("mini");
    const brandL = window.innerWidth - openW - 12 - brand.offsetWidth;
    setAttr(DOC, "data-ribbon", hdr.getBoundingClientRect().width < 900 ? "icons" : null);
    hdr.querySelectorAll(".btn:not([title])").forEach((b) => { const t = b.textContent.replace(/[▾\s]+$/, "").trim(); if (t) b.title = t; });   // icon-only toolbar needs its names
    const room = brandL - left0 - 12;
    // R6B-05: beside an open drawer on a ~900 px window the box was clamped to 110 px and its input to 16 px, an
    // unreadable filter. Below SB_MIN it moves to its own row under the header (the filter strip), list-wide.
    const row = room - 34 < SB_MIN, mainW = window.innerWidth - openW;
    const left = row ? 8 : left0;
    const sbw = row ? Math.max(SB_MIN, Math.min(440, mainW - 16 - 230)) : Math.min(440, room - 34);   // 34 = the clear-list button; 230 = the strip's match count
    host.style.setProperty("--sb-left", left + "px");
    host.style.setProperty("--sb-w", sbw + "px");
    if (host.hasAttribute("data-sbrow") !== row) { if (row) host.setAttribute("data-sbrow", ""); else host.removeAttribute("data-sbrow"); drawStrip(); }
    if (host.hasAttribute("data-tight") !== (sbw < 270)) { if (sbw < 270) host.setAttribute("data-tight", ""); else host.removeAttribute("data-tight"); }
    host.style.setProperty("--hb", hb + "px");
    const rib = hdr.querySelector(":scope > div"), rr = rib ? rib.getBoundingClientRect() : null;
    host.style.setProperty("--fab-top", Math.round(rr && rr.height > 4 ? rr.top + (rr.height - 32) / 2 : hb + 8) + "px");
    $("sbar").style.top = (row ? hb + 1 : Math.round(nr.top + (nr.height - 30) / 2)) + "px";
    $("spop").style.top = (row ? hb + 32 : Math.round(nr.top + (nr.height - 30) / 2 + 36)) + "px";
  }
  wireSearch();


  // ───────────── Right-click on a call (the place Proxyman users reach for first) ─────────────
  const closeCallMenu = () => $("cmenu").classList.remove("open");
  async function openCallMenu(x, y, tr) {
    const mf = flowOf(tr); if (!mf) return;
    if (!tr.classList.contains("selected")) tr.click();                  // select it first, exactly like a left click
    // The row already carries everything the menu shows (type, method, host, path, connection): open it at once from that, so a proxy
    // that is not answering cannot hold the menu back. The panel's own cache is only a fresher copy of the same call.
    const f = flowCache.byId.get(mf.id) || mf;
    const m = $("cmenu"), mod = KMOD;
    const isHttp = !!f && f.type === "http", address = (f && f.server_conn && f.server_conn.address) || [],
      tunnelHost = (f && ((f.client_conn || {}).sni || (f.server_conn || {}).sni)) || address[0] || "",
      hostName = isHttp ? f.request.pretty_host : (tunnelHost && address[1] && !String(tunnelHost).endsWith(":" + address[1]) ? tunnelHost + ":" + address[1] : tunnelHost);
    const item = (k, label, icon, extra = "", cls = "", dis = false) => `<button role="menuitem" data-k="${k}" class="${cls}" ${dis ? "disabled" : ""}>${ico(icon, "sm")}${label}${extra}</button>`;
    const focused = state && isHttp && state.focus_host === hostName;
    const src = sourceOfFlow(f), srcOn = !!(src && state.source && (state.source === src.key || state.source === deviceKey(src)));
    m.innerHTML = (isHttp
      ? `<div class="hd">${esc(f.request.method)} ${esc(hostName)}${esc(f.request.path.split("?")[0])}</div>` +
        item("map", "Map Local this call…", "map") +
        (state && state.rules.some((r) => r.action === "map_local" && (!r.method || r.method === f.request.method) && (() => {
          const req = f.request, port = req.port && !((req.scheme === "http" && req.port === 80) || (req.scheme === "https" && req.port === 443)) ? ":" + req.port : "";
          try { return new RegExp(r.match).test(req.pretty_url || req.url || (req.scheme + "://" + req.pretty_host + port + req.path)); } catch (e) { return false; }
        })()) ? item("mapvariant", "Add as a new variant…", "map") : "") +
        item("bp", "Pause on this call (Breakpoint)", "bp") +
        `<hr>` + item("repeat", "Repeat", "retry", `<kbd>${mod} ↵</kbd>`) + item("retry", "Edit &amp; Repeat…", "compose", `<kbd>${KALT} ${KSHIFT} ↵</kbd>`) + item("cmpA", "Compare: set as A", "cmp") +
        `<hr>` + item("curl", "Copy as cURL", "call") + item("url", "Copy URL", "call") +
        `<hr>` + item("host", focused ? "Show all hosts again" : "Show only this host", "search") + (src ? item("src", srcOn ? "Show every source again" : `Show only ${esc(src.app || deviceName(src))}`, "phone") : "") + item("tls", "Stop decrypting this host", "lock")
      : `<div class="hd">${esc(hostName || "Host-only row")} — not decrypted</div>` + item("tlson", "Decrypt this host", "unlock")) +
      `<hr>` + item("del", "Delete this call", "trash", "", "d");
    m.classList.add("open"); openCallMenu.at = Date.now(); openCallMenu.size = [window.innerWidth, window.innerHeight];
    const w = m.offsetWidth, h = m.offsetHeight;
    m.style.left = Math.max(6, Math.min(x, window.innerWidth - w - 6)) + "px"; m.style.top = Math.max(6, Math.min(y, window.innerHeight - h - 6)) + "px";
    const first = m.querySelector("button:not(:disabled)"); if (first) first.focus();
    m.querySelectorAll("button").forEach((b) => (b.onclick = async () => {
      closeCallMenu();
      const k = b.dataset.k, id = mf.id;
      if (k === "map") { const res = await run("mock", { flow_id: id, draft: true }, mockToast); if (res) { if (!$("drawer").classList.contains("open")) { setOpen(true); } openEditor(res.name); } }
      else if (k === "mapvariant") { const name = await ask("Name the new variant from this call", { input: "" }); if (name) { const res = await run("mock", { flow_id: id, variant_name: name }, "Saved variant '" + name + "'"); if (res) { if (!$("drawer").classList.contains("open")) setOpen(true); openEditor(res.name); } } }
      else if (k === "bp") { const added = await run("bp_add", { flow_id: id, request: true, response: true }); if (added) breakpointOn(id); }
      else if (k === "repeat") run("retry", { flow_id: id, edits: {} }, "Repeated — the new call is in the list (newest first)");
      else if (k === "retry") openRetry(id);
      else if (k === "cmpA") { cmpA = { id, label: f.request.method + " " + hostName + f.request.path }; openDrawer("cmp"); toast("Now select another call and press Compare"); }
      else if (k === "curl" || k === "url") copyExport(id, k);
      else if (k === "host") run("focus_host", { host: focused ? null : hostName }, focused ? "Showing all hosts" : "Showing only " + hostName);
      else if (k === "src") setSource(srcOn ? null : (src.app ? src.key : deviceKey(src)));
      else if (k === "tls" || k === "tlson") run("tls_host", { flow_id: id, host: hostName, decrypt: k === "tlson" }, (r) => r.message);
      else if (k === "del" && await ask("Delete this call from the list?", { yes: "Delete", danger: true })) {
        try { const r = await fetchT("./flows/" + id, { method: "DELETE", credentials: "same-origin", headers: { "X-XSRFToken": xsrf() } }, NORMAL_MS, "delete"); if (!r.ok) throw new Error("HTTP " + r.status); toast("Call deleted"); }
        catch (err) { toast("Could not delete: " + err.message, true); }
      }
    }));
  }
  // A left click on a call must select it even when a new call is drawn above it between the press and the release. The browser then
  // sends the click to the nearest common ancestor of the two targets (the table body, not a row), so mitmweb's row handler never
  // runs and the click does nothing. Remember the row the press started on and finish the click there, as the user meant.
  let rowPress = null;
  window.addEventListener("mousedown", (e) => {
    const tr = e.button === 0 && e.target.closest && e.target.closest(".flow-table tbody tr");
    const f = tr && flowOf(tr);
    rowPress = f ? { id: f.id, at: Date.now(), x: e.clientX, y: e.clientY } : null;
  }, true);
  window.addEventListener("click", (e) => {
    const press = rowPress; rowPress = null;
    if (!press || e.button !== 0 || Date.now() - press.at > 2000 || Math.hypot(e.clientX - press.x, e.clientY - press.y) > 5) return;   // a drag is not a click
    if (e.target.closest && e.target.closest(".flow-table tbody tr")) return;          // delivered to a row: mitmweb handles it
    if (!e.target.closest || !e.target.closest(".flow-table")) return;
    for (const tr of document.querySelectorAll(".flow-table tbody tr")) {
      const f = flowOf(tr);
      if (f && f.id === press.id) { tr.click(); return; }
    }
  }, true);
  document.addEventListener("contextmenu", (e) => {
    const tr = e.target.closest && e.target.closest(".flow-table tbody tr");
    if (!tr || !flowOf(tr)) { closeCallMenu(); return; }
    e.preventDefault(); openCallMenu(e.clientX, e.clientY, tr);
  }, true);
  // The menu closes on USER intent only: a press outside it (a scrollbar drag starts with one), the wheel, touch-drag, a scroll key,
  // Escape, the window losing focus, or a window whose size really changed. A `scroll` event is never a reason: the call list scrolls
  // itself whenever a new call arrives while it follows the end (and when a row is selected / re-anchored), so closing on it made the
  // menu vanish under the pointer on a live list, at any scroll position.
  // A press that starts inside the menu must finish as a click: Safari and macOS WebKit do not focus a button on mousedown, so focus
  // drops from the menu's button to the page (a blur) in the middle of the press. Closing then hid the button before mouseup.
  let pressInMenu = false;
  const menuOpen = () => $("cmenu").classList.contains("open");
  const menuSettled = () => Date.now() - openCallMenu.at >= 700;     // inertia of the gesture that opened it must not close it
  const SCROLL_KEYS = ["PageUp", "PageDown", "Home", "End", "ArrowUp", "ArrowDown", " "];
  window.addEventListener("mousedown", (e) => {
    pressInMenu = e.composedPath().includes($("cmenu"));
    if (!pressInMenu) closeCallMenu();
  }, true);
  ["wheel", "touchmove"].forEach((t) => window.addEventListener(t, () => { if (menuOpen() && menuSettled()) closeCallMenu(); }, { capture: true, passive: true }));
  window.addEventListener("keydown", (e) => {
    if (menuOpen() && menuSettled() && SCROLL_KEYS.includes(e.key) && !e.composedPath().includes($("cmenu"))) closeCallMenu();
    else if (menuOpen() && ["PageUp", "PageDown", "Home", "End"].includes(e.key)) closeCallMenu();
  }, true);
  window.addEventListener("blur", (e) => { if (e.target === window && !pressInMenu && menuSettled()) closeCallMenu(); }, true);
  window.addEventListener("resize", (e) => {
    if (e.target !== window || pressInMenu) return;
    if (openCallMenu.size && (openCallMenu.size[0] !== window.innerWidth || openCallMenu.size[1] !== window.innerHeight)) closeCallMenu();
  }, true);
  ["mouseup", "dragend", "contextmenu"].forEach((t) => window.addEventListener(t, () => setTimeout(() => (pressInMenu = false), 0), true));
  $("cmenu").addEventListener("keydown", (e) => {
    const bs = [...$("cmenu").querySelectorAll("button:not(:disabled)")], i = bs.indexOf(root.activeElement);
    if (e.key === "Escape") { closeCallMenu(); e.preventDefault(); }
    else if (e.key === "ArrowDown") { bs[(i + 1) % bs.length].focus(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { bs[(i - 1 + bs.length) % bs.length].focus(); e.preventDefault(); }
  });

  // ───────────── Edit & Repeat (request editor in the sheet) ─────────────
  async function openRetry(id) {
    let p;
    try { p = await api("retry_get", { flow_id: id }); } catch (e) { return toast(e.message, true); }
    $("sheet").innerHTML = `
      <header class="retry"><b>${ico("retry", "sm")} Edit &amp; Repeat</b><span class="sub">sends a copy; the original stays in the list</span></header>
      <main>
        <div class="btns" style="margin-top:0"><select id="rm">${methodOpts(p.method)}</select>
          <input type="text" id="ru" class="grow" value="${esc(p.url)}"></div>
        <div class="seg"><button data-rsub="body" class="on">Body</button><button data-rsub="headers">Headers</button></div>
        <div id="rpb"><textarea id="rb" spellcheck="false" ${p.req_body_editable ? "" : "readonly"}>${esc(p.req_body)}</textarea></div>
        <div id="rph" style="display:none">${headersHTML(p.req_headers, "rhd")}</div>
      </main>
      <footer><button class="b" id="rcancel">Cancel</button><button class="b p" id="rsend">Send</button></footer>`;
    openSheet("pause", "#ru");     // R6B-04: the keyboard lands in the editor, not behind it
    wireHeaders($("sheet"));
    // R6-02: Esc is a shortcut, so it must not invoke Cancel after any loaded value changes.
    sheetDirty = () => $("rm").value !== p.method || $("ru").value !== p.url || $("rb").value !== p.req_body ||
      JSON.stringify(readHeaders("rhd")) !== JSON.stringify(p.req_headers);
    root.querySelectorAll("[data-rsub]").forEach((b) => (b.onclick = () => {
      $("rpb").style.display = b.dataset.rsub === "body" ? "" : "none"; $("rph").style.display = b.dataset.rsub === "headers" ? "" : "none";
      root.querySelectorAll("[data-rsub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    $("rcancel").onclick = () => closeSheet("pause");
    $("rsend").onclick = async () => {
      const edits = { method: $("rm").value, url: $("ru").value, headers: readHeaders("rhd") };
      if ($("rb").value !== p.req_body && !$("rb").readOnly) edits.body = $("rb").value;
      const r = await run("retry", { flow_id: id, edits }, "Sent — the new call is in the list (newest first)");
      if (r) closeSheet("pause");
    };
  }

  // ───────────── Copy as … (code generation, secrets masked by default) ─────────────
  const maskOn = () => { try { return localStorage.getItem("proxy-mask") !== "off"; } catch (e) { return true; } };
  const lastTarget = () => { try { return localStorage.getItem("proxy-copyas") || "curl"; } catch (e) { return "curl"; } };
  const remember = (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private window */ } };
  const copyAsHTML = (idp) => `
    <div class="btns"><span class="sub">As</span><select id="${idp}-t" aria-label="Copy as language">${(state.codegen_targets || []).map((t) =>
        `<option value="${esc(t.id)}" ${t.id === lastTarget() ? "selected" : ""}>${esc(t.name)}</option>`).join("")}</select>
      <button class="b p" id="${idp}-go">Copy</button>
      <label class="sub" style="display:flex;gap:4px;align-items:center"><input type="checkbox" id="${idp}-mask" ${maskOn() ? "checked" : ""}> Mask secrets</label></div>
    <div class="sub" id="${idp}-note">${maskOn() ? "Tokens, cookies, API keys and passwords become &lt;redacted&gt;." : "⚠ Tokens and cookies will be included — keep this out of tickets and chats."}</div>`;
  function wireCopyAs(idp, payload) {
    $(idp + "-mask").onchange = () => {
      remember("proxy-mask", $(idp + "-mask").checked ? "on" : "off");
      $(idp + "-note").innerHTML = $(idp + "-mask").checked ? "Tokens, cookies, API keys and passwords become &lt;redacted&gt;."
        : "⚠ Tokens and cookies will be included — keep this out of tickets and chats.";
    };
    $(idp + "-go").onclick = async () => {
      const target = $(idp + "-t").value, mask = $(idp + "-mask").checked;
      remember("proxy-copyas", target);
      const r = await run("codegen", { ...payload(), target, mask });
      if (!r) return;
      const label = $(idp + "-t").selectedOptions[0].textContent;
      try { await navigator.clipboard.writeText(r.text); toast("Copied as " + label + (mask ? " (secrets masked)" : " — contains secrets!")); }
      catch (e) { ask("Copy this text", { input: r.text, yes: "Done", no: "Close" }); }
    };
  }

  // ───────────── TLS: which hosts are decrypted ─────────────
  const tlsRe = (pattern) => {   // same wildcard rules as proxy_common.tls_host_regex, for hints only
    let p = String(pattern).trim().toLowerCase().replace(/\.+$/, ""), port = "";
    const m = p.match(/^([^:]*):(\d+)$/);
    if (m) { p = m[1]; port = m[2]; }
    const body = [...p].map((c) => (c === "*" ? ".*" : c === "?" ? "." : c.replace(/[.+^${}()|[\]\\\/-]/g, "\\$&"))).join("");
    return new RegExp("^" + body + (port ? ":" + port : "(?::\\d+)?") + "$", "i");
  };
  const tlsCovers = (list, host) => (list || []).filter((p) => { try { return tlsRe(p).test(host); } catch (e) { return false; } });
  function tlsVerdict(host) {
    const t = state.tls || { mode: "all", allow: [], ignore: [] };
    if (t.mode === "all") return { on: true, why: "every host is decrypted" };
    if (t.mode === "allow") { const hit = tlsCovers(t.allow, host); return hit.length ? { on: true, why: "on your decrypt list (" + hit.join(", ") + ")" } : { on: false, why: "it isn't on your decrypt list" }; }
    const hit = tlsCovers(t.ignore, host);
    return hit.length ? { on: false, why: "it's on your leave-alone list (" + hit.join(", ") + ")" } : { on: true, why: "decrypting everything except your leave-alone list" };
  }
  function tlsQuickHTML(host) {
    const v = tlsVerdict(host);
    return `<h4>HTTPS ${info((state.tls || {}).note || "Takes effect for new connections, no restart.")}</h4>
      <div class="sub">${ico(v.on ? "unlock" : "lock", "sm")} ${v.on ? `Decrypting <b>${esc(host)}</b> — you can read its calls` : `Not decrypting <b>${esc(host)}</b> — ${esc(v.why)}`}</div>
      <div class="btns">${v.on ? `<button class="b" id="tlsno">Stop decrypting this host</button>` : `<button class="b p" id="tlsdec">Decrypt this host</button>`}
        <span class="sub">${v.on ? "Rules, Map Local and breakpoints work on it." : "Its calls pass through unread — nothing to edit or mock."} New connections only.</span></div>`;
  }
  function wireTlsQuick(flowId, host) {
    const go = (decrypt) => run("tls_host", { flow_id: flowId, host, decrypt }, (x) => x.message);
    if ($("tlsdec")) $("tlsdec").onclick = () => go(true);
    if ($("tlsno")) $("tlsno").onclick = () => go(false);
  }
  function tlsSectionHTML() {
    const t = state.tls || { mode: "all", allow: [], ignore: [] };
    const modes = [["all", "Every host"], ["allow", "Only listed hosts"], ["ignore", "All except listed"]];
    const list = (which, title) => `
      <div class="sub" style="margin-top:8px"><b>${title}</b>${t.mode === which ? " · in use" : ""}</div>
      <div class="btns" style="margin-top:4px">${t[which].map((p) => `<span class="chip">${esc(p)} <span data-tlsrm="${which}" data-p="${esc(p)}" title="Remove">${ico("x", "sm")}</span></span>`).join("") || '<span class="sub">(none)</span>'}</div>
      <div class="btns"><input type="text" class="grow" data-tlsadd="${which}" placeholder="*.example.test or api.example.test:8443"><button class="b" data-tlsaddbtn="${which}">Add</button></div>`;
    return `<h4 id="tlssec">HTTPS decryption ${info("Which hosts are decrypted so you can read their calls. Same idea as an SSL Proxying list.")}</h4>
      <div class="seg" id="tlsmode">${modes.map(([id, label]) => `<button data-tm="${id}" class="${t.mode === id ? "on" : ""}">${label}</button>`).join("")}</div>
      ${t.error ? `<div class="errbox">${esc(t.error)}</div>` : ""}
      ${list("allow", "Hosts to decrypt")}${list("ignore", "Hosts to leave alone")}
      <div class="sub" style="margin-top:6px">Changes apply to new connections — no restart. ${info(t.note || "")}</div>`;
  }
  function wireTlsSection() {
    root.querySelectorAll("[data-tm]").forEach((b) => (b.onclick = () => run("tls_set", { mode: b.dataset.tm }, "Decrypting: " + ({ all: "every host", allow: "only listed hosts", ignore: "everything except listed hosts" }[b.dataset.tm] || b.dataset.tm))));
    root.querySelectorAll("[data-tlsrm]").forEach((x) => (x.onclick = () => run("tls_update", { list: x.dataset.tlsrm, action: "remove", pattern: x.dataset.p }, "Removed " + x.dataset.p)));
    const add = (which) => {
      const input = root.querySelector(`[data-tlsadd="${which}"]`), value = input.value.trim().toLowerCase();
      if (value) run("tls_update", { list: which, action: "add", pattern: value }, "Added " + value);
    };
    root.querySelectorAll("[data-tlsaddbtn]").forEach((b) => (b.onclick = () => add(b.dataset.tlsaddbtn)));
    root.querySelectorAll("[data-tlsadd]").forEach((i) => (i.onkeydown = (e) => { if (e.key === "Enter") add(i.dataset.tlsadd); }));
  }

  // Client certificates (mutual TLS): the certificate a server that asks for one gets, per host and project.
  // The Network tab redraws on every poll, so a half-filled form lives here, not only in the inputs (files and the
  // password stay in this page's memory; nothing is saved until Add).
  const ccDraft = { host: "", pass: "", file: null, key: null };
  function clientCertsHTML() {
    const rows = state.client_certs || [];
    const when = (t) => (t ? new Date(t * 1000).toLocaleDateString() : "?");
    return `<h4 id="ccsec">Client certificates ${info("For servers that ask the app for a certificate of its own (mutual TLS). The certificate added for a host is sent to it; same idea as Client Certificates in other proxies.")}</h4>
      ${rows.length ? rows.map((r) => `<div class="row" data-cc="${esc(r.host)}"><div class="n"><div><b>${esc(r.host)}</b>${r.expired ? ' <span class="tag err">expired</span>' : ""}</div>
          <div class="sub">${r.error ? "unreadable: " + esc(r.error) : esc(r.subject) + " · expires " + esc(when(r.not_after))}</div></div>
          <button class="b d" data-ccrm="${esc(r.host)}" aria-label="Remove the client certificate of ${esc(r.host)}">${ico("x", "sm")}</button></div>`).join("")
        : '<div class="sub">None. Add one when a server answers with a TLS error about a missing certificate.</div>'}
      <div class="grid" id="ccadd">
        <label>Host<input type="text" id="cchost" placeholder="api.example.test or *.example.test" autocomplete="off" value="${esc(ccDraft.host)}"></label>
        <label>Certificate (.p12, .pfx or .pem)<input type="file" id="ccfile" accept=".p12,.pfx,.pem,.crt,.cer">${ccDraft.file ? `<span class="sub">${esc(ccDraft.file.name)}</span>` : ""}</label>
        <label>Password (for a .p12 or an encrypted key)<input type="password" id="ccpass" autocomplete="new-password" value="${esc(ccDraft.pass)}"></label>
        <label>Private key, if it is in a separate .pem<input type="file" id="cckey" accept=".pem,.key">${ccDraft.key ? `<span class="sub">${esc(ccDraft.key.name)}</span>` : ""}</label>
      </div>
      <div class="btns"><button class="b p" id="ccaddbtn">Add client certificate</button>
        <span class="sub">Kept unencrypted in this project's private folder. Used from the next connection, no restart.</span></div>`;
  }
  function wireClientCerts() {
    const b64 = async (file) => { const bytes = new Uint8Array(await file.arrayBuffer()); let s = ""; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)); return btoa(s); };
    if (!$("ccaddbtn")) return;
    $("cchost").oninput = () => (ccDraft.host = $("cchost").value);
    $("ccpass").oninput = () => (ccDraft.pass = $("ccpass").value);
    $("ccfile").onchange = () => { ccDraft.file = $("ccfile").files[0] || null; };
    $("cckey").onchange = () => { ccDraft.key = $("cckey").files[0] || null; };
    $("ccaddbtn").onclick = async () => {
      const host = ccDraft.host.trim(), file = ccDraft.file, key = ccDraft.key;
      if (!host) return toast("Type the host the certificate is for", true);
      if (!file) return toast("Choose the certificate file first", true);
      const replacing = (state.client_certs || []).some((r) => r.host === host.toLowerCase());
      if (replacing && !await ask("Replace the client certificate of " + host + "?", { yes: "Replace" })) return;
      const args = { host, file_b64: await b64(file), password: ccDraft.pass };
      if (key) args.key_b64 = await b64(key);
      run("client_cert_add", args, (x) => {
        Object.assign(ccDraft, { host: "", pass: "", file: null, key: null });
        return "Client certificate for " + x.cert.host + ": " + x.cert.subject + (x.cert.expired ? " (EXPIRED)" : "");
      });
    };
    root.querySelectorAll("[data-ccrm]").forEach((x) => (x.onclick = async () => {
      if (await ask("Remove the client certificate of " + x.dataset.ccrm + "?", { yes: "Remove", danger: true }))
        run("client_cert_rm", { host: x.dataset.ccrm }, "Removed the client certificate of " + x.dataset.ccrm);
    }));
  }

  // ───────────── Compose (a new request from scratch) ─────────────
  const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
  // the call's own method is always an option: with PROPFIND, PURGE, … missing, the browser selected GET and an
  // untouched Continue / Repeat sent GET (QA-05)
  const methodOpts = (cur) => [...METHODS, ...(cur && !METHODS.includes(cur) ? [cur] : [])]
    .map((x) => `<option ${x === cur ? "selected" : ""}>${esc(x)}</option>`).join("");
  const newDraft = () => ({ name: "", method: "GET", url: "", query: [], headers: [], body_mode: "none", body: "", form: [], note: "" });
  let draft = newDraft(), composeSub = "params", varRows = null, focusNew = null;
  const encQ = (x) => encodeURIComponent(x).replace(/%7B/gi, "{").replace(/%7D/gi, "}");
  const decQ = (x) => { try { return decodeURIComponent(String(x).replace(/\+/g, " ")); } catch (e) { return x; } };
  const urlParts = (u) => {
    const h = u.indexOf("#"), plain = h >= 0 ? u.slice(0, h) : u, q = plain.indexOf("?");
    return q < 0 ? [plain, ""] : [plain.slice(0, q), plain.slice(q + 1)];
  };
  function urlFromRows() {          // table → URL (only ticked rows)
    const base = urlParts(draft.url)[0], on = draft.query.filter((r) => r[2] !== false && String(r[0]).length);
    draft.url = base + (on.length ? "?" + on.map((r) => encQ(r[0]) + "=" + encQ(r[1])).join("&") : "");
  }
  function rowsFromUrl() {          // URL → table (unticked rows are kept)
    const q = urlParts(draft.url)[1];
    const parsed = q ? q.split("&").filter(Boolean).map((p) => { const i = p.indexOf("="); return i < 0 ? [decQ(p), "", true] : [decQ(p.slice(0, i)), decQ(p.slice(i + 1)), true]; }) : [];
    draft.query = parsed.concat(draft.query.filter((r) => r[2] === false));
  }
  const specOf = () => ({ method: draft.method, url: draft.url, query: draft.query, headers: draft.headers,
    body_mode: draft.body_mode, body: draft.body, form: draft.form });
  const loadDraft = (spec, name) => {
    draft = { ...newDraft(), ...spec, name: name || "" };
    ["query", "headers", "form"].forEach((k) => (draft[k] = (draft[k] || []).map((r) => [r[0], r[1], r[2] !== false])));
    if (!(spec.query || []).length) rowsFromUrl();
    composeSub = "params";
  };
  const kvHTML = (key, rows, ph) => `<div data-kv="${key}">${rows.map((r, i) =>
      `<div class="krow" data-i="${i}"><input type="checkbox" title="send this row" ${r[2] === false ? "" : "checked"}><input type="text" value="${esc(r[0])}" placeholder="${ph[0]}"><input type="text" value="${esc(r[1])}" placeholder="${ph[1]}"><button class="b d" data-kdel aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")}</div>
    <button class="b" data-kadd="${key}">+ Add</button>`;
  const rowsOf = (key) => (key === "vars" ? varRows : draft[key]);
  function wireKV(scope) {
    scope.querySelectorAll("[data-kv]").forEach((box) => {
      const key = box.dataset.kv;
      box.querySelectorAll(".krow").forEach((row) => {
        const i = Number(row.dataset.i), [cb, k, v] = row.querySelectorAll("input");
        const sync = () => {
          rowsOf(key)[i] = [k.value, v.value, cb.checked];
          if (key === "query") { urlFromRows(); if ($("cu")) $("cu").value = draft.url; }
        };
        k.oninput = sync; v.oninput = sync; cb.onchange = sync;
        row.querySelector("[data-kdel]").onclick = () => { rowsOf(key).splice(i, 1); if (key === "query") urlFromRows(); render(); };
      });
    });
    scope.querySelectorAll("[data-kadd]").forEach((b) => (b.onclick = () => { rowsOf(b.dataset.kadd).push(["", "", true]); focusNew = b.dataset.kadd; render(); }));
  }
  function composeSection() {
    if (composeSub === "params") return `<div class="sub" style="margin-bottom:6px">Stays in sync with the URL. Untick a row to keep it without sending it.</div>${kvHTML("query", draft.query, ["name", "value"])}`;
    if (composeSub === "headers") return `${kvHTML("headers", draft.headers, ["Header", "Value"])}
      <div class="btns"><button class="b" id="ctok">Use latest token for this host</button></div>
      <div class="sub">Takes the newest <code>Authorization: Bearer</code> JWT seen for the URL's host, stores it as <code>{{token}}</code> and adds the header.</div>`;
    if (composeSub === "vars") {
      if (!varRows) varRows = Object.entries((state.composer || {}).vars || {}).map(([k, v]) => [k, v, true]);
      return `<div class="sub" style="margin-bottom:6px">Use <code>{{name}}</code> in the URL, headers, params and body. Stored per project in composer/vars.json.</div>
        ${kvHTML("vars", varRows, ["name", "value"])}<div class="btns"><button class="b p" id="cvsave">Save variables</button></div>`;
    }
    const modes = [["none", "None"], ["json", "JSON"], ["form", "Form"], ["raw", "Raw"]];
    const seg = `<div class="seg">${modes.map(([id, l]) => `<button data-bm="${id}" class="${draft.body_mode === id ? "on" : ""}">${l}</button>`).join("")}</div>`;
    if (draft.body_mode === "json") return `${seg}<textarea id="cb" spellcheck="false" style="min-height:150px;height:210px">${esc(draft.body)}</textarea>
      <div class="btns"><button class="b" id="cpretty">Pretty-print</button><span class="sub" id="cjs"></span></div>`;
    if (draft.body_mode === "raw") return `${seg}<textarea id="cb" spellcheck="false" style="min-height:150px;height:210px">${esc(draft.body)}</textarea>`;
    if (draft.body_mode === "form") return `${seg}${kvHTML("form", draft.form, ["field", "value"])}`;
    return `${seg}<p class="muted">No request body.</p>`;
  }
  function drawSection() {
    const area = $("carea"); area.innerHTML = composeSection(); wireKV(area);
    area.querySelectorAll("[data-bm]").forEach((b) => (b.onclick = () => { draft.body_mode = b.dataset.bm; drawSection(); }));
    if ($("cb")) $("cb").oninput = () => { draft.body = $("cb").value; if (draft.body_mode === "json") jsonCheck($("cb"), $("cjs")); };
    if ($("cpretty")) $("cpretty").onclick = () => {
      try { draft.body = JSON.stringify(JSON.parse($("cb").value), null, 2); $("cb").value = draft.body; jsonCheck($("cb"), $("cjs")); }
      catch (e) { $("cjs").textContent = "Not JSON: " + e.message; }
    };
    if ($("cvsave")) $("cvsave").onclick = () => {
      const vars = {}; varRows.forEach(([k, v]) => { if (String(k).trim()) vars[String(k).trim()] = v; });
      varRows = null; run("compose_vars", { vars }, "Variables saved");
    };
    if ($("ctok")) $("ctok").onclick = useLatestToken;
  }
  async function useLatestToken() {
    const vars = (state.composer || {}).vars || {};
    const base = urlParts(draft.url)[0].replace(/{{\s*([A-Za-z_][\w.-]*)\s*}}/g, (_, n) => vars[n] ?? "");
    let host = "";
    try { host = new URL(base).hostname; } catch (e) { return toast("Enter the URL first — the token is looked up by host", true); }
    const t = await run("compose_token", { host });
    if (!t) return;
    draft.headers = draft.headers.filter((h) => String(h[0]).toLowerCase() !== "authorization").concat([["Authorization", "Bearer {{token}}", true]]);
    varRows = null;
    await run("compose_vars", { vars: { ...vars, token: t.token } }, `Using the latest token for ${host} (sub ${t.sub || "?"}) as {{token}}`);
  }
  function renderCompose(m) {
    const names = (state.composer || {}).names || [];
    const count = { params: draft.query.filter((r) => r[2] !== false).length, headers: draft.headers.filter((r) => r[2] !== false).length };
    const subs = [["params", "Params"], ["headers", "Headers"], ["body", "Body"], ["vars", "Variables"]];
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><select id="cs" class="grow" aria-label="Saved requests"><option value="">Saved requests…</option>${names.map((n) => `<option ${n === draft.name ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>
        <button class="b" id="cload">Load</button><button class="b" id="cnew">New</button><button class="b" id="cpaste">Paste cURL…</button></div>
      <div class="btns" style="margin-top:4px"><button class="b sm" id="csave">Save</button><button class="b sm" id="csaveas">Save as…</button>
        <button class="b sm" id="cren" ${names.includes(draft.name) ? "" : "disabled"}>Rename</button>
        <button class="b sm d" id="cdel" ${names.includes(draft.name) ? "" : "disabled"}>Delete</button></div>
      ${draft.name ? `<div class="sub">Saved request: <b>${esc(draft.name)}</b> · CLI: <code>${esc((state.product || {}).cli || "proxy")} compose send ${esc(draft.name)}</code></div>` : ""}
      ${draft.note ? `<div class="sub">${esc(draft.note)}</div>` : ""}
      ${(state.composer || {}).error ? `<div class="errbox">${esc(state.composer.error)}</div>` : ""}
      <div class="btns"><input type="text" id="cm" list="cmlist" value="${esc(draft.method)}" style="width:84px" placeholder="METHOD" aria-label="Method">
        <datalist id="cmlist">${METHODS.map((x) => `<option value="${x}">`).join("")}</datalist>
        <input type="text" id="cu" class="grow" value="${esc(draft.url)}" placeholder="https://host/path?x=1  or  {{edge}}/path" aria-label="URL"><button class="b p" id="csend">Send</button></div>
      <div class="seg">${subs.map(([id, l]) => `<button data-cs="${id}" class="${composeSub === id ? "on" : ""}">${l}${count[id] ? " (" + count[id] + ")" : ""}</button>`).join("")}</div>
      <div id="carea"></div>
      <div class="sub" style="margin-top:6px">Runs through your rules and scripts · shows up in the list tagged COMPOSED.</div>
      <h4>Copy</h4>${copyAsHTML("cc")}`;
    drawSection();
    $("cm").oninput = () => (draft.method = $("cm").value.trim().toUpperCase());
    $("cu").oninput = () => { draft.url = $("cu").value; rowsFromUrl(); if (composeSub === "params") drawSection(); };
    root.querySelectorAll("[data-cs]").forEach((b) => (b.onclick = () => { composeSub = b.dataset.cs; if (composeSub !== "vars") varRows = null; render(); }));
    $("cnew").onclick = () => { draft = newDraft(); composeSub = "params"; render(); };
    $("cpaste").onclick = async () => {
      const command = await ask("Paste cURL command", { input: "", multiline: true, yes: "Import" }); if (!command) return;
      try { const r = await api("compose_from_curl", { command }); loadDraft(r.spec, ""); render(); if (r.ignored.length) toast("Ignored: " + r.ignored.join(", ")); else toast("cURL loaded into Compose"); }
      catch (e) { toast(e.message, true); }
    };
    $("cload").onclick = async () => {
      const name = $("cs").value; if (!name) return toast("Pick a saved request first", true);
      const r = await run("compose_load", { name }); if (!r) return;
      loadDraft(r.spec, name); render();
    };
    const saveAs = async (name) => {
      if (!name) return;
      const exists = names.includes(name), current = name === draft.name;
      if (exists && !current && !await ask("A saved request named '" + name + "' already exists. Replace it?", { yes: "Replace", danger: true })) return;
      const r = await run("compose_save", { name, spec: specOf(), overwrite: exists }, "Saved " + name);
      if (r) { draft.name = name; drawerTypingDirty = false; render(); }
    };
    const askName = (start) => ask("Save as\n\nLetters, digits and . _ - only.", { input: start, yes: "Save" });
    $("csave").onclick = async () => (draft.name ? saveAs(draft.name) : saveAs(await askName("")));
    $("csaveas").onclick = async () => saveAs(await askName(draft.name || ""));
    $("cren").onclick = async () => {
      const next = await ask("New name", { input: draft.name, yes: "Rename" }); if (!next || next === draft.name) return;
      const r = await run("compose_rename", { old: draft.name, new: next }, "Renamed to " + next);
      if (r) { draft.name = next; render(); }
    };
    $("cdel").onclick = async () => {
      if (!await ask("Delete saved request '" + draft.name + "'?", { yes: "Delete", danger: true })) return;
      const r = await run("compose_delete", { name: draft.name }, "Deleted " + draft.name);
      if (r) { draft.name = ""; render(); }
    };
    $("csend").onclick = () => run("compose_send", { spec: specOf() }, (x) => "Sent " + x.method + " " + x.url + " — it is in the list, tagged COMPOSED");
    wireCopyAs("cc", () => ({ spec: specOf() }));
    if (focusNew) {
      const rows = m.querySelectorAll(`[data-kv="${focusNew}"] .krow`);
      if (rows.length) rows[rows.length - 1].querySelectorAll("input")[1].focus();
      focusNew = null;
    }
  }

  // ───────────── All rules ─────────────
  const ACTION_NAME = { map_local: "Map Local", map_remote: "Map Remote", respond: "Fixed reply", status: "Force status", delay: "Delay", json_patch: "Edit JSON", set_header: "Header", block: "Block", drop: "Block" };
  function describe(r) {
    const a = r.action;
    if (a === "map_local") { const v = (r.variants || []).find((x) => x.name === r.active); return r.base ? "Map Local folder → " + tilde(r.file) : "answers from a saved response" + (v ? " · " + v.name + " (" + (v.status || r.status || 200) + ")" : r.status ? " (" + r.status + ")" : ""); }
    if (a === "respond") return "answers with " + r.status;
    if (a === "status") return "changes the status to " + r.status;
    if (a === "delay") return "waits " + r.ms + " ms first";
    if (a === "json_patch") return "changes " + Object.keys(r.set || {}).join(", ") + " in the JSON reply";
    if (a === "set_header") return (r.value == null ? "removes the " : "sets the ") + r.header + " header";
    if (a === "map_remote") return "sends it to " + r.with;
    if (a === "block" || a === "drop") return "blocks the call (the app gets a network error)";
    return a;
  }
  // Rule hit counts (from the proxy) — so an ON rule that never fires is visible, not silent
  let ruleTest = null;                       // {flowId, result} of the last "Test against the selected call"
  const ago = (t) => { const d = Math.max(0, Date.now() / 1000 - t); return d < 5 ? "just now" : d < 60 ? Math.round(d) + "s ago" : d < 3600 ? Math.round(d / 60) + " min ago" : Math.round(d / 3600) + " h ago"; };
  const NEVER_MATCHED_AFTER = 10;            // calls seen since the rule was switched on before it is flagged
  function hitHTML(r) {
    const h = r.enabled !== false && ((state.rule_hits || {}).rules || {})[r.name];
    if (!h) return "";
    if (h.count > 0) return `<div class="sub rule-hits">${ico("check", "sm")}matched ${h.count} call${h.count === 1 ? "" : "s"} · last ${ago(h.last)}${h.noop ? ` · ${h.noop} matched without changing anything` : ""}</div>`;
    if (h.noop > 0) return `<div class="sub rule-hits warn" role="note">${ico("warn", "sm")}matched ${h.noop} call${h.noop === 1 ? "" : "s"} but changed nothing — ${esc(h.noop_reason || "")}</div>`;
    if (h.calls_since >= NEVER_MATCHED_AFTER) return `<div class="sub rule-hits warn" role="note">${ico("warn", "sm")}ON, but none of the ${h.calls_since} calls since it was switched on matched it. Select a call it should change, then <b>Test against the selected call</b>.</div>`;
    return `<div class="sub rule-hits">no matching call yet</div>`;
  }
  function ruleTestHTML() {
    const id = selectedFlow();
    const btn = `<div class="btns" style="margin-top:0"><button class="b" id="ruletest" ${id ? "" : "disabled"} title="${id ? "Explain what each rule would do to the selected call" : "Select a call in the list first"}">Test against the selected call</button>${id ? "" : '<span class="sub">select a call in the list first</span>'}</div>`;
    if (!ruleTest || ruleTest.flowId !== id) return btn;
    const t = ruleTest.result;
    return btn + `<div class="ruletest" aria-live="polite"><div class="sub"><b>${esc(t.method)}</b> ${esc(t.url)}${t.sent_to ? " · sent to " + esc(t.sent_to) : ""}</div>` +
      (t.rules.length ? t.rules.map((x) => `<div class="sub ${x.fires ? "fires" : x.inert ? "warn" : ""}">${x.fires ? ico("check", "sm") + "<b>" + esc(x.name) + "</b> fires: " + esc(x.effect) : (x.inert ? ico("warn", "sm") : "· ") + "<b>" + esc(x.name) + "</b> does not fire: " + esc(x.reason)}</div>`).join("") : '<div class="sub">No rules.</div>') + "</div>";
  }
  function wireRuleTest(m) {
    const b = m.querySelector("#ruletest");
    if (b) b.onclick = async () => {
      const id = selectedFlow();
      try { ruleTest = { flowId: id, result: await api("rule_test", { flow_id: id }) }; render(); }
      catch (e) { toast(e.message, true); }
    };
  }
  function renderRules(m) {
    const skipped = state.skipped_rules || [], outside = state.rules_outside || [];
    const bps = state.breakpoints || [], scripts = state.scripts || [], status = state.script_status || {};
    const net = state.throttle !== "off" || Number(state.loss || 0) > 0;
    const prof = (state.profiles.find((p) => p.id === state.throttle) || {}).name || state.throttle;
    const section = (title, n) => `<h4>${title} (${n})</h4>`;
    m.innerHTML = (state.rules_error ? `<div class="banner bad"><b>${ico("warn", "sm")} rules.json has an error:</b> ${esc(state.rules_error)}</div>` : "") + (skipped.length ? `<div class="banner bad" style="display:block"><b>${ico("warn", "sm")} ${skipped.length} rule(s) skipped</b>${skipped.map((r) => `<div class="sub">${esc(r.name)} — ${esc(r.error)}</div>`).join("")}</div>` : "") +
      `<h4>New rule</h4><div class="btns" style="margin-top:0"><select id="rtype" aria-label="Rule type">${RULE_TYPES.map(([id, label]) => `<option value="${id}">${esc(label)}</option>`).join("")}</select>
        <button class="b p" id="rnew">New</button>${info("Every kind of rule lives here: replies, status, JSON edits, delays, headers, Map Remote, blocks, Map Local, breakpoints, scripts and network conditions.")}</div>` +
      `<div class="btns"><button class="b" id="rfolderopen">Add Map Local folder</button><button class="b" id="rimport">Import from Proxyman…</button></div>
       <form id="rfolderform" style="display:none"><div class="btns"><input id="rfoldername" type="text" placeholder="Rule name" aria-label="Rule name" required>
       <input id="rfolderbase" type="url" placeholder="https://api.example.com/v1/" aria-label="URL prefix" required>
       <input id="rfolderpath" type="text" placeholder="Folder path" aria-label="Folder path" required>
       <button class="b p" type="submit">Add folder</button></div></form>` +
      ruleTestHTML() + section("Rules", state.rules.length) + (state.rules.length ? state.rules.map((r, i) => `
      <div class="row">${sw(`data-i="${i}"`, r.enabled !== false)}
        <div class="n"><div><b>${esc(r.name)}</b><span class="tag">${esc(ACTION_NAME[r.action] || r.action)}</span>${outside.includes(r.name) ? `<span class="tag" title="Reads a file outside the project. Allowed only for files you trusted on this machine (${esc(state.product.cli)} rules trusted-files). Edit it in your own editor.">external file</span>` : ""}</div>
          <div class="sub">${esc(r.method ? r.method + " " : "")}${esc(pretty(r))} — ${esc(describe(r))}</div>
          ${(state.rule_warnings || {})[r.name] ? `<div class="sub rule-hits warn" role="alert">${ico("warn", "sm")} ${esc(state.rule_warnings[r.name])}</div>` : ""}${hitHTML(r)}</div>
        ${outside.includes(r.name) || (r.action === "map_local" && r.base) ? "" : `<button class="b" data-edit="${i}">Edit</button>`}
        <button class="b d" data-del="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")
        : emptyState("rules", "No rules yet", "Pick a type above and click <b>New</b>, or select a call and use <b>This call</b> — Map Local, a forced status, a block or a delay all become rules here.")) +
      section("Breakpoints", bps.length) + (bps.length ? bps.map((b, i) => `
      <div class="row">${sw(`data-rbi="${i}"`, b.enabled !== false)}
        <div class="n"><div><b>${esc(b.name)}</b><span class="tag">Breakpoint</span></div>
          <div class="sub">${esc(b.method ? b.method + " " : "")}${esc(pretty(b))} — pauses at ${esc([b.request && "request", b.response && "response"].filter(Boolean).join(" and "))}</div></div>
        <button class="b" data-rbedit="${i}">Edit</button><button class="b d" data-rbdel="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") : '<p class="sub">None.</p>') +
      section("Scripts", scripts.length) + (scripts.length ? scripts.map((x, i) => `
      <div class="row">${sw(`data-rsi="${i}"`, x.enabled !== false)}
        <div class="n"><div><b>${esc(x.name)}</b><span class="tag">Script · ${esc(x.lang)}</span></div>
          <div class="sub">${esc(x.method || "ANY")} · ${esc(x.match || ".")}${x.exists ? "" : " · FILE MISSING"}${status.errors && status.errors[x.file] ? ` · <span class="tag err">ERROR</span> ${esc((status.errors[x.file].message || status.errors[x.file]))}` : ""}</div></div>
        <button class="b" data-rsedit="${i}">Edit</button><button class="b d" data-rsdel="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") : '<p class="sub">None.</p>') +
      `<h4>Network</h4>` + (net ? `
      <div class="row"><div class="n"><div><b>${esc(prof)}</b><span class="tag">Network throttle</span></div>
        <div class="sub">${state.throttle_match ? "URLs matching " + esc(state.throttle_match) : "every call"}${Number(state.loss || 0) ? " · " + esc(state.loss) + "% extra loss" : ""}</div></div>
        <button class="b" id="rnetedit">Edit</button><button class="b d" id="rnetoff" title="Switch off" aria-label="Switch off">${ico("x", "sm")}</button></div>` : '<p class="sub">No throttle.</p>') +
      (state.no_cache ? `<div class="row">${sw('id="rnocache"', true)}<div class="n"><div><b>No caching</b><span class="tag">Network</span></div><div class="sub">strips conditional request headers, forces fresh responses</div></div></div>` : "") +
      `<p class="sub">Saved in ${esc(tilde(state.rules_file))} — also editable with <code>${esc(state.product.cli)} rules</code>.</p>`;
    wireRuleRows(m);
    wireRuleTest(m);
    $("rnew").onclick = () => openRuleForm($("rtype").value);
    $("rfolderopen").onclick = () => { $("rfolderform").style.display = "block"; $("rfoldername").focus(); };
    $("rfolderform").onsubmit = async (event) => {
      event.preventDefault();
      await run("maplocal_folder_add", { name: $("rfoldername").value.trim(), base: $("rfolderbase").value.trim(), folder: $("rfolderpath").value.trim() }, "Map Local folder added");
    };
    $("rimport").onclick = () => run("proxyman_import", {}, (r) => r.summary);
    m.querySelectorAll("input[data-rbi]").forEach((c) => (c.onchange = async () => {
      const done = await run("bp_update", { name: bps[c.dataset.rbi].name, enabled: c.checked }, c.checked ? null : "Breakpoint off");
      if (done && c.checked) breakpointOn();
    }));
    m.querySelectorAll("[data-rbedit]").forEach((b) => (b.onclick = () => openRuleForm("bp", bps[b.dataset.rbedit])));
    m.querySelectorAll("[data-rbdel]").forEach((b) => (b.onclick = async () => { const n = bps[b.dataset.rbdel].name; if (await ask("Delete breakpoint '" + n + "'?", { yes: "Delete", danger: true })) run("bp_delete", { name: n }, "Breakpoint removed"); }));
    m.querySelectorAll("input[data-rsi]").forEach((c) => (c.onchange = () => run("script_toggle", { file: scripts[c.dataset.rsi].file, enabled: c.checked }, c.checked ? "Script on" : "Script off")));
    m.querySelectorAll("[data-rsedit]").forEach((b) => (b.onclick = () => openScript(scripts[b.dataset.rsedit].file)));
    m.querySelectorAll("[data-rsdel]").forEach((b) => (b.onclick = async () => { const x = scripts[b.dataset.rsdel]; if (await ask("Delete script '" + x.name + "' and its source file?", { yes: "Delete", danger: true })) run("script_delete", { file: x.file }, "Deleted " + x.file); }));
    if ($("rnetedit")) { $("rnetedit").onclick = () => openRuleForm("throttle"); $("rnetoff").onclick = () => run("profile", { id: "off" }, "Network throttle off"); }
    if ($("rnocache")) $("rnocache").onchange = () => run("nocache", { on: $("rnocache").checked }, "No caching " + ($("rnocache").checked ? "on" : "off"));
  }
  // ───────────── Rules tab: the New / Edit form for every type ─────────────
  const RULE_TYPES = [["respond", "Fixed reply"], ["status", "Force status"], ["json_patch", "Edit JSON"], ["delay", "Delay"], ["set_header", "Header"],
    ["map_remote", "Map Remote"], ["block", "Block"], ["map_local", "Map Local"], ["bp", "Breakpoint"], ["script", "Script"], ["throttle", "Network throttle"], ["nocache", "No caching"]];
  const RULE_KEYS = { respond: ["status", "body"], status: ["status"], json_patch: ["set"], delay: ["ms"], set_header: ["side", "header", "value"], map_remote: ["replace", "with"], block: [] };
  function openRuleForm(type, item) {
    if (type === "map_local") { tab = "map"; editing = null; render(); return; }          // Map Local keeps its own tab and editor
    noteReturn("editor");
    editing = { kind: "rule", type, item: item || null };
    if (item && item.action && item.action !== "map_local") editing.type = item.action;
    render();
  }
  function renderRuleForm(m) {
    const e = editing, it = e.item, t = e.type, v = it || {};
    const fld = (id, label, inner) => `<div class="btns"><label class="sub" for="rf-${id}" style="min-width:90px">${label}</label>${inner}</div>`;
    const txt = (id, val, ph = "", extra = "") => `<input type="text" id="rf-${id}" class="grow" value="${esc(val ?? "")}" placeholder="${esc(ph)}" ${extra}>`;
    const method = (val) => `<select id="rf-method"><option value="">ANY</option>${METHODS.map((x) => `<option ${x === (val || "").toUpperCase() ? "selected" : ""}>${x}</option>`).join("")}</select>`;
    const label = (RULE_TYPES.find((x) => x[0] === t) || [])[1] || t;
    const isRule = t in RULE_KEYS;
    let body = "";
    if (isRule || t === "bp" || t === "script") {
      if (!it && t !== "bp") body += fld("name", "Name", txt("name", "", "letters, digits . _ -"));
      if (it && isRule) body += `<div class="sub"><b>${esc(it.name)}</b></div>`;
      if (t !== "script" || !it) body += fld("match", "URL pattern", txt("match", v.match, "regex, e.g. /api/login — . = every call"));
      if (t !== "script" || !it) body += fld("method", "Method", method(v.method));
    }
    if (t === "respond") {
      body += fld("status", "Status", `<input type="number" id="rf-status" value="${esc(v.status ?? 200)}" style="width:80px">`);
      body += v.body_file ? `<div class="sub">The body is read from ${esc(tilde(v.body_file))} (change it with ${esc(state.product.cli)} rules edit).</div>`
        : fld("body", "Body", `<textarea id="rf-body" class="grow" rows="5" spellcheck="false" placeholder='{"ok": true}'>${esc(typeof v.body === "object" && v.body !== null ? JSON.stringify(v.body, null, 2) : v.body ?? "")}</textarea>`);
    } else if (t === "status") {
      body += fld("status", "Status", `<input type="number" id="rf-status" value="${esc(v.status ?? 503)}" style="width:80px">`);
    } else if (t === "json_patch") {
      body += fld("set", "Set fields", `<textarea id="rf-set" class="grow" rows="4" spellcheck="false" placeholder='{"user.name": "QA", "items[0].price": 1}'>${esc(it ? JSON.stringify(v.set, null, 2) : "")}</textarea>`);
    } else if (t === "delay") {
      body += fld("ms", "Delay (ms)", `<input type="number" id="rf-ms" value="${esc(v.ms ?? 1000)}" style="width:100px">`);
    } else if (t === "set_header") {
      body += fld("side", "Change", `<select id="rf-side"><option value="request" ${v.side !== "response" ? "selected" : ""}>the request</option><option value="response" ${v.side === "response" ? "selected" : ""}>the response</option></select>`);
      body += fld("header", "Header", txt("header", v.header, "X-QA"));
      body += fld("value", "Value", txt("value", v.value, "", v.value == null && it ? "disabled" : ""));
      body += fld("remove", "Remove it", `<input type="checkbox" id="rf-remove" ${it && v.value == null ? "checked" : ""} aria-label="Remove the header">`);
    } else if (t === "map_remote") {
      body += fld("replace", "Replace (URL regex)", txt("replace", v.replace, "https://api.example.com/v1"));
      body += fld("with", "With", txt("with", v.with, "https://staging.example.com/v1"));
    } else if (t === "bp") {
      body += fld("pause", "Pause at", `<label><input type="checkbox" id="rf-req" ${!it || v.request ? "checked" : ""}> Request</label> <label><input type="checkbox" id="rf-resp" ${!it || v.response ? "checked" : ""}> Response</label>`);
    } else if (t === "script") {
      if (!it) {
        body += fld("lang", "Language", `<select id="rf-lang"><option value="js">JavaScript</option><option value="py">Python</option></select>`);
        body += fld("template", "Template", `<select id="rf-template"><option value="header">Request header</option><option value="json">JSON response field</option><option value="mock">Local mock</option><option value="latency">Endpoint latency</option><option value="token">Log token refresh</option></select>`);
        body += fld("smethod", "Method", method(""));
      }
    } else if (t === "throttle") {
      body += fld("profile", "Profile", `<select id="rf-profile">${state.profiles.filter((p) => p.id !== "manual" && p.id !== "off").map((p) => `<option value="${p.id}" ${p.id === state.throttle ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select>`);
      body += fld("tmatch", "Only URLs like", txt("tmatch", state.throttle_match, "regex — empty = every call"));
      body += `<div class="sub">Your own numbers (manual profile) are on the Network tab. There is one throttle per project: saving replaces the current one.</div>`;
    } else if (t === "nocache") {
      body += `<div class="sub">Strips If-None-Match / If-Modified-Since from requests and marks responses no-store, so the app always gets fresh content.</div>`;
    }
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><button class="b" id="back">${ico("back", "sm")}Back</button>
        <b style="flex:1;align-self:center">${it ? "Edit" : "New"} — ${esc(label)}</b></div>
      ${body}
      <div class="btns"><button class="b p" id="rsave">${it ? "Save" : "Add"}</button></div>
      <div class="sub" id="rerr" role="alert" style="color:var(--rv-warn)"></div>`;
    const val = (id) => ($("rf-" + id) || {}).value || "";
    const leave = () => { editing = null; drawerTypingDirty = false; render().then(() => giveBack("editor")); };
    $("back").onclick = leave;
    if ($("rf-remove")) $("rf-remove").onchange = () => { $("rf-value").disabled = $("rf-remove").checked; };
    $("rsave").onclick = async () => {
      let op, args, ok;
      try {
        if (isRule) {
          const rule = { match: val("match").trim(), method: val("method") };
          if (t === "respond") {
            rule.status = Number(val("status"));
            if (!v.body_file) { const b = val("body"); if (/^\s*[\[{]/.test(b)) { try { rule.body = JSON.parse(b); } catch (x) { rule.body = b; } } else rule.body = b; }
          } else if (t === "status") rule.status = Number(val("status"));
          else if (t === "json_patch") {
            let o; try { o = JSON.parse(val("set")); } catch (x) { throw new Error("Set fields must be a JSON object, e.g. {\"user.name\": \"QA\"}"); }
            if (!o || typeof o !== "object" || Array.isArray(o) || !Object.keys(o).length) throw new Error("Set fields must be a JSON object with at least one path");
            rule.set = o;
          } else if (t === "delay") rule.ms = Number(val("ms"));
          else if (t === "set_header") { rule.side = val("side"); rule.header = val("header").trim(); rule.value = $("rf-remove").checked ? null : val("value"); }
          else if (t === "map_remote") { rule.replace = val("replace"); rule.with = val("with"); }
          if (it) { op = "update"; args = { name: it.name, rule, keys: ["match", "method", ...RULE_KEYS[t]] }; ok = "Rule '" + it.name + "' saved"; }
          else {
            const name = val("name").trim();
            op = "add"; args = { rule: { name, enabled: true, action: t, ...rule } }; ok = "Rule '" + name + "' is on";
          }
        } else if (t === "bp") {
          const request = $("rf-req").checked, response = $("rf-resp").checked;
          if (!request && !response) throw new Error("Pick Request, Response or both");
          const match = val("match").trim();
          if (!match) throw new Error("URL pattern is required");
          if (it) { op = "bp_update"; args = { name: it.name, match, method: val("method"), request, response }; ok = "Breakpoint saved"; }
          else { op = "bp_add"; args = { match, method: val("method"), request, response }; ok = null; }
        } else if (t === "script") {
          if (it) return openScript(it.file);
          op = "script_new"; args = { name: val("name").trim(), lang: val("lang"), template: val("template"), match: val("match").trim() || ".", method: val("smethod") }; ok = (x) => "Created " + x.file;
        } else if (t === "throttle") {
          op = "profile"; args = { id: val("profile"), match: val("tmatch") }; ok = "Network: throttle on";
        } else if (t === "nocache") { op = "nocache"; args = { on: true }; ok = "No caching on"; }
      } catch (x) { $("rerr").textContent = x.message; return; }
      try {
        const r = await api(op, args);
        if (r.state) state = r.state;
        if (ok) toast(typeof ok === "function" ? ok(r) : ok);
        if (t === "bp" && !it) breakpointOn();
        if (t === "script" && !it) { return openScript(r.file); }
        leave();
      } catch (x) { $("rerr").textContent = x.message; toast(x.message, true); }
    };
    const first = m.querySelector("input[type=text], textarea, select");
    if (first) first.focus();
  }
  function wireRuleRows(m) {
    m.querySelectorAll("input[data-i]").forEach((c) => (c.onchange = () =>
      run("toggle", { name: state.rules[c.dataset.i].name, enabled: c.checked }, c.checked ? "Rule on" : "Rule off")));
    m.querySelectorAll("[data-del]").forEach((b) => (b.onclick = async () => {
      const n = state.rules[b.dataset.del].name;
      if (await ask("Delete rule '" + n + "'?", { yes: "Delete", danger: true })) run("delete", { name: n }, (r) => r.message || "Deleted " + n);
    }));
    m.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => {
      const r = state.rules[b.dataset.edit];
      if (r.action === "map_local") openEditor(r.name); else openRuleForm(r.action, r);
    }));
  }

  // ───────────── Map Local editor (Body / Headers, like FRTMProxy) ─────────────
  const mockToast = (x) => x.existing ? "Opened existing Map Local '" + x.name + "' (on)"
    : "Map Local '" + x.name + "': edit the response, then Save to turn it on";
  async function openEditor(name, from) {
    noteReturn("editor", from);           // R6B-06: Back / Esc give focus back to the button that opened it
    try { const r = await api("mockfile_get", { name }); editing = { name, sub: "body", focus: true, ...r,
      original: { content: r.content, status: String(r.status), headers: JSON.stringify(r.headers) } }; render(); }  // R3A-10
    catch (e) { returnTo.editor = null; toast(e.message, true); }
  }
  const mockEditorChanged = (e) => {      // read from the live fields; true when they are gone (cannot tell: keep the draft)
    const ta = $("body"), st = $("st");
    return !ta || !st || ta.value !== e.original.content || st.value !== e.original.status || JSON.stringify(readHeaders("hd")) !== e.original.headers;
  };
  const previewKB = (s) => Math.max(1, Math.round(s.length / 1024));   // a binary body above the server's preview size arrives clipped
  const BIG_BODY = 1024 * 1024;         // above this, JSON is checked after typing pauses, not on every key (R6B-09)
  function renderEditor(m) {
    const e = editing;
    // R6B-09: the body goes in through .value, never as escaped HTML: a 20 MB body through innerHTML froze the tab
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><button class="b" id="back">${ico("back", "sm")}Back</button>
        <b style="flex:1;align-self:center;overflow:hidden;text-overflow:ellipsis">${esc(e.name)}</b>
        status <input type="number" id="st" value="${esc(e.status)}" style="width:70px" aria-label="Status code"></div>
      <div class="sub" style="margin-top:6px">${esc(e.method || "ANY")} ${esc(pretty({ match: e.match }))}</div>
      <div class="btns" id="variants"><label>Variant <select id="variant">${(e.variants.length ? e.variants : ["Default"]).map((n) => `<option value="${esc(n)}" ${n === (e.active || "Default") ? "selected" : ""}>${esc(n)}</option>`).join("")}</select></label>
        <button class="b" id="vadd">Add</button><button class="b" id="vrename">Rename</button><button class="b d" id="vrm">Delete</button></div>
      <div class="seg"><button data-sub="body" class="${e.sub === "body" ? "on" : ""}">Body</button><button data-sub="headers" class="${e.sub === "headers" ? "on" : ""}">Headers</button></div>
      <div id="pbody" style="${e.sub === "body" ? "" : "display:none"}">
        ${e.clipped ? `<div class="sub" id="binclip" style="margin-bottom:4px">Binary file (${e.size} bytes): a read-only preview of the first ${previewKB(e.content)} KB. Save keeps the file's bytes; status and headers can still be changed.</div>`
          : e.binary ? `<div class="sub" style="margin-bottom:4px">Binary file (${e.size} bytes), shown as text. Save keeps its bytes unless you edit the text here.</div>` : ""}
        <textarea id="body" spellcheck="false" aria-label="Response body" ${e.editable && !e.clipped ? "" : "readonly"}></textarea>
        <div class="btns"><button class="b" id="fmt" ${e.clipped ? "disabled" : ""}>Format JSON</button><span class="sub" id="jsonok"></span></div></div>
      <div id="phdr" style="${e.sub === "headers" ? "" : "display:none"}">${headersHTML(e.headers, "hd")}
        <div class="sub">Content-Type defaults to the file type when not set.</div></div>
      <div class="btns"><button class="b p" id="save" ${e.editable ? "" : "disabled"}>Save</button><span class="sub" id="dirty"></span></div>
      <div class="errbox" id="discard" role="alert" style="display:none">Discard unsaved Map Local edits?
        <div class="btns"><button class="b" id="keep">Keep editing</button><button class="b" id="discard-yes">Discard and Back</button></div></div>
      <div class="sub">${esc(tilde(e.file))} — the next matching call gets this.</div>`;
    const ta = $("body");
    ta.value = e.content;
    // R3A-10: input and tab switches mutate editing; only Save updates e.original (read live: Save keeps this DOM)
    const check = () => { clearTimeout(editorCheckT); if (ta.value.length < BIG_BODY) jsonCheck(ta, $("jsonok")); else editorCheckT = setTimeout(() => { if (ta.isConnected && $("jsonok")) jsonCheck(ta, $("jsonok")); }, 400); };
    check();
    ta.oninput = () => { check(); editing.content = ta.value; $("dirty").textContent = "Modified"; };
    const changeVariant = async (action, variant, newName) => {
      if (mockEditorChanged(e)) { toast("Save or discard these edits before changing variants", true); $("variant").value = e.active || "Default"; return; }
      try { await api("mockvariant", { name: e.name, action, variant, new_name: newName }); await openEditor(e.name); }
      catch (x) { $("variant").value = e.active || "Default"; toast(x.message, true); }
    };
    $("variant").onchange = () => changeVariant("use", $("variant").value);
    $("vadd").onclick = async () => { const name = await ask("Name the new variant (a copy of the current response)", { input: "" }); if (name) changeVariant("add", name); };
    $("vrename").onclick = async () => { const old = e.active || "Default"; const name = await ask("Rename variant '" + old + "'", { input: old }); if (name && name !== old) changeVariant("rename", old, name); };
    $("vrm").onclick = async () => { const old = e.active || "Default"; if (await ask("Delete variant '" + old + "'? Its saved file is kept.", { yes: "Delete", danger: true })) changeVariant("rm", old); };
    root.querySelectorAll("[data-sub]").forEach((b) => (b.onclick = () => {   // R6B-09: a tab switch only shows / hides
      e.sub = b.dataset.sub; $("pbody").style.display = e.sub === "body" ? "" : "none"; $("phdr").style.display = e.sub === "headers" ? "" : "none";
      root.querySelectorAll("[data-sub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    wireHeaders(m);
    const leave = () => { clearTimeout(editorCheckT); editing = null; drawerTypingDirty = false; render().then(() => giveBack("editor")); }; // R6-05
    $("back").onclick = async () => {
      // R3A-10: Back may delete a draft or discard an edit; require an in-panel choice only after a change.
      const changed = mockEditorChanged(e);
      if (changed) { $("discard").style.display = ""; $("keep").focus(); return; }
      // a new Map Local that was never saved is discarded, so it never answers a call (r1 B-03)
      if (e.draft) { try { const r = await api("delete", { name: e.name }); toast(r.message || "Map Local '" + e.name + "' discarded (not saved)"); } catch (x) { toast(x.message, true); return; } }
      leave();
    };
    $("keep").onclick = () => { $("discard").style.display = "none"; $("back").focus(); };
    $("discard-yes").onclick = async () => {
      if (e.draft) { try { const r = await api("delete", { name: e.name }); if (r.message) toast(r.message); } catch (x) { toast(x.message, true); return; } }
      leave();
    };
    $("fmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2) + "\n"; ta.oninput(); } catch (x) { toast("Not JSON — cannot format", true); } };
    let saving = false;     // not save.disabled: disabling the focused button would drop keyboard focus to <body>
    $("save").onclick = async () => {
      if (saving) return;
      clearTimeout(editorCheckT);
      const headers = readHeaders("hd"), content = ta.value, status = $("st").value;
      // F-02: warn about invalid JSON only for a JSON mock — an HTML / XML / text mock is saved as it is
      const ctype = ((headers.find((h) => String(h[0]).toLowerCase() === "content-type") || [])[1] || "").toLowerCase();
      const isJson = ctype ? /json/.test(ctype) : /\.json$/i.test(e.file || "");
      if (isJson && !jsonCheck(ta, $("jsonok")) && !await ask("This is not valid JSON. Save anyway?", { yes: "Save anyway" })) return;
      // R6B-09: an unchanged body is not sent again (the server keeps the file's bytes), and Save does not redraw
      // the editor: re-sending and re-rendering 20 MB blocked the page for ~8 s per Save
      const body = { name: e.name, status, headers };
      if (content !== e.original.content) body.content = content;
      saving = true; $("dirty").textContent = "Saving…";
      try {
        const r = await api("mockfile_put", body);
        if (r.state) state = r.state;
        Object.assign(e, { content, status, headers, draft: false,
          original: { content, status: String(status), headers: JSON.stringify(headers) } });   // R3A-10
        $("dirty").textContent = ""; drawerTypingDirty = false; badges();
        toast("Saved — next call gets it");
      } catch (x) { $("dirty").textContent = "Modified"; toast(x.message, true); }
      finally { saving = false; }
    };
    if (e.focus) { e.focus = false; focusInto(m, e.sub === "body" ? "#body" : "#st"); }   // R6B-06
  }

  // ───────────── Paused call sheet (opens by itself) ─────────────
  const formRows = (rows, id, valueLabel = "Value") => `<div id="${id}">${rows.map(([k, v]) =>
    `<div class="hrow"><input type="text" aria-label="Name" value="${esc(k)}" placeholder="Name"><input type="text" aria-label="${valueLabel}" value="${esc(v)}" placeholder="${valueLabel}"><button class="b d" data-fdel aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")}</div><button class="b" data-fadd="${id}">+ Add</button>`;
  const formValues = (id) => [...$(id).querySelectorAll(".hrow")].map((r) => [...r.querySelectorAll("input")].map((i) => i.value)).filter(([k]) => k !== "");
  function wireFormRows(scope) {
    scope.querySelectorAll("[data-fdel]").forEach((b) => b.onclick = () => b.parentElement.remove());
    scope.querySelectorAll("[data-fadd]").forEach((b) => b.onclick = () => {
      const box = $(b.dataset.fadd), d = document.createElement("div"); d.className = "hrow";
      d.innerHTML = `<input type="text" aria-label="Name" placeholder="Name"><input type="text" aria-label="Value" placeholder="Value"><button class="b d" data-fdel aria-label="Remove">${ico("x", "sm")}</button>`;
      box.appendChild(d); d.querySelector("[data-fdel]").onclick = () => d.remove(); d.querySelector("input").focus();
    });
  }
  function renderPausedForm(p, isResp) {
    const headers = readHeaders("phd"), raw = $("pb").value;
    let url;
    try { url = new URL($("pu").value); } catch (x) { url = null; }
    const type = (headers.find(([k]) => k.toLowerCase() === "content-type") || ["", ""])[1].toLowerCase();
    let kind = "none", fields = [];
    if (/application\/x-www-form-urlencoded/.test(type)) { kind = "urlencoded"; fields = [...new URLSearchParams(raw).entries()]; }
    else { try { const doc = JSON.parse(raw); if (doc && typeof doc === "object" && !Array.isArray(doc)) { kind = "json"; fields = Object.entries(doc); } } catch (x) {
      if (!raw.trim() && /json/.test(type)) kind = "json";
    } }
    p.formKind = kind;
    const jsonRows = fields.map(([k, v]) => { const t = v === null ? "null" : Array.isArray(v) || typeof v === "object" ? "json" : typeof v;
      const value = t === "json" ? JSON.stringify(v) : v === null ? "" : String(v);
      return `<div class="hrow"><input type="text" aria-label="JSON key" value="${esc(k)}" placeholder="Key"><select aria-label="Value type">${["string", "number", "boolean", "null", "json"].map((x) => `<option ${x === t ? "selected" : ""}>${x}</option>`).join("")}</select><input type="text" aria-label="JSON value" value="${esc(value)}" placeholder="Value"><button class="b d" data-jdel aria-label="Remove">${ico("x", "sm")}</button></div>`; }).join("");
    $("ppf").innerHTML = `${isResp ? `<div class="btns">Status <input type="number" id="pfst" value="${esc($("pst").value)}" aria-label="Status code"></div>`
      : `<div class="btns"><select id="pfm" aria-label="Method">${methodOpts($("pm").value)}</select><input type="text" id="pfpath" class="grow" aria-label="Path" value="${esc(url ? url.pathname : "")}" placeholder="Path"></div>
         <h4>Query parameters</h4>${formRows(url ? [...url.searchParams.entries()] : [], "pfquery")}`}
      <h4>Headers</h4>${headersHTML(headers, "pfhd")}
      <h4>Body fields</h4>${kind === "json" ? `<div id="pfjson">${jsonRows}</div><button class="b" id="pfjadd">+ Add field</button>`
        : kind === "urlencoded" ? formRows(fields, "pffields") : `<div class="sub">${raw.trim() ? "This body is not a JSON object or URL encoded form. Edit it in Body." : "No body fields. Edit the raw body to add one."}</div>`}`;
    wireHeaders($("ppf")); wireFormRows($("ppf"));
    $("ppf").querySelectorAll("[data-jdel]").forEach((b) => b.onclick = () => b.parentElement.remove());
    if ($("pfjadd")) $("pfjadd").onclick = () => {
      const d = document.createElement("div"); d.className = "hrow";
      d.innerHTML = `<input type="text" aria-label="JSON key" placeholder="Key"><select aria-label="Value type">${["string", "number", "boolean", "null", "json"].map((x) => `<option>${x}</option>`).join("")}</select><input type="text" aria-label="JSON value" placeholder="Value"><button class="b d" data-jdel aria-label="Remove">${ico("x", "sm")}</button>`;
      $("pfjson").appendChild(d); d.querySelector("[data-jdel]").onclick = () => d.remove(); d.querySelector("input").focus();
    };
  }
  function applyPausedForm(p, isResp) {
    try {
      if (isResp) $("pst").value = $("pfst").value;
      else { const url = new URL($("pu").value); url.pathname = $("pfpath").value; url.search = "";
        formValues("pfquery").forEach(([k, v]) => url.searchParams.append(k, v)); $("pu").value = url.href; $("pm").value = $("pfm").value; }
      const headers = readHeaders("pfhd"); $("pph").innerHTML = headersHTML(headers, "phd");
      wireHeaders($("sheet"));
      if (p.formKind === "urlencoded") $("pb").value = new URLSearchParams(formValues("pffields")).toString();
      if (p.formKind === "json") {
        const obj = {};
        $("pfjson").querySelectorAll(".hrow").forEach((r) => { const key = r.querySelector("input").value, type = r.querySelector("select").value, val = r.querySelectorAll("input")[1].value;
          if (!key) return;
          if (type === "number") { const n = Number(val); if (!val.trim() || !Number.isFinite(n)) throw Error("Enter a valid number for " + key); obj[key] = n; }
          else if (type === "boolean") { if (val !== "true" && val !== "false") throw Error("Use true or false for " + key); obj[key] = val === "true"; }
          else if (type === "null") obj[key] = null;
          else if (type === "json") obj[key] = JSON.parse(val);
          else obj[key] = val;
        });
        $("pb").value = JSON.stringify(obj);
      }
      jsonCheck($("pb"), $("pjs")); return true;
    } catch (x) { toast("Form: " + x.message, true); return false; }
  }
  async function openPaused(id, auto = false) {
    try { pausedOpen = await api("paused_get", { id }); pausedOpen.sub = "body"; drawPaused(auto);
      if (/NEXT matching call/.test($("toast").textContent)) $("toast").style.display = "none"; }   // it has hit: the hint is stale
    catch (e) { pausedOpen = null; closeSheet("pause"); toast(e.message, true); }
  }
  function drawPaused(auto = false) {
    const p = pausedOpen, isResp = p.phase === "response";
    const q = state ? state.paused.length : 1;
    $("sheet").innerHTML = `
      <header class="paused"><b>${ico("pause", "sm")} Paused at ${isResp ? "response — edit what the app receives" : "request — edit what the app sends"}${q > 1 ? ` · ${q} waiting` : ""}</b>
        <span class="sub" style="max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.method)} ${esc(p.url)}</span></header>
      <main>
        ${isResp ? `<div class="btns" style="margin-top:0">Status <input type="number" id="pst" value="${esc(p.status)}" style="width:80px"></div>`
                 : `<div class="btns" style="margin-top:0"><select id="pm">${methodOpts(p.method)}</select>
                    <input type="text" id="pu" class="grow" value="${esc(p.url)}"></div>`}
        ${isResp ? "" : `<div class="sub" id="pnext" style="margin:0 0 8px">${p.response_next
          ? "To change what the app <b>receives</b>, press Continue: the response pauses next."
          : `To change what the app <b>receives</b>, pause its response. <button class="lnk" id="presp">Pause the response too</button>`}</div>`}
        <div class="seg"><button data-psub="body" class="${p.sub === "body" ? "on" : ""}">${isResp ? "Response body" : "Request body"}</button><button data-psub="headers" class="${p.sub === "headers" ? "on" : ""}">Headers</button><button data-psub="form" class="${p.sub === "form" ? "on" : ""}">Form</button></div>
        <div id="ppb" style="${p.sub === "body" ? "" : "display:none"}"><textarea id="pb" spellcheck="false" placeholder="No body" class="${(isResp ? p.resp_body : p.req_body) ? "" : "nobody"}" ${(isResp ? p.resp_body_editable : p.req_body_editable) ? "" : "readonly"}>${esc(isResp ? p.resp_body : p.req_body)}</textarea>
          <div class="btns">${(isResp ? p.resp_body : p.req_body) && (isResp ? p.resp_body_editable : p.req_body_editable) ? `<button class="b" id="pfmt">Format JSON</button>` : ""}<span class="sub" id="pjs"></span></div></div>
        <div id="pph" style="${p.sub === "headers" ? "" : "display:none"}">${headersHTML(isResp ? p.resp_headers : p.req_headers, "phd")}</div>
        <div id="ppf" style="display:none"></div>
      </main>
      <footer><span class="sub" style="margin-right:auto">The app is waiting — continue within its timeout (~30–60 s).<br>
        ${q > 1 ? `<button class="lnk" id="pall">Resume all ${q}</button> · ` : ""}<button class="lnk" id="pbpoff">Turn off this breakpoint</button></span>
        <button class="b d" id="pabort">Abort</button><button class="b" id="pskip">Skip (send unchanged)</button>
        <button class="b p" id="pcont">Continue</button></footer>`;
    openSheet("pause", isResp ? "#pst" : "#pu", auto); // R6-01: polling must leave the current typing target focused.
    const ta = $("pb"); jsonCheck(ta, $("pjs")); ta.oninput = () => jsonCheck(ta, $("pjs"));
    wireHeaders($("sheet"));
    // R6-02: a hidden paused sheet still owns unsent changes, so Esc cannot dismiss it while dirty.
    sheetDirty = () => (p.sub === "form" && !applyPausedForm(p, isResp)) || $("pb").value !== (isResp ? p.resp_body : p.req_body) ||
      JSON.stringify(readHeaders("phd")) !== JSON.stringify(isResp ? p.resp_headers : p.req_headers) ||
      (isResp ? $("pst").value !== String(p.status) : $("pm").value !== p.method || $("pu").value !== p.url);
    root.querySelectorAll("[data-psub]").forEach((b) => (b.onclick = () => {
      if (p.sub === "form" && !applyPausedForm(p, isResp)) return;
      p.sub = b.dataset.psub;
      if (p.sub === "form") renderPausedForm(p, isResp);
      $("ppb").style.display = p.sub === "body" ? "" : "none"; $("pph").style.display = p.sub === "headers" ? "" : "none"; $("ppf").style.display = p.sub === "form" ? "" : "none";
      root.querySelectorAll("[data-psub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    if ($("pfmt")) $("pfmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); jsonCheck(ta, $("pjs")); } catch (x) { toast("Not JSON", true); } };
    const done = async (op, edits) => {
      const id = p.id;
      const r = await run(op, { id, edits }, op === "paused_continue" ? "Continued with your edits" : op === "paused_skip" ? "Sent unchanged" : "Aborted");
      if (!r) return;
      pausedOpen = null; closeSheet("pause");
      const next = (state.paused || []).find((x) => !dismissed.has(x.id));
      if (next) openPaused(next.id);
    };
    $("pcont").onclick = () => {
      if (p.sub === "form" && !applyPausedForm(p, isResp)) return;
      const original = isResp ? p.resp_body : p.req_body;
      const edits = { headers: readHeaders("phd") };
      if (ta.value !== original && !ta.readOnly) edits.body = ta.value;   // untouched body: bytes pass through as-is
      if (isResp) edits.status = Number($("pst").value); else { edits.method = $("pm").value; edits.url = $("pu").value; }
      done("paused_continue", edits);
    };
    if ($("presp")) $("presp").onclick = async () => {
      const r = await run("bp_add", { flow_id: p.id, request: true, response: true }, "The response of this call pauses too");
      if (r) { p.response_next = true; $("pnext").innerHTML = "To change what the app <b>receives</b>, press Continue: the response pauses next."; }
    };
    $("pskip").onclick = () => done("paused_skip");
    $("pabort").onclick = () => done("paused_abort");
    // A breakpoint on a busy endpoint queues a sheet per call (twice with request + response): give a way out
    const resumeAll = async () => {
      let n = 0;
      try { n = (await api("paused_resume_all", {})).resumed || 0; } catch (e) { toast(e.message, true); }
      pausedOpen = null; closeSheet("pause");
      return n;
    };
    if ($("pall")) $("pall").onclick = async () => toast("Resumed " + await resumeAll() + " paused call(s) unchanged");
    $("pbpoff").onclick = async () => {
      const hits = (state.breakpoints || []).filter((b) => b.enabled !== false && (!b.method || b.method === p.method) &&
        (() => { try { return new RegExp(b.match).test(p.url); } catch (e) { return false; } })());
      for (const b of hits) await run("bp_update", { name: b.name, enabled: false });
      let n = await resumeAll();
      // the proxy picks the change up within a second: a call released at its request can still stop at its
      // response under the old filter, so sweep a few more times
      for (let i = 0; i < 4 && hits.length; i++) {
        await new Promise((ok) => setTimeout(ok, 800));
        const left = ((await api("state").catch(() => ({}))).paused || []).length;
        if (!left) break;
        n += await resumeAll();
      }
      toast((hits.length ? "Breakpoint off" : "No matching breakpoint found") + (n ? " — resumed " + n + " waiting call(s)" : ""));
    };
  }

  // poll for paused calls so the sheet opens by itself, like FRTMProxy / Proxyman
  let viewerPoll = null;
  async function refreshViewerSummaries() {
    if (viewerPoll || !$("drawer").classList.contains("open")) return viewerPoll;
    viewerPoll = api("viewer_summaries", { limit:12 }, 5000).then((r) => {
      viewers = r.viewers || viewers;
      tagCells();
    }).catch(() => {}).finally(() => { viewerPoll = null; });
    return viewerPoll;
  }
  // A proxy that died or froze must not look healthy: a hung request never fails, so the check has a deadline,
  // and two missed checks in a row (~10 s) raise a banner until it answers again.
  let lostSince = 0, missed = 0;
  const showLost = (on) => {
    const bar = $("lostbar"), cli = (state && state.product && state.product.cli) || "rivis";
    if (on) bar.innerHTML = `${esc((state && state.product && state.product.name) || "Rivis")} is not responding (no answer for ${Math.round((Date.now() - lostSince) / 1000)} s) — calls may <b>not</b> be captured, and menu actions will fail. Check it with <code>${esc(cli)} status</code>; if that hangs, run <code>${esc(cli)} restart</code>; if it is stopped, <code>${esc(cli)} start --background</code>.`;
    bar.classList.toggle("open", on);
  };
  // Another proxy app as the Mac's proxy: the iOS Simulator's calls go there instead (a leftover on a dead port is
  // cleared by the add-on itself and reported once)
  let proxyFixShown = false;
  // In-app updates (signed releases, addons/updater.py). The page reloads itself once the restarted proxy is the new version.
  let loadedVersion = null;
  const updateLater = (v) => LS.set("rivis-update-later", v);
  const showUpdateBar = (s) => {
    const bar = $("updatebar"), u = s.update || {}, name = (s.product && s.product.name) || "Rivis";
    if (loadedVersion === null && s.version) loadedVersion = s.version;
    if (loadedVersion && s.version && s.version !== loadedVersion) { location.reload(); return; }
    let html = "";
    if (u.installing) html = `Updating ${esc(name)} to ${esc(u.installing.version)}… It restarts by itself in about a minute, and this page reloads.`;
    else if (u.available && LS.get("rivis-update-later", "") !== u.available.version)
      html = `${esc(name)} ${esc(u.available.version)} is available.<button class="lnk" id="upd-notes">What's new</button>` +
        `<button class="b p" id="upd-go">Update to ${esc(u.available.version)}</button><button class="lnk" id="upd-later">Later</button>`;
    if (bar.dataset.html !== html) {
      bar.dataset.html = html; bar.innerHTML = html;
      if ($("upd-go")) $("upd-go").onclick = () => run("update_install", {}, "Updating… it restarts by itself in about a minute");
      if ($("upd-later")) $("upd-later").onclick = () => { updateLater(u.available.version); showUpdateBar(s); };
      if ($("upd-notes")) $("upd-notes").onclick = () => openHelp("settings");
    }
    bar.classList.toggle("open", !!html && !$("lostbar").classList.contains("open"));
  };
  // An emulator set up with `android on` came back without its proxy (cold boot): the proxy put it back; say so once.
  let androidSeen = null;
  const showAndroidRestored = (s) => {
    const last = (s.android_restored || []).slice(-1)[0];
    if (androidSeen === null) { androidSeen = last ? last.at : 0; return; }    // only what happens while the page is open
    if (last && last.at > androidSeen) { androidSeen = last.at; toast(`${last.avd || last.serial} came back without its proxy setting — set it back`); }
  };
  const showProxyBar = (sp) => {
    const bar = $("proxybar"), name = (state && state.product && state.product.name) || "Rivis";
    if (sp && sp.fixed && !proxyFixShown) {
      proxyFixShown = true;
      toast(`Fixed: another proxy app had left your Mac's proxy on ${sp.host}:${sp.port} with nothing running there. The Simulator and your Mac apps can connect again.`);
    }
    if (sp && !sp.fixed) proxyFixShown = false;
    const other = sp && sp.owner && !sp.ours;
    if (other) { bar.innerHTML = `<b>${esc(sp.owner)}</b> is your Mac's proxy (${esc(sp.host)}:${esc(sp.port)}): the iOS Simulator sends its calls there, not to ${esc(name)}. Quit ${esc(sp.owner)}; ${esc(name)} cleans up what it leaves behind.`; bar.dataset.html = ""; }
    else showTrustBar(bar, name);
    bar.classList.toggle("open", (!!other || !!(state && (state.untrusted || []).length)) && !$("lostbar").classList.contains("open"));
  };
  // A simulator / emulator that does not trust the Rivis certificate refused its HTTPS: those hosts now pass through
  // undecrypted (the app works, the calls are not listed). Say which, and how to set the device up.
  const showTrustBar = (bar, name) => {
    const hosts = (state && state.untrusted) || [];
    const html = hosts.length ? `A simulator or emulator does not trust the ${esc(name)} certificate, so <b>${esc(hosts[0].host)}</b>${hosts.length > 1 ? ` and ${hosts.length - 1} more` : ""}
      ${hosts.length > 1 ? "pass" : "passes"} through without being recorded. <button class="b sm" id="trust-setup">Set up devices</button><button class="lnk" id="trust-retry">Decrypt again</button>` : "";
    if (bar.dataset.html === html) return;
    bar.dataset.html = html; bar.innerHTML = html;
    if ($("trust-setup")) $("trust-setup").onclick = () => { tab = "dev"; editing = null; if (!$("drawer").classList.contains("open")) setOpen(true); render(); };
    if ($("trust-retry")) $("trust-retry").onclick = () => run("untrusted_retry", {}, "Decrypting again from the next connection");
  };
  // B15: the open Rules / Breakpoints / Map Local / Scripts tab follows changes made elsewhere (CLI, another browser tab,
  // the proxy's hit counts). Redraw only when that tab's data changed and nobody is typing; give focus back to the same
  // control afterwards, so a keyboard user does not lose their place.
  let openTabSig = "";
  const hitSig = (s) => Object.entries((s.rule_hits || {}).rules || {}).map(([n, h]) => [n, h.count, h.noop, h.calls_since >= NEVER_MATCHED_AFTER]);
  function tabSig(s) {
    if (tab === "rules") return JSON.stringify([tab, s.rules, s.skipped_rules, s.rule_warnings, s.rules_outside, s.rules_error, hitSig(s),
      s.breakpoints, s.scripts, s.script_status, s.throttle, s.throttle_match, s.loss, s.no_cache]);
    if (tab === "map") return JSON.stringify([tab, s.rules, s.skipped_rules, s.rule_warnings, s.rules_outside, s.rules_error, hitSig(s)]);
    if (tab === "bp") return JSON.stringify([tab, s.breakpoints]);
    return JSON.stringify([tab, s.scripts, s.script_status]);
  }
  function refreshOpenTab(s) {
    const sig = tabSig(s);
    if (sig === openTabSig) return;
    const field = root.activeElement;
    if (field && field.closest && field.closest("#main") && /^(INPUT|SELECT|TEXTAREA)$/.test(field.tagName) && field.type !== "checkbox") return;
    const again = focusKey();
    render().then(() => refocus(again));
  }
  let pointerHeld = false;                 // a mouse button is down somewhere in the panel (see poll)
  root.addEventListener("pointerdown", () => { pointerHeld = true; }, true);
  for (const ev of ["pointerup", "pointercancel"]) window.addEventListener(ev, () => { pointerHeld = false; }, true);
  window.addEventListener("blur", (e) => { if (e.target === window) pointerHeld = false; });   // the window, not a field losing focus
  async function poll() {
    try {
      pollState = api("state", undefined, 4000);       // aborted at 4 s, so a hung proxy never holds a connection
      const s = await pollState.finally(() => { pollState = null; });
      missed = 0; lostSince = 0; showLost(false);
      state = s; columns = s.columns || columns; badges(); showProxyBar(s.system_proxy); showUpdateBar(s); refreshUpdatesRow(); showAndroidRestored(s);
      if ($("drawer").classList.contains("open")) await refreshViewerSummaries();
      // the call list (megabytes at a few thousand calls) is for the Tools drawer's own tabs: skip it while the drawer is
      // closed or the page is hidden (row tags come from mitmweb's own rows), and flowsById() fetches on demand
      if ($("drawer").classList.contains("open") && !document.hidden) await refreshFlows().catch(() => {});   // its own 10 s budget; never stalls the heartbeat
      tagCells(); syncColumns(); sizeBuckets(); placeBars(); pullSearch(); drawStrip();
      const waiting = s.paused.filter((x) => !dismissed.has(x.id));
      if (!pausedOpen && waiting.length && !$("pause").classList.contains("open")) openPaused(waiting[0].id, true);
      if (pausedOpen && !s.paused.some((x) => x.id === pausedOpen.id)) { pausedOpen = null; closeSheet("pause"); }
      // Never redraw a tab under a held mouse button: the press and the release would land on different elements and the browser
      // drops the click. The next poll catches up.
      if ($("drawer").classList.contains("open") && tab === "net" && !editing && !pointerHeld) {
        const field = root.activeElement;     // a field being typed in is never redrawn; a switch is, and keeps the keyboard
        if (!(field && field.closest && field.closest("#main") && /^(INPUT|SELECT|TEXTAREA)$/.test(field.tagName) && field.type !== "checkbox")) {
          const again = focusKey();
          Promise.resolve(render()).then(() => refocus(again));
        }
      }
      if ($("drawer").classList.contains("open") && tab === "coll" && !editing && !pointerHeld && !root.activeElement && s.collections.recording) render();
      if ($("drawer").classList.contains("open") && !editing && !pointerHeld && (tab === "bp" || tab === "rules" || tab === "map" || tab === "scripts")) refreshOpenTab(s);
    } catch (e) {          // mitmweb restarting, stopped or frozen: say so after two misses, keep trying
      if (!lostSince) lostSince = Date.now();
      if (++missed >= 2) showLost(true);
    }
    setTimeout(poll, 1200);
  }

  const setOpen = (open) => {
    const W = drawerW();
    host.style.setProperty("--drawer-w", W + "px"); host.style.setProperty("--open-w", open ? W + "px" : "0px");
    $("drawer").classList.toggle("open", open);
    $("brand").style.right = open ? W + 12 + "px" : "";
    document.body.style.marginRight = open ? W + "px" : "";   // push mitmweb over instead of covering it
    document.body.style.width = open ? `calc(100% - ${W}px)` : "";
    window.dispatchEvent(new Event("resize")); placeBars();
  };
  window.addEventListener("resize", () => { if ($("drawer").classList.contains("open") && host.style.getPropertyValue("--drawer-w") !== drawerW() + "px") setOpen(true); });
  $("fab").onclick = () => {
    if (state && state.paused.length && !pausedOpen) { dismissed.clear(); return openPaused(state.paused[0].id); }
    const opening = !$("drawer").classList.contains("open");
    if (!opening) return closeDrawer();   // R6-04/07: click close shares focus and stale-target cleanup with X.
    noteReturn("drawer"); setOpen(true); state = null; render(); refreshViewerSummaries().then(() => {
      if ($("drawer").classList.contains("open") && tab === "call" && !editing) render();
    });
  };
  $("close").onclick = () => closeDrawer();
  const dismissPaused = () => { dismissed.add(pausedOpen && pausedOpen.id); pausedOpen = null; closeSheet("pause"); toast("Still paused — click the Tools button (it shows how many are waiting) to reopen"); };
  $("pause").onclick = (e) => { if (e.target === $("pause")) dismissPaused(); };
  $("project").onchange = () => {
    const v = $("project").value, label = $("project").selectedOptions[0].textContent.replace(/ only$/, "");
    if (v === "__all") return run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic");
    const hint = v === state.active_project ? "" : ` Its rules load when you start with --project ${v}`;
    run("view", { project: v, project_only: true, show_dns: false }, `Showing only ${label} calls.${hint}`);
  };
  const setSource = (v) => run("source", { source: v || null }, v ? "Showing only " + sourceName(v) : "Showing every source");
  $("source").onchange = () => { const v = $("source").value; $("source").blur();
    if (v === "__devices") { $("source").value = (state && state.source) || ""; openDrawer("dev"); return; }   // the "not set up" hint
    setSource(v); };
  // Track whether the Source <select>'s native dropdown is actually open. Rebuilding the options while the dropdown
  // is open would close it (the browser tears it down when innerHTML changes). But rebuilding while the <select>
  // merely has focus is fine — and necessary, because Chromium keeps focus on a <select> after the dropdown closes.
  // mousedown / keydown that opens the popup: rebuild FIRST (so the user sees current sources), then mark open.
  // change / blur / Escape: the dropdown closed. A safety timeout clears the flag if the browser swallows events.
  {
    const sel = $("source");
    let safetyT = 0, openedAt = 0;
    const markOpen = () => {
      sel._rvDropOpen = true;
      openedAt = Date.now();
      clearTimeout(safetyT);
      safetyT = setTimeout(() => { sel._rvDropOpen = false; }, 4000);
    };
    const markClosed = () => {
      sel._rvDropOpen = false;
      openedAt = 0;
      clearTimeout(safetyT);
    };
    sel.addEventListener("mousedown", () => {
      if (sel._rvDropOpen && Date.now() - openedAt > 200) {
        markClosed();
        return;
      }
      sourceOptions(true);
      markOpen();
    });
    sel.addEventListener("keydown", (e) => {
      if (e.key === "Escape" || e.key === "Tab") {
        markClosed();
        return;
      }
      if ([" ", "Enter", "ArrowDown", "ArrowUp"].includes(e.key)) {
        if (sel._rvDropOpen && (e.key === "Enter" || e.key === " ")) {
          markClosed();
          return;
        }
        sourceOptions(true);
        markOpen();
      }
    });
    sel.addEventListener("focus", () => {
      if (!sel._rvDropOpen) sourceOptions(true);
    });
    sel.addEventListener("change", markClosed);
    sel.addEventListener("blur", markClosed);
  }
  root.querySelectorAll("nav button").forEach((b) => (b.onclick = async () => {
    clearTimeout(editorCheckT);
    const draft = editing && editing.kind !== "script" && editing.draft && !mockEditorChanged(editing) ? editing.name : null;
    tab = b.dataset.t; editing = null; render();   // R6-05
    // m10: a new Map Local left unchanged is discarded on a tab switch too, as Back does, so no disabled rule or mock file stays behind
    if (draft) { try { await api("delete", { name: draft }); toast("Map Local '" + draft + "' discarded (not saved)"); } catch (x) { /* it stays a draft: Rules lists it */ } }
  }));
  // R6-03: remember typing across a redraw or tab switch; Esc must not silently drop a Tools draft.
  $("drawer").addEventListener("input", (e) => { if (e.target.matches("input:not([type=checkbox]), textarea")) drawerTypingDirty = true; });
  // mitmweb changes the selection with history.replaceState, which fires no "hashchange" —
  // so watch the selected call id ourselves
  // tells flow retention which call to keep; mitmweb sets its XSRF cookie only after its first requests,
  // so skip until then (a POST without it is refused and logs a console error)
  // (one request at a time: the latest selection waits for the one in flight instead of stacking up behind a stuck proxy)
  let noting = false, noteNext;
  const noteSelected = (id) => {
    if (!xsrf()) return;
    if (noting) { noteNext = { id }; return; }
    noting = true;
    api("flow_selected", { id }, 5000).catch(() => {}).finally(() => { noting = false; if (noteNext) { const n = noteNext; noteNext = null; noteSelected(n.id); } });
  };
  let lastSel = selectedFlow();
  noteSelected(lastSel);
  setInterval(() => {
    const cur = selectedFlow();
    if (cur === lastSel) return;
    lastSel = cur;
    noteSelected(cur);
    if ($("drawer").classList.contains("open") && (tab === "call" || tab === "cmp") && !editing) render();
  }, 300);
  // ───────────── Help · shortcuts · "Coming from Proxyman?" · settings · empty state ─────────────
  const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "");
  const KMOD = isMac ? "⌘" : "Ctrl", KALT = isMac ? "⌥" : "Alt", KSHIFT = isMac ? "⇧" : "Shift";
  const kb = (...k) => k.map((x) => `<kbd>${x}</kbd>`).join(" ");
  // a chord that targets a section lower in a tab: scroll it into view once the tab has drawn (R3-NET-06b)
  const revealWhenDrawn = (id, tries = 30) => { const el = $(id); if (el) el.scrollIntoView({ block: "start" }); else if (tries > 0) setTimeout(() => revealWhenDrawn(id, tries - 1), 100); };
  const openDrawer = (t) => {
    if (!$("drawer").classList.contains("open")) { noteReturn("drawer"); setOpen(true); state = null; }
    if (t) { tab = t; editing = null; }
    return render();
  };
  // R6B-01: a chord moves the keyboard into the drawer (Compose: its URL field; other tabs: their tab button), so
  // keys typed next go to the panel and never to mitmweb's list shortcuts. Checked once more after a redraw.
  const focusDrawer = (again = 1) => {
    // the drawer draws after a state request, so this runs a moment after the chord: a user who has moved on to a field
    // outside the drawer by then (Cmd+F right after the chord) keeps it (flaky-test hunt 2026-10-23: the filter box lost
    // the keyboard after its first letter)
    const a = root.activeElement;
    if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && !$("drawer").contains(a)) return;
    const el = (tab === "compose" && !editing && $("cu")) || root.querySelector("nav button.on");
    if (el && $("drawer").classList.contains("open")) el.focus({ preventScroll: true });
    if (again) setTimeout(() => { if ($("drawer").classList.contains("open") && !$("drawer").contains(root.activeElement)) focusDrawer(0); }, 300);
  };
  const closeDrawer = () => { clearTimeout(editorCheckT); setOpen(false); returnTo.editor = null; giveBack("drawer"); }; // R6-05/07
  const repeatSelected = () => {
    const id = selectedFlow();
    if (!id) return toast("Select a call in the list first", true);
    run("retry", { flow_id: id, edits: {} }, "Repeated — the new call is in the list (newest first)");
  };
  // R3A-09: mitmweb's toolbar Replay mutates the selected flow; route it through repeat before React sees it.
  document.addEventListener("click", (e) => {
    const b = e.target.closest("#container > header button");
    if (b && /\bReplay\b/i.test([b.textContent, b.title, b.getAttribute("aria-label")].join(" "))) {
      e.preventDefault(); e.stopImmediatePropagation(); repeatSelected();
    }
  }, true);
  const focusFilter = () => {
    if (skinOn() && host.hasAttribute("data-sbar")) return focusSearch();
    const link = [...document.querySelectorAll("header nav a")].find((a) => a.textContent.trim() === "Flow List");
    if (link) link.click();
    setTimeout(() => { const i = document.querySelector('.filter-input input[placeholder="Search"]'); if (i) { i.focus(); i.select(); } }, 80);
  };
  // chords are Alt+Shift+<key>: the Cmd/Cmd-Alt combinations desktop proxy tools use are claimed by the browser
  const CHORDS = {
    // R6B-08: open/closed is the drawer's own class; waiting for state as well made a fast second press open it again
    KeyP: ["Open / close the tools drawer", () => ($("drawer").classList.contains("open") ? closeDrawer() : openDrawer().then(() => focusDrawer()))],
    KeyC: ["Compose a new request", () => openDrawer("compose").then(() => focusDrawer())],
    KeyL: ["Map Local", () => openDrawer("map").then(() => focusDrawer())],
    KeyB: ["Breakpoints", () => openDrawer("bp").then(() => focusDrawer())],
    KeyN: ["Network conditions", () => openDrawer("net").then(() => focusDrawer())],
    KeyE: ["TLS decryption list (SSL proxying)", () => { openDrawer("net").then(() => focusDrawer()); revealWhenDrawn("tlssec"); }],
    KeyS: ["Scripts", () => openDrawer("scripts").then(() => focusDrawer())],
    KeyD: ["Compare (diff) two calls", () => openDrawer("cmp").then(() => focusDrawer())],
    KeyV: ["Devices: set up simulators / emulators", () => openDrawer("dev").then(() => focusDrawer())],
    KeyF: ["Search / filter the list", focusFilter],
    Enter: ["Edit & Repeat the selected call", () => { const id = selectedFlow(); if (id) openRetry(id); else toast("Select a call in the list first", true); }],
  };
  const SHORTCUTS = [
    ["Rivis", [
      [kb(KALT, KSHIFT, "P"), "Open / close the tools drawer"],
      [kb(KALT, KSHIFT, "C"), "Compose a new request"],
      [kb(KALT, KSHIFT, "L"), "Map Local"],
      [kb(KALT, KSHIFT, "B"), "Breakpoints"],
      [kb(KALT, KSHIFT, "N"), "Network conditions"],
      [kb(KALT, KSHIFT, "E"), "TLS decryption list (SSL proxying)"],
      [kb(KALT, KSHIFT, "S"), "Scripts"],
      [kb(KALT, KSHIFT, "D"), "Compare (diff) two calls"],
      [kb(KALT, KSHIFT, "V"), "Devices: set up simulators / emulators"],
      [kb(KMOD, "F"), "Filter the list — Esc clears"],
      [kb(KALT, KSHIFT, "F"), "Filter the list (same)"],
      [kb(KMOD, "↵"), "Repeat the selected call"],
      [kb(KALT, KSHIFT, "↵"), "Edit & Repeat the selected call"],
      [kb("?"), "This sheet"],
      [kb("Esc"), "Close the open sheet, editor or drawer — focus goes back where it was"],
      ["Right-click a call", "Map Local, Breakpoint, Repeat, Copy as cURL, Delete…"],
    ]],
    ["Built-in list shortcuts (click the list first)", [
      [kb("↑") + " " + kb("↓") + " or " + kb("k") + " " + kb("j"), "Previous / next call"],
      [kb("r"), "Replay the selected call"],
      [kb("d"), "Delete the selected call"],
      [kb("D"), "Duplicate the selected call"],
      [kb("Esc"), "Deselect"],
    ]],
  ];
  const MAPPING = [
    ["Certificate → Install on iOS Simulator / Android Emulator", "<b>Devices</b> tab: every booted simulator and running emulator, <b>Set up</b> per device (or <code>rivis setup</code>)", "dev"],
    ["Map Local (answer a call from a saved response)", "On the call: <b>This call → Map Local this call…</b>; or the <b>Map Local</b> tab to add by host and path", "call"],
    ["Breakpoint", "<b>This call → Breakpoint</b> (Request / Response); manage in the <b>Breakpoints</b> tab", "bp"],
    ["Network Conditions (throttle)", "<b>Network</b> tab → traffic profiles", "net"],
    ["Compose a new request", "<b>Compose</b> tab, or <b>Compose from this call</b>", "compose"],
    ["Repeat / Edit & Repeat", "Repeat: " + kb(KMOD, "↵") + " or " + kb("r") + ". Edit: <b>This call → Edit &amp; Repeat…</b>", "call"],
    ["Diff two requests", "<b>Compare</b> tab: <i>Compare: set as A</i> on a call, then select another", "cmp"],
    ["Export HAR", "<b>Sessions</b> or <b>Collections</b> → <i>HAR</i>", "sess"],
    ["Filter by host", "The filter box at the top (" + kb(KMOD, "F") + "): type a host or part of a URL. Or <b>right-click → Show only this host</b>", "filter"],
    ["Filter by device / app", "<b>Source</b> menu in the Tools header: one simulator or emulator, or one app on it (two builds of one app stay apart). Or <b>right-click → Show only &lt;app&gt;</b>", "source"],
    ["Clear the session", "The trash button next to the filter box (asks first)", "filter"],
    ["Right-click a call", "Map Local, Breakpoint, Repeat, Copy as cURL, Show only this host…", "call"],
    ["SSL Proxying list", "<b>Network → HTTPS decryption</b> (every host, only the hosts you list, or all except the ones you list)", "net"],
    ["Client Certificates", "<b>Network → Client certificates</b> (a .p12 or PEM per host, for mutual TLS)", "net"],
    ["Scripting", "<b>Scripts</b> tab (JavaScript or Python, per project)", "scripts"],
    ["Save a session", "<b>Sessions</b> tab → save, add a note, reopen later", "sess"],
    ["Copy as cURL", "<b>This call → Copy cURL</b> or <b>Copy as…</b> (many languages)", "call"],
  ];
  const goTo = (t) => { closeHelp(); if (t === "filter") focusFilter(); else if (t === "source") { openDrawer("call"); $("source").focus(); } else openDrawer(t); };
  const mapTable = (rows) => `<table class="map"><tr><th>In Proxyman you did</th><th>Here</th><th></th></tr>${rows.map(([a, b, g]) =>
    `<tr><td>${a}</td><td>${b}</td><td class="go"><button class="lnk" data-go="${g}">Open →</button></td></tr>`).join("")}</table>`;
  const closeHelp = () => closeSheet("help");
  function updatesRowHTML() {
    const u = (state && state.update) || {}, name = (state && state.product && state.product.name) || "Rivis", v = (state && state.version) || "";
    let sub = "", act = "", extra = "";
    if (u.pending) sub = "Checking…";
    else if (!u.configured) sub = "Updates are not set up in this build.";
    else if (!u.installed) sub = "This copy runs from a source checkout — update it with git.";
    else if (!u.signed_in && (u.login || (u.error && /private.*sign in/i.test(u.error)))) {     // sign-in is only the fallback for a private repo
      const l = u.login || {};
      if (l.status === "waiting") {
        sub = "On GitHub, enter this code and click Authorize:";
        extra = `<div class="devcode">${esc(l.user_code)}</div><div class="btns" style="margin:0"><a class="b p" href="${esc(l.uri)}" target="_blank" rel="noopener">Open GitHub</a>` +
          `<button class="b" id="upd-copy">Copy code</button></div>`;
      } else {
        sub = l.status === "error" ? `Sign-in failed: ${esc(l.error || "")}` : `This release repository needs GitHub sign-in.`;
        act = `<button class="b p" id="upd-login" ${l.status === "starting" ? "disabled" : ""}>Sign in with GitHub</button>`;
      }
    } else {
      sub = u.error ? `Version ${esc(v)} · check failed: ${esc(u.error)}` : u.available ? `Version ${esc(v)} · <b>${esc(u.available.version)} is available</b>` : `Version ${esc(v)} · up to date`;
      act = (u.available && !u.installing ? `<button class="b p" id="upd-go2">Update to ${esc(u.available.version)}</button>` : "") +
        `<button class="b" id="upd-check">Check now</button>${u.signed_in ? '<button class="b" id="upd-logout">Sign out</button>' : ''}`;
      if (u.available && u.available.notes) extra = `<div class="updnotes">${esc(u.available.notes)}</div>`;
    }
    return `<div class="set"><div><b>Updates</b><span class="sub">${sub}</span>${extra}</div><div class="btns" style="margin:0">${act}</div></div>`;
  }
  let updatesKey = "";
  function wireUpdatesRow() {
    if ($("upd-login")) $("upd-login").onclick = () => run("update_login_start", {}, `Opening the sign-in…`);
    if ($("upd-check")) $("upd-check").onclick = () => run("update_check", {}, "Checking for updates…");
    if ($("upd-logout")) $("upd-logout").onclick = () => run("update_logout", {}, "Signed out of GitHub");
    if ($("upd-go2")) $("upd-go2").onclick = () => run("update_install", {}, "Updating… it restarts by itself in about a minute");
    if ($("upd-copy")) $("upd-copy").onclick = async () => {
      try { await navigator.clipboard.writeText(state.update.login.user_code); toast("Code copied"); } catch (e) { toast("Copy failed — type the code", true); } };
  }
  function refreshUpdatesRow() {   // the Settings sheet is static HTML: redraw only the Updates row, only when it changes
    const box = $("set-updates"); if (!box) return;
    const key = JSON.stringify([state && state.update, state && state.version]);
    if (key === updatesKey) return;
    updatesKey = key; box.innerHTML = updatesRowHTML(); wireUpdatesRow();
  }
  function openHelp(which) {
    const tabs = { map: "Coming from Proxyman?", keys: "Shortcuts", settings: "Settings" };
    const body = {
      map: () => `<p class="sub" style="margin:0 0 8px">Same tools, same names where they are generic — placed on the call or in the drawer. Rivis runs in a browser tab, captures the simulator per process (no system proxy) and has a project switcher.</p>${mapTable(MAPPING)}`,
      keys: () => SHORTCUTS.map(([h, rows]) => `<h4>${h}</h4><table class="map">${rows.map(([k, d]) => `<tr><td style="width:46%">${k}</td><td>${d}</td></tr>`).join("")}</table>`).join("") +
        `<p class="sub">Single keys are ignored while focus is in the ${esc((state && state.product.name) || "Rivis")} panel. Tab stays inside an open sheet or the drawer. Alt+Shift chords avoid the browser's own ${KMOD} shortcuts.</p>`,
      settings: () => `
        <div class="set"><div><b>Theme</b><span class="sub">System follows your OS setting</span></div>
          <div class="seg" style="margin:0">${["system", "light", "dark"].map((m) => `<button data-theme-set="${m}" class="${themeMode() === m ? "on" : ""}">${m[0].toUpperCase() + m.slice(1)}</button>`).join("")}</div></div>
        <div class="set"><div><b>Compact rows</b><span class="sub">Tighter type and padding in the call list</span></div>${sw('id="set-compact"', compactOn())}</div>
        <div class="set"><div><b>Rivis look</b><span class="sub">Off = the plain built-in look. Also: add <code>?theme=off</code> to the page address</span></div>${sw('id="set-skin"', skinOn())}</div>
        <div class="set"><div><b>Welcome card</b><span class="sub">The first-open “Coming from Proxyman?” card</span></div><button class="b" id="set-welcome">Show again</button></div>
        <div id="set-updates">${updatesRowHTML()}</div>`,
    };
    $("hsheet").innerHTML = `
      <header><span class="mark">${ico("mark")}</span><b>${esc((state && state.product.name) || "Rivis")} <small>/ Help</small></b>
        <div class="seg" style="margin:0">${Object.entries(tabs).map(([k, v]) => `<button data-h="${k}" class="${k === which ? "on" : ""}">${v}</button>`).join("")}</div>
        <button class="x" id="hclose" aria-label="Close">×</button></header>
      <main>${body[which]()}</main>`;
    openSheet("help", "[data-h].on");
    $("hclose").onclick = closeHelp;
    root.querySelectorAll("[data-h]").forEach((b) => (b.onclick = () => openHelp(b.dataset.h)));
    root.querySelectorAll("#hsheet [data-go]").forEach((a) => (a.onclick = () => goTo(a.dataset.go)));
    root.querySelectorAll("[data-theme-set]").forEach((b) => (b.onclick = () => { applyTheme(b.dataset.themeSet); openHelp("settings"); }));
    if ($("set-compact")) $("set-compact").onchange = () => applyDensity($("set-compact").checked);
    if ($("set-skin")) $("set-skin").onchange = () => { setSkin($("set-skin").checked); toast($("set-skin").checked ? "Rivis look on" : "Plain built-in look"); };
    if ($("set-welcome")) $("set-welcome").onclick = () => { LS.set("rivis-welcome", ""); closeHelp(); showWelcome(); };
    updatesKey = JSON.stringify([state && state.update, state && state.version]); wireUpdatesRow();
  }
  $("help").onclick = (e) => { if (e.target === $("help")) closeHelp(); };
  $("bhelp").onclick = () => openHelp("map");
  $("gear").onclick = () => openHelp("settings");
  $("btheme").onclick = () => applyTheme({ system: "light", light: "dark", dark: "system" }[themeMode()]);

  const closeWelcome = () => { LS.set("rivis-welcome", "done"); closeSheet("welcome"); try { drawEmptyList(); } catch (e) { /* cosmetic */ } };
  $("wscrim").onclick = closeWelcome;
  function showWelcome() {
    if (LS.get("rivis-welcome", "") === "done") return;
    const name = (state && state.product.name) || "Rivis";
    $("welcome").innerHTML = `
      <h3><span class="mark">${ico("mark")}</span>Welcome to ${esc(name)}</h3>
      <div class="wbody"><p>Coming from Proxyman? Open Tools → Devices or Tools → Network in the drawer on the right; call actions are on the selected call.
        Same names where they are generic. Rivis runs in a browser tab and does not set a system proxy.</p>
      ${mapTable(MAPPING)}</div>
      <div class="btns wfoot" style="justify-content:flex-end"><button class="b" id="w-keys">Shortcuts</button><button class="b p" id="w-ok">Got it</button></div>`;
    openSheet("welcome", "#w-ok");
    $("w-ok").onclick = closeWelcome;
    $("w-keys").onclick = () => { closeWelcome(); openHelp("keys"); };
    root.querySelectorAll("#welcome [data-go]").forEach((a) => (a.onclick = () => { closeWelcome(); goTo(a.dataset.go); }));
  }

  // empty list → teach the next step (first run), or explain why everything is hidden (filter / limits)
  function emptyKind() {
    const st = mwStore(); if (!st || !state) return null;
    if (!document.querySelector(".flow-table, .main-view > div[style*='padding: 1em 2em']")) return null;   // the Capture tab etc. are showing instead of the list
    let f; try { f = st.getState().flows; } catch (e) { return null; }
    if (!f || !f.list) return null;
    if (Number(state.flow_count || 0) === 0) return "first";
    return f.list.length === 0 || f.view.length === 0 ? "hidden" : null;
  }
  // Over the call list only: with a call open, mitmweb's detail pane sits to the right of the list
  function placeEmptyList(box) {
    const ft = document.querySelector(".flow-table");
    if (!ft) return;
    const r = ft.getBoundingClientRect();
    if (r.width < 50) return;
    Object.assign(box.style, { left: r.left + "px", top: r.top + "px", width: r.width + "px", height: r.height + "px", bottom: "auto" });
  }
  function drawEmptyList() {
    const box = $("emptylist");
    if (box.classList.contains("open")) placeEmptyList(box);
    const kind = skinOn() ? emptyKind() : null;
    if (!kind || $("welcome").classList.contains("open")) { if (box.classList.contains("open")) { box.classList.remove("open"); box.dataset.sig = ""; } setAttr(DOC, "data-rv-empty", null); return; }
    const cli = state.product.cli || "rivis", proj = state.active_project && state.active_project !== "default" ? ` --project ${state.active_project}` : "";
    const q = (storeSearch() === lastSent && sq().value.trim()) || storeSearch(), label = (state.project && state.project.label) || state.view_project;
    const limits = [];
    if (state.project_only) limits.push(`only ${label} calls`);
    if (state.focus_host) limits.push(`only ${state.focus_host}`);
    if (state.graphql_operation) limits.push(`GraphQL ${state.graphql_operation}`);
    if (state.source) limits.push(`only ${sourceName(state.source)}`);
    const sig = JSON.stringify([kind, q, limits, cli, proj]);
    if (box.dataset.sig === sig && box.classList.contains("open")) return;
    box.dataset.sig = sig;
    if (kind === "first") {
      box.innerHTML = `<div class="box"><div class="glyph">${ico("inbox")}</div>
        <h3>Nothing captured yet</h3>
        <div class="lede">${esc(state.product.name || "Rivis")} is listening${label ? " for <b>" + esc(label) + "</b>" : ""}. Set up the simulator or emulator you test on (once), then use the app — its calls show up here within a second.</div>
        <div class="btns" style="justify-content:center;margin:4px 0 14px"><button class="b p" data-act="devices">${ico("phone", "sm")}Set up a device</button></div>
        <div class="cols">
          <div class="opt"><h5>${ico("phone", "sm")} iOS Simulator</h5><code class="cmd" data-copy="${esc(cli + proj + " ios on")}" title="Click to copy">${esc(cli + proj + " ios on")}</code>
            <div class="sub">Trusts the certificate on the booted simulator (once). Then open the app.</div></div>
          <div class="opt"><h5>${ico("phone", "sm")} Android emulator</h5><code class="cmd" data-copy="${esc(cli + proj + " android on")}" title="Click to copy">${esc(cli + proj + " android on")}</code>
            <div class="sub">Points the emulator at ${esc(state.product.name || "Rivis")} and installs the certificate. Then open the app.</div></div>
        </div>
        <div class="foot">Or from a terminal, as above (<code>${esc(cli + proj + " setup")}</code> does every running device). Nothing from a simulator? Another proxy app (Proxyman, Charles) may have set the Mac's system proxy — quit it, or run <code>${esc(cli)} net-reset</code>.</div></div>`;
    } else {
      // R9-03: with no search and no limit nothing is hidden — the list was cleared (or a file replaced it)
      const why = q ? `No calls match <b>${esc(q)}</b>` : limits.length ? "No matching calls" : "No calls in the list";
      // R8C-05: when a Source / host / project limit is also on, it may be what hides the calls — say so
      const sub = q && limits.length ? `Showing ${esc(limits.join(" and "))}, and none of those calls match. The other calls are still captured — try <b>Show all traffic</b>, or a shorter word.`
                : q ? "Try a shorter word, or the host name only. Filters with <code>~</code> must be written exactly (see the examples in the search box)."
                    : limits.length ? `Showing ${esc(limits.join(" and "))}. The calls are still captured — remove the limit to see them.`
                    : "The list is empty — nothing is hidden. New calls show up here within a second as the app makes them.";
      box.innerHTML = `<div class="box"><div class="glyph">${ico("search")}</div><h3>${why}</h3><div class="lede">${sub}</div>
        <div class="btns">${q ? '<button class="b p" data-act="clear">Clear filter</button>' : ""}${limits.length ? `<button class="b ${q ? "" : "p"}" data-act="all">Show all traffic</button>` : ""}</div></div>`;
    }
    box.classList.add("open"); placeEmptyList(box); setAttr(DOC, "data-rv-empty", "1");
    box.querySelectorAll("[data-copy]").forEach((c) => (c.onclick = () => navigator.clipboard.writeText(c.dataset.copy).then(() => toast("Copied — paste it in a terminal"), () => toast("Select the command and copy it"))));
    box.querySelectorAll("[data-act]").forEach((b) => (b.onclick = async () => {
      if (b.dataset.act === "devices") { tab = "dev"; editing = null; if (!$("drawer").classList.contains("open")) setOpen(true); render(); }
      else if (b.dataset.act === "clear") { sq().value = ""; sbSync(); commitSearch(""); }
      else { if (state.focus_host) await run("focus_host", { host: null }); if (state.graphql_operation) await run("graphql_filter", { name: null }); if (state.source) await run("source", { source: null }); await run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic"); }
    }));
  }

  window.addEventListener("keydown", (e) => {
    const path = e.composedPath ? e.composedPath() : [e.target], t = path[0];
    const typing = !!t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
    // R6B-01: anything focused inside the panel (a Send button, a tab) is not mitmweb's list: no single-key replay
    const inPanel = path.includes(host), inDrawer = path.includes($("drawer"));
    if (e.key === "Tab" && !e.metaKey && !e.ctrlKey && !e.altKey) {      // R6B-02/04/06: Tab stays in what is open
      const box = topSheet() || (inDrawer && $("drawer").classList.contains("open") ? $("drawer") : null);
      if (box) { trapTab(e, box); return; }
    }
    if (e.key === "Escape" && !$("help").classList.contains("open") && !e.defaultPrevented) {
      if ($("pause").classList.contains("open")) {       // Esc = Cancel on Edit & Repeat, = the backdrop click on a paused call
        e.preventDefault(); e.stopPropagation();
        if (sheetDirty()) return;  // R6-02: the explicit buttons remain available for a deliberate discard.
        if ($("rcancel")) $("rcancel").click(); else if (pausedOpen) dismissPaused(); else closeSheet("pause");
        return;
      }
      if ($("source") && $("source")._rvDropOpen) {
        $("source")._rvDropOpen = false;
        e.preventDefault(); e.stopPropagation();
        return;
      }
      if (inDrawer && !$("welcome").classList.contains("open") && $("drawer").classList.contains("open")) {
        e.preventDefault(); e.stopPropagation();
        const back = $("main").querySelector("#back, #sback");     // an editor: Esc = its Back (asks first when edited)
        if (back && back.id === "back") back.click(); else if (!drawerTypingDirty) { if (back) back.click(); else closeDrawer(); } // R6-03
        return;
      }
    }
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.code === "KeyF" && t && t.closest && t.closest(".flow-detail") && skinOn()) {
      const field = document.querySelector(".flow-detail .rv-body-find");
      if (field) { e.preventDefault(); e.stopPropagation(); field.focus(); field.select(); return; }
    }
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.code === "KeyF" && skinOn() && host.hasAttribute("data-sbar") && root.activeElement !== sq()) { e.preventDefault(); e.stopPropagation(); focusSearch(); return; }   // a second press lets the browser's find-in-page open
    if (e.altKey && e.shiftKey && !e.metaKey && !e.ctrlKey && CHORDS[e.code]) { e.preventDefault(); e.stopPropagation(); CHORDS[e.code][1](); return; }
    if (e.altKey && !e.shiftKey && !e.metaKey && !e.ctrlKey && /^Digit[1-9]$/.test(e.code) && !typing && !topSheet()) { const i = Number(e.code.slice(5)) - 1; if (savedRows()[i]) { e.preventDefault(); e.stopPropagation(); applySaved(i); } return; }
    if (topSheet() && !inPanel && !typing && !e.metaKey && !e.ctrlKey && !e.altKey && e.key.length === 1) { e.stopPropagation(); return; }   // a modal sheet is up: list keys wait
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key === "Enter" && !typing && !inPanel && !topSheet()) { e.preventDefault(); e.stopPropagation(); repeatSelected(); return; }
    if (e.key.toLowerCase() === "r" && !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey && !typing && !inPanel && !topSheet()) { e.preventDefault(); e.stopPropagation(); repeatSelected(); return; }
    if (e.key === "?" && !e.metaKey && !e.ctrlKey && !e.altKey && !typing) { e.preventDefault(); e.stopPropagation(); openHelp("keys"); return; }
    if (e.key === "Escape" && $("askdlg").classList.contains("open")) { e.stopPropagation(); if (askDone) askDone(null); }
    else if (e.key === "Escape" && $("help").classList.contains("open")) { e.stopPropagation(); closeHelp(); }
    else if (e.key === "Escape" && $("opendlg").classList.contains("open")) { e.stopPropagation(); if (openAsk) openAsk(); }
    else if (e.key === "Escape" && $("welcome").classList.contains("open")) { e.stopPropagation(); closeWelcome(); }
  }, true);
  setInterval(() => { try { drawEmptyList(); } catch (err) { /* cosmetic */ } }, 1500);
  window.addEventListener("resize", () => { const b = $("emptylist"); if (b.classList.contains("open")) placeEmptyList(b); });

  // mitmweb's native Export group copies raw credentials and bodies without Rivis redaction. Keep it unavailable even
  // when the optional visual skin is off; masked Copy as… / HAR exports remain in the Rivis panel.
  const hideNativeExport = () => document.querySelectorAll("#container > header .menu-group").forEach((group) => {
    const legend = group.querySelector(".menu-legend");
    if (legend && legend.textContent.trim().toLowerCase() === "export") {
      group.hidden = true;
      group.setAttribute("aria-hidden", "true");
    }
  });
  // R6B-07: proxy_panel clips a body view too big to paint and says so in mitmweb's view title; next to it, offer the
  // whole body. Our own <span> at the end of the controls row, kept in step with the title (React owns the rest).
  const linkClipped = () => document.querySelectorAll(".contentview > .controls").forEach((c) => {
    const h = c.querySelector("h5"), m = h && /\((showing first [^)]+)\)/.exec(h.textContent);
    const side = (location.hash.replace(/^#\/?/, "").split("?")[0].split("/")[2] || "").toLowerCase(), id = selectedFlow();
    let a = c.querySelector(":scope > .rv-clip");
    if (!m || !id || !/^(request|response)$/.test(side)) { if (a) a.remove(); return; }
    const url = `./flows/${encodeURIComponent(id)}/${side}/content.data`;
    if (a && a.dataset.url === url) return;
    if (!a) { a = document.createElement("span"); a.className = "rv-clip"; c.appendChild(a); }
    a.dataset.url = url;
    a.innerHTML = `<b>${esc(m[1])}</b> · <a href="${esc(url)}" download>Download</a> · <a href="${esc(url)}" target="_blank" rel="noopener">Open raw</a>`;
  });
  let exportCheck = 0;     // the call list mutates constantly under traffic: check at most once per frame
  // Hide the native Export group in the same turn mitmweb draws it (a few header nodes), so no click, script or paint ever
  // sees it; the clipped-body link is cosmetic and stays once per frame.
  new MutationObserver(() => { hideNativeExport(); if (!exportCheck) exportCheck = requestAnimationFrame(() => { exportCheck = 0; try { linkClipped(); } catch (e) { /* cosmetic */ } }); })
    .observe(document.body, { childList: true, subtree: true });
  hideNativeExport();

  // Scroll anchoring, like Proxyman: at the very top the newest calls come into view; once you scroll away, the rows
  // you are looking at stay put while calls keep arriving (or old ones are trimmed). The anchor is the first visible
  // row's call id and its offset; after each list update the scroll position is corrected before the next paint.
  (function anchorList() {
    let ft = null, anchor = null, mo = null, correctedScroll = null, observedScroll = null, recordTimer = null, missTimer = null;
    const rows = () => ft.querySelectorAll("tbody tr");
    const headH = () => { const h = ft.querySelector("thead"); return h ? h.getBoundingClientRect().height : 0; };
    const record = () => {
      clearTimeout(missTimer); missTimer = null;
      anchor = null;
      if (!ft || ft.scrollTop <= 0) return;                 // at the top: follow the newest calls
      const top = ft.getBoundingClientRect().top + headH();
      for (const tr of rows()) {
        const r = tr.getBoundingClientRect();
        if (r.height && r.bottom > top + 1) { const f = flowOf(tr); if (f) anchor = { id: f.id, off: r.top - top }; return; }
      }
    };
    const scheduleRecord = (replace) => {
      if (replace) { clearTimeout(recordTimer); recordTimer = null; }
      if (recordTimer !== null) return;
      recordTimer = setTimeout(() => { recordTimer = null; record(); }, 50);
    };
    const onScroll = () => {
      // A corrective scroll must keep the existing anchor. A user's scroll gets a brief debounce so mitmweb's
      // virtual rows represent the new scrollTop before we choose the anchor (the scroll event itself is too early).
      if (correctedScroll !== null && Math.abs(ft.scrollTop - correctedScroll) < 1) { correctedScroll = null; return; }
      correctedScroll = null;
      if (observedScroll !== null && Math.abs(ft.scrollTop - observedScroll) < 1 && recordTimer !== null) return;
      observedScroll = ft.scrollTop;
      if (ft.scrollTop <= 0) anchor = null;                // follow new calls as soon as the user reaches the top
      scheduleRecord(true);
    };
    const correct = () => {
      if (!ft) return;
      if (recordTimer !== null) return;                    // virtual rows are changing for a user scroll, not new traffic
      if (!anchor) { scheduleRecord(false); return; }
      const top = ft.getBoundingClientRect().top + headH();
      for (const tr of rows()) {
        const f = flowOf(tr);
        if (f && f.id === anchor.id) {
          clearTimeout(missTimer); missTimer = null;
          const d = tr.getBoundingClientRect().top - top - anchor.off;
          if (Math.abs(d) >= 1) { correctedScroll = ft.scrollTop + d; ft.scrollTop = correctedScroll; }
          return;                                             // keep this anchor across every partial React render
        }
      }
      // The anchor may be absent for one virtual-list render. Only replace it if it stays gone (for example, the
      // retention cap removed it), never in the middle of a list update.
      if (!missTimer) missTimer = setTimeout(record, 100);
    };
    const attach = () => {
      const now = document.querySelector(".flow-table");
      if (now === ft) return;
      if (mo) mo.disconnect();
      ft = now; anchor = null;
      if (!ft) return;
      ft.style.overflowAnchor = "none";                    // ours, not the browser's: rows are virtualized
      ft.addEventListener("scroll", onScroll, { passive: true });
      mo = new MutationObserver(correct);
      mo.observe(ft, { childList: true, subtree: true });
    };
    new MutationObserver(attach).observe(document.body, { childList: true, subtree: true });
    setInterval(attach, 1000); attach();
  })();
  setTimeout(showWelcome, 900);

  // Newest call first, like Proxyman. mitmweb has no default sort, so once per page load sort "Start time"
  // descending. A header click cycles asc → desc → off and reads the sort from the last render, so the two
  // clicks are a frame apart. Any column the user already sorted wins; after this they sort as usual.
  (function newestFirst(tries) {
    const sorted = document.querySelector(".flow-table th.sort-asc, .flow-table th.sort-desc");
    const th = document.querySelector(".flow-table th.col-timestamp");
    if (sorted && !(sorted === th && sorted.classList.contains("sort-asc"))) return;
    if (th) th.click();
    if (tries > 0) setTimeout(() => newestFirst(tries - 1), th ? 50 : 300);
  })(40);
  poll();
})();
