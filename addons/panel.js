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
  const api = async (op, body) => {
    const opts = body === undefined
      ? { credentials: "same-origin" }
      : { method: "POST", credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(body) };
    const r = await fetch("./proxy/api/" + op, opts);
    let j = {};
    try { j = await r.json(); } catch (e) { j = { error: "HTTP " + r.status }; }
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    return j;
  };
  const selectedFlow = () => {   // mitmweb keeps the selection in the hash: #/flows/<id>/<tab>
    const p = location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
    return p[0] === "flows" && p[1] ? p[1] : null;
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const emptyState = (icon, title, hint) =>
    `<div class="empty">${ico(icon)}<b>${esc(title)}</b><span class="sub">${hint}</span></div>`;
  const info = (t) => `<span class="info" tabindex="0" role="img" aria-label="${esc(t)}" title="${esc(t)}">ⓘ</span>`;
  const hostPath = (u) => { try { const x = new URL(u); return [x.host, x.pathname]; } catch (e) { return ["", u]; } };
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
    .drawer { position: fixed; top: 0; right: 0; height: 100vh; width: var(--drawer-w, 460px); max-width: 100vw; z-index: 2147483001; background: var(--rv-surface); color: var(--rv-text);
              border-left: 1px solid var(--rv-border); box-shadow: var(--rv-shadow-2); display: none; flex-direction: column; font-size: 13px; }
    .drawer.open { display: flex; animation: slide var(--rv-dur) var(--rv-ease); }
    @keyframes slide { from { transform: translateX(18px); opacity: .4; } }
    header { display: flex; align-items: center; gap: 8px; padding: 10px 12px 10px 14px; border-bottom: 1px solid var(--rv-border); }
    header .mark { width: 22px; height: 22px; border-radius: 7px; background: var(--rv-accent); color: var(--rv-accent-fg); display: grid; place-items: center; flex: none; }
    header .mark svg { width: 14px; height: 14px; stroke-width: 2.2; }
    header b { font-size: 14px; flex: 1; font-weight: 650; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    header b small { font-weight: 500; color: var(--rv-text-2); font-size: 13px; }
    .x { border: 0; background: transparent; font-size: 20px; line-height: 1; cursor: pointer; color: var(--rv-text-2); width: 26px; height: 26px; border-radius: var(--rv-r-md); }
    .x:hover { background: var(--rv-surface-2); color: var(--rv-text); }
    nav { display: grid; grid-template-columns: repeat(6, 1fr); gap: 2px; padding: 6px 8px 0; border-bottom: 1px solid var(--rv-border); background: var(--rv-surface); }   /* 6 + 5: every tab visible, even widths */
    nav::-webkit-scrollbar { display: none; }
    nav button { position: relative; display: flex; flex-direction: column; align-items: center; gap: 3px; border: 0; background: none; padding: 7px 2px 7px; cursor: pointer; font-size: 11.5px; font-weight: 500; color: var(--rv-text-2);
                 border-bottom: 2px solid transparent; border-radius: var(--rv-r-md) var(--rv-r-md) 0 0; white-space: nowrap; min-width: 0; transition: color var(--rv-dur) var(--rv-ease), background var(--rv-dur) var(--rv-ease); }
    nav button svg.i { width: 17px; height: 17px; }
    nav button:hover { color: var(--rv-text); background: var(--rv-surface-2); }
    nav button.on { color: var(--rv-accent-text); border-bottom-color: var(--rv-accent); font-weight: 600; }
    label.pj { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--rv-text-3); }
    .info { color: var(--rv-text-3); cursor: help; font-size: 11px; }
    nav .cnt:empty { display: none; }
    nav .cnt { position: absolute; top: 3px; right: calc(50% - 24px); background: var(--rv-accent-soft); color: var(--rv-accent-text); border-radius: var(--rv-r-pill); padding: 0 6px; font-size: 10.5px; font-weight: 700; line-height: 16px; font-variant-numeric: tabular-nums; }
    nav .cnt.err { background: var(--rv-danger-soft); color: var(--rv-danger); }
    main { flex: 1; overflow: auto; padding: 14px; }
    h4 { margin: 18px 0 7px; font-size: 10.5px; text-transform: uppercase; letter-spacing: .07em; color: var(--rv-text-3); font-weight: 700; display: flex; align-items: center; gap: 8px; }
    h4::after { content: ""; flex: 1; height: 1px; background: var(--rv-border); }
    h4:first-child { margin-top: 2px; }
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
    textarea { width: 100%; min-height: 260px; height: calc(100vh - 420px); font-family: var(--rv-mono); font-size: 12px; line-height: 1.55; border: 1px solid var(--rv-control); border-radius: var(--rv-r-md);
               padding: 10px; resize: vertical; background: var(--rv-surface-2); color: var(--rv-text); tab-size: 2; }
    textarea[readonly] { opacity: .75; }
    .hrow input, .krow input[type=text], td input { font-family: var(--rv-mono); }
    .toast { position: fixed; left: 50%; transform: translateX(-50%); bottom: 26px; z-index: 2147483003; background: var(--rv-text); color: var(--rv-surface); padding: 9px 16px; border-radius: var(--rv-r-md);
             font-size: 12.5px; font-weight: 500; display: none; max-width: 80vw; box-shadow: var(--rv-shadow-2); animation: toast var(--rv-dur) var(--rv-ease); }
    .toast.err { background: var(--rv-danger); color: var(--rv-danger-fg); }
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
    .emptylist { position: fixed; z-index: 1; left: 0; top: calc(var(--hb, 80px) + 30px + var(--strip-h, 0px)); width: calc(100vw - var(--open-w, 0px)); bottom: 30px; pointer-events: none; display: none; align-items: center; justify-content: center; padding: 16px; }
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
      <button class="ib" id="sclear" hidden aria-label="Clear filter" title="Clear filter (Esc)">${ico("x", "sm")}</button><kbd>${/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "") ? "⌘F" : "Ctrl F"}</kbd></div>
    <button class="ib" id="strash" aria-label="Clear all calls" title="Clear all calls from the list">${ico("trash")}</button></div>
  <div class="spop" id="spop" role="status"></div>
  <div class="fstrip" id="fstrip"></div>
  <div class="cmenu" id="cmenu" role="menu" aria-label="Call actions"></div>
  <div class="drawer" id="drawer">
    <header><span class="mark">${ico("mark")}</span><b id="ptitle">Tools</b><label class="pj" title="Choose which project's calls the list shows">Show<select id="project" aria-label="Project shown in the call list"></select></label><button class="ib" id="gear" title="Settings and help">${ico("gear")}</button><button class="x" id="close" title="Close" aria-label="Close">×</button></header>
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
  <div class="emptylist" id="emptylist"></div>
  <div class="toast" id="toast"></div>`;

  const $ = (id) => root.getElementById(id);
  let tab = "call", state = null, editing = null, pausedOpen = null, dismissed = new Set();
  let viewers = { tokens:[], graphql_ops:[], graphql_error_ids:[], complete:false };
  const toast = (msg, err) => {
    const t = $("toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); t.style.display = "block";
    clearTimeout(toast._t); toast._t = setTimeout(() => (t.style.display = "none"), err ? 5000 : 2500);
  };
  const busy = new Set();
  const run = async (op, body, ok) => {
    const key = op + JSON.stringify(body || {});
    if (busy.has(key)) return;
    busy.add(key);
    try { const r = await api(op, body); if (r.state) state = r.state; if (ok) toast(typeof ok === "function" ? ok(r) : ok); render(); return r; }
    catch (e) { toast(e.message, true); }
    finally { busy.delete(key); }
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

  const flowCache = { at: 0, byId: new Map(), pending: null };
  async function refreshFlows() {
    if (!flowCache.pending) flowCache.pending = fetch("./flows", { credentials: "same-origin" })
      .then((r) => r.json()).then((all) => {
        flowCache.byId = new Map(all.map((f) => [f.id, f])); flowCache.at = Date.now();
      }).finally(() => { flowCache.pending = null; });
    await flowCache.pending;
  }
  async function flowsById(id) {
    try {
      const fresh = Date.now() - flowCache.at < 800;
      if (fresh && flowCache.byId.has(id)) return flowCache.byId.get(id);
      await refreshFlows();
      return flowCache.byId.get(id) || null;
    }
    catch (e) { return null; }
  }
  async function builtinContent(id, side, views) {
    for (const view of views) {
      try {
        const r = await fetch(`./flows/${id}/${side}/content/${encodeURIComponent(view)}.json`, { credentials:"same-origin" });
        if (r.ok) return await r.json();
      } catch (e) { /* use the panel-side schema-less fallback */ }
    }
    return null;
  }

  let renderSeq = 0;
  async function render() {
    const seq = ++renderSeq;
    if (!state) state = await api("state").catch(() => null);
    if (seq !== renderSeq) return;
    if (!state) { $("main").innerHTML = '<p class="muted">Cannot reach the panel API.</p>'; return; }
    badges();
    root.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.t === tab));
    const m = $("main");
    if (editing) return editing.kind === "script" ? renderScriptEditor(m) : renderEditor(m);
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
    const active = on(state.rules) || on(state.breakpoints) || state.throttle !== "off";
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
    $("fablabel").textContent = state.paused.length ? `${state.paused.length} paused` : "Tools";
    $("fab").title = active ? "Tools — rules, breakpoints or network conditions are switched on (Alt+Shift+P)" : "Tools — Map Local, breakpoints, network conditions, scripts (Alt+Shift+P)";
  }

  // ───────────── This call ─────────────
  async function renderCall(m, seq) {
    const id = selectedFlow();
    const f = id ? await flowsById(id) : null;
    if (seq !== renderSeq) return;
    if (f && f.type === "tcp") {       // a host that is not decrypted: only the tunnel is visible
      const conn = f.server_conn || {}, hostName = conn.sni || (f.client_conn || {}).sni || (conn.address || [""])[0] || "", portNo = (conn.address || [])[1];
      m.innerHTML = `<div class="call"><span class="m">HOST ONLY</span>${esc(hostName)}${portNo ? ":" + esc(portNo) : ""}
          <div class="sub">${ico("lock", "sm")} Not decrypted — you can see the host, but not the URL, headers or body</div></div>
        ${tlsQuickHTML(hostName)}`;
      wireTlsQuick(f.id, hostName);
      return;
    }
    if (!f || f.type !== "http") {
      m.innerHTML = emptyState("call", "No call selected", "Click a row in the list. Everything for that call — Map Local, Breakpoint, Copy as cURL, Edit &amp; Retry — is on this tab.");
      return;
    }
    const r = f.request, s = f.response;
    const bpFor = state.breakpoints.find((b) => b.label === r.pretty_host + r.path.split("?")[0] && b.method === r.method);
    let viewer = null;
    try { viewer = await api("viewer", { flow_id: f.id }); } catch (e) { /* call tools still work */ }
    if (viewer && viewer.grpc) {
      const views = viewer.grpc.content_type === "protobuf" ? ["Protocol Buffer", "gRPC/Protocol Buffer"] : ["gRPC/Protocol Buffer", "Protocol Buffer"];
      const decoded = await Promise.all([builtinContent(f.id, "request", views), s ? builtinContent(f.id, "response", views) : null]);
      viewer.grpc.builtin_request = decoded[0]; viewer.grpc.builtin_response = decoded[1];
    }
    if (seq !== renderSeq) return;
    const focused = state.focus_host === r.pretty_host;
    m.innerHTML = `
      <div class="call"><span class="m">${esc(r.method)}</span><span class="dim">${esc(r.pretty_host)}</span>${esc(r.path)}
        <div class="sub">${s ? "→ " + s.status_code : "no response yet"} · <button class="lnk" id="focus">${focused ? "Showing only this host — show all" : "Show only this host"}</button></div></div>
      <h4>Map Local ${info("Saves this response and serves it instead of the server's. You can edit its body, status and headers.")}</h4>
      <div class="btns" style="margin-top:0"><button class="b p" id="mock">Map Local this call…</button>${s ? "" : '<span class="sub">no response yet — starts from 200 {}</span>'}</div>
      <h4>Breakpoint ${info("Pause calls to this endpoint so you can edit them. Request = before it reaches the server; Response = before the app gets it.")}</h4>
      <div class="btns" style="margin-top:0"><span class="sub">Pause at</span>
        <div class="seg" style="margin:0"><button data-ph="request" class="${bpFor && bpFor.request ? "on" : ""}" aria-pressed="${!!(bpFor && bpFor.request)}">Request</button><button data-ph="response" class="${bpFor && bpFor.response ? "on" : ""}" aria-pressed="${!!(bpFor && bpFor.response)}">Response</button></div>
        <span class="sub">${bpFor ? "on for this endpoint" : "off"}</span></div>
      <h4>Edit &amp; repeat</h4>
      <div class="btns" style="margin-top:0"><button class="b" id="retry">Edit &amp; Retry…</button>
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
        <button class="b" id="delay">Delay this call</button></div>
      ${tlsQuickHTML(r.pretty_host)}
      ${viewerHTML(viewer)}${viewerListsHTML()}`;
    $("mock").onclick = async () => {
      const res = await run("mock", { flow_id: f.id }, (x) => (x.existing ? "Opened existing mock '" : "Map Local '") + x.name + "' is on");
      if (res) openEditor(res.name);
    };
    root.querySelectorAll("[data-ph]").forEach((c) => (c.onclick = () => {
      const want = { request: !!(bpFor && bpFor.request), response: !!(bpFor && bpFor.response) };
      want[c.dataset.ph] = !want[c.dataset.ph];
      if (!want.request && !want.response) return bpFor && run("bp_delete", { name: bpFor.name }, "Breakpoint removed");
      run("bp_add", { flow_id: f.id, ...want }, "Breakpoint on — matching calls will pause");
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
            <div class="sub">${esc(r.method || "ANY")} · status ${esc(r.status || 200)} · ${esc(r.name)}</div></div>
          <button class="b" data-edit="${i}">Edit</button><button class="b d" data-del="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("")
      : emptyState("map", "No Map Local rules yet", "Select a call and use <b>Map Local this call</b>, or add one above with a host and path. <b>*</b> and <b>?</b> are wildcards.")}`;
    const split = () => { const v = $("mh").value.trim(); if (/^https?:\/\//.test(v)) { const [h, p] = hostPath(v); $("mh").value = h; $("mp").value = p; } };
    $("mh").onchange = split;
    $("madd").onclick = async () => {
      split();
      const res = await run("maplocal_add", { host: $("mh").value, path: $("mp").value, method: $("mm").value, status: $("ms2").value }, (x) => "Map Local '" + x.name + "' added");
      if (res) openEditor(res.name);
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
    $("badd").onclick = () => { split(); run("bp_add", { host: $("bh").value, path: $("bpth").value, method: $("bm").value, request: ph("request"), response: ph("response") }, (x) => "Breakpoint '" + x.name + "' is on"); };
    root.querySelectorAll("[data-bi]").forEach((c) => (c.onchange = () => run("bp_update", { name: bps[c.dataset.bi].name, enabled: c.checked }, c.checked ? "Breakpoint on" : "Breakpoint off")));
    root.querySelectorAll("[data-bph]").forEach((c) => (c.onclick = () => {
      const [i, p] = c.dataset.bph.split(":"); const b = bps[i];
      const next = { request: b.request, response: b.response }; next[p] = !next[p];
      if (!next.request && !next.response) return toast("Keep Request or Response on — or delete the breakpoint", true);
      run("bp_update", { name: b.name, ...next });
    }));
    root.querySelectorAll("[data-bdel]").forEach((b) => (b.onclick = () => run("bp_delete", { name: bps[b.dataset.bdel].name }, "Breakpoint removed")));
    $("showp") && ($("showp").onclick = () => { dismissed.clear(); openPaused(state.paused[0].id); });
  }

  // ───────────── Network: traffic profiles ─────────────
  function renderNet(m) {
    const icons = { off: "net", "3g-urban": "wifi", "lte-congested": "down", "high-latency-vpn": "lock", "packet-loss-8": "warn", manual: "sliders" };
    const desc = (p) => p.desc || `${p.latency_ms}ms ±${p.jitter_ms}ms latency · ↓${p.down_kbps}kbps / ↑${p.up_kbps}kbps · ${p.loss_pct}% packet loss`;
    const cur = state.throttle || "off";
    const known = state.profiles.some((p) => p.id === cur);
    const mn = state.manual;
    m.innerHTML = `
      <h4>Traffic profiles</h4>
      <div class="row" style="border:0;padding:0 0 8px;flex-wrap:wrap"><label class="sub" for="tm" style="white-space:nowrap">Only slow URLs containing</label>
        <input type="text" id="tm" class="grow" value="${esc(state.throttle_match)}" placeholder="e.g. neo.sa — empty = every call" title="Text (or a pattern) matched against the URL, e.g. neo.sa. Empty slows down every call."></div>
      <div class="sub" style="margin:-2px 0 10px">${cur === "off" ? "Pick a profile — it only slows calls whose URL contains the text above." : `<b>On</b> for ${state.throttle_match ? "URLs containing <code>" + esc(state.throttle_match) + "</code>" : "every call"}.`}</div>
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
      ${tlsSectionHTML()}
      <h4>What the list shows</h4>
      <div class="row">${sw('id="project-filter"', state.project_only)}<div class="n">Only ${esc(state.project.label)} calls <div class="sub">Hides other apps' traffic. Also in the “Show” menu above</div></div></div>
      <div class="row">${sw('id="dns"', state.show_dns)}<div class="n">Show background lookups (DNS) <div class="sub">Off = only web calls are listed</div></div></div>
      <div class="row"><div class="n">Appearance <div class="sub">Theme and compact rows live in Settings (this browser only)</div></div><button class="b" id="openset">${ico("gear", "sm")}Settings</button></div>`;
    wireTlsSection();
    root.querySelectorAll("[data-prof]").forEach((c) => (c.onclick = () => {
      if (c.dataset.prof === "manual") { $("manual").style.display = ""; root.querySelectorAll("[data-prof]").forEach((x) => x.classList.toggle("on", x === c)); return; }
      run("profile", { id: c.dataset.prof, match: $("tm").value }, "Network: " + c.querySelector(".t").textContent);
    }));
    $("mapply").onclick = () => {
      const manual = {}; root.querySelectorAll("[data-mk]").forEach((i) => (manual[i.dataset.mk] = Number(i.value || 0)));
      run("profile", { id: "manual", manual, match: $("tm").value }, "Network: manual profile");
    };
    $("tm").onchange = () => run("profile", { id: cur, match: $("tm").value }, "Applies to: " + ($("tm").value || "all calls"));
    $("project-filter").onchange = () => run("view", { project: state.view_project, project_only: $("project-filter").checked, show_dns: false }, "Call list updated");
    $("dns").onchange = () => run("view", { project_only: false, show_dns: $("dns").checked }, "Call list updated");
    $("openset").onclick = () => openHelp("settings");
  }

  // ───────────── Devices (Proxyman's Certificate → Simulator / Emulator menu) ─────────────
  // Status is polled while the tab is open (and every 30 s for the badge); "Set up" runs the CLI's own command as a
  // background job and streams its output here. Google Play emulators get the same consent text as the terminal.
  let dev = null, devConsent = null, devTimer = null;
  const devRefresh = async () => {
    try { dev = await api("devices", {}); } catch (e) { dev = { error: e.message }; }
    const notReady = dev && !dev.error ? [...(dev.ios || []), ...(dev.android || [])].filter((d) => !d.ready).length : 0;
    const c = $("c-dev"); if (c) { c.textContent = notReady ? `! ${notReady}` : ""; c.classList.toggle("err", notReady > 0); }
    if (tab === "dev" && !editing) renderDev($("main"));
  };
  const devLoop = () => { clearTimeout(devTimer); devLoop.fast = tab === "dev"; devTimer = setTimeout(async () => { await devRefresh(); devLoop(); },
    tab === "dev" ? ((dev && dev.job && dev.job.running) ? 1500 : 4000) : 30000); };
  function renderDev(m) {
    if (!devLoop.fast) { devLoop.fast = true; devLoop(); }          // entering the tab: poll every few seconds
    if (!dev) { m.innerHTML = '<p class="muted">Looking for simulators and emulators…</p>'; devRefresh(); return; }
    if (dev.error) { m.innerHTML = `<p class="muted">${esc(dev.error)}</p>`; return; }
    const job = dev.job, busy = !!(job && job.running);
    const row = (platform, d) => {
      const detail = platform === "ios" ? (d.ready ? "Trusts the Rivis certificate" : "Certificate not trusted yet")
        : !d.ca_ok ? (d.play ? "Google Play image — certificate not installed yet" : "Certificate not installed yet")
        : !d.proxy_ok ? "Certificate OK — proxy not pointing at Rivis" : "Certificate and proxy set";
      return `<div class="row"><div class="n">${esc(d.name)} <span class="sub">${esc(d.os)}</span><div class="sub">${detail}</div></div>
        ${d.ready ? `<span class="ok" title="Ready">${ico("check")}</span>`
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
        <b>One-time setup for ${esc(devConsent.name === "all" ? "these Google Play emulators" : devConsent.name)}</b>
        <div class="sub" style="margin:6px 0">Google Play images refuse adb root, so Rivis installs its certificate the way Proxyman does:
          Magisk (official release, checksum verified) patches a temporary copy of the ramdisk; the emulator restarts twice —
          once with that copy, where a one-shot service copies the certificate, then normally. About 2–4 minutes; the window
          closes and reopens. Nothing else gets root, and the SDK image and AVD settings are not changed.
          Use test emulators only (no personal Google account).</div>
        <div class="btns"><button class="b p" id="dyes">Continue</button><button class="b" id="dno">Cancel</button></div>
        ${dev.magisk ? "" : '<div class="sub">Magisk is not installed with this copy of Rivis, so it will drive the emulator\'s Settings screens instead (about a minute — hands off the emulator).</div>'}
      </div>` : "";
    const log = job ? `<h4>${busy ? "Setting up" : job.rc === 0 ? "Done" : "Failed"} — ${esc(job.label)}</h4>
      <pre class="devlog" style="max-height:220px;overflow:auto;font-size:11.5px;white-space:pre-wrap;margin:0">${esc(job.lines.join("\n")) || "starting…"}</pre>` : "";
    m.innerHTML = `
      <div class="sub" style="margin-bottom:8px">Rivis sets up each simulator or emulator once: its certificate, and for Android the proxy. Like Proxyman's Certificate menu — one click per device.</div>
      ${consent}${log}
      ${section("ios", "iOS Simulators", dev.ios, "Xcode command-line tools are not installed (xcrun simctl).")}
      ${section("android", "Android emulators", dev.android, "adb was not found. Install Android Studio (SDK platform-tools) to use emulators.")}
      <div class="sub" style="margin-top:10px">Same from a terminal: <code>rivis setup</code>. Physical phones need a separate approval.</div>`;
    const start = (b, consentGiven) => run("device_setup", { platform: b.dataset.dsetup, target: b.dataset.id, name: b.dataset.name, consent: consentGiven },
      "Setup started").then(() => { devConsent = null; devRefresh(); devLoop(); });
    m.querySelectorAll("[data-dsetup]").forEach((b) => (b.onclick = () => {
      if (b.dataset.dsetup === "android" && b.dataset.play) { devConsent = { b, name: b.dataset.name }; renderDev(m); return; }
      start(b, false);
    }));
    if (devConsent) {
      $("dyes").onclick = () => start(devConsent.b, true);
      $("dno").onclick = () => { devConsent = null; renderDev(m); };
    }
  }
  devLoop();

  // ───────────── Copy URL / cURL ─────────────
  async function copyExport(id, fmt) {
    const mask = maskOn();
    const r = await run("export", { flow_id: id, fmt, mask });
    if (!r) return;
    try { await navigator.clipboard.writeText(r.text); toast(fmt === "url" ? "URL copied" : "cURL copied" + (mask ? " (secrets masked)" : " — contains secrets!")); }
    catch (e) { prompt("Copy:", r.text); }
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
      <div class="row">${sw('id="cstrict"', c.strict)}<div class="n">Strict replay <div class="sub">Calls not in a replayed collection get a 404</div></div></div>
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
    m.querySelectorAll("[data-ci]").forEach((cb) => (cb.onchange = () => run("coll_replay", { name: c.items[cb.dataset.ci].name, enabled: cb.checked }, cb.checked ? "Replaying " + c.items[cb.dataset.ci].name : "Replay off")));
    m.querySelectorAll("[data-cdel]").forEach((b) => (b.onclick = () => { const n = c.items[b.dataset.cdel].name; if (confirm("Delete collection '" + n + "'?")) run("coll_delete", { name: n }, "Deleted " + n); }));
    m.querySelectorAll("[data-cexp]").forEach((b) => (b.onclick = () => downloadHar("coll_export", c.items[b.dataset.cexp].name, "chsec")));
    m.querySelectorAll("[data-cview]").forEach((b) => (b.onclick = () => { const n = c.items[b.dataset.cview].name; collOpen = collOpen === n ? null : n; render(); }));
    $("cimp").onclick = async () => {
      const file = $("chf").files[0];
      if (!file) return toast("Choose a .har file first", true);
      let har; try { har = JSON.parse(await file.text()); } catch (e) { return toast("Not a valid HAR (JSON) file", true); }
      const name = $("chn").value.trim() || file.name.replace(/\.har$|\.json$/i, "").replace(/[^A-Za-z0-9._-]/g, "-");
      run("coll_import", { name, har }, (x) => "Imported " + x.count + " calls into " + name);
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
    if (withSecrets && !confirm("This HAR will contain tokens, cookies and passwords in clear text.\n\nKeep it on this machine — never attach it to a ticket or chat. Continue?")) return;
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
    $("ssave").onclick = () => run("sess_save", { name: $("sn").value.trim(), note: $("snote").value, visible_only: $("svis").checked }, (x) => "Saved " + x.count + " calls");
    m.querySelectorAll("[data-sload]").forEach((b) => (b.onclick = () => {
      const x = ss[b.dataset.sload];
      const replace = confirm("Open '" + x.name + "'.\n\nOK = replace the current list\nCancel = add to the current list");
      run("sess_load", { name: x.name, replace }, (r) => "Opened " + r.count + " calls");
    }));
    m.querySelectorAll("[data-sdel]").forEach((b) => (b.onclick = () => { const x = ss[b.dataset.sdel]; if (confirm("Delete session '" + x.name + "'?")) run("sess_delete", { name: x.name }, "Deleted"); }));
    m.querySelectorAll("[data-note]").forEach((d) => (d.onclick = () => {
      const x = ss[d.dataset.note]; const note = prompt("Note for " + x.name, x.note || "");
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
        <div class="n"><div><b>${esc(s.name)}</b><span class="tag">${esc(s.lang)}</span></div><div class="sub">${esc(s.method || "ANY")} · ${esc(s.match || ".")} · ${esc(s.file)}${s.exists ? "" : " · FILE MISSING"}${errorHTML(status.errors && status.errors[s.file])}</div></div>
        <button class="b" data-sedit="${i}">Edit</button><button class="b d" data-sdelete="${i}" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") : emptyState("scripts", "No scripts yet", "Pick a template above and click <b>New</b>. Rules run first; enabled scripts run after them, in filename order.")}`;
    $("snew").onclick = async () => {
      const r = await run("script_new", { name: $("sn").value, lang: $("sl").value, template: $("stpl").value, match: $("smatch").value, method: $("smethod").value }, (x) => "Created " + x.file);
      if (r) openScript(r.file);
    };
    m.querySelectorAll("input[data-si]").forEach((c) => (c.onchange = () => run("script_toggle", { file: scripts[c.dataset.si].file, enabled: c.checked }, c.checked ? "Script on" : "Script off")));
    m.querySelectorAll("[data-sedit]").forEach((b) => (b.onclick = () => openScript(scripts[b.dataset.sedit].file)));
    m.querySelectorAll("[data-sdelete]").forEach((b) => (b.onclick = () => { const s = scripts[b.dataset.sdelete]; if (confirm("Delete script '" + s.name + "' and its source file?")) run("script_delete", { file: s.file }, "Deleted " + s.file); }));
  }

  async function openScript(file) {
    try { const r = await api("script_get", { file }); editing = { kind:"script", ...r }; render(); }
    catch (e) { toast(e.message, true); }
  }
  function renderScriptEditor(m) {
    const e = editing, s = e.script;
    m.innerHTML = `<div class="btns" style="margin-top:0"><button class="b" id="sback">${ico("back", "sm")}Back</button><b style="flex:1">${esc(s.file)}</b></div>
      <div class="btns"><input id="sematch" type="text" class="grow" value="${esc(s.match || ".")}" placeholder="URL pattern"><select id="semethod"><option value="">ANY</option>${["GET","POST","PUT","PATCH","DELETE"].map((x) => `<option ${s.method === x ? "selected" : ""}>${x}</option>`).join("")}</select></div>
      <textarea id="sebody" spellcheck="false">${esc(e.content)}</textarea><div class="btns"><button class="b p" id="sesave">Save</button><span class="sub">${esc(e.file)}</span></div>`;
    $("sback").onclick = () => { editing = null; render(); };
    $("sesave").onclick = async () => {
      const r = await run("script_put", { file:s.file, match:$("sematch").value, method:$("semethod").value, content:$("sebody").value }, "Script saved — hot reloads within 1 s");
      if (r) { editing = null; tab = "scripts"; render(); }
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

  // mitmweb's row components receive the flow as a prop; reading it from the React fiber (read-only) is exact even when the list is
  // virtualised, sorted or filtered — unlike guessing by row index (the first <tr> is a spacer).
  let fiberKey = null;
  function flowOf(el) {
    if (!fiberKey) fiberKey = Object.keys(el).find((k) => k.startsWith("__reactFiber$")) || "";
    let f = fiberKey && el[fiberKey];
    for (let n = 0; f && n < 8; n++, f = f.return) { const p = f.memoizedProps; if (p && p.flow && p.flow.id) return p.flow; }
    return null;
  }
  const TAG_TEXT = { mock: "MOCK", rule: "RULE", script: "SCRIPT", composed: "COMPOSED" };
  function tagsOf(comment) {
    const out = new Set(), mockNames = new Set(((state && state.rules) || []).filter((r) => r.action === "map_local").map((r) => r.name));
    for (const part of String(comment || "").split(" | ")) {
      if (part.startsWith("mock:")) out.add("mock");
      else if (part.startsWith("rule:")) out.add(mockNames.has(part.slice(5).split(" ")[0]) ? "mock" : "rule");
      else if (part.startsWith("script:")) out.add("script");
      else if (part === "composed" || part.startsWith("edit & retry")) out.add("composed");
    }
    return out;
  }
  const setAttr = (el, k, v) => { if (v === null) { if (el.hasAttribute(k)) el.removeAttribute(k); } else if (el.getAttribute(k) !== v) el.setAttribute(k, v); };
  function tagCells() {
    // host-only tunnel rows (not decrypted): attribute on the <tr> only (the path cell of a TCP flow reads "client ↔ server")
    document.querySelectorAll(".flow-table tbody tr").forEach((tr) => {
      const cell = tr.querySelector("td.col-path");
      const tunnel = cell && cell.textContent.includes(" ↔ ") ? "1" : "0";
      if (tr.dataset.tunnel !== tunnel) tr.dataset.tunnel = tunnel;
    });
    if (!skinOn()) return;
    const errors = new Set(viewers.graphql_error_ids || []);
    document.querySelectorAll(".flow-table tbody tr").forEach((tr) => {
      const path = tr.querySelector("td.col-path");
      if (!path) return;                                   // spacer rows
      const method = tr.querySelector("td.col-method"), status = tr.querySelector("td.col-status");
      if (method) setAttr(method, "data-m", method.textContent.trim());
      if (status) { const t = status.textContent.trim(); setAttr(status, "data-code", t || "—"); setAttr(status, "data-s", /^\d/.test(t) ? t.charAt(0) : "x"); }
      const txt = path.textContent, at = txt.indexOf("://"), cut = at < 0 ? -1 : txt.indexOf("/", at + 3);
      const hl = String(cut < 0 ? txt.length : cut);
      if (path.style.getPropertyValue("--hl") !== hl) path.style.setProperty("--hl", hl);
      const flow = flowOf(path);
      const tags = flow ? tagsOf(flow.comment) : new Set();
      const top = ["mock", "rule", "script", "composed"].find((t) => tags.has(t));
      const icon = tr.querySelector("td.col-icon");
      setAttr(path, "data-tag", top || null);
      setAttr(path, "data-tag-text", top ? TAG_TEXT[top] + (tags.size > 1 ? " +" + (tags.size - 1) : "") : null);
      setAttr(path, "title", top ? flow.comment : null);
      if (icon) {                                          // narrow list: the same tag as a one-letter glyph in the type-icon column
        setAttr(icon, "data-tag", top || null);
        setAttr(icon, "data-tag-glyph", top ? TAG_TEXT[top][0] : null);
        setAttr(icon, "title", top ? TAG_TEXT[top] + " — " + flow.comment : (tr.dataset.tunnel === "1" ? "TLS tunnel — not decrypted (add the host to the decrypt list in Network)" : null));
      }
      if (status) { const g = flow && (errors.has(flow.id) || String(flow.comment || "").split(" | ").includes("graphql:error")); setAttr(status, "data-gql-error", g ? "1" : "0"); setAttr(status, "title", g ? "GraphQL: the response body contains errors" : null); }
    });
    const line = document.querySelector(".flow-detail section.response .first-line");   // status line colour in the details pane
    if (line) { const m = line.textContent.match(/\b([1-5])\d\d\b/); setAttr(line, "data-s", m ? m[1] : null); }
    paintURLs();
    paintJSONBody();
    footerLabels();
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
      if ((m = t.match(/^(\d+) of (\d+) flows? selected$/))) {
        const kept = state && state.retention && state.retention.limit ? ` · showing last ${state.retention.limit} calls` : "";
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
  // list width buckets for theme.css: narrow (< 520px) drops size; wide (> 640px) shows the word chips
  const sizeBuckets = () => {
    const t = document.querySelector(".flow-table"); if (!t) return;
    const w = t.getBoundingClientRect().width;
    if (w) { setAttr(DOC, "data-narrow", w < 520 ? "1" : null); setAttr(DOC, "data-wide", w > 640 ? "1" : null); }
  };
  window.addEventListener("resize", () => { sizeBuckets(); placeBars(); });
  new MutationObserver(() => { clearTimeout(tagCells._t); tagCells._t = setTimeout(() => { tagCells(); sizeBuckets(); placeBars(); }, 60); })
    .observe(document.body, { childList: true, subtree: true, characterData: true });


  // ───────────── Search bar: always visible, drives mitmweb's own list filter ─────────────
  // mitmweb keeps the filter in its redux store (ui.filter.search) and sends it to the server, which evaluates it.
  // Its own Search box only exists on the "Flow List" tab (it vanishes as soon as a call is selected), so this bar
  // finds the store through the React root (read-only fiber walk, like flowOf) and dispatches the same action the
  // stock box does.  An INVALID filter makes the server close the websocket, so every filter is checked with the
  // server's own parser first (op filter_check).  Plain words become  ~u 'word'  (URL contains).
  const reFilter = (w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\/g, "\\\\").replace(/'/g, "\\'");   // regex-escape, then the filter parser's own un-escaping (HANDOVER §6 #3)
  const isExpr = (t) => /~[A-Za-z]/.test(t) || /^[!(]/.test(t) || /\s[&|]\s/.test(t);
  const toFilter = (text) => {
    const t = text.trim();
    if (!t) return "";
    if (isExpr(t)) return t;
    return t.split(/\s+/).map((w) => "~u '" + reFilter(w) + "'").join(" & ");
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
    if (!st) { toast("Can't reach mitmweb's filter (version changed?). Use the Search box on the Flow List tab.", true); return; }
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
  const sbSync = () => {
    const v = sq().value; $("sclear").hidden = !v; $("sbox").classList.toggle("has", !!v);
  };
  function wireSearch() {
    const input = sq();
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
      if (!confirm(`Clear all ${n} calls from the list?\n\nSaved sessions, rules and scripts are not affected.`)) return;
      try { const r = await fetch("./clear", { method: "POST", credentials: "same-origin", headers: { "X-XSRFToken": xsrf() } }); if (!r.ok) throw new Error("HTTP " + r.status); toast("List cleared"); }
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
    const chips = [];
    if (state) {
      const label = (state.project && state.project.label) || state.view_project;
      if (state.project_only) chips.push(["project", `Only ${label} calls`]);
      if (state.focus_host) chips.push(["host", `Only ${state.focus_host}`]);
      if (state.graphql_operation) chips.push(["gql", `GraphQL: ${state.graphql_operation}`]);
    }
    const searching = !!(st && storeSearch());
    let counts = "";
    if (st) { try { const f = st.getState().flows; counts = searching ? `${f.view.length} of ${f.list.length} calls match` : ""; } catch (e) { /* cosmetic */ } }
    const sig = JSON.stringify([chips, searching, counts]);
    const show = chips.length > 0 || searching;
    if (drawStrip._sig !== sig) {
      drawStrip._sig = sig;
      el.innerHTML = (chips.length ? `<span>Showing</span>` : "") + chips.map(([k, t]) => `<span class="fchip"><span title="${esc(t)}">${esc(t)}</span><button data-un="${k}" aria-label="Show everything again: ${esc(t)}" title="Remove this limit">${ico("x", "sm")}</button></span>`).join("") +
        (counts ? `<span class="cnt2">${esc(counts)} · <button class="lnk" data-un="search">Clear filter</button></span>` : "");
      el.querySelectorAll("[data-un]").forEach((b) => (b.onclick = () => {
        const k = b.dataset.un;
        if (k === "search") { sq().value = ""; sbSync(); commitSearch(""); }
        else if (k === "host") run("focus_host", { host: null }, "Showing all hosts");
        else if (k === "gql") run("graphql_filter", { name: null }, "GraphQL filter cleared");
        else run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic");
      }));
    }
    if (DOC.getAttribute("data-fstrip") !== (show ? "1" : null) && (show || DOC.hasAttribute("data-fstrip"))) { setAttr(DOC, "data-fstrip", show ? "1" : null); window.dispatchEvent(new Event("resize")); }
    el.style.display = show ? "" : "none";
    host.style.setProperty("--strip-h", show ? "28px" : "0px");
  }
  // fixed bars follow mitmweb's header: left edge after the tabs, right edge before the brand pill
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
    const brandL = window.innerWidth - openW - 12 - brand.offsetWidth;
    setAttr(DOC, "data-ribbon", hdr.getBoundingClientRect().width < 900 ? "icons" : null);
    hdr.querySelectorAll(".btn:not([title])").forEach((b) => { const t = b.textContent.replace(/[▾\s]+$/, "").trim(); if (t) b.title = t; });   // icon-only toolbar needs its names
    const links = [...nav.querySelectorAll("a")], last = links[links.length - 1];
    const left = Math.round((last.dataset.rv === "Selected call" ? last.getBoundingClientRect().right : last.getBoundingClientRect().right + 112) + 16), room = brandL - left - 12;
    host.style.setProperty("--sb-left", left + "px");
    const sbw = Math.max(140, Math.min(440, room - 34));   // 34 = the clear-list button
    host.style.setProperty("--sb-w", sbw + "px");
    if (host.hasAttribute("data-tight") !== (sbw < 270)) { if (sbw < 270) host.setAttribute("data-tight", ""); else host.removeAttribute("data-tight"); }
    host.style.setProperty("--hb", hb + "px");
    const rib = hdr.querySelector(":scope > div"), rr = rib ? rib.getBoundingClientRect() : null;
    host.style.setProperty("--fab-top", Math.round(rr && rr.height > 4 ? rr.top + (rr.height - 32) / 2 : hb + 8) + "px");
    $("sbar").style.top = Math.round(nr.top + (nr.height - 30) / 2) + "px";
    $("spop").style.top = Math.round(nr.top + (nr.height - 30) / 2 + 36) + "px";
  }
  wireSearch();


  // ───────────── Right-click on a call (the place Proxyman users reach for first) ─────────────
  const closeCallMenu = () => $("cmenu").classList.remove("open");
  async function openCallMenu(x, y, tr) {
    const mf = flowOf(tr); if (!mf) return;
    if (!tr.classList.contains("selected")) tr.click();                  // select it first, exactly like a left click
    const f = await flowsById(mf.id);
    const m = $("cmenu"), mod = KMOD;
    const isHttp = !!f && f.type === "http", hostName = isHttp ? f.request.pretty_host : ((f && (f.server_conn || {}).sni) || ((f && f.server_conn && f.server_conn.address) || [""])[0] || "");
    const item = (k, label, icon, extra = "", cls = "", dis = false) => `<button role="menuitem" data-k="${k}" class="${cls}" ${dis ? "disabled" : ""}>${ico(icon, "sm")}${label}${extra}</button>`;
    const focused = state && isHttp && state.focus_host === hostName;
    m.innerHTML = (isHttp
      ? `<div class="hd">${esc(f.request.method)} ${esc(hostName)}${esc(f.request.path.split("?")[0])}</div>` +
        item("map", "Map Local this call…", "map") + item("bp", "Pause on this call (Breakpoint)", "bp") +
        `<hr>` + item("repeat", "Repeat", "retry", `<kbd>${mod} ↵</kbd>`) + item("retry", "Edit &amp; Repeat…", "compose", `<kbd>${KALT} ${KSHIFT} ↵</kbd>`) + item("cmpA", "Compare: set as A", "cmp") +
        `<hr>` + item("curl", "Copy as cURL", "call") + item("url", "Copy URL", "call") +
        `<hr>` + item("host", focused ? "Show all hosts again" : "Show only this host", "search") + item("tls", "Stop decrypting this host", "lock")
      : `<div class="hd">${esc(hostName || "Host-only row")} — not decrypted</div>` + item("tlson", "Decrypt this host", "unlock")) +
      `<hr>` + item("del", "Delete this call", "trash", "", "d");
    m.classList.add("open"); openCallMenu.at = Date.now();
    const w = m.offsetWidth, h = m.offsetHeight;
    m.style.left = Math.max(6, Math.min(x, window.innerWidth - w - 6)) + "px"; m.style.top = Math.max(6, Math.min(y, window.innerHeight - h - 6)) + "px";
    const first = m.querySelector("button:not(:disabled)"); if (first) first.focus();
    m.querySelectorAll("button").forEach((b) => (b.onclick = async () => {
      closeCallMenu();
      const k = b.dataset.k, id = mf.id;
      if (k === "map") { const res = await run("mock", { flow_id: id }, (r) => (r.existing ? "Opened existing Map Local '" : "Map Local '") + r.name + "' is on"); if (res) { if (!$("drawer").classList.contains("open")) { setOpen(true); } openEditor(res.name); } }
      else if (k === "bp") run("bp_add", { flow_id: id, request: true, response: true }, "Breakpoint on — matching calls will pause");
      else if (k === "repeat") run("retry", { flow_id: id, edits: {} }, "Repeated — the new call is at the bottom of the list");
      else if (k === "retry") openRetry(id);
      else if (k === "cmpA") { cmpA = { id, label: f.request.method + " " + hostName + f.request.path }; openDrawer("cmp"); toast("Now select another call and press Compare"); }
      else if (k === "curl" || k === "url") copyExport(id, k);
      else if (k === "host") run("focus_host", { host: focused ? null : hostName }, focused ? "Showing all hosts" : "Showing only " + hostName);
      else if (k === "tls" || k === "tlson") run("tls_host", { flow_id: id, host: hostName, decrypt: k === "tlson" }, (r) => r.message);
      else if (k === "del" && confirm("Delete this call from the list?")) {
        try { const r = await fetch("./flows/" + id, { method: "DELETE", credentials: "same-origin", headers: { "X-XSRFToken": xsrf() } }); if (!r.ok) throw new Error("HTTP " + r.status); toast("Call deleted"); }
        catch (err) { toast("Could not delete: " + err.message, true); }
      }
    }));
  }
  document.addEventListener("contextmenu", (e) => {
    const tr = e.target.closest && e.target.closest(".flow-table tbody tr");
    if (!tr || !flowOf(tr)) { closeCallMenu(); return; }
    e.preventDefault(); openCallMenu(e.clientX, e.clientY, tr);
  }, true);
  // selecting the row scrolls / re-lays-out the list for a moment: only outside clicks, a real scroll later, or leaving the window close the menu
  ["mousedown", "scroll", "blur", "resize"].forEach((t) => window.addEventListener(t, (e) => {
    if (t === "mousedown" ? e.composedPath().includes($("cmenu")) : Date.now() - openCallMenu.at < 700) return;
    closeCallMenu();
  }, true));
  $("cmenu").addEventListener("keydown", (e) => {
    const bs = [...$("cmenu").querySelectorAll("button:not(:disabled)")], i = bs.indexOf(root.activeElement);
    if (e.key === "Escape") { closeCallMenu(); e.preventDefault(); }
    else if (e.key === "ArrowDown") { bs[(i + 1) % bs.length].focus(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { bs[(i - 1 + bs.length) % bs.length].focus(); e.preventDefault(); }
  });

  // ───────────── Edit & Retry (request editor in the sheet) ─────────────
  async function openRetry(id) {
    let p;
    try { p = await api("retry_get", { flow_id: id }); } catch (e) { return toast(e.message, true); }
    $("sheet").innerHTML = `
      <header class="retry"><b>${ico("retry", "sm")} Edit &amp; Retry</b><span class="sub">sends a copy; the original stays in the list</span></header>
      <main>
        <div class="btns" style="margin-top:0"><select id="rm">${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option ${x === p.method ? "selected" : ""}>${x}</option>`).join("")}</select>
          <input type="text" id="ru" class="grow" value="${esc(p.url)}"></div>
        <div class="seg"><button data-rsub="body" class="on">Body</button><button data-rsub="headers">Headers</button></div>
        <div id="rpb"><textarea id="rb" spellcheck="false" ${p.req_body_editable ? "" : "readonly"}>${esc(p.req_body)}</textarea></div>
        <div id="rph" style="display:none">${headersHTML(p.req_headers, "rhd")}</div>
      </main>
      <footer><button class="b" id="rcancel">Cancel</button><button class="b p" id="rsend">Send</button></footer>`;
    $("pause").classList.add("open");
    wireHeaders($("sheet"));
    root.querySelectorAll("[data-rsub]").forEach((b) => (b.onclick = () => {
      $("rpb").style.display = b.dataset.rsub === "body" ? "" : "none"; $("rph").style.display = b.dataset.rsub === "headers" ? "" : "none";
      root.querySelectorAll("[data-rsub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    $("rcancel").onclick = () => $("pause").classList.remove("open");
    $("rsend").onclick = async () => {
      const edits = { method: $("rm").value, url: $("ru").value, headers: readHeaders("rhd") };
      if ($("rb").value !== p.req_body && !$("rb").readOnly) edits.body = $("rb").value;
      const r = await run("retry", { flow_id: id, edits }, "Sent — the new call is at the bottom of the list");
      if (r) $("pause").classList.remove("open");
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
      catch (e) { prompt("Copy:", r.text); }
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
    return `<h4>HTTPS decryption ${info("Which hosts are decrypted so you can read their calls. Same idea as an SSL Proxying list.")}</h4>
      <div class="seg" id="tlsmode">${modes.map(([id, label]) => `<button data-tm="${id}" class="${t.mode === id ? "on" : ""}">${label}</button>`).join("")}</div>
      ${t.error ? `<div class="errbox">${esc(t.error)}</div>` : ""}
      ${list("allow", "Hosts to decrypt")}${list("ignore", "Hosts to leave alone")}
      <div class="sub" style="margin-top:6px">Changes apply to new connections — no restart. ${info(t.note || "")}</div>`;
  }
  function wireTlsSection() {
    const t = state.tls;
    root.querySelectorAll("[data-tm]").forEach((b) => (b.onclick = () => run("tls_set", { mode: b.dataset.tm }, "Decrypting: " + ({ all: "every host", allow: "only listed hosts", ignore: "everything except listed hosts" }[b.dataset.tm] || b.dataset.tm))));
    root.querySelectorAll("[data-tlsrm]").forEach((x) => (x.onclick = () => run("tls_set", { [x.dataset.tlsrm]: t[x.dataset.tlsrm].filter((p) => p !== x.dataset.p) }, "Removed " + x.dataset.p)));
    const add = (which) => {
      const input = root.querySelector(`[data-tlsadd="${which}"]`), value = input.value.trim().toLowerCase();
      if (value) run("tls_set", { [which]: t[which].concat(t[which].includes(value) ? [] : [value]) }, "Added " + value);
    };
    root.querySelectorAll("[data-tlsaddbtn]").forEach((b) => (b.onclick = () => add(b.dataset.tlsaddbtn)));
    root.querySelectorAll("[data-tlsadd]").forEach((i) => (i.onkeydown = (e) => { if (e.key === "Enter") add(i.dataset.tlsadd); }));
  }

  // ───────────── Compose (a new request from scratch) ─────────────
  const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
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
        <button class="b" id="cload">Load</button><button class="b" id="cnew">New</button></div>
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
      <div class="sub" style="margin-top:6px">Runs through your rules and scripts · appears at the bottom of the list as COMPOSED.</div>
      <h4>Copy</h4>${copyAsHTML("cc")}`;
    drawSection();
    $("cm").oninput = () => (draft.method = $("cm").value.trim().toUpperCase());
    $("cu").oninput = () => { draft.url = $("cu").value; rowsFromUrl(); if (composeSub === "params") drawSection(); };
    root.querySelectorAll("[data-cs]").forEach((b) => (b.onclick = () => { composeSub = b.dataset.cs; if (composeSub !== "vars") varRows = null; render(); }));
    $("cnew").onclick = () => { draft = newDraft(); composeSub = "params"; render(); };
    $("cload").onclick = async () => {
      const name = $("cs").value; if (!name) return toast("Pick a saved request first", true);
      const r = await run("compose_load", { name }); if (!r) return;
      loadDraft(r.spec, name); render();
    };
    const saveAs = async (name) => {
      if (!name) return;
      const r = await run("compose_save", { name, spec: specOf() }, "Saved " + name);
      if (r) { draft.name = name; render(); }
    };
    $("csave").onclick = () => (draft.name ? saveAs(draft.name) : saveAs(prompt("Save as (letters, digits . _ -):", "")));
    $("csaveas").onclick = () => saveAs(prompt("Save as (letters, digits . _ -):", draft.name || ""));
    $("cren").onclick = async () => {
      const next = prompt("New name:", draft.name); if (!next || next === draft.name) return;
      const r = await run("compose_rename", { old: draft.name, new: next }, "Renamed to " + next);
      if (r) { draft.name = next; render(); }
    };
    $("cdel").onclick = async () => {
      if (!confirm("Delete saved request '" + draft.name + "'?")) return;
      const r = await run("compose_delete", { name: draft.name }, "Deleted " + draft.name);
      if (r) { draft.name = ""; render(); }
    };
    $("csend").onclick = () => run("compose_send", { spec: specOf() }, (x) => "Sent " + x.method + " " + x.url + " — see the bottom of the list");
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
    if (a === "map_local") return "answers from a saved response" + (r.status ? " (" + r.status + ")" : "");
    if (a === "respond") return "answers with " + r.status;
    if (a === "status") return "changes the status to " + r.status;
    if (a === "delay") return "waits " + r.ms + " ms first";
    if (a === "json_patch") return "changes " + Object.keys(r.set || {}).join(", ") + " in the JSON reply";
    if (a === "set_header") return (r.value == null ? "removes the " : "sets the ") + r.header + " header";
    if (a === "map_remote") return "sends it to " + r.with;
    if (a === "block" || a === "drop") return "blocks the call (the app gets a network error)";
    return a;
  }
  function renderRules(m) {
    const skipped = state.skipped_rules || [];
    if (!state.rules.length && !skipped.length) { m.innerHTML = emptyState("rules", "No rules yet", "Select a call and use <b>This call</b> — Map Local, a forced status, a block or a delay all become rules here."); return; }
    m.innerHTML = (state.rules_error ? `<div class="banner bad"><b>${ico("warn", "sm")} rules.json has an error:</b> ${esc(state.rules_error)}</div>` : "") + (skipped.length ? `<div class="banner bad" style="display:block"><b>${ico("warn", "sm")} ${skipped.length} rule(s) skipped</b>${skipped.map((r) => `<div class="sub">${esc(r.name)} — ${esc(r.error)}</div>`).join("")}</div>` : "") + state.rules.map((r, i) => `
      <div class="row">${sw(`data-i="${i}"`, r.enabled !== false)}
        <div class="n"><div><b>${esc(r.name)}</b><span class="tag">${esc(ACTION_NAME[r.action] || r.action)}</span>${(state.rules_outside || []).includes(r.name) ? `<span class="tag" title="Reads a file outside the project. Allowed only for files you trusted on this machine (${esc(state.product.cli)} rules trusted-files). Edit it in your own editor.">external file</span>` : ""}</div>
          <div class="sub">${esc(r.method ? r.method + " " : "")}${esc(pretty(r))} — ${esc(describe(r))}</div></div>
        ${r.action === "map_local" && !(state.rules_outside || []).includes(r.name) ? `<button class="b" data-edit="${i}">Edit</button>` : ""}
        <button class="b d" data-del="${i}" title="Delete" aria-label="Remove">${ico("x", "sm")}</button></div>`).join("") +
      `<p class="sub">Saved in ${esc(state.rules_file)} — also editable with <code>${esc(state.product.cli)} rules</code>.</p>`;
    wireRuleRows(m);
  }
  function wireRuleRows(m) {
    m.querySelectorAll("input[data-i]").forEach((c) => (c.onchange = () =>
      run("toggle", { name: state.rules[c.dataset.i].name, enabled: c.checked }, c.checked ? "Rule on" : "Rule off")));
    m.querySelectorAll("[data-del]").forEach((b) => (b.onclick = () => {
      const n = state.rules[b.dataset.del].name;
      if (confirm("Delete rule '" + n + "'?")) run("delete", { name: n }, "Deleted " + n);
    }));
    m.querySelectorAll("[data-edit]").forEach((b) => (b.onclick = () => openEditor(state.rules[b.dataset.edit].name)));
  }

  // ───────────── Map Local editor (Body / Headers, like FRTMProxy) ─────────────
  async function openEditor(name) {
    try { const r = await api("mockfile_get", { name }); editing = { name, sub: "body", ...r }; render(); }
    catch (e) { toast(e.message, true); }
  }
  function renderEditor(m) {
    const e = editing;
    m.innerHTML = `
      <div class="btns" style="margin-top:0"><button class="b" id="back">${ico("back", "sm")}Back</button>
        <b style="flex:1;align-self:center;overflow:hidden;text-overflow:ellipsis">${esc(e.name)}</b>
        status <input type="number" id="st" value="${esc(e.status)}" style="width:70px"></div>
      <div class="sub" style="margin-top:6px">${esc(e.method || "ANY")} ${esc(pretty({ match: e.match }))}</div>
      <div class="seg"><button data-sub="body" class="${e.sub === "body" ? "on" : ""}">Body</button><button data-sub="headers" class="${e.sub === "headers" ? "on" : ""}">Headers</button></div>
      <div id="pbody" style="${e.sub === "body" ? "" : "display:none"}">
        <textarea id="body" spellcheck="false" ${e.editable ? "" : "readonly"}>${esc(e.content)}</textarea>
        <div class="btns"><button class="b" id="fmt">Format JSON</button><span class="sub" id="jsonok"></span></div></div>
      <div id="phdr" style="${e.sub === "headers" ? "" : "display:none"}">${headersHTML(e.headers, "hd")}
        <div class="sub">Content-Type defaults to the file type when not set.</div></div>
      <div class="btns"><button class="b p" id="save" ${e.editable ? "" : "disabled"}>Save</button><span class="sub" id="dirty"></span></div>
      <div class="sub">${esc(e.file)} — the next matching call gets this.</div>`;
    const ta = $("body");
    jsonCheck(ta, $("jsonok"));
    ta.oninput = () => { jsonCheck(ta, $("jsonok")); editing.content = ta.value; $("dirty").textContent = "Modified"; };
    root.querySelectorAll("[data-sub]").forEach((b) => (b.onclick = () => {
      editing.content = ta.value; editing.headers = readHeaders("hd"); editing.status = $("st").value; editing.sub = b.dataset.sub; render();
    }));
    wireHeaders(m);
    $("back").onclick = () => { editing = null; render(); };
    $("fmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2) + "\n"; ta.oninput(); } catch (x) { toast("Not JSON — cannot format", true); } };
    $("save").onclick = async () => {
      if (!jsonCheck(ta, $("jsonok")) && !confirm("This is not valid JSON. Save anyway?")) return;
      const headers = readHeaders("hd");
      const r = await run("mockfile_put", { name: e.name, content: ta.value, status: $("st").value, headers }, "Saved — next call gets it");
      if (r) editing = { ...editing, content: ta.value, status: $("st").value, headers };
    };
  }

  // ───────────── Paused call sheet (opens by itself) ─────────────
  async function openPaused(id) {
    try { pausedOpen = await api("paused_get", { id }); pausedOpen.sub = "body"; drawPaused(); }
    catch (e) { pausedOpen = null; $("pause").classList.remove("open"); toast(e.message, true); }
  }
  function drawPaused() {
    const p = pausedOpen, isResp = p.phase === "response";
    const q = state ? state.paused.length : 1;
    $("sheet").innerHTML = `
      <header class="paused"><b>${ico("pause", "sm")} Paused at ${isResp ? "response" : "request"}${q > 1 ? ` · ${q} waiting` : ""}</b>
        <span class="sub" style="max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.method)} ${esc(p.url)}</span></header>
      <main>
        ${isResp ? `<div class="btns" style="margin-top:0">Status <input type="number" id="pst" value="${esc(p.status)}" style="width:80px"></div>`
                 : `<div class="btns" style="margin-top:0"><select id="pm">${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((x) => `<option ${x === p.method ? "selected" : ""}>${x}</option>`).join("")}</select>
                    <input type="text" id="pu" class="grow" value="${esc(p.url)}"></div>`}
        <div class="seg"><button data-psub="body" class="${p.sub === "body" ? "on" : ""}">Body</button><button data-psub="headers" class="${p.sub === "headers" ? "on" : ""}">Headers</button></div>
        <div id="ppb" style="${p.sub === "body" ? "" : "display:none"}"><textarea id="pb" spellcheck="false" placeholder="No body" class="${(isResp ? p.resp_body : p.req_body) ? "" : "nobody"}" ${(isResp ? p.resp_body_editable : p.req_body_editable) ? "" : "readonly"}>${esc(isResp ? p.resp_body : p.req_body)}</textarea>
          <div class="btns"><button class="b" id="pfmt">Format JSON</button><span class="sub" id="pjs"></span></div></div>
        <div id="pph" style="${p.sub === "headers" ? "" : "display:none"}">${headersHTML(isResp ? p.resp_headers : p.req_headers, "phd")}</div>
      </main>
      <footer><span class="sub" style="margin-right:auto">The app is waiting — continue within its timeout (~30–60 s).</span>
        <button class="b d" id="pabort">Abort</button><button class="b" id="pskip">Skip (send unchanged)</button>
        <button class="b p" id="pcont">Continue</button></footer>`;
    $("pause").classList.add("open");
    const ta = $("pb"); jsonCheck(ta, $("pjs")); ta.oninput = () => jsonCheck(ta, $("pjs"));
    wireHeaders($("sheet"));
    root.querySelectorAll("[data-psub]").forEach((b) => (b.onclick = () => {
      $("ppb").style.display = b.dataset.psub === "body" ? "" : "none"; $("pph").style.display = b.dataset.psub === "headers" ? "" : "none";
      root.querySelectorAll("[data-psub]").forEach((x) => x.classList.toggle("on", x === b));
    }));
    $("pfmt").onclick = () => { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); jsonCheck(ta, $("pjs")); } catch (x) { toast("Not JSON", true); } };
    const done = async (op, edits) => {
      const id = p.id;
      const r = await run(op, { id, edits }, op === "paused_continue" ? "Continued with your edits" : op === "paused_skip" ? "Sent unchanged" : "Aborted");
      if (!r) return;
      pausedOpen = null; $("pause").classList.remove("open");
      const next = (state.paused || []).find((x) => !dismissed.has(x.id));
      if (next) openPaused(next.id);
    };
    $("pcont").onclick = () => {
      const original = isResp ? p.resp_body : p.req_body;
      const edits = { headers: readHeaders("phd") };
      if (ta.value !== original && !ta.readOnly) edits.body = ta.value;   // untouched body: bytes pass through as-is
      if (isResp) edits.status = Number($("pst").value); else { edits.method = $("pm").value; edits.url = $("pu").value; }
      done("paused_continue", edits);
    };
    $("pskip").onclick = () => done("paused_skip");
    $("pabort").onclick = () => done("paused_abort");
  }

  // poll for paused calls so the sheet opens by itself, like FRTMProxy / Proxyman
  let viewerPoll = null;
  async function refreshViewerSummaries() {
    if (viewerPoll || !$("drawer").classList.contains("open")) return viewerPoll;
    viewerPoll = api("viewer_summaries", { limit:12 }).then((r) => {
      viewers = r.viewers || viewers;
      tagCells();
    }).catch(() => {}).finally(() => { viewerPoll = null; });
    return viewerPoll;
  }
  async function poll() {
    try {
      const s = await api("state");
      state = s; badges();
      if ($("drawer").classList.contains("open")) await refreshViewerSummaries();
      await refreshFlows(); tagCells(); sizeBuckets(); placeBars(); pullSearch(); drawStrip();
      const waiting = s.paused.filter((x) => !dismissed.has(x.id));
      if (!pausedOpen && waiting.length && !$("pause").classList.contains("open")) openPaused(waiting[0].id);
      if (pausedOpen && !s.paused.some((x) => x.id === pausedOpen.id)) { pausedOpen = null; $("pause").classList.remove("open"); }
      if ($("drawer").classList.contains("open") && tab === "coll" && !editing && !root.activeElement && s.collections.recording) render();
      if ($("drawer").classList.contains("open") && !editing && (tab === "bp" || tab === "rules" || tab === "map" || tab === "scripts") && !root.activeElement) render();
    } catch (e) { /* mitmweb restarting: try again */ }
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
    setOpen(!$("drawer").classList.contains("open")); state = null; render(); refreshViewerSummaries().then(() => {
      if ($("drawer").classList.contains("open") && tab === "call" && !editing) render();
    });
  };
  $("close").onclick = () => setOpen(false);
  $("pause").onclick = (e) => { if (e.target === $("pause")) { dismissed.add(pausedOpen && pausedOpen.id); pausedOpen = null; $("pause").classList.remove("open"); toast("Still paused — click the Tools button (it shows how many are waiting) to reopen"); } };
  $("project").onchange = () => {
    const v = $("project").value, label = $("project").selectedOptions[0].textContent.replace(/ only$/, "");
    if (v === "__all") return run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic");
    run("view", { project: v, project_only: true, show_dns: false }, `Showing only ${label} calls. Its rules load when you start with --project ${v}`);
  };
  root.querySelectorAll("nav button").forEach((b) => (b.onclick = () => { tab = b.dataset.t; editing = null; render(); }));
  // mitmweb changes the selection with history.replaceState, which fires no "hashchange" —
  // so watch the selected call id ourselves
  // tells flow retention which call to keep; mitmweb sets its XSRF cookie only after its first requests,
  // so skip until then (a POST without it is refused and logs a console error)
  const noteSelected = (id) => { if (xsrf()) api("flow_selected", { id }).catch(() => {}); };
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
  const openDrawer = (t) => {
    if (!$("drawer").classList.contains("open")) { setOpen(true); state = null; }
    if (t) { tab = t; editing = null; }
    render();
  };
  const repeatSelected = () => {
    const id = selectedFlow();
    if (!id) return toast("Select a call in the list first", true);
    run("retry", { flow_id: id, edits: {} }, "Repeated — the new call is at the bottom of the list");
  };
  const focusFilter = () => {
    if (skinOn() && host.hasAttribute("data-sbar")) return focusSearch();
    const link = [...document.querySelectorAll("header nav a")].find((a) => a.textContent.trim() === "Flow List");
    if (link) link.click();
    setTimeout(() => { const i = document.querySelector('.filter-input input[placeholder="Search"]'); if (i) { i.focus(); i.select(); } }, 80);
  };
  // chords are Alt+Shift+<key>: the Cmd/Cmd-Alt combinations desktop proxy tools use are claimed by the browser
  const CHORDS = {
    KeyP: ["Open / close the tools drawer", () => (state && $("drawer").classList.contains("open") ? setOpen(false) : openDrawer())],
    KeyC: ["Compose a new request", () => openDrawer("compose")],
    KeyL: ["Map Local", () => openDrawer("map")],
    KeyB: ["Breakpoints", () => openDrawer("bp")],
    KeyN: ["Network conditions", () => openDrawer("net")],
    KeyE: ["TLS decryption list (SSL proxying)", () => openDrawer("net")],
    KeyS: ["Scripts", () => openDrawer("scripts")],
    KeyD: ["Compare (diff) two calls", () => openDrawer("cmp")],
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
      [kb(KMOD, "F"), "Filter the list — Esc clears"],
      [kb(KALT, KSHIFT, "F"), "Filter the list (same)"],
      [kb(KMOD, "↵"), "Repeat the selected call"],
      [kb(KALT, KSHIFT, "↵"), "Edit & Repeat the selected call"],
      [kb("?"), "This sheet"],
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
    ["Map Local (answer a call from a saved response)", "On the call: <b>This call → Map Local this call…</b>; or the <b>Map Local</b> tab to add by host and path", "call"],
    ["Breakpoint", "<b>This call → Breakpoint</b> (Request / Response); manage in the <b>Breakpoints</b> tab", "bp"],
    ["Network Conditions (throttle)", "<b>Network</b> tab → traffic profiles", "net"],
    ["Compose a new request", "<b>Compose</b> tab, or <b>Compose from this call</b>", "compose"],
    ["Repeat / Edit & Repeat", "Repeat: " + kb(KMOD, "↵") + " or " + kb("r") + ". Edit: <b>This call → Edit &amp; Retry…</b>", "call"],
    ["Diff two requests", "<b>Compare</b> tab: <i>Compare: set as A</i> on a call, then select another", "cmp"],
    ["Export HAR", "<b>Sessions</b> or <b>Collections</b> → <i>HAR</i>", "sess"],
    ["Filter by host / app", "The filter box at the top (" + kb(KMOD, "F") + "): type a host or part of a URL. Or <b>right-click → Show only this host</b>", "filter"],
    ["Clear the session", "The trash button next to the filter box (asks first)", "filter"],
    ["Right-click a call", "Map Local, Breakpoint, Repeat, Copy as cURL, Show only this host…", "call"],
    ["SSL Proxying list", "<b>Network → HTTPS decryption</b> (every host, only the hosts you list, or all except the ones you list)", "net"],
    ["Scripting", "<b>Scripts</b> tab (JavaScript or Python, per project)", "scripts"],
    ["Save a session", "<b>Sessions</b> tab → save, add a note, reopen later", "sess"],
    ["Copy as cURL", "<b>This call → Copy cURL</b> or <b>Copy as…</b> (many languages)", "call"],
  ];
  const goTo = (t) => { closeHelp(); if (t === "filter") focusFilter(); else openDrawer(t); };
  const mapTable = (rows) => `<table class="map"><tr><th>In Proxyman you did</th><th>Here</th><th></th></tr>${rows.map(([a, b, g]) =>
    `<tr><td>${a}</td><td>${b}</td><td class="go"><button class="lnk" data-go="${g}">Open →</button></td></tr>`).join("")}</table>`;
  const closeHelp = () => $("help").classList.remove("open");
  function openHelp(which) {
    const tabs = { map: "Coming from Proxyman?", keys: "Shortcuts", settings: "Settings" };
    const body = {
      map: () => `<p class="sub" style="margin:0 0 8px">Same tools, same names where they are generic — placed on the call or in the drawer. Rivis runs in a browser tab, captures the simulator per process (no system proxy) and has a project switcher.</p>${mapTable(MAPPING)}`,
      keys: () => SHORTCUTS.map(([h, rows]) => `<h4>${h}</h4><table class="map">${rows.map(([k, d]) => `<tr><td style="width:46%">${k}</td><td>${d}</td></tr>`).join("")}</table>`).join("") +
        `<p class="sub">Single keys are ignored while you type in a field. Alt+Shift chords avoid the browser's own ${KMOD} shortcuts.</p>`,
      settings: () => `
        <div class="set"><div><b>Theme</b><span class="sub">System follows your OS setting</span></div>
          <div class="seg" style="margin:0">${["system", "light", "dark"].map((m) => `<button data-theme-set="${m}" class="${themeMode() === m ? "on" : ""}">${m[0].toUpperCase() + m.slice(1)}</button>`).join("")}</div></div>
        <div class="set"><div><b>Compact rows</b><span class="sub">Tighter type and padding in the call list</span></div>${sw('id="set-compact"', compactOn())}</div>
        <div class="set"><div><b>Rivis look</b><span class="sub">Off = the plain built-in look. Also: add <code>?theme=off</code> to the page address</span></div>${sw('id="set-skin"', skinOn())}</div>
        <div class="set"><div><b>Welcome card</b><span class="sub">The first-open “Coming from Proxyman?” card</span></div><button class="b" id="set-welcome">Show again</button></div>`,
    };
    $("hsheet").innerHTML = `
      <header><span class="mark">${ico("mark")}</span><b>${esc((state && state.product.name) || "Rivis")} <small>/ Help</small></b>
        <div class="seg" style="margin:0">${Object.entries(tabs).map(([k, v]) => `<button data-h="${k}" class="${k === which ? "on" : ""}">${v}</button>`).join("")}</div>
        <button class="x" id="hclose" aria-label="Close">×</button></header>
      <main>${body[which]()}</main>`;
    $("help").classList.add("open");
    $("hclose").onclick = closeHelp;
    root.querySelectorAll("[data-h]").forEach((b) => (b.onclick = () => openHelp(b.dataset.h)));
    root.querySelectorAll("#hsheet [data-go]").forEach((a) => (a.onclick = () => goTo(a.dataset.go)));
    root.querySelectorAll("[data-theme-set]").forEach((b) => (b.onclick = () => { applyTheme(b.dataset.themeSet); openHelp("settings"); }));
    if ($("set-compact")) $("set-compact").onchange = () => applyDensity($("set-compact").checked);
    if ($("set-skin")) $("set-skin").onchange = () => { setSkin($("set-skin").checked); toast($("set-skin").checked ? "Rivis look on" : "Plain built-in look"); };
    if ($("set-welcome")) $("set-welcome").onclick = () => { LS.set("rivis-welcome", ""); closeHelp(); showWelcome(); };
  }
  $("help").onclick = (e) => { if (e.target === $("help")) closeHelp(); };
  $("bhelp").onclick = () => openHelp("map");
  $("gear").onclick = () => openHelp("settings");
  $("btheme").onclick = () => applyTheme({ system: "light", light: "dark", dark: "system" }[themeMode()]);

  const closeWelcome = () => { LS.set("rivis-welcome", "done"); $("welcome").classList.remove("open"); try { drawEmptyList(); } catch (e) { /* cosmetic */ } };
  $("wscrim").onclick = closeWelcome;
  function showWelcome() {
    if (LS.get("rivis-welcome", "") === "done") return;
    const name = (state && state.product.name) || "Rivis";
    $("welcome").innerHTML = `
      <h3><span class="mark">${ico("mark")}</span>Welcome to ${esc(name)}</h3>
      <div class="wbody"><p>Coming from Proxyman? The tools you know are here, placed on the call or in the drawer on the right.
        Same names where they are generic. Rivis runs in a browser tab and does not set a system proxy.</p>
      ${mapTable(MAPPING)}</div>
      <div class="btns wfoot" style="justify-content:flex-end"><button class="b" id="w-keys">Shortcuts</button><button class="b p" id="w-ok">Got it</button></div>`;
    $("welcome").classList.add("open");
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
    if (f.list.length === 0) return "first";
    return f.view.length === 0 ? "hidden" : null;
  }
  function drawEmptyList() {
    const box = $("emptylist");
    const kind = skinOn() ? emptyKind() : null;
    if (!kind || $("welcome").classList.contains("open")) { if (box.classList.contains("open")) { box.classList.remove("open"); box.dataset.sig = ""; } setAttr(DOC, "data-rv-empty", null); return; }
    const cli = state.product.cli || "rivis", proj = state.active_project && state.active_project !== "default" ? ` --project ${state.active_project}` : "";
    const q = (storeSearch() === lastSent && sq().value.trim()) || storeSearch(), label = (state.project && state.project.label) || state.view_project;
    const limits = [];
    if (state.project_only) limits.push(`only ${label} calls`);
    if (state.focus_host) limits.push(`only ${state.focus_host}`);
    if (state.graphql_operation) limits.push(`GraphQL ${state.graphql_operation}`);
    const sig = JSON.stringify([kind, q, limits, cli, proj]);
    if (box.dataset.sig === sig && box.classList.contains("open")) return;
    box.dataset.sig = sig;
    if (kind === "first") {
      box.innerHTML = `<div class="box"><div class="glyph">${ico("inbox")}</div>
        <h3>Nothing captured yet</h3>
        <div class="lede">${esc(state.product.name || "Rivis")} is listening${label ? " for <b>" + esc(label) + "</b>" : ""}. Run one command for the device you test on, then use the app — its calls show up here within a second.</div>
        <div class="cols">
          <div class="opt"><h5>${ico("phone", "sm")} iOS Simulator</h5><code class="cmd" data-copy="${esc(cli + proj + " ios on")}" title="Click to copy">${esc(cli + proj + " ios on")}</code>
            <div class="sub">Trusts the certificate on the booted simulator (once). Then open the app.</div></div>
          <div class="opt"><h5>${ico("phone", "sm")} Android emulator</h5><code class="cmd" data-copy="${esc(cli + proj + " android on")}" title="Click to copy">${esc(cli + proj + " android on")}</code>
            <div class="sub">Points the emulator at ${esc(state.product.name || "Rivis")} and installs the certificate. Then open the app.</div></div>
        </div>
        <div class="foot">Run these in a terminal. Nothing from a simulator? Quit any other proxy app first — only one tool can own the system proxy.</div></div>`;
    } else {
      const why = q ? `No calls match <b>${esc(q)}</b>` : "Every call is hidden by your view settings";
      const sub = q ? "Try a shorter word, or the host name only. Filters with <code>~</code> must be written exactly (see the examples in the search box)."
                    : `Showing ${esc(limits.join(" and "))}. The calls are still captured — remove the limit to see them.`;
      box.innerHTML = `<div class="box"><div class="glyph">${ico("search")}</div><h3>${why}</h3><div class="lede">${sub}</div>
        <div class="btns">${q ? '<button class="b p" data-act="clear">Clear filter</button>' : ""}${limits.length ? `<button class="b ${q ? "" : "p"}" data-act="all">Show all traffic</button>` : ""}</div></div>`;
    }
    box.classList.add("open"); setAttr(DOC, "data-rv-empty", kind === "first" ? "1" : null);
    box.querySelectorAll("[data-copy]").forEach((c) => (c.onclick = () => navigator.clipboard.writeText(c.dataset.copy).then(() => toast("Copied — paste it in a terminal"), () => toast("Select the command and copy it"))));
    box.querySelectorAll("[data-act]").forEach((b) => (b.onclick = async () => {
      if (b.dataset.act === "clear") { sq().value = ""; sbSync(); commitSearch(""); }
      else { if (state.focus_host) await run("focus_host", { host: null }); if (state.graphql_operation) await run("graphql_filter", { name: null }); await run("view", { project_only: false, show_dns: state.show_dns }, "Showing all traffic"); }
    }));
  }

  window.addEventListener("keydown", (e) => {
    const t = e.composedPath ? e.composedPath()[0] : e.target;
    const typing = !!t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.code === "KeyF" && skinOn() && host.hasAttribute("data-sbar") && root.activeElement !== sq()) { e.preventDefault(); e.stopPropagation(); focusSearch(); return; }   // a second press lets the browser's find-in-page open
    if (e.altKey && e.shiftKey && !e.metaKey && !e.ctrlKey && CHORDS[e.code]) { e.preventDefault(); e.stopPropagation(); CHORDS[e.code][1](); return; }
    if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key === "Enter" && !typing) { e.preventDefault(); e.stopPropagation(); repeatSelected(); return; }
    if (e.key === "?" && !e.metaKey && !e.ctrlKey && !e.altKey && !typing) { e.preventDefault(); e.stopPropagation(); openHelp("keys"); return; }
    if (e.key === "Escape" && $("help").classList.contains("open")) { e.stopPropagation(); closeHelp(); }
    else if (e.key === "Escape" && $("welcome").classList.contains("open")) { e.stopPropagation(); closeWelcome(); }
  }, true);
  setInterval(() => { try { drawEmptyList(); } catch (err) { /* cosmetic */ } }, 1500);
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
