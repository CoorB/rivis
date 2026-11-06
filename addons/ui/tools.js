/* Rivis main window: tool windows. Each tool (Map Local, Map Remote, Breakpoint, Scripting,
 * Network, …) has its own window, opened from the toolbar, its shortcut or the right-click menu, as in Proxyman.
 * Windows float over the main window: drag by the title, resize from the corner, Esc closes, the front one is the one
 * last clicked. Position and size are kept per tool (this browser only).
 *
 * A tool file registers itself:
 *   RivisTools.register(id, { title, render(win), onState(state, win), dirty(win) })
 *     render  fills win.body (and win.foot) each time the window opens
 *     onState runs with every state poll while the window is open (and for a tool with always: true, also when shut)
 *     dirty   true when closing would lose typed changes: the window asks first
 * The tool talks to the server only through window.RivisApp (app.js). */
(() => {
  "use strict";
  const A = window.RivisApp;
  if (!A) return;
  const { $, esc } = A;
  const store = {
    get(k) { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private window */ } },
  };
  const defs = new Map(), wins = new Map();
  let z = 30, cascade = 0;

  function front(w) { w.el.style.zIndex = String(++z); wins.forEach((x) => x.el.classList.toggle("front", x === w)); }

  // A tool window opens DOCKED on the right, beside the list, and the list shrinks to make room (like the classic
  // Tools drawer), so the call being worked on stays visible. Dragging it by its title bar makes it a free window,
  // remembered as such; docked or free is remembered per window.
  function mainBox() {
    const m = document.querySelector(".rv-main"), r = m && m.getBoundingClientRect();
    return r && r.height > 50 ? { top: r.top, bottom: r.bottom } : { top: 70, bottom: innerHeight - 28 };
  }
  const DOCK_MIN = 380;      // = .rv-win min-width in app.css
  function dock(w, def, saved) {
    // docked: at most 480px and never more than ~36% of the window, so the list and the call keep the larger part
    const width = Math.round(Math.max(DOCK_MIN, Math.min((saved && saved.w) || Math.min(def.width || 720, 480), innerWidth * 0.36)));   // never below the CSS min-width, or the window overhangs its own left edge
    const b = mainBox();
    w.docked = true;
    Object.assign(w.el.style, { left: (innerWidth - width - 6) + "px", top: Math.round(b.top) + "px", width: width + "px",
                                height: Math.max(200, Math.round(b.bottom - b.top)) + "px" });
  }
  function relayout() {
    // size the docked windows FIRST, then reserve exactly the room they now take (measuring before sizing reserved
    // the width the window had before this call, so the list ended up under the dock below ~1440 px)
    let px = 0;
    wins.forEach((w) => { if (w.shown && w.docked && !w.el.hidden) dock(w, w.def, { w: w.el.offsetWidth }); });
    wins.forEach((w) => { if (w.shown && w.docked && !w.el.hidden) px = Math.max(px, w.el.offsetWidth + 12); });
    document.documentElement.style.setProperty("--rv-dock", px + "px");
  }
  addEventListener("resize", () => relayout());
  function place(w, def) {
    const saved = store.get("rivis-win-" + w.id);
    if (!saved || saved.docked) { dock(w, def, saved); return; }
    w.docked = false;
    const vw = innerWidth, vh = innerHeight;
    const width = Math.min((saved && saved.w) || def.width || 720, vw - 24), height = Math.min((saved && saved.h) || def.height || 520, vh - 24);
    let left = saved ? saved.x : Math.round((vw - width) / 2) + (cascade % 5) * 24, top = saved ? saved.y : 70 + (cascade % 5) * 24;
    if (!saved) cascade++;
    left = Math.max(4, Math.min(left, vw - 120)); top = Math.max(4, Math.min(top, vh - 60));
    Object.assign(w.el.style, { left: left + "px", top: top + "px", width: width + "px", height: height + "px" });
  }
  const remember = (w) => { const r = w.el.getBoundingClientRect(); store.set("rivis-win-" + w.id, { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height), docked: !!w.docked }); };

  function build(id, def) {
    const el = document.createElement("section");
    el.className = "rv-win"; el.dataset.win = id;
    el.setAttribute("role", "dialog"); el.setAttribute("aria-modal", "false"); el.setAttribute("aria-labelledby", "win-t-" + id);
    el.innerHTML = `<header class="rv-win-h"><b id="win-t-${esc(id)}">${esc(def.title)}</b><span class="rv-win-sub"></span>`
      + `<button class="rv-win-x" type="button" aria-label="Close ${esc(def.title)}" title="Close (Esc)">✕</button></header>`
      + `<div class="rv-win-b"></div><footer class="rv-win-f" hidden></footer>`;
    document.body.appendChild(el);
    const w = { id, def, el, body: el.querySelector(".rv-win-b"), foot: el.querySelector(".rv-win-f"), sub: el.querySelector(".rv-win-sub"),
      data: {}, opener: null, setSub: (t) => { w.sub.textContent = t || ""; } };
    el.querySelector(".rv-win-x").onclick = () => close(id);
    el.addEventListener("pointerdown", () => front(w), true);
    el.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !e.defaultPrevented && !document.querySelector("#dialog:not([hidden])")) { e.preventDefault(); e.stopPropagation(); close(id); }
    });
    // drag by the title bar (not by its buttons)
    const head = el.querySelector(".rv-win-h");
    head.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || e.target.closest("button, input, select, a")) return;
      e.preventDefault();
      const r = el.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top, x0 = e.clientX, y0 = e.clientY;
      const move = (m) => {
        if (w.docked && Math.abs(m.clientX - x0) + Math.abs(m.clientY - y0) < 6) return;   // a click, not a drag
        if (w.docked) { w.docked = false; relayout(); }
        el.style.left = Math.max(-r.width + 120, Math.min(innerWidth - 120, m.clientX - dx)) + "px";
        el.style.top = Math.max(0, Math.min(innerHeight - 40, m.clientY - dy)) + "px";
      };
      const up = () => { removeEventListener("pointermove", move); removeEventListener("pointerup", up); remember(w); };
      addEventListener("pointermove", move); addEventListener("pointerup", up);
    });
    if (window.ResizeObserver) {
      let t = 0;
      new ResizeObserver(() => { clearTimeout(t); t = setTimeout(() => { if (!el.hidden) { remember(w); if (w.docked) relayout(); } }, 300); }).observe(el);
    }
    place(w, def);
    return w;
  }

  function open(id, opts) {
    const def = defs.get(id);
    if (!def) return null;
    let w = wins.get(id);
    if (!w) { w = build(id, def); wins.set(id, w); }
    const wasOpen = !w.el.hidden && w.el.isConnected && w.shown;
    w.opts = opts || {};
    if (!wasOpen) w.opener = document.activeElement;
    w.el.hidden = false; w.shown = true;
    front(w);
    relayout();
    try { def.render(w, w.opts); } catch (e) { w.body.innerHTML = `<p class="rv-win-err">${esc(e.message)}</p>`; }
    const st = A.state();
    if (st && def.onState) { try { def.onState(st, w); } catch (e) { /* drawn on the next poll */ } }
    if (!wasOpen || (opts && opts.focus)) {
      const f = (opts && opts.focus && w.el.querySelector(opts.focus)) || w.body.querySelector("[autofocus], input, select, textarea, button") || w.el.querySelector(".rv-win-x");
      if (f) f.focus({ preventScroll: true });
    }
    return w;
  }

  async function close(id, force) {
    const w = wins.get(id);
    if (!w || w.el.hidden) return true;
    if (!force && w.def.dirty && w.def.dirty(w) && !await A.ask("Close " + w.def.title + "?", "Your changes in this window are not saved.", "Close without saving", true)) return false;
    w.el.hidden = true; w.shown = false;
    relayout();
    if (w.def.closed) { try { w.def.closed(w); } catch (e) { /* nothing to clean */ } }
    const back = w.opener;
    w.opener = null;
    if (back && back.isConnected && back.focus) back.focus({ preventScroll: true });
    else { const t = $("tscroll"); if (t) t.focus({ preventScroll: true }); }
    return true;
  }

  A.onState((st) => {
    defs.forEach((def, id) => {
      const w = wins.get(id), shown = w && w.shown;
      if (def.onState && (shown || def.always)) { try { def.onState(st, w || null); } catch (e) { /* next poll */ } }
    });
  });

  // ── small builders the tools share ────────────────────────────────────────────────────────────────────────────────
  const ui = {
    // an editable name/value table (headers, query): rows = [[k, v], …]
    kvHTML(rows, id, names) {
      const [kn, vn] = names || ["Name", "Value"];
      return `<div class="rv-kvg" id="${esc(id)}" role="table" aria-label="${esc(kn)}s">`
        + rows.map(([k, v]) => ui.kvRow(k, v, kn, vn)).join("")
        + `</div><button type="button" class="rv-lnk" data-kvadd="${esc(id)}">+ Add</button>`;
    },
    kvRow: (k, v, kn, vn) => `<div class="rv-kvr" role="row"><input type="text" aria-label="${esc(kn || "Name")}" placeholder="${esc(kn || "Name")}" value="${esc(k)}" spellcheck="false">`
      + `<input type="text" aria-label="${esc(vn || "Value")}" placeholder="${esc(vn || "Value")}" value="${esc(v)}" spellcheck="false">`
      + `<button type="button" class="rv-icon-btn" data-kvdel aria-label="Remove">✕</button></div>`,
    kvWire(scope) {
      scope.addEventListener("click", (e) => {
        const del = e.target.closest("[data-kvdel]");
        if (del) { const box = del.closest(".rv-kvg"); del.parentElement.remove(); box && box.dispatchEvent(new Event("input", { bubbles: true })); return; }
        const add = e.target.closest("[data-kvadd]");
        if (add) {
          const box = scope.querySelector("#" + CSS.escape(add.dataset.kvadd));
          const tmp = document.createElement("div"); tmp.innerHTML = ui.kvRow("", "");
          const row = tmp.firstElementChild; box.appendChild(row); row.querySelector("input").focus();
        }
      });
    },
    kvRead: (scope, id) => [...scope.querySelectorAll("#" + CSS.escape(id) + " .rv-kvr")]
      .map((r) => [...r.querySelectorAll("input")].map((i) => i.value)).filter(([k]) => k.trim() !== ""),
    // a segmented control: [[value, label], …]
    seg: (name, items, on) => `<div class="rv-seg" role="tablist">` + items.map(([v, l]) =>
      `<button type="button" role="tab" data-${esc(name)}="${esc(v)}" aria-selected="${v === on}">${esc(l)}</button>`).join("") + `</div>`,
    jsonState(text) {
      if (!text.trim()) return "";
      try { JSON.parse(text); return "ok"; } catch (e) { return "bad"; }
    },
    empty: (title, hint) => `<div class="rv-win-empty"><b>${esc(title)}</b>${hint ? `<span>${hint}</span>` : ""}</div>`,
    methods: ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    methodSelect: (id, value, anyLabel) => `<select id="${esc(id)}" aria-label="Method">` + ui.methods.map((m) =>
      `<option value="${m}"${(value || "") === m ? " selected" : ""}>${m || esc(anyLabel || "Any")}</option>`).join("") + `</select>`,
    // "https://host/path*" → { host, path } for the wildcard ops (bp_add, maplocal_add)
    // (a full URL with its scheme goes as it is: the server reads it, query included)
    splitUrl(text) {
      const t = String(text || "").trim();
      if (/^https?:\/\//i.test(t)) return { host: t, path: "/" };
      const i = t.indexOf("/");
      return i < 0 ? { host: t, path: "/*" } : { host: t.slice(0, i), path: t.slice(i) || "/" };
    },
    // the server's wildcard_regex: host/path* → the match regex stored in rules / breakpoints
    wildcardRe(text) {
      let { host, path } = ui.splitUrl(text);
      if (/^https?:\/\//i.test(host)) { try { const u = new URL(host); host = u.host; path = (u.pathname || "/") + (u.search || ""); } catch (e) { /* kept as typed */ } }
      if (!host) throw new Error("Enter a host/path, e.g. api.example.com/v1/*");
      const wc = (x, star) => [...x].map((c) => c === "*" ? star : c === "?" ? "." : c.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&")).join("");
      const pth = path.startsWith("/") ? path : "/" + path;
      if (pth.includes("?")) {
        const i = pth.indexOf("?"), route = pth.slice(0, i), query = pth.slice(i + 1);
        return "^https?://" + wc(host.toLowerCase(), "[^/:]*") + "(:\\d+)?" + wc(route, ".*") + "\\?" + wc(query, ".*") + "$";
      }
      return "^https?://" + wc(host.toLowerCase(), "[^/:]*") + "(:\\d+)?" + wc(pth, ".*") + "(\\?|$)";
    },
    // run an op, toast its outcome, refresh the state at once; returns the answer or null
    async run(op, body, ok) {
      try {
        const r = await A.api(op, body);
        if (ok) A.toast(ok);
        A.refresh(); A.toolsChanged();
        return r || {};
      } catch (e) { A.toast(e.message, true); return null; }
    },
  };

  // Esc closes the front window from anywhere (help sheet); a text field keeps Esc for its own clear/blur first
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented) return;
    if (document.querySelector("#dialog:not([hidden])")) return;
    if (e.target.closest && e.target.closest("input, textarea, select, [contenteditable]")) return;
    let front = null, zMax = -1;
    wins.forEach((w) => {
      if (!w.shown || w.el.hidden) return;
      const z = Number(w.el.style.zIndex || 0);
      if (z >= zMax) { zMax = z; front = w; }
    });
    if (front) { e.preventDefault(); close(front.id); }
  });

  window.RivisTools = Object.freeze({
    register(id, def) { defs.set(id, def); },
    has: (id) => defs.has(id),
    open, close,
    isOpen: (id) => { const w = wins.get(id); return !!(w && w.shown); },
    win: (id) => wins.get(id) || null,
    ui,
  });
})();
