// Terms of Use gate for both windows (the classic panel and the new main window load this same file).
// While the current terms are not accepted the proxy passes no traffic (proxy_terms.py); this covers the window
// with the terms until the user types their name and agrees, or declines (Rivis then stops). Nothing from the
// server is ever inserted as HTML: the text is shown with textContent.
(() => {
  if (window.__rivisTermsGate) return;
  window.__rivisTermsGate = true;
  const API = location.pathname.startsWith("/rivis") ? "../proxy/api/" : "./proxy/api/";
  const xsrf = () => {
    let v = (document.cookie.match(/(?:^|;\s*)_mitmproxy_xsrf=([^;]+)/) || [])[1];
    if (!v) {        // tornado only checks that the cookie and the header match: make the pair on first use
      v = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
      document.cookie = "_mitmproxy_xsrf=" + v + "; path=/; SameSite=Strict";
    }
    return v;
  };
  async function api(op, body) {
    const c = new AbortController(), t = setTimeout(() => c.abort(), 10000);
    try {
      const r = await fetch(API + op, Object.assign({ credentials: "same-origin", signal: c.signal }, body === undefined ? {} : {
        method: "POST", headers: { "Content-Type": "application/json", "X-XSRFToken": xsrf() }, body: JSON.stringify(body) }));
      let j = {};
      try { j = await r.json(); } catch (e) { j = { error: "HTTP " + r.status }; }
      if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
      return j;
    } finally { clearTimeout(t); }
  }

  let box = null, shownSha = null, stopped = false;
  const el = (tag, css, text) => { const e = document.createElement(tag); if (css) e.style.cssText = css; if (text != null) e.textContent = text; return e; };
  const BTN = "font:inherit;padding:7px 14px;border-radius:6px;border:1px solid #8a96a3;background:#fff;color:#14202b;cursor:pointer";

  function keepKeysInside(ev) {    // mitmweb's and the window's own shortcuts must not act behind the terms
    if (box && !box.contains(ev.target)) { ev.stopPropagation(); ev.preventDefault(); box.querySelector("input")?.focus(); }
  }

  function close() {
    if (!box) return;
    box.remove(); box = null; shownSha = null;
    document.removeEventListener("keydown", keepKeysInside, true);
  }

  function frame() {
    close();
    box = el("div", "position:fixed;inset:0;z-index:2147483647;background:rgba(12,18,23,.72);display:flex;align-items:center;justify-content:center;font:14px/1.45 -apple-system,system-ui,sans-serif");
    box.id = "rivis-terms";
    box.setAttribute("role", "dialog"); box.setAttribute("aria-modal", "true"); box.setAttribute("aria-labelledby", "rivis-terms-title");
    const card = el("div", "background:#fff;color:#14202b;width:min(760px,calc(100vw - 32px));max-height:calc(100vh - 32px);display:flex;flex-direction:column;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.35);overflow:hidden");
    box.appendChild(card);
    document.addEventListener("keydown", keepKeysInside, true);
    document.body.appendChild(box);
    return card;
  }

  function message(title, text) {
    const card = frame();
    const t = el("h2", "margin:0;padding:18px 20px 8px;font-size:18px", title); t.id = "rivis-terms-title";
    card.append(t, el("p", "margin:0;padding:0 20px 20px", text));
  }

  async function show(st) {
    let doc;
    try { doc = await api("terms_text", {}); } catch (e) { message("Terms of Use", e.message); return; }
    if (box && shownSha === doc.sha256) return;
    const card = frame();
    shownSha = doc.sha256;
    const head = el("h2", "margin:0;padding:18px 20px 4px;font-size:18px", doc.title || "Terms of Use"); head.id = "rivis-terms-title";
    const sub = el("p", "margin:0;padding:0 20px 10px;color:#4a5866",
      st.state === "changed" ? "The Terms of Use changed since you agreed. Read them again; Rivis passes no traffic until you agree."
        : "Before you use Rivis, read the Terms of Use. Rivis passes no traffic until you agree.");
    const text = el("div", "margin:0 20px;padding:12px 14px;border:1px solid #d5dde4;border-radius:6px;background:#f7f9fb;overflow:auto;white-space:pre-wrap;flex:1;min-height:160px");
    text.textContent = doc.text.replace(/^\s*<!--[\s\S]*?-->\s*$/gm, "").replace(/\n{3,}/g, "\n\n").trim();
    text.tabIndex = 0; text.setAttribute("aria-label", "Terms of Use text");
    const form = el("form", "padding:14px 20px 18px;display:flex;flex-direction:column;gap:10px");
    const read = el("label", "display:flex;gap:8px;align-items:center");
    const check = el("input"); check.type = "checkbox"; check.id = "rivis-terms-read";
    read.append(check, el("span", null, "I have read the Terms of Use and I agree to follow them."));
    const nameRow = el("label", "display:flex;flex-direction:column;gap:4px");
    const name = el("input", "font:inherit;padding:7px 9px;border:1px solid #8a96a3;border-radius:6px");
    name.id = "rivis-terms-name"; name.autocomplete = "name"; name.maxLength = 100; name.placeholder = "Your full name";
    nameRow.append(el("span", null, "Type your full name as your signature"), name);
    const err = el("div", "color:#b3261e;min-height:1.2em"); err.setAttribute("role", "alert"); err.id = "rivis-terms-error";
    const row = el("div", "display:flex;gap:8px;justify-content:flex-end");
    const no = el("button", BTN, "I do not agree"); no.type = "button"; no.id = "rivis-terms-decline";
    const yes = el("button", BTN + ";background:#0f6cbd;border-color:#0f6cbd;color:#fff", "Agree"); yes.type = "submit"; yes.id = "rivis-terms-accept";
    row.append(no, yes);
    form.append(read, nameRow, err, row);
    card.append(head, sub, text, form);
    const ready = () => { yes.disabled = !(check.checked && name.value.trim().length >= 3); yes.style.opacity = yes.disabled ? ".5" : "1"; };
    check.onchange = ready; name.oninput = ready; ready();
    form.onsubmit = async (ev) => {
      ev.preventDefault();
      if (yes.disabled) return;
      err.textContent = "";
      try { await api("terms_accept", { name: name.value, sha256: doc.sha256 }); close(); }
      catch (e) { err.textContent = e.message; if (/changed/.test(e.message)) { shownSha = null; close(); } }
    };
    no.onclick = async () => {
      if (no.dataset.sure !== "1") {
        no.dataset.sure = "1"; no.textContent = "Stop Rivis";
        err.textContent = "If you do not agree, Rivis stops and cannot be used. Press Stop Rivis to confirm.";
        return;
      }
      try { await api("terms_decline", {}); } catch (e) { /* stopping: the connection may close first */ }
      stopped = true;
      message("Rivis has stopped", "You did not agree to the Terms of Use, so Rivis will not run. To read them again, run 'rivis terms' in a terminal or start Rivis again.");
    };
    name.focus();
  }

  // Both windows poll "state" anyway and hand its "terms" here (seen), so the cover adds no requests of its own while
  // they run. Only a page with no such poll (or before its first answer) makes the cover ask once by itself.
  let heard = false, busy = false;
  async function seen(st) {
    heard = true;
    st = st || {};
    if (stopped || busy) return;
    if (st.state === "accepted") { close(); return; }
    busy = true;
    try {
      if (st.state === "missing") {
        if (shownSha !== "missing") {
          message("Terms of Use missing", "This copy of Rivis has no Terms of Use text, so it cannot be used. Reinstall it from the official release.");
          shownSha = "missing";
        }
      } else if (!box || !shownSha || shownSha === "missing") await show(st);
    } finally { busy = false; }
  }
  window.RivisTermsGate = { seen };
  async function ask() {
    if (heard || stopped) return;
    try { await seen((await api("terms_status", {})).terms); } catch (e) { setTimeout(ask, 3000); }
  }
  const start = () => { setTimeout(ask, 4000); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
