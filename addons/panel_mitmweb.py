"""mitmweb page injection: pre-paint theme boot and the flow-list scroll-crash patch.

Used by proxy_panel when it rewrites mitmweb's index page and serves /proxy/boot.js and the
patched static bundle. Kept here so the add-on file stays about panel behaviour, not mitmweb's HTML.
"""
import re

# mitmweb serves a strict CSP (default-src 'self'; no 'unsafe-inline' for scripts), so the boot logic
# CANNOT be an inline <script> — it would be blocked and the skin would only apply late, after panel.js
# loads (a flash of stock mitmweb), and the ?theme=off kill switch would never run. It is therefore
# served as a same-origin external script (/proxy/boot.js), injected synchronously into <head> so it
# runs before first paint. It applies the remembered theme / density and, unless the skin is switched
# off (?theme=off or the panel toggle), parser-writes the /proxy/theme.css link (render-blocking → no
# flash). Everything is wrapped in try/catch because localStorage can throw in private windows.
THEME_BOOT = '<script src="./proxy/boot.js"></script>'
BOOT_JS = b"""(function(){var load=true;try{
var d=document.documentElement,s=window.localStorage,q=new URLSearchParams(location.search),t=q.get("theme");
if(t==="off"||t==="on")s.setItem("rivis-skin",t);else if(t==="light"||t==="dark"||t==="system")s.setItem("rivis-theme",t);
var k=s.getItem("rivis-skin")||s.getItem("proxy-restyle")||"on",m=s.getItem("rivis-theme");
if(m==="light"||m==="dark")d.setAttribute("data-theme",m);
if(s.getItem("rivis-compact")==="on")d.setAttribute("data-density","compact");
if(k==="off"){d.setAttribute("data-skin","off");load=false;}
}catch(e){}
if(load)document.write('<link rel="stylesheet" href="./proxy/theme.css" id="rivis-theme">');})();"""

# ── mitmweb bundle fix ──────────────────────────────────────────────────────────
# mitmweb 12's FlowTable.onViewportUpdate stores min(scrollTop, end * rowHeight) as viewportTop but compares the
# UNclamped scrollTop against it. Whenever scrollTop is past the last rendered row (the sticky header's height, a list
# that just shrank under the retention cap, a very short list pane) the two never match, every componentDidUpdate
# calls setState again, and React aborts the page with error #185 ("mitmproxy has crashed") while the user scrolls.
# The fix compares the clamped value. Matched by shape, not minified names; if a future mitmweb changes the code the
# bundle is served unchanged and a warning is logged.
MITMWEB_PATCH_VERSION = "1"
_VIEWPORT_LOOP = re.compile(
    r"if\(this\.state\.viewportTop!==(\w+)\|\|!(\w+)\(this\.state\.vScroll,(\w+)\)\)\{"
    r"const (\w+)=Math\.min\(\1,\3\.end\*this\.props\.rowHeight\);"
    r"this\.setState\(\{vScroll:\3,viewportTop:\4\}\)\}")


def patch_mitmweb_js(source, warn=None):
    patched, n = _VIEWPORT_LOOP.subn(
        lambda m: ("{const %(t)s=Math.min(%(s)s,%(v)s.end*this.props.rowHeight);"
                   "if(this.state.viewportTop!==%(t)s||!%(eq)s(this.state.vScroll,%(v)s))"
                   "this.setState({vScroll:%(v)s,viewportTop:%(t)s})}")
        % {"s": m.group(1), "eq": m.group(2), "v": m.group(3), "t": m.group(4)}, source)
    if n != 1 and warn and "this.state.viewportTop" in source:
        warn("proxy_panel: mitmweb's flow-list code changed; the scroll-crash fix was not applied")
    return patched if n == 1 else source
