/* ClickFix Guard v2 — MAIN-world hook.
 * Runs at document_start, before any page script. Wraps every script-initiated route into
 * the clipboard, analyses the text (decoding base-N layers), judges the context (was there a
 * real user gesture? is the text visible? does the button label match?) and blocks/warns.
 * A user's own Ctrl+C is never analysed unless the page replaces the copied data. */
(() => {
  "use strict";
  if (window.__cfgHookLoaded) return;
  try { Object.defineProperty(window, "__cfgHookLoaded", { value: true }); } catch (e) { return; }

  /* ---------- natives captured before the page can tamper with them ---------- */
  const _dispatch = EventTarget.prototype.dispatchEvent;
  const _listen = EventTarget.prototype.addEventListener;
  const _CE = window.CustomEvent;
  const _stringify = JSON.stringify.bind(JSON);
  const _parse = JSON.parse.bind(JSON);
  const _now = performance.now.bind(performance);
  const _atob = window.atob.bind(window);
  const _decodeURI = decodeURIComponent;
  const _Set = Set, _Map = Map;
  const _getRandom = crypto.getRandomValues.bind(crypto);
  const _getSelection = window.getSelection ? window.getSelection.bind(window) : () => "";
  const _gcs = window.getComputedStyle ? window.getComputedStyle.bind(window) : () => ({});

  /* ---------- private channel to the isolated-world script ---------- */
  const nonce = Array.from(_getRandom(new Uint8Array(12)), b => b.toString(16).padStart(2, "0")).join("");
  const fire = (name, detail) => { try { _dispatch.call(window, new _CE(name, { detail })); } catch (e) {} };
  let claimed = false;
  _listen.call(window, "__cfg_req", () => {          // first requester (our content script) wins
    if (claimed) return;
    claimed = true;
    fire("__cfg_ack", nonce);
  }, true);

  const state = { risk: false, approved: new _Set(), debug: false };
  const pending = new _Map();                         // blocked text, kept for "Copy anyway"
  const chain = { eth: false, ethT: -1e9, c2: false };
  const dbg = (...a) => { if (state.debug) { try { console.debug("[ClickFix Guard]", ...a); } catch (e) {} } };

  _listen.call(window, "__cfg_state_" + nonce, e => {
    try {
      const s = _parse(e.detail);
      state.risk = !!s.risk;
      if (Array.isArray(s.approved)) state.approved = new _Set(s.approved);
      state.debug = !!s.debug;
    } catch (err) {}
  }, true);

  _listen.call(window, "__cfg_allow_" + nonce, e => {   // user pressed "Copy anyway"
    try {
      const { id } = _parse(e.detail);
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      state.approved.add(p.hash);
      nativeCopy(p.text);
      fire("__cfg_ok_" + nonce, _stringify({ hash: p.hash }));
    } catch (err) {}
  }, true);

  /* ---------- helpers ---------- */
  const squash = s => String(s).toLowerCase()
    .replace(/[\u201C\u201D]/g, '"').replace(/[\u2018\u2019]/g, "'").replace(/\s+/g, "");

  function hashStr(str) {                              // cyrb53
    let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761); h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
  }

  /* ---------- normalisation: undo cheap obfuscation ---------- */
  function normalize(raw) {
    return String(raw).slice(0, 20000)
      .replace(/[\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060\uFEFF\u00AD]/g, "") // invisible chars
      .normalize("NFKC")                                                            // fullwidth etc.
      .replace(/`/g, "")                                                            // p`ower`shell
      .replace(/\^/g, "")                                                           // p^o^w^e^r (cmd)
      .replace(/["']\s*\+\s*["']/g, "")                                             // 'po'+'wer'
      .replace(/(["'])\1/g, "");                                                    // po""wer
  }

  /* ---------- base-N decoders (recursive, depth-limited) ---------- */
  const printable = s => {
    if (s.length < 6) return false;
    let ok = 0;
    for (let i = 0; i < s.length; i++) {
      const n = s.charCodeAt(i);
      if ((n >= 32 && n < 127) || n === 9 || n === 10 || n === 13) ok++;
    }
    return ok / s.length > 0.85;
  };

  function decodeB64(str) {
    try {
      let b = str.replace(/-/g, "+").replace(/_/g, "/");
      while (b.length % 4) b += "=";
      const bin = _atob(b);
      let zeros = 0;
      for (let i = 1; i < bin.length; i += 2) if (bin.charCodeAt(i) === 0) zeros++;
      if (bin.length > 8 && zeros / (bin.length / 2) > 0.8) {            // UTF-16LE (-EncodedCommand)
        let out = "";
        for (let i = 0; i + 1 < bin.length; i += 2) out += String.fromCharCode(bin.charCodeAt(i) | (bin.charCodeAt(i + 1) << 8));
        return printable(out) ? out : null;
      }
      return printable(bin) ? bin : null;
    } catch (e) { return null; }
  }
  function decodeB32(str) {
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "", out = "";
    for (const c of str.replace(/=+$/, "")) {
      const v = A.indexOf(c);
      if (v < 0) return null;
      bits += v.toString(2).padStart(5, "0");
    }
    for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
    return printable(out) ? out : null;
  }
  function decodeHex(str) {
    let out = "";
    for (let i = 0; i + 1 < str.length; i += 2) out += String.fromCharCode(parseInt(str.slice(i, i + 2), 16));
    return printable(out) ? out : null;
  }
  function decodeLayers(text, depth = 0, out = []) {
    if (depth >= 3 || out.length >= 8) return out;
    const found = [];
    const take = (re, fn, kind) => {
      let n = 0;
      for (const m of text.matchAll(re)) {
        if (n++ >= 20) break;
        const d = fn(m[0]);
        if (d && d !== text) found.push({ kind, text: d });
      }
    };
    take(/[A-Za-z0-9+\/_-]{24,}={0,2}/g, decodeB64, "base64");
    take(/\b[A-Z2-7]{32,}={0,6}/g, decodeB32, "base32");
    take(/\b(?:[0-9a-fA-F]{2}){20,}\b/g, decodeHex, "hex");
    if ((text.match(/%[0-9a-f]{2}/gi) || []).length >= 3) {
      try { const d = _decodeURI(text); if (d !== text) found.push({ kind: "url-encoding", text: d }); } catch (e) {}
    }
    for (const f of found) {
      if (out.length >= 8) break;
      out.push(f);
      decodeLayers(f.text, depth + 1, out);
    }
    return out;
  }

  /* ---------- payload rules (applied to lower-cased text and every decoded layer) ---------- */
  const RULES = [
    { id: "shell-launcher", score: 3, label: "Launches PowerShell / cmd / a script host",
      re: /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s*\/[ck]|mshta|wscript|cscript|conhost|(?:ba|z)?sh\s+-c|osascript)\b/ },
    { id: "web-download", score: 4, label: "Downloads content from the internet",
      re: /\b(?:irm|iwr|invoke-restmethod|invoke-webrequest|start-bitstransfer|downloadstring|downloadfile|downloaddata|net\.webclient|bitsadmin|curl|wget)\b|certutil[^\n]{0,40}urlcache/ },
    { id: "remote-exec", score: 4, label: "Executes downloaded or dynamic code",
      re: /\b(?:iex|invoke-expression)\b|\|\s*(?:iex|bash|sh|zsh|powershell|pwsh)\b|\b(?:mshta|msiexec|regsvr32|rundll32)\b[^\n]{0,80}https?:/ },
    { id: "url", score: 1, label: "Contains a URL or IP address",
      re: /https?:\/\/|\b\d{1,3}(?:\.\d{1,3}){3}\b/ },
    { id: "raw-ip-url", score: 2, label: "URL points to a raw IP address",
      re: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/ },
    { id: "encoded-command", score: 4, label: "PowerShell encoded command (-enc)",
      re: /\s-(?:e|ec|enc|encodedcommand)\s+[a-z0-9+\/=]{16,}/ },
    { id: "base-keywords", score: 3, label: "Uses base-N decoding (base64/32/58/85...)",
      re: /frombase64string|\bbase64\b|b64decode|\batob\s*\(|certutil[^\n]{0,30}-decode|\bbase(?:32|45|58|62|85)\b|ascii85|\[convert\]::/ },
    { id: "stealth-flags", score: 2, label: "Hidden window / policy-bypass flags",
      re: /-(?:w|windowstyle)\s+hidden|-(?:nop|noprofile|noni|noninteractive)\b|-(?:ep|executionpolicy)\s+bypass/ },
    { id: "comment-spoof", score: 3, label: "Trailing comment mimics a verification message",
      re: /(?:#|\brem\s|::|\/\/)[^\n]{0,80}(?:robot|captcha|verif|human|ray\s*id|cloudflare)/ }
  ];
  const EXEC_IDS = ["shell-launcher", "web-download", "remote-exec"];

  function analyze(raw) {
    const norm = normalize(raw);
    const layers = decodeLayers(norm);
    const hit = new _Map();
    let hiddenKind = "";
    [{ kind: "raw", text: norm }, ...layers].forEach((t, i) => {
      const low = t.text.toLowerCase();
      for (const r of RULES) {
        if (!r.re.test(low)) continue;
        hit.set(r.id, r);
        if (i > 0 && EXEC_IDS.includes(r.id)) hiddenKind = t.kind;
      }
    });
    if (hiddenKind) hit.set("hidden-layer", { score: 4, label: "Decoded " + hiddenKind + " content contains executable commands" });
    if (/\s{40,}/.test(String(raw))) hit.set("padding", { score: 2, label: "Command padded with long whitespace" });
    let score = 0;
    for (const r of hit.values()) score += r.score;
    return {
      score,
      ids: new _Set(hit.keys()),
      labels: [...hit.values()].map(r => r.label),
      decoded: layers.length ? layers[layers.length - 1].text.slice(0, 200) : ""
    };
  }

  /* ---------- provenance: did a real user action cause this write? ---------- */
  const g = { t: -1e9, kind: "", target: null, trusted: false, ctxT: -1e9 };
  for (const type of ["pointerdown", "mousedown", "click", "keydown", "touchstart", "contextmenu"]) {
    _listen.call(window, type, e => {
      if (type === "contextmenu") { g.ctxT = _now(); return; }
      g.t = _now(); g.trusted = e.isTrusted; g.target = e.target;
      g.kind = (type === "keydown" && (e.ctrlKey || e.metaKey) && /^(c|x|insert)$/i.test(e.key)) ? "copykey" : type;
    }, true);
  }
  const userCopyIntent = () =>
    (g.kind === "copykey" && _now() - g.t < 1500) || (_now() - g.ctxT < 20000 && g.t < g.ctxT);

  function provenance() {
    const age = _now() - g.t;
    if (userCopyIntent()) return "user-copy";
    const active = navigator.userActivation ? navigator.userActivation.isActive : true;
    if (!active || age > 5000) return "silent";          // no recent user activation
    return g.trusted ? "gesture" : "synthetic";           // synthetic = el.click() from script
  }

  let userSel = "";
  _listen.call(window, "copy", e => { if (e.isTrusted) userSel = selectionText(); }, true);
  _listen.call(window, "cut", e => { if (e.isTrusted) userSel = selectionText(); }, true);
  function selectionText() {
    try {
      const el = document.activeElement;
      if (el && typeof el.value === "string" && el.selectionStart != null && el.selectionEnd > el.selectionStart)
        return el.value.slice(el.selectionStart, el.selectionEnd);
    } catch (e) {}
    try { return String(_getSelection()); } catch (e) { return ""; }
  }

  /* ---------- context: was the text visible? does the button look honest? ---------- */
  function isShown(el) {
    try {
      for (let n = el, i = 0; n && i < 4; n = n.parentElement, i++) {
        const cs = _gcs(n);
        if (cs.display === "none" || cs.visibility === "hidden" || parseFloat(cs.opacity) < 0.05) return false;
      }
      const r = el.getBoundingClientRect();
      return r.width >= 4 && r.height >= 4 && r.right > 0 && r.bottom > 0;
    } catch (e) { return false; }
  }
  function probesFor(text) {
    const s = squash(text);
    if (s.length < 8) return null;
    return s.length > 240 ? [s.slice(0, 100), s.slice(-100)] : [s];
  }
  function visibleOnPage(text) {
    const probes = probesFor(text);
    if (!probes) return false;
    const hay = squash(((document.documentElement || {}).innerText || "").slice(0, 400000));
    if (probes.every(p => hay.includes(p))) return true;
    let n = 0;
    for (const el of document.querySelectorAll("input,textarea")) {
      if (++n > 200) break;
      if (!isShown(el)) continue;
      const v = squash(el.value || "");
      if (probes.every(p => v.includes(p))) return true;
    }
    return false;
  }
  function targetInfo(el, text) {
    const out = { copyLabel: false, lureLabel: false, shownNear: false };
    try {
      const btn = (el && el.closest && el.closest("button,a,[role=button],input[type=button],input[type=submit]")) || el;
      const label = ((btn && (btn.innerText || btn.value || (btn.getAttribute && (btn.getAttribute("aria-label") || btn.title))) || "") + "").trim().slice(0, 60).toLowerCase();
      out.copyLabel = /\b(copy|copiar|copier|kopieren|clipboard)\b|\u{1F4CB}/u.test(label);
      out.lureLabel = /verif|human|robot|captcha|continue|\bfix\b|authori[sz]e|confirm|i'?m not/.test(label);
      const probes = probesFor(text);
      if (probes && btn) {
        for (let n = btn, i = 0; n && i < 4 && !out.shownNear; n = n.parentElement, i++) {
          let k = 0;
          for (const c of n.querySelectorAll("pre,code,samp,kbd,textarea,input,[class*=code i],[class*=command i]")) {
            if (++k > 40) break;
            const v = squash(c.value != null && c.value !== "" ? c.value : (c.innerText || c.textContent || ""));
            if (probes.every(p => v.includes(p)) && isShown(c)) { out.shownNear = true; break; }
          }
        }
      }
    } catch (e) {}
    return out;
  }

  /* ---------- decision: payload score P  x  context risk R ---------- */
  function contextRisk(ctx) {
    let r = 0;
    if (state.risk) r += 3;                              // page already looks like ClickFix
    if (chain.c2) r += 3;                                // page loaded a script from a blockchain-resolved server
    if (ctx.prov === "silent" || ctx.prov === "synthetic") r += 3;
    if (!ctx.visible) r += 3;                            // the user never saw this text
    if (ctx.lureLabel && !ctx.copyLabel) r += 3;         // "Verify" button that copies a command
    if (ctx.hijack) r += 4;                              // page replaced what the user selected
    if (ctx.copyLabel && ctx.shownNear && ctx.prov === "gesture") r -= 4;  // honest copy button
    return r;
  }
  function decide(P, R) {
    if (P < 5) return "allow";
    if (R >= 6) return "block";
    if (R >= 3 || P >= 10) return "warn";
    return "allow";
  }

  const recent = new _Map();
  let idSeq = 0;
  function handle(raw, source, snap) {
    try {
      const text = String(raw == null ? "" : raw);
      if (text.length < 6) return "allow";
      const a = analyze(text);
      if (a.score < 5) return "allow";                   // cheap exit before any DOM work
      snap = snap || { prov: provenance(), target: g.target, intent: userCopyIntent() };
      // the user selected this exact text and pressed Ctrl+C: the page did not alter anything
      if (snap.intent && userSel && squash(userSel) === squash(text)) return "allow";
      const hash = hashStr(location.origin + "|" + squash(text));
      if (state.approved.has(hash)) return "allow";
      const prev = recent.get(hash);
      if (prev && _now() - prev.t < 1500) return prev.verdict;
      const visible = visibleOnPage(text);
      const ti = (snap.prov === "gesture" || snap.prov === "synthetic") ? targetInfo(snap.target, text)
                                                                       : { copyLabel: false, lureLabel: false, shownNear: false };
      const hijack = !!(snap.intent && userSel && squash(userSel) !== squash(text));
      const ctx = { prov: snap.prov, visible, hijack, ...ti };
      const R = contextRisk(ctx);
      const verdict = decide(a.score, R);
      recent.set(hash, { t: _now(), verdict });
      dbg("clipboard", source, { P: a.score, R, verdict, ctx, labels: a.labels });

      if (verdict !== "allow") {
        const id = "i" + (++idSeq);
        if (verdict === "block") pending.set(id, { text, hash });
        fire("__cfg_clip_" + nonce, _stringify({
          id, verdict, P: a.score, R, source, prov: ctx.prov, visible,
          labels: a.labels.slice(0, 12),
          preview: text.replace(/[\u0000-\u001f]+/g, " ").trim().slice(0, 200),
          decoded: a.decoded.replace(/[\u0000-\u001f]+/g, " ").trim()
        }));
      }
      return verdict;
    } catch (e) { return "allow"; }                      // fail open: never break pages
  }

  /* ---------- native copy used by "Copy anyway" ---------- */
  const origWriteText = (typeof Clipboard !== "undefined") ? Clipboard.prototype.writeText : null;
  const origExec = (typeof Document !== "undefined") ? Document.prototype.execCommand : null;
  async function nativeCopy(text) {
    try { if (origWriteText && navigator.clipboard) { await origWriteText.call(navigator.clipboard, text); return true; } } catch (e) {}
    try {
      const ta = document.createElement("textarea");
      ta.value = text; ta.style.cssText = "position:fixed;left:-9999px;opacity:0";
      (document.body || document.documentElement).appendChild(ta);
      ta.select(); origExec.call(document, "copy"); ta.remove();
      return true;
    } catch (e) { return false; }
  }

  /* ---------- hooks (Proxy keeps the wrapped functions looking native) ---------- */
  function wrap(proto, name, build) {
    try {
      const d = proto && Object.getOwnPropertyDescriptor(proto, name);
      if (!d || typeof d.value !== "function") return;
      const orig = d.value;
      Object.defineProperty(proto, name, { ...d, value: new Proxy(orig, { apply: build(orig) }) });
    } catch (e) {}
  }

  if (typeof Clipboard !== "undefined") {
    wrap(Clipboard.prototype, "writeText", orig => (t, self, args) =>
      handle(args[0], "writeText") === "block" ? Promise.resolve() : Reflect.apply(orig, self, args));

    wrap(Clipboard.prototype, "write", orig => (t, self, args) => {
      const snap = { prov: provenance(), target: g.target, intent: userCopyIntent() };   // capture before awaiting
      return (async () => {
        let block = false;
        try {
          for (const item of (args[0] || [])) {
            if (item.types && item.types.includes("text/plain")) {
              const txt = await (await item.getType("text/plain")).text();
              if (handle(txt, "write", snap) === "block") block = true;
            }
          }
        } catch (e) {}
        return block ? undefined : Reflect.apply(orig, self, args);
      })();
    });
  }

  if (typeof Document !== "undefined") {
    wrap(Document.prototype, "execCommand", orig => (t, self, args) => {
      const cmd = String(args[0]).toLowerCase();
      if (cmd === "copy" || cmd === "cut") {
        if (handle(selectionText(), "execCommand") === "block") return true;           // pretend success
      }
      return Reflect.apply(orig, self, args);
    });
  }

  // copy-event path: e.clipboardData.setData(...)
  let activeDT = null;
  for (const type of ["copy", "cut"]) {
    _listen.call(window, type, e => { activeDT = e.clipboardData; setTimeout(() => { activeDT = null; }, 0); }, true);
  }
  if (typeof DataTransfer !== "undefined") {
    wrap(DataTransfer.prototype, "setData", orig => (t, self, args) => {
      if (self === activeDT && /^text\/(plain|html)$/i.test(String(args[0])) && handle(args[1], "copy-event") === "block")
        args = [args[0], ""];
      return Reflect.apply(orig, self, args);
    });
  }

  /* ---------- loader-chain hooks (EtherHiding-style C2 lookup + dynamic script injection) ---------- */
  const emitChain = (kind, url) => fire("__cfg_chain_" + nonce, _stringify({ kind, url: String(url || "").slice(0, 200) }));
  const ETH_RE = /"method"\s*:\s*"eth_(?:call|getCode|getStorageAt)"/;
  function onRpcBody(body, url) {
    try {
      if (typeof body !== "string" || !ETH_RE.test(body)) return;
      if (typeof window.ethereum !== "undefined") return;             // genuine dApp with a wallet
      chain.eth = true; chain.ethT = _now();
      emitChain("eth-call", url);
    } catch (e) {}
  }
  function onScriptSrc(v) {
    try {
      const s = String(v);
      let cross = false;
      try { cross = new URL(s, location.href).origin !== location.origin; } catch (e) {}
      if (!cross) return;
      if (/\/get_script\b|\/api\.php\?s=/.test(s)) { chain.c2 = true; emitChain("c2-script", s); }
      else if (chain.eth && _now() - chain.ethT < 60000) { chain.c2 = true; emitChain("script-after-eth-call", s); }
    } catch (e) {}
  }
  if (typeof XMLHttpRequest !== "undefined") {
    wrap(XMLHttpRequest.prototype, "open", orig => (t, self, args) => { try { self.__cfgUrl = args[1]; } catch (e) {} return Reflect.apply(orig, self, args); });
    wrap(XMLHttpRequest.prototype, "send", orig => (t, self, args) => { onRpcBody(args[0], self.__cfgUrl); return Reflect.apply(orig, self, args); });
  }
  if (typeof window.fetch === "function") {
    const of = window.fetch;
    window.fetch = new Proxy(of, { apply(t, self, args) {
      try { const init = args[1]; if (init && typeof init.body === "string") onRpcBody(init.body, args[0] && args[0].url || args[0]); } catch (e) {}
      return Reflect.apply(t, self, args);
    } });
  }
  if (typeof HTMLScriptElement !== "undefined") {
    try {
      const sd = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, "src");
      if (sd && sd.set) Object.defineProperty(HTMLScriptElement.prototype, "src", { ...sd, set(v) { onScriptSrc(v); return sd.set.call(this, v); } });
    } catch (e) {}
    wrap(Element.prototype, "setAttribute", orig => (t, self, args) => {
      try { if (self instanceof HTMLScriptElement && String(args[0]).toLowerCase() === "src") onScriptSrc(args[1]); } catch (e) {}
      return Reflect.apply(orig, self, args);
    });
  }
})();
