/* ClickFix Guard v2 — isolated-world script.
 * Page scanner (text + full-screen overlays + inline scripts incl. XOR-decoded layers),
 * runtime loader-chain evidence, clipboard incidents from the MAIN-world hook, and the alert UI. */
(() => {
  "use strict";
  if (window.__clickFixGuardLoaded) return;
  window.__clickFixGuardLoaded = true;

  const DEBUG = true;                                   // console.debug("[ClickFix Guard] ...")
  const log = (...a) => { if (DEBUG) console.debug("[ClickFix Guard]", ...a); };
  const CONFIG = { maxTextLength: 200000, maxScriptLength: 250000, maxSingleScriptLength: 60000, debounceMs: 250 };

  /* ================= channel to the MAIN-world hook ================= */
  let nonce = null;
  let approved = [];
  let pageRisk = false;
  const ch = name => name + "_" + nonce;
  function send(name, obj) {
    if (!nonce) return;
    window.dispatchEvent(new CustomEvent(ch(name), { detail: JSON.stringify(obj) }));
  }
  const pushState = () => send("__cfg_state", { risk: pageRisk, approved, debug: DEBUG });

  window.addEventListener("__cfg_ack", e => {
    if (nonce || typeof e.detail !== "string" || !/^[0-9a-f]{24}$/.test(e.detail)) return;
    nonce = e.detail;
    window.addEventListener(ch("__cfg_clip"), onClip, true);
    window.addEventListener(ch("__cfg_chain"), onChain, true);
    window.addEventListener(ch("__cfg_ok"), onOk, true);
    loadApproved(() => { pushState(); scheduleScan(); });
  }, true);
  const requestNonce = () => { if (!nonce) window.dispatchEvent(new CustomEvent("__cfg_req")); };
  requestNonce();
  { let tries = 0; const iv = setInterval(() => { if (nonce || ++tries > 40) clearInterval(iv); else requestNonce(); }, 50); }

  const origin = location.origin;
  function loadApproved(cb) {
    try {
      chrome.storage.local.get({ approved: [] }, r => {
        approved = (r.approved || []).filter(x => typeof x === "string" && x.startsWith(origin + "|")).map(x => x.slice(origin.length + 1));
        cb && cb();
      });
    } catch (e) { cb && cb(); }
  }
  function onOk(e) {
    try {
      const { hash } = JSON.parse(e.detail);
      if (typeof hash !== "string") return;
      chrome.storage.local.get({ approved: [] }, r => {
        const list = r.approved || [];
        const key = origin + "|" + hash;
        if (!list.includes(key)) list.push(key);
        chrome.storage.local.set({ approved: list.slice(-500) });
      });
      approved.push(hash);
    } catch (err) {}
  }

  /* ================= rules ================= */
  const norm = t => String(t || "").toLowerCase().replace(/[\u2630\u21b5\u229e\u2318\u2022\u00b7]/g, " ").replace(/\s+/g, " ").trim();

  // group: ctx = verification context, os = "open an OS tool" step, paste = paste step, enter = press Enter
  const TEXT_RULES = [
    { id: "verification-language", group: "ctx", score: 2, label: "Human-verification wording",
      re: /i['\u2019]?m not a robot|i am not a robot|verify(?:ing)? (?:that )?(?:you are|you're) (?:a )?human|human verification|complete (?:these|the) verification|security verification|are you a robot|robot check/ },
    { id: "os-shortcut", group: "os", score: 4, label: "Tells you to press the Windows key + X / R",
      re: /(?:windows|win)\s*(?:key|button|logo key)?[^.]{0,40}?(?:\+|then|and)\s*(?:press\s*)?(?:x|r)\b|\bwin\s*\+\s*[xr]\b|power user menu|run dialog/ },
    { id: "open-system-tool", group: "os", score: 4, label: "Tells you to open Terminal / PowerShell / Run",
      re: /\bopens?\b[^.]{0,55}\b(?:terminal|powershell|windows terminal|command prompt|cmd(?:\.exe)?|run dialog|run box)\b|\bselect\s+(?:windows\s+)?(?:terminal|powershell)|\b(?:terminal|powershell|command prompt)\s*\((?:admin|administrator)\)|\b(?:launch|start|bring up)\b[^.]{0,40}\b(?:terminal|powershell|command prompt|run dialog)\b/ },
    { id: "terminal-verification", group: "os", score: 3, label: "Asks for 'verification' inside a terminal",
      re: /terminal[^.]{0,30}verification|verification[^.]{0,40}terminal|(?:paste|run)[^.]{0,30}(?:verification|captcha) (?:code|command|token)/ },
    { id: "paste-shortcut", group: "paste", score: 4, label: "Tells you to paste with Ctrl+V",
      re: /\b(?:ctrl|control|cmd|command)\s*\+\s*v\b|\bpaste (?:it|the (?:copied|following)|this)\b[^.]{0,40}\b(?:terminal|prompt|powershell|window|dialog)\b/ },
    { id: "press-enter", group: "enter", score: 1, label: "Tells you to press Enter to finish",
      re: /press[^.]{0,25}\benter\b|\benter\b[^.]{0,12}to (?:complete|finish|run|verify)/ }
  ];
  const CHALLENGE_RE = /cloudflare|ray id|needs to review the security of your connection|verif(?:y|ying) (?:that )?(?:you are|you're) (?:a )?human|human verification|i['\u2019]?m not a robot/;

  const SCRIPT_RULES = [
    { id: "clipboard-api", group: "script", score: 2, label: "Page script writes to the clipboard",
      re: /navigator\s*\.\s*clipboard\s*\.\s*write(?:text)?|execCommand\s*\(\s*['"]copy['"]|copyCommandToClipboard\s*\(/i },
    { id: "obfuscated-script", group: "script", score: 2, label: "Script uses decode-and-run obfuscation",
      re: /\beval\s*\(\s*(?:atob|decodeURIComponent|unescape)|new\s+Function\s*\(\s*(?:atob|[\w$]+\s*\))|data:text\/javascript;base64,/i },
    { id: "download-and-execute", group: "script", score: 4, label: "Script stages a downloaded command file and runs it",
      re: /\bcurl\b[\s\S]{0,300}%tmp%[\s\S]{0,200}\.cmd[\s\S]{0,180}(?:&|&&)[\s\S]{0,120}%tmp%/i },
    { id: "web3-c2-lookup", group: "loader", score: 5, label: "Page reads a blockchain contract (eth_call) to find its payload server",
      re: /["']eth_call["'][\s\S]{0,600}(?:["']latest["']|jsonrpc)|(?:jsonrpc|["']latest["'])[\s\S]{0,600}["']eth_call["']/i },
    { id: "xor-loader", group: "loader", score: 5, label: "Numeric array decoded with XOR/charCode and executed",
      re: /\[\s*(?:\d{1,3}\s*,\s*){60,}\d{1,3}\s*\][\s\S]{0,600}fromCharCode[\s\S]{0,300}\^[\s\S]{0,300}(?:new\s+Function|eval)\s*\(/ },
    { id: "dynamic-c2-script", group: "loader", score: 3, label: "Loads a script from a '/get_script' or 'api.php?s=' server",
      re: /\/get_script\b|\/api\.php\?s=/ },
    { id: "cloaking", group: "loader", score: 2, label: "Only activates for Windows and hides from bots/crawlers",
      re: /["'](?:bot|spider|googlebot)["'][\s\S]{0,700}navigator\s*\.\s*platform|navigator\s*\.\s*platform[\s\S]{0,300}["']win["'][\s\S]{0,700}["'](?:bot|spider|googlebot)["']/i }
  ];
  const RUNTIME_RULES = {
    "eth-call":              { id: "rt-eth-call", group: "loader", score: 4, label: "Page queried a blockchain RPC (eth_call) at runtime" },
    "c2-script":             { id: "rt-c2-script", group: "loader", score: 4, label: "Page injected a script from a '/get_script'-style server" },
    "script-after-eth-call": { id: "rt-c2-script", group: "loader", score: 4, label: "Page injected a third-party script right after a blockchain lookup" }
  };
  const chainKinds = new Set();

  /* ================= page collection ================= */
  function findOverlays() {
    const found = new Set();
    const pts = [[.5, .5], [.2, .3], [.8, .7]];
    for (const [fx, fy] of pts) {
      let stack = [];
      try { stack = document.elementsFromPoint(innerWidth * fx, innerHeight * fy); } catch (e) {}
      for (const el of stack.slice(0, 6)) {
        for (let n = el; n && n !== document.body && n !== document.documentElement; n = n.parentElement) {
          if (n.id === "clickfix-guard-alert") break;
          const cs = getComputedStyle(n);
          if (cs.position !== "fixed" && cs.position !== "absolute") continue;
          const r = n.getBoundingClientRect();
          if (r.width >= innerWidth * 0.8 && r.height >= innerHeight * 0.8 && (parseInt(cs.zIndex, 10) || 0) >= 1000) found.add(n);
        }
      }
    }
    return [...found];
  }
  // whole document, NOT just <body>: overlays are often appended to <html>
  function getPageText() { return ((document.documentElement && document.documentElement.innerText) || "").slice(0, CONFIG.maxTextLength); }

  function decodeNumericArrays(src) {
    const out = [];
    if (!/fromCharCode/.test(src) || !/\^/.test(src)) return out;
    const re = /\[\s*((?:\d{1,3}\s*,\s*){99,}\d{1,3})\s*\]/g;
    let m, n = 0;
    while ((m = re.exec(src)) && n++ < 3) {
      const nums = m[1].split(",").map(x => +x);
      if (nums.some(v => !(v >= 0 && v <= 255))) continue;
      for (let k = 1; k < 256; k++) {
        const L = Math.min(nums.length, 160);
        let ok = 0;
        for (let i = 0; i < L; i++) { const c = nums[i] ^ k; if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++; }
        if (ok / L < 0.97) continue;
        let s = "";
        for (const v of nums) s += String.fromCharCode(v ^ k);
        if (/function|var |eth_call|https?:/.test(s.slice(0, 400))) { out.push(s.slice(0, 30000)); break; }
      }
    }
    return out;
  }

  let scriptSig = "", scriptCache = "";
  function getScripts() {
    const list = document.querySelectorAll("script");
    let sig = String(list.length);
    for (const s of list) sig += "," + (s.src ? s.src.length : (s.textContent ? s.textContent.length : 0));
    if (sig === scriptSig) return scriptCache;
    let out = "";
    for (const s of list) {
      if (s.src) { out += "\nSCRIPT-SRC " + s.src; continue; }
      const t = (s.type || "").toLowerCase();
      if (t && !/javascript|module|ecmascript/.test(t)) continue;
      const v = (s.textContent || "").slice(0, CONFIG.maxSingleScriptLength);
      if (!v) continue;
      out += "\n" + v;
      for (const d of decodeNumericArrays(v)) out += "\n/*decoded*/" + d;       // see through XOR-packed loaders
      if (out.length >= CONFIG.maxScriptLength) break;
    }
    scriptSig = sig; scriptCache = out.slice(0, CONFIG.maxScriptLength);
    return scriptCache;
  }

  /* ================= evaluation (pure function, unit-testable) ================= */
  function matchText(text) {
    const m = new Map();
    for (const r of TEXT_RULES) if (r.re.test(text)) m.set(r.id, r);
    return m;
  }
  function evaluate(inp) {
    const evidence = [];
    let score = 0;
    const seen = new Set();
    const addOnce = r => { if (!seen.has(r.id)) { seen.add(r.id); evidence.push({ id: r.id, label: r.label, score: r.score }); score += r.score; } };

    const pageIds = matchText(inp.pageText);
    const ovIds = matchText(inp.overlayText);
    for (const r of pageIds.values()) addOnce(r);
    for (const r of ovIds.values()) addOnce(r);

    let ovChallenge = false;
    if (inp.overlayCount > 0 && CHALLENGE_RE.test(inp.overlayText)) {
      ovChallenge = true;
      addOnce({ id: "overlay-challenge", group: "ctx", score: 3, label: "Full-screen overlay imitating a CAPTCHA / Cloudflare check" });
      if (inp.scrollLocked) addOnce({ id: "scroll-lock", group: "ctx", score: 1, label: "Page scrolling is locked behind the overlay" });
    }
    const scriptIds = new Map();
    for (const r of SCRIPT_RULES) if (r.re.test(inp.scripts)) scriptIds.set(r.id, r);
    for (const r of scriptIds.values()) addOnce(r);
    const rt = new Set();
    for (const k of inp.chainKinds || []) { const r = RUNTIME_RULES[k]; if (r) { addOnce(r); rt.add(r.id); } }

    const count = (ids, g) => [...ids.values()].filter(r => r.group === g).length;
    const osPage = count(pageIds, "os"), osOv = count(ovIds, "os");
    const pastePage = pageIds.has("paste-shortcut"), pasteOv = ovIds.has("paste-shortcut");
    const ctxStrong = pageIds.has("verification-language") || ovIds.has("verification-language") || ovChallenge;
    const loader = count(scriptIds, "loader") + rt.size;
    const recipeOv = osOv >= 1 && pasteOv;                      // overlay says: open a tool + paste
    const recipePage = osPage >= 1 && pastePage;

    let level = "No alert";
    if (recipeOv || (recipePage && (ctxStrong || loader >= 1)) || (ctxStrong && loader >= 2)) level = "High";
    else if ((ctxStrong && (osPage >= 1 || (pastePage && inp.overlayCount > 0))) || loader >= 2 || (recipePage && inp.overlayCount > 0)) level = "Medium";
    else if (loader >= 1) level = "Review";

    return { level, score, evidence, flags: { recipeOv, recipePage, ctxStrong, loader, osOv } };
  }

  /* ================= alert UI ================= */
  let scan = { level: "No alert", score: 0, evidence: [], flags: {} };
  let incident = null;
  let alertNode = null, shadowRoot = null;
  let dismissedKey = "", lastKey = "";

  const RANK = { "No alert": 0, "Review": 1, "Medium": 2, "High": 3 };
  const CLICKFIX_SUMMARY =
    "This is a ClickFix scam: a fake \u201cverification\u201d page that tricks you into pasting a malicious command into Run, PowerShell or Terminal. Do not paste anything and close this page.";
  function compose() {

     let level = scan.level;
    if (incident) {
      const il = incident.verdict === "block" ? "High" : "Medium";
      if (RANK[il] > RANK[level]) level = il;
    }
    return { level, evidence: [], summary: CLICKFIX_SUMMARY };
  }
  

  function removeAlert() {
    if (alertNode && alertNode.isConnected) { try { alertNode.hidePopover && alertNode.hidePopover(); } catch (e) {} alertNode.remove(); }
    alertNode = null; shadowRoot = null;
  }

  function ensureAlert() {
    if (alertNode && alertNode.isConnected && shadowRoot) return;
    alertNode = document.createElement("div");
    alertNode.id = "clickfix-guard-alert";
    alertNode.setAttribute("role", "alert");
    shadowRoot = alertNode.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .cfx-panel { box-sizing:border-box; width:100%; padding:16px; border:1px solid #b42318; border-radius:12px;
        background:#fff; color:#202124; box-shadow:0 8px 28px rgba(0,0,0,.35); font:14px/1.45 Arial,Helvetica,sans-serif; }
      .cfx-top { display:flex; align-items:center; justify-content:space-between; gap:12px; }
      .cfx-title { font-size:15px; font-weight:700; }
      .cfx-close { border:0; background:transparent; color:#555; cursor:pointer; font-size:24px; line-height:1; }
      .cfx-level { margin-top:10px; font-weight:700; color:#b42318; }
      .cfx-summary { margin:8px 0; }
      .cfx-evidence { margin:8px 0; padding-left:20px; max-height:220px; overflow:auto; font-size:13px; }
      .cfx-evidence li { margin:4px 0; word-break:break-word; }
      .cfx-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
      .cfx-btn { border:0; border-radius:6px; padding:8px 11px; background:#b42318; color:#fff; cursor:pointer; font-weight:600; }
      .cfx-btn.secondary { background:#eceff3; color:#202124; }
      .cfx-btn:disabled { opacity:.65; cursor:wait; }
      .cfx-note { margin:10px 0 0; padding-top:9px; border-top:1px solid #ddd; font-size:12px; color:#555; }
      .cfx-panel[data-level="medium"] { border-color:#b54708; } .cfx-panel[data-level="medium"] .cfx-level { color:#b54708; }
      .cfx-panel[data-level="review"] { border-color:#667085; } .cfx-panel[data-level="review"] .cfx-level { color:#475467; }
    `;
    shadowRoot.appendChild(style);

    const panel = document.createElement("section");
    panel.className = "cfx-panel";
    panel.innerHTML = `
      <div class="cfx-top"><strong class="cfx-title">ClickFix Guard</strong>
        <button type="button" class="cfx-close" aria-label="Dismiss warning">\u00d7</button></div>
      <div class="cfx-level"></div>
      <p class="cfx-summary"></p>
   
      <div class="cfx-actions">
        <button type="button" class="cfx-btn cfx-clear">Clear clipboard now</button>
        <button type="button" class="cfx-btn secondary cfx-allow" hidden>Copy anyway</button>
      </div>
      <p class="cfx-note">Never paste commands into Run, PowerShell or Terminal to \u201cverify\u201d or \u201cfix\u201d something on a web page.</p>`;
    shadowRoot.appendChild(panel);

    shadowRoot.querySelector(".cfx-close").addEventListener("click", ev => { if (!ev.isTrusted) return; dismissedKey = lastKey; removeAlert(); });
    shadowRoot.querySelector(".cfx-clear").addEventListener("click", ev => { if (ev.isTrusted) clearClipboard(ev.currentTarget); });
    shadowRoot.querySelector(".cfx-allow").addEventListener("click", ev => {
      if (!ev.isTrusted || !incident) return;
      send("__cfg_allow", { id: incident.id });
      incident.allowed = true;
      shadowRoot.querySelector(".cfx-note").textContent = "Copied once. This exact command is now trusted on this site.";
      shadowRoot.querySelector(".cfx-allow").hidden = true;
    });

    (document.documentElement || document).appendChild(alertNode);
    try { alertNode.popover = "manual"; alertNode.showPopover(); } catch (e) {}   // top layer: above any z-index overlay
  }

  function render() {
    const v = compose();
     if (v.level === "High") { blockPage(); return; }
    if (v.level === "No alert") { removeAlert(); return; }
    const key = v.level + "|" + (incident ? incident.id : "") + "|" + scan.evidence.map(e => e.id).join(",");
    lastKey = key;
    if (dismissedKey === key) { removeAlert(); return; }
    ensureAlert();
    const panel = shadowRoot.querySelector(".cfx-panel");
    panel.dataset.level = v.level.toLowerCase();
    shadowRoot.querySelector(".cfx-level").textContent = v.level + " risk";
    shadowRoot.querySelector(".cfx-summary").textContent = v.summary;
    shadowRoot.querySelector(".cfx-allow").hidden = !(incident && incident.verdict === "block" && !incident.allowed);
  }

  async function clearClipboard(button) {
    const note = shadowRoot && shadowRoot.querySelector(".cfx-note");
    if (!button || !note) return;
    button.disabled = true; button.textContent = "Clearing\u2026";
    try {
      await navigator.clipboard.writeText("");
      note.textContent = "Clipboard text was cleared."; button.textContent = "Clipboard cleared";
    } catch (err) {
      note.textContent = "The browser blocked clipboard clearing. Clear it manually.";
      button.textContent = "Could not clear"; button.disabled = false;
    }
  }

  /* ================= events from the MAIN-world hook ================= */
  const cut = (s, n) => String(s == null ? "" : s).slice(0, n);
  function onClip(e) {
    let d;
    try { d = JSON.parse(e.detail); } catch (err) { return; }
    if (!d || typeof d.id !== "string" || !Array.isArray(d.labels)) return;
    incident = {
      id: cut(d.id, 16), verdict: d.verdict === "block" ? "block" : "warn", P: +d.P || 0, R: +d.R || 0,
      source: cut(d.source, 24), prov: cut(d.prov, 16), visible: !!d.visible,
      labels: d.labels.slice(0, 12).map(x => cut(x, 120)), preview: cut(d.preview, 200), decoded: cut(d.decoded, 200), allowed: false
    };
    dismissedKey = "";
    log("clipboard incident", incident);
    render();
  }
  function onChain(e) {
    try { const d = JSON.parse(e.detail); if (RUNTIME_RULES[d.kind]) { chainKinds.add(d.kind); log("loader chain", d.kind, d.url); scheduleScan(); } } catch (err) {}
  }

  /* ================= scanning ================= */
  let scanTimer = null, scansInWindow = 0, windowStart = Date.now();
  function runScan() {
    scanTimer = null;
    if (!document.documentElement) return;
    const overlays = findOverlays();
    const inp = {
      pageText: norm(getPageText()),
      overlayText: norm(overlays.map(o => o.innerText || "").join("\n")),
      overlayCount: overlays.length,
      scrollLocked: !!(document.body && getComputedStyle(document.body).overflow === "hidden"),
      scripts: getScripts(),
      chainKinds: [...chainKinds]
    };
    scan = evaluate(inp);
    const risk = scan.level === "Medium" || scan.level === "High";
    if (risk !== pageRisk) { pageRisk = risk; pushState(); }
    log("scan", scan.level, scan.evidence.map(e => e.id).join(","));
    render();
  }
  function scheduleScan() {
    if (scanTimer !== null) clearTimeout(scanTimer);
    const now = Date.now();
    if (now - windowStart > 10000) { windowStart = now; scansInWindow = 0; }
    const delay = ++scansInWindow > 20 ? 1500 : CONFIG.debounceMs;   // back off on very busy pages
    scanTimer = setTimeout(runScan, delay);
  }
  let observer = null;
  function startObserver() {
    if (observer || !document.documentElement) return;
    observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  }


 let redirected = false;
  async function blockPage() {
    if (redirected || window !== window.top) return;      // top frame only
    redirected = true;
    try {
      const { cfxAllowHosts = [] } = await chrome.storage.local.get("cfxAllowHosts");
      if (cfxAllowHosts.includes(location.hostname)) { redirected = false; return; }
    } catch (e) {}
    location.replace(chrome.runtime.getURL("warning.html") + "?u=" + encodeURIComponent(location.href));
  }


  if (document.documentElement) startObserver(); else document.addEventListener("DOMContentLoaded", startObserver, { once: true });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scheduleScan, { once: true }); else scheduleScan();
  window.addEventListener("load", scheduleScan);
  window.addEventListener("popstate", scheduleScan);
  window.addEventListener("hashchange", scheduleScan);
})();
