(() => {
  "use strict";

  // Prevent duplicate execution in the same frame.
  if (window.__clickFixGuardLoaded) return;
  window.__clickFixGuardLoaded = true;

  const CONFIG = {
    maxTextLength: 180000,
    maxScriptLength: 80000,
    maxSingleScriptLength: 20000,
    debounceMs: 200,
    minAlertScore: 7
  };

  const ACTION_IDS = new Set([
    "os-shortcut",
    "open-system-tool",
    "paste-command",
    "execution-language"
  ]);

  const RULES = [
    {
      id: "verification-language",
      score: 2,
      label: "Human-verification wording",
      regex: /\b(?:i['’]?m not a robot|i am not a robot|verify you are human|human verification|complete these verification steps|security verification)\b/i
    },
    {
      id: "captcha-widget",
      score: 1,
      label: "CAPTCHA-like page element",
      selector: [
        ".cjs-container",
        ".checkbox-window",
        ".verify-window",
        "[id*='captcha' i]",
        "[class*='captcha' i]",
        "[aria-label*='captcha' i]"
      ].join(",")
    },
    {
      id: "os-shortcut",
      score: 4,
      label: "Instruction to use a Windows shortcut",
      regex: /\b(?:press|hold|use|hit)\b.{0,45}\b(?:windows?\s*(?:key|button)?|win)\b.{0,35}(?:\+\s*(?:x|r)|power\s*user|run\s*dialog)\b|\b(?:windows?\s*key|win)\s*\+\s*(?:x|r)\b/i
    },
    {
      id: "open-system-tool",
      score: 4,
      label: "Instruction to open a system utility",
      regex: /\b(?:open|launch|start|bring up)\b.{0,55}\b(?:run dialog|powershell|windows terminal|command prompt|cmd(?:\.exe)?|terminal|power user menu)\b/i
    },
    {
      id: "paste-command",
      score: 4,
      label: "Instruction to copy or paste a command",
      regex: /\b(?:copy|paste|type|enter)\b.{0,70}\b(?:command|code|script|powershell|cmd(?:\.exe)?|terminal)\b|\b(?:copy and paste|paste the following|paste this command)\b/i
    },
    {
      id: "execution-language",
      score: 4,
      label: "Command execution wording",
      regex: /\b(?:press\s+enter\s+to\s+run|execute\s+the command|run\s+the following|powershell(?:\.exe)?\s+-|cmd(?:\.exe)?\s+\/c)\b/i
    },
    {
      id: "clipboard-api",
      score: 2,
      label: "Inline script references clipboard access",
      scriptRegex: /navigator\s*\.\s*clipboard|clipboard\s*\.\s*writeText|document\.execCommand\s*\(\s*['"]copy/i
    },
    {
      id: "obfuscated-script",
      score: 2,
      label: "Inline script contains common decoding or obfuscation patterns",
      scriptRegex: /\beval\s*\(\s*(?:atob|decodeURIComponent)|atob\s*\(|data:text\/javascript;base64,/i
    }
  ];

  let scanTimer = null;
  let lastSignature = "";
  let lastRenderedSignature = "";
  let dismissedSignature = "";
  let alertNode = null;
  let shadowRoot = null;
  let observer = null;

  function getPageText() {
    const source = document.body?.innerText ||
      document.documentElement?.innerText || "";
    return source.slice(0, CONFIG.maxTextLength);
  }

  function getInlineScripts() {
    let output = "";

    for (const script of document.querySelectorAll("script:not([src])")) {
      const value = script.textContent || "";
      if (!value) continue;

      output += value.slice(0, CONFIG.maxSingleScriptLength) + "\n";
      if (output.length >= CONFIG.maxScriptLength) break;
    }

    return output.slice(0, CONFIG.maxScriptLength);
  }

  function collectEvidence(text, scripts) {
    const evidence = [];
    let score = 0;

    for (const rule of RULES) {
      let matched = false;

      if (rule.regex?.test(text)) matched = true;

      if (rule.selector) {
        try {
          if (document.querySelector(rule.selector)) matched = true;
        } catch {
          // Ignore invalid or unsupported selectors.
        }
      }

      if (rule.scriptRegex?.test(scripts)) matched = true;

      if (matched) {
        evidence.push({
          id: rule.id,
          label: rule.label,
          score: rule.score
        });
        score += rule.score;
      }
    }

    const ids = new Set(evidence.map(item => item.id));
    const hasVerificationContext =
      ids.has("verification-language") || ids.has("captcha-widget");

    const actionEvidence = evidence.filter(item => ACTION_IDS.has(item.id));
    const hasActionInstructions = actionEvidence.length > 0;

    // A CAPTCHA element or verification phrase alone must not trigger an alert.
    // Require verification context plus concrete operating-system/command instructions.
    const hasClickFixCombination =
      hasVerificationContext && hasActionInstructions;

    // A secondary review signal catches pages that combine command instructions
    // with suspicious inline clipboard/obfuscation code, even without CAPTCHA wording.
    const hasScriptSupport =
      ids.has("clipboard-api") || ids.has("obfuscated-script");

    let level = "No alert";

    if (hasClickFixCombination && score >= 11) {
      level = "High";
    } else if (hasClickFixCombination && score >= CONFIG.minAlertScore) {
      level = "Medium";
    } else if (actionEvidence.length > 0 && hasScriptSupport && score >= 8) {
      level = "Review";
    }

    return {
      score,
      level,
      evidence,
      hasVerificationContext,
      hasActionInstructions,
      hasClickFixCombination
    };
  }

  function removeAlert() {
    if (alertNode?.isConnected) alertNode.remove();
    alertNode = null;
    shadowRoot = null;
  }

  function ensureAlert() {
    if (alertNode?.isConnected && shadowRoot) return;

    alertNode = document.createElement("div");
    alertNode.id = "clickfix-guard-alert";
    alertNode.setAttribute("role", "status");
    alertNode.setAttribute("aria-live", "polite");

    shadowRoot = alertNode.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .cfx-panel {
        box-sizing: border-box; width: 100%; padding: 16px;
        border: 1px solid #b42318; border-radius: 12px;
        background: #fff; color: #202124;
        box-shadow: 0 8px 28px rgba(0,0,0,.25);
        font: 14px/1.45 Arial, Helvetica, sans-serif;
      }
      .cfx-top {
        display:flex; align-items:center; justify-content:space-between; gap:12px;
      }
      .cfx-title { font-size: 15px; font-weight: 700; }
      .cfx-close {
        border:0; background:transparent; color:#555;
        cursor:pointer; font-size:24px; line-height:1;
      }
      .cfx-level { margin-top:10px; font-weight:700; color:#b42318; }
      .cfx-summary { margin:8px 0; }
      .cfx-evidence { margin:8px 0; padding-left:20px; }
      .cfx-evidence li { margin:4px 0; }
      .cfx-actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; }
      .cfx-clear {
        border:0; border-radius:6px; padding:8px 11px;
        background:#b42318; color:#fff; cursor:pointer; font-weight:600;
      }
      .cfx-clear:disabled { opacity:.65; cursor:wait; }
      .cfx-note {
        margin:10px 0 0; padding-top:9px; border-top:1px solid #ddd;
        font-size:12px; color:#555;
      }
      .cfx-panel[data-level="medium"] { border-color:#b54708; }
      .cfx-panel[data-level="medium"] .cfx-level { color:#b54708; }
      .cfx-panel[data-level="review"] { border-color:#667085; }
      .cfx-panel[data-level="review"] .cfx-level { color:#475467; }
    `;
    shadowRoot.appendChild(style);

    const panel = document.createElement("section");
    panel.className = "cfx-panel";
    panel.innerHTML = `
      <div class="cfx-top">
        <strong class="cfx-title">ClickFix Guard</strong>
        <button type="button" class="cfx-close" aria-label="Dismiss warning">×</button>
      </div>
      <div class="cfx-level"></div>
      <p class="cfx-summary"></p>
      <ul class="cfx-evidence"></ul>
      <div class="cfx-actions">
        <button type="button" class="cfx-clear">Clear clipboard</button>
      </div>
      <p class="cfx-note">
        Do not paste commands into Run, PowerShell, or Terminal to complete a CAPTCHA.
        Clipboard clearing requires your explicit click.
      </p>
    `;
    shadowRoot.appendChild(panel);

    shadowRoot.querySelector(".cfx-close").addEventListener("click", () => {
      dismissedSignature = lastSignature;
      removeAlert();
    });
    shadowRoot.querySelector(".cfx-clear").addEventListener("click", clearClipboardFromUserAction);

    (document.documentElement || document).appendChild(alertNode);
  }

  function renderAlert(result) {
    if (result.level === "No alert") {
      removeAlert();
      return;
    }

    ensureAlert();

    const panel = shadowRoot.querySelector(".cfx-panel");
    panel.dataset.level = result.level.toLowerCase();

    shadowRoot.querySelector(".cfx-level").textContent =
      `${result.level} risk · Score ${result.score}`;

    shadowRoot.querySelector(".cfx-summary").textContent =
      result.hasClickFixCombination
        ? "This page combines verification-style content with instructions to interact with Windows or execute commands."
        : "Suspicious command instructions and inline script indicators were found. Review the page carefully.";

    const list = shadowRoot.querySelector(".cfx-evidence");
    list.replaceChildren();

    for (const item of result.evidence) {
      const li = document.createElement("li");
      li.textContent = item.label;
      list.appendChild(li);
    }
  }

  async function clearClipboardFromUserAction(event) {
    const button = event.currentTarget;
    const note = shadowRoot?.querySelector(".cfx-note");
    if (!button || !note) return;

    button.disabled = true;
    button.textContent = "Clearing…";

    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API is unavailable in this page context.");
      }

      await navigator.clipboard.writeText("");
      note.textContent = "Clipboard text was cleared.";
      button.textContent = "Clipboard cleared";
    } catch (error) {
      console.warn("[ClickFix Guard] Clipboard clearing failed:", error);
      note.textContent =
        "The browser blocked clipboard clearing. You can clear it manually using your device's clipboard controls.";
      button.textContent = "Could not clear";
      button.disabled = false;
    }
  }

  function scan() {
    scanTimer = null;
    if (!document.documentElement) return;

    const result = collectEvidence(getPageText(), getInlineScripts());

    const signature = JSON.stringify({
      score: result.score,
      level: result.level,
      evidence: result.evidence.map(item => item.id)
    });

    if (signature !== lastSignature) {
      lastSignature = signature;
      if (dismissedSignature && dismissedSignature !== signature) {
        dismissedSignature = "";
      }
    }

    if (result.level === "No alert") {
      if (alertNode) removeAlert();
      lastRenderedSignature = "";
      dismissedSignature = "";
      return;
    }

    // Keep a dismissed warning hidden until the detection evidence changes.
    if (dismissedSignature === signature) {
      if (alertNode) removeAlert();
      return;
    }

    // Restore the warning if the webpage removes it, or refresh it when evidence changes.
    if (!alertNode?.isConnected || !shadowRoot || signature !== lastRenderedSignature) {
      renderAlert(result);
      lastRenderedSignature = signature;
    }
  }

  function scheduleScan() {
    if (scanTimer !== null) clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, CONFIG.debounceMs);
  }

  function startObserver() {
    if (observer || !document.documentElement) return;

    observer = new MutationObserver(scheduleScan);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  // At document_start, documentElement may not exist yet.
  if (document.documentElement) {
    startObserver();
  } else {
    document.addEventListener("DOMContentLoaded", startObserver, { once: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scheduleScan, { once: true });
  } else {
    scheduleScan();
  }

  // Re-scan after browser history navigation and hash-based SPA navigation.
  window.addEventListener("popstate", scheduleScan);
  window.addEventListener("hashchange", scheduleScan);
})();
