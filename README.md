 ClickFix Guard 

## What it does

- Watches every clipboard write a page makes (`writeText`, `write`, `execCommand`, `setData`) and blocks or flags commands that download or run code.
- Scans the page for ClickFix lures: fake verification screens, overlays, hidden or packed scripts, and loader chains.
- On a confirmed scam, replaces the page with a full-screen warning. On a lower-confidence match, shows a small warning popup instead.
- The warning only says that the page is a ClickFix scam. It never displays the copied command.

## Install

1. Open `chrome://extensions` and switch on **Developer mode**.
2. Click **Load unpacked** and select the `clickfix-guard` folder.
3. After editing any file, press the reload icon on the extension card **and reload the page you are testing**.

## Files

| File | Runs in | Job |
|---|---|---|
| `manifest.json` | n/a | Extension config. Exposes `warning.html` and `warning.js` to web pages for the redirect. |
| `clipboard-hook.js` | page (MAIN world), `document_start` | Wraps clipboard APIs, decodes base-N layers, scores the payload and context, blocks or warns. Also hooks XHR, fetch and script loading to spot loader chains. |
| `content.js` | extension (isolated world) | Scans the document, inline scripts and runtime evidence. Shows the popup, redirects on High risk, stores "Copy anyway" approvals. |
| `content.css` | extension | Host styles for the popup (the panel itself lives in a closed shadow root in the top layer). |
| `warning.html` / `warning.js` | extension page | Full-screen warning shown after a High-risk redirect. |


## What the user sees

| Risk level | Result |
|---|---|
| **High** | The page is replaced by `warning.html`. Buttons: **Go back to safety** and **Continue anyway (not recommended)**. |
| **Medium / Review** | A small popup in the top-right corner with a one-sentence explanation and a **Clear clipboard now** button. The page stays usable. |
| **No alert** | Nothing happens. |

"Continue anyway" saves the site's hostname in `chrome.storage.local` (`cfxAllowHosts`), so the redirect is skipped for that site afterwards. To reset, clear the extension's storage or remove the entry.

Only the top frame is redirected. A lure inside an iframe still gets the popup.

A user's own Ctrl+C is never analysed, unless the page replaces the selected text.

Separately, the page scanner (`content.js`) rates the page itself as Review, Medium or High from the overlay, page text and loader evidence. A blocked copy counts as High, a warned copy as Medium. The highest level wins.

##Demo
![Video](https://github.com/frameman/det-clickfix-web-extension/blob/main/demo.gif)


Reference example form AnyRun
link: https://app.any.run/tasks/823d8b34-36ca-42c1-86d1-dd493f1cc98c/
