# ClickFix Guard (Chrome Extension, Manifest V3)

ClickFix Guard is a browser extension prototype that identifies webpage content resembling ClickFix social-engineering instructions.

## Install locally

1. Extract this ZIP file.
2. Open `chrome://extensions` in Chrome or `edge://extensions` in Microsoft Edge.
3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Choose the `clickfix_extension` folder.

## Detection approach

The extension combines several indicators:

- Human-verification wording and CAPTCHA-like page elements.
- Windows shortcut instructions such as `Win + R` and `Win + X`.
- Instructions to open PowerShell, Terminal, Command Prompt, or the Run dialog.
- Instructions to copy, paste, or execute commands.
- Clipboard API references and common inline-script decoding patterns.

A CAPTCHA element or the phrase "I'm not a robot" alone should not trigger a ClickFix warning. The main alert requires verification context together with concrete operating-system or command instructions.

## Clipboard protection

The warning panel provides a **Clear clipboard** button. Clipboard text is cleared only after the user explicitly clicks the button.

Automatic clipboard clearing is intentionally disabled. A webpage's suspicious content does not prove that the current clipboard contents are malicious, and silently clearing the clipboard could destroy unrelated user data. Browser clipboard access can also be restricted by permissions, security context, and user-activation requirements.

The extension requests the `clipboardWrite` permission to support the user-initiated clear action. Clipboard clearing remains best-effort; the browser may block it.

## Limitations

- This is a heuristic prototype, not a guarantee of maliciousness or a replacement for browser reputation/security controls.
- It scans accessible DOM content and inline scripts. It does not inspect all external scripts, browser UI, or content inside cross-origin frames that Chrome does not allow it to access.
- Text may be obfuscated, translated, rendered in images, or changed to evade these rules.
- `all_frames` allows injection into frames where Chrome permits it.
- Broad host permissions enable scanning across HTTP and HTTPS websites. For narrower deployment, restrict `host_permissions` and `content_scripts.matches`.
- The extension warns users but does not block navigation or disable webpage controls.

## Testing

Test in a controlled environment using pages that represent:

1. A normal CAPTCHA containing only "I'm not a robot" — should not alert.
2. A CAPTCHA with "Press Windows Key + R" — should alert.
3. A verification page instructing users to open PowerShell and paste a command — should alert.
4. A normal page discussing PowerShell without verification instructions — should not produce a ClickFix alert unless additional suspicious script indicators are present.
5. A page that injects ClickFix-like instructions after load — should be detected after the DOM changes.

After replacing the extension files, open `chrome://extensions` and click **Reload** on ClickFix Guard.
