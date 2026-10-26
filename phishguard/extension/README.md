# PhishGuard Sentinel

Sentinel is a plain JavaScript Chromium Manifest V3 extension. It has no separate bundler or compilation step: the files in this directory are the unpacked extension.

## Build / package

From the project root, start the FastAPI app and download its generated package:

```bash
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
curl -f http://127.0.0.1:8000/api/extension/package -o /tmp/phishguard-sentinel.zip
unzip -q /tmp/phishguard-sentinel.zip -d /tmp/phishguard-sentinel
```

Or make a local ZIP directly from this directory:

```bash
cd extension
zip -r ../phishguard-sentinel.zip .
```

## Install in Chrome or Edge

1. Extract the ZIP if using the generated package.
2. Open `chrome://extensions` in Chrome or `edge://extensions` in Edge.
3. Enable **Developer mode**.
4. Choose **Load unpacked** and select the `phishguard-sentinel` directory (or this `extension/` directory).
5. Open the Sentinel popup, expand **Privacy & site controls** to choose local-only or backend mode, exclusions, and whether protection is enabled. Use **More settings** to configure the backend URL and language.

The extension works with its dashboard closed. Standard and Strict modes send only URL hostname/path plus structural metadata to the configured PhishGuard backend. Query values and fragments are removed; credentials are never sent. Local-only mode runs the bundled rules and Public Suffix List without backend requests. The Python backend currently has no trained ML artifact, so it returns its actual URL-heuristic findings; Sentinel does not claim ML predictions. “View Detailed Analysis” opens the existing dashboard with the redacted destination prefilled and invokes its normal scanner after the user explicitly chooses that action.

## Permissions

- `webNavigation`: observe top-level HTTP(S) navigation starts and commits.
- `webRequest`: observe main-frame redirects so redirected destinations are checked.
- `tabs`: replace a strongly flagged navigation with the warning page and open the dashboard.
- `storage`: keep settings, per-tab analysis status, and short-lived warning/continue state.
- `<all_urls>` host access: inspect and call the configured backend across arbitrary supported sites. Chrome displays this broad site-access scope during installation.

Sentinel does not read page contents, forms, passwords, or cookies. Session storage retains the original destination only while its warning is active and the last committed site origin per open tab so **Go Back to Safety** can return without replaying the blocked navigation; tab close clears this state. Navigation events are asynchronous; an extension-owned warning can interrupt a page while it is loading, but Chrome/Edge do not let this service worker synchronously block every request before it starts.

## Checks

From the project root:

```bash
node --check extension/background.js
node --check extension/local-detector.js
node --check extension/popup.js
node --check extension/warning.js
node tests/test_sentinel_local.js
node tests/sentinel_browser_e2e.js
.venv/bin/python -m pytest -q
```

The browser-level workflow uses Chromium with an isolated profile and synthetic fixture domains; it does not visit live malicious sites.
