# PhishGuard 3.0

**Detect the Threat. Understand the Attack. Expose the Connection.**

A local-first URL investigation workspace. The project was already a functioning FastAPI/SQLite/vanilla HTML/CSS/JS heuristic scanner; the existing PSL-aware parsing, brand configuration, safe no-fetch behavior, baseline history, and risk rules were preserved and extended rather than replaced with an assumed ML system.

## Run locally

```bash
cd /home/node/phishguard
uv pip install --python .venv/bin/python -r requirements.txt
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`; API docs are at `/api/docs`, and health is `/api/health`. To use another SQLite file, set `PHISHGUARD_DB=/path/to/phishguard.sqlite3` before starting. No paid API, model, or frontend build is required.

## Test

```bash
cd /home/node/phishguard
PYTHONPATH=. .venv/bin/python -m pytest -q
node --check static/app-v2.js
```

## Implemented capabilities

- Responsive SOC-style application with overview, URL investigation, Attack DNA, Counterfactual Lab, batch analysis/CSV import, searchable history, model evaluation status, grounded copilot, JSON reports, and integration/privacy settings. Dark theme is default; theme toggle persists a light theme.
- URL parsing accepts HTTP(S), uses an offline Public Suffix List snapshot, preserves relevant parser details and displays the registered domain. It never fetches or executes submitted URLs.
- Explainable URL heuristics and Trust Gap checks for configured brands, including subdomain mismatch and IDN/Punycode display. Heuristic points are a triage scale, not a probability.
- Every scan report identifies completed, unavailable, and skipped pipeline stages. URLs' query strings and fragments are removed from persisted report URLs.
- Counterfactual Lab reruns both inputs through the same `run_scan` pipeline, compares actual extracted features, rules, scores and domains, handles identical outputs without forcing a verdict, and discloses non-causality.
- Attack DNA derives relationships only from reports. Shared registered domains are direct parser observations; hostname brand references are marked heuristic hypotheses. Every edge carries evidence, source, classification, strength and limitations. Optional graph demo uses reserved `example.*` URLs and is explicitly synthetic; it invents no IP/DNS/certificate facts.
- Batch endpoint supports up to 50 URL strings with partial failure handling. CSV import is constrained to 1 MB and reads a first-column URL-like value; submitted URLs are not opened.
- Copilot is a rules-based fallback grounded in selected stored report fields; it clearly states no LLM is configured.
- Model Evaluation Center returns **Not evaluated**: no dataset, trained artifact, or scikit-learn is present. It does not invent metrics.
- SQLite scan history, individual and all-record deletion, dashboard counts based on stored records, per-report JSON download, simple in-memory request throttling, and endpoint input limits.

## Risk methodology

The baseline risk score sums visible, URL-derived heuristic points and caps at 100: userinfo (25), IP hostname (20), normalized URL over 120 chars (10), at least three subdomains (15), brand/registered-domain mismatch (40), lookalike registered label (15), internationalized hostname (15), and HTTP (5). Categories are Lower Risk (0–24), Caution (25–49), High Risk (50–74), and Very High Risk (75–100). Signals may correlate. This is not calibrated attack likelihood, a verdict, or proof of maliciousness. HTTPS alone never implies trust; missing reputation data never lowers the score as a trust signal.

## Machine learning and model evaluation

No model or dataset existed in the supplied project directory, and scikit-learn is not installed in its local virtual environment. Therefore this version reports heuristic-only analysis and **Not evaluated**. No UCI dataset, trained model, label mapping, accuracy, or feature importance is claimed. To add a model, establish dataset label semantics and provenance, deduplicate before splitting, preserve the training feature order and preprocessing, version the artifact, validate prediction classes/probabilities, and evaluate held-out records only before enabling inference or reporting metrics.

## Integrations and limitations

- Threat reputation, DNS, registration, certificate and hosting lookups are not configured or performed. No submitted URL is sent to a provider.
- No LLM is configured; copilot answers are a narrow rules fallback, not generated AI.
- PDF export, authentication, user separation, distributed rate limiting, configurable retention, and production deployment hardening are not implemented.
- SQLite history is local, shared by anyone with access to the running instance. Don't expose publicly without authentication, HTTPS, access controls, stronger rate limits and retention governance.
- Query strings and fragments are excluded before persistence; URL paths can still contain sensitive information. Avoid pasting credentials, account-recovery links, or access tokens.
- `tldextract` uses its offline packaged suffix snapshot. Official-domain mappings are a small manually curated list in `app/scanner.py`, not a complete verified brand directory.
- A valid TLS certificate, low heuristic score, or lack of reputation matches does not establish legitimacy. No content, ownership or infrastructure findings are implied.

## Demonstration sequence

1. Overview: observe empty/real local summary and model-unavailable status.
2. URL Investigation: scan `https://google.com.account-verification.example.org/login`; inspect registered domain `example.org`, brand mismatch finding, stages and limitations. This is illustrative only.
3. Counterfactual Lab: compare `https://example.org/` with the above variant, then compare `https://example.com/a` and `https://example.net/b` to see unchanged output reported honestly.
4. Batch: submit `https://login.example.org/a` and `https://accounts.example.org/b`, optionally add an invalid row; inspect partial result and evidence graph.
5. Attack DNA: refresh saved-history graph, select a shared-domain edge and read its direct evidence and no-attribution limitation; load synthetic demonstration graph separately.
6. Copilot: select a saved report and ask “Why was this URL flagged?” or “Which checks were unavailable?”
7. Model Evaluation: confirm **Not evaluated**. Download JSON from Reports & Exports.

Synthetic graph records are clearly labelled and are not inserted into actual scan statistics/history.

## PhishGuard Sentinel extension (Chromium / Edge)

Download the extension archive while the app is running at `/api/extension/package`, or load the `extension/` folder directly:

1. Extract `phishguard-sentinel.zip`.
2. Open `chrome://extensions` or `edge://extensions` and enable Developer mode.
3. Select **Load unpacked** and choose the extracted `phishguard-sentinel` folder.
4. Open the extension settings and keep or enter the local API URL (normally `http://127.0.0.1:8000`), then save.

The Manifest V3 service worker observes top-level HTTP(S) navigation events and checks each URL through `POST /api/extension/check` in Standard and Strict modes. That endpoint uses the same `run_scan` parser/rules as manual analysis and does not persist the browsing event in manual history. Standard mode only warns at 50+ points with a brand mismatch or URL-userinfo finding; Strict mode warns at 25+ with a strong finding or multiple findings. Thresholds are triage rules, not probabilities. The warning page shows the report and allows back, continue, detailed dashboard, and locally stored incorrect-warning feedback. Continue preserves the original destination URL, including query and fragment.

The extension requests broad host access so it can inspect supported top-level navigation destinations across sites; it also uses `webNavigation`, `webRequest`, `tabs`, and `storage`. That broad host permission also allows requests to the configured backend, so settings do not trigger a second origin-permission prompt. It does not read page content, forms, passwords, or cookies. The hostname and path are sent to the configured PhishGuard backend; userinfo, query values and fragments are stripped first. Their presence and query length are sent as structural metadata. The original destination is held in extension session storage only until a warning is dismissed or continued. No destination is sent to a third-party intelligence provider or added to manual scan history. If backend analysis fails, the popup shows the local result with an explicit fallback status, or **unavailable** if local analysis also failed. Navigation analysis is asynchronous: Chromium's navigation events do not let this extension synchronously hold every request, so a warning may replace a page after loading begins. This is not guaranteed pre-navigation blocking. **Local-only** runs the bundled PSL-aware URL heuristic detector without sending URLs to the backend; it does not provide ML or external reputation checks.

## Styling repair and current scope

The current dashboard had linked `v2.css`, which only contained a small graph-control override. `styles.css` was a 2.0-era stylesheet whose selectors did not match the current dashboard's `.shell`, `.sidebar`, `.metric`, and `.panel` markup. A Chromium headless screenshot confirmed default browser controls and unstyled cards. The page now loads `dashboard.css` (the matching layout/design stylesheet) and `v2.css`; static CSS is served as `text/css`. A second Chromium screenshot confirmed the dark responsive dashboard, sidebar, metric cards, panels, and table styling.

The web language selector persists English, Hindi, Marathi, or Hinglish. Browser-language fallback selects Hindi or Marathi when detected. Current translation resources cover navigation, page headings, and key actions; the rest of the page copy, investigation report, and Copilot responses remain mostly English. Extension warning chrome supports English, Hindi, Marathi, and Hinglish, while the evidence details remain in the original report language/technical terms. This is a partial localization foundation, not a fully translated product.

The ZIP endpoint packages only reviewed extension source files; it contains no API keys. To run the updated backend, restart the existing server with the command in **Run locally**. The extension package route is generated from the `extension/` directory at request time.

## PhishGuard 3.0 implementation status

Preserved and still available: local URL parsing and heuristic findings, PSL-aware domain extraction, Trust Gap rules, Counterfactual Lab, Attack DNA from saved reports, batch analysis, SQLite history, JSON exports, evaluation-unavailable reporting, and the evidence-grounded rules Copilot.

Added in this upgrade: the dashboard stylesheet matched to current markup; a non-persisting extension analysis endpoint; a downloadable Manifest V3 Sentinel package with a bundled PSL-aware local detector; configurable Standard/Strict/Local-only checks, pause, exclusions and warning language; localized dashboard navigation/headings/actions; extension installation guidance; and backend, detector, and Chromium browser-level checks.

Still incomplete: no trained ML model/evaluation set, external threat-intelligence providers, DNS/TLS/registration lookups, authentication or user separation, PDF/CSV report exports, retention scheduling, or complete UI/Copilot localization. The extension warning is asynchronous and does not guarantee interception before content begins loading. Chromium browser-level checks exercise the unpacked extension, but do not cover every browser version or lifecycle/redirect condition. Do not expose the unauthenticated local service publicly without adding access controls.
