# PatchPilot AI

**Find vulnerabilities. Fix them with AI. Verify every fix.**

An AI security reviewer for websites built with AI coding tools. JU Techfest 2026, problem statement **CY-02: AI Security Reviewer for Vibe-Coded Websites**.

PatchPilot scans a project's source (ZIP or individual files), reports evidence-backed findings with file, line and masked code, explains them in plain language, generates a ready-to-paste repair prompt for an AI coding assistant, and then **verifies the fix by rescanning** the corrected code and showing what was resolved, what remains and what is new.

> Findings come from automated rules and require human review. A clean scan does not prove an application is secure.

---

## Quick start

Requirements: Python 3.10+ and Node 18+.

```bash
./run.sh            # macOS / Linux
./run.ps1           # Windows PowerShell
```

Then open **http://localhost:8000**. The script installs Python packages, builds the UI if `frontend/dist` is missing, and serves the UI and API from one port. Interactive API docs are at http://localhost:8000/docs.

Manual start:

```bash
cd backend && pip install -r requirements.txt
cd ../frontend && npm install && npm run build
cd ../backend && uvicorn app.main:app --port 8000
```

Frontend development with hot reload: run the backend as above, then `cd frontend && npm run dev` and open http://localhost:5173 (Vite proxies `/api` to port 8000).

### Optional: AI explanations

Copy `.env.example` to `.env` and set, for example:

```
PATCHPILOT_AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=...
```

`openai` works with any OpenAI-compatible endpoint (`OPENAI_BASE_URL`). Without a key, every feature still works; explanations come from the built-in deterministic templates. Keys are read only by the backend and never reach the browser.

### Tests

```bash
cd backend && python -m pytest -q      # 57 tests
```

---

## Demo script for judges (about 3 minutes)

1. Open http://localhost:8000. The dashboard is empty; click **Load and scan demo project**.
2. The results page shows **18 findings** in *Campus Bazaar*, a synthetic marketplace with planted bugs. Score **22 / F**. Every finding has a real file path, line number and masked code snippet.
3. Click **Hardcoded API key with a known provider format** (`src/config.js:5`). Note the key is masked (`sk-p••••••[masked 48 chars]`). Open the **Code** tab to see the full file with the line highlighted, then **AI explanation → Explain this finding**.
4. Click **Server trusts a role supplied by the client** (`server/index.js:39`): the delete-user route checks `req.query.isAdmin`.
5. Click **Generate fix prompt** (top right). The prompt lists every issue with evidence, requires key **rotation**, **server-side** authorization and real sanitization, and specifies tests and verification steps. Click **Copy prompt** and paste it anywhere to show it really copied.
6. Click **Rescan with fixes → Rescan with corrected demo**. The verification panel shows **22 → 87**: **16 resolved**, **2 remaining**, **1 newly introduced** (the "fix" added a `console.log` of the Authorization header, a realistic AI-fix regression).
7. Open the original scan from the verification panel: resolved findings are now **Fixed**, set by the rescan, not by a person or the AI. Try setting a finding to *Fixed* manually: the option does not exist, and the API refuses it.
8. Visit **Evaluation** to see detection metrics computed live on the synthetic test set, and **Report (.md)** to download a report.

To scan your own code, use **New scan** and drop a ZIP, a folder or individual files. You can also download the demo projects as ZIPs from `/api/demo/vulnerable/download` and `/api/demo/fixed/download` and upload them the normal way; results are identical every time.

---

## What it detects

25 deterministic rules in six categories. Each finding has a stable rule ID, title, description, severity, confidence, type, file, line, masked snippet, evidence, impact, remediation and CWE.

| Rule | Category | Title | Default severity | CWE |
|---|---|---|---|---|
| PP-SEC-001 | Secrets | Hardcoded API key with a known provider format | critical | CWE-798 |
| PP-SEC-002 | Secrets | Private key committed to source | critical | CWE-321 |
| PP-SEC-003 | Secrets | Hardcoded credential in source | high | CWE-798 |
| PP-SEC-004 | Secrets | Secret exposed through a browser-visible environment variable | critical | CWE-200 |
| PP-SEC-005 | Secrets | Database URL with embedded password | high | CWE-798 |
| PP-XSS-001 | Cross-site scripting | Unsanitized dangerouslySetInnerHTML | high | CWE-79 |
| PP-XSS-002 | Cross-site scripting | DOM HTML sink assigned a dynamic value | high | CWE-79 |
| PP-XSS-003 | Cross-site scripting | Template outputs raw, unescaped HTML | medium | CWE-79 |
| PP-AUTH-001 | Access control | Authorization decided in client-side code | medium | CWE-602 |
| PP-AUTH-002 | Access control | Server trusts a role supplied by the client | critical | CWE-639 |
| PP-AUTH-003 | Access control | Sensitive route without visible server-side authorization | medium | CWE-862 |
| PP-AUTH-004 | Access control | Privilege read from client-controlled storage | high | CWE-602 |
| PP-CFG-001 | Insecure configuration | Overly permissive CORS policy | medium | CWE-942 |
| PP-CFG-002 | Insecure configuration | Debug mode enabled | medium | CWE-489 |
| PP-CFG-003 | Insecure configuration | TLS certificate verification disabled | high | CWE-295 |
| PP-CFG-004 | Insecure configuration | Session data stored in an insecure cookie or browser storage | medium | CWE-1004 |
| PP-CFG-005 | Insecure configuration | JWT signature not verified | critical | CWE-347 |
| PP-INJ-001 | Injection | SQL query built with string concatenation | high | CWE-89 |
| PP-INJ-002 | Injection | Shell command built from dynamic input | critical | CWE-78 |
| PP-INJ-003 | Injection | Dynamic code evaluation | high | CWE-95 |
| PP-INJ-004 | Injection | Unsafe deserialization of untrusted data | high | CWE-502 |
| PP-EXP-001 | Sensitive data exposure | Sensitive value written to logs | medium | CWE-532 |
| PP-EXP-002 | Sensitive data exposure | Environment file with real values committed | high | CWE-538 |
| PP-EXP-003 | Sensitive data exposure | Internal error details returned to the client | low | CWE-209 |
| PP-EXP-004 | Sensitive data exposure | Internal network address in client-side code | low | CWE-200 |

Severity can be raised by context (e.g. CORS `*` plus `credentials: true` becomes high; a command built from request input becomes critical).

### Reducing false positives

- **Placeholder filtering**: `your_api_key_here`, `changeme`, `<TOKEN>`, `USER:PASSWORD`, AWS `…EXAMPLE` keys, `process.env.X` references, low-entropy strings and UI labels are ignored.
- **Light taint tracking**: a variable assigned from `location.search`, `URLSearchParams`, `req.query` etc. (up to a few hops) makes an XSS or SQL finding high-confidence.
- **Literal awareness**: `el.innerHTML = ''`, parameterized queries (`$1`, `%s` with a tuple), `subprocess.run([...])` without a shell, and DOMPurify-sanitized HTML are not reported.
- **Comments** are skipped for code-pattern rules (but not for secrets, which leak either way).
- **Client vs server classification** decides which access-control rules apply to a file.

### Three kinds of findings

| Type | Meaning |
|---|---|
| Pattern match | A precise match, e.g. a known key format or `verify=False`. |
| Heuristic | Usually risky, depends on context (e.g. a variable passed to `innerHTML`). |
| Review candidate | Insufficient evidence. Used for "route without visible auth" and client-side role checks, which may be protected in another layer. Defaults to *Needs review*, low confidence. |

AI output is shown separately and labelled *AI-generated*; it never changes a finding.

---

## Security score

```
penalty per finding = severity weight × confidence factor
  weights: critical 25, high 12, medium 5, low 2, info 0
  confidence: high 1.0, medium 0.7, low 0.4
repeats of one rule are capped at 2× that rule's single-finding weight
score = 100 × 60 ÷ (60 + total penalty)
```

One critical finding gives about 71; a clean scan gives 100. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below. The method is shown on every results page. The score reflects detected patterns only.

## Rescan verification

A rescan runs the same rules on the uploaded new version, then matches each original finding:

1. **Fingerprint**: rule ID + normalized file path + normalized, masked line text (survives code moving).
2. **Location**: same rule ID + file within ±8 lines (survives light edits).

Unmatched originals are **resolved / no longer detected** and their status becomes **Fixed** with a link to the verifying scan. Unmatched new findings are **newly introduced**. Matched pairs are **remaining**, with severity changes listed. Users can set *Open*, *Needs review* or *Accepted risk*, but **only a rescan can set Fixed** (the API returns 409 otherwise).

## AI design

- The LLM is used only for explanations: what the code does, why it's risky, a realistic impact, a fix, a safer code example and verification steps.
- Provider abstraction (`app/ai.py`): Anthropic, any OpenAI-compatible API, or none.
- Only the **masked** snippet is sent, and `redact_text` runs again right before the request. The model's output is masked too.
- Submitted code is wrapped in `<untrusted_code>` tags and the system prompt forbids following instructions inside it.
- Responses must be JSON matching a Pydantic schema. Network errors, HTTP errors, non-JSON or schema-invalid output all fall back to the deterministic explanation with a clear message; the finding is never altered.
- Repair prompts are built deterministically from the evidence, so they are reproducible and contain no unmasked secrets.

---

## API

All endpoints are typed FastAPI routes; see `/docs` for schemas.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Service status, rule count, AI provider, URL scanning flag |
| GET | `/api/limits` | Upload limits and accepted extensions |
| GET | `/api/rules` | Rule catalogue |
| GET | `/api/dashboard` | Totals, severity distribution, recent scans, activity |
| POST | `/api/scans` | Create a scan. Multipart: `project_name`, plus `archive` (ZIP) **or** `files[]` (filenames are relative paths), optional `target_url` |
| GET | `/api/scans` | Scan history |
| DELETE | `/api/scans` | Clear history |
| GET | `/api/scans/{id}` | Scan summary, score, counts, comparison (for rescans) |
| GET | `/api/scans/{id}/findings` | Findings; filters `severity=high,critical`, `q=` |
| PATCH | `/api/scans/{id}/findings/{fid}` | Set status `open`, `needs_review`, `accepted_risk` (`fixed` → 409) |
| GET | `/api/scans/{id}/files` | Files stored for the scan |
| GET | `/api/scans/{id}/file?path=` | Masked file content for the code viewer |
| POST | `/api/scans/{id}/findings/{fid}/explain` | AI explanation with deterministic fallback |
| POST | `/api/scans/{id}/repair-prompt` | Body `{finding_ids: []}`; empty = all open findings |
| POST | `/api/scans/{id}/rescan` | Upload the updated project (ZIP or files) and compare |
| GET | `/api/scans/{id}/report?format=md\|json` | Download a report |
| GET | `/api/demo` | Demo project file listing |
| GET | `/api/demo/{vulnerable\|fixed}/download` | Demo project as a ZIP |
| POST | `/api/demo/scan` | Scan the vulnerable demo |
| POST | `/api/scans/{id}/rescan/demo` | Rescan a demo scan with the corrected demo |
| GET | `/api/evaluation` | Run the evaluation set and return metrics |

Status codes: 201 created, 400 invalid input or archive, 404 unknown scan/finding, 409 forbidden state change, 413 too large, 415 unsupported/binary file, 422 validation or refused URL.

---

## Security and privacy of PatchPilot itself

- **Nothing uploaded is executed.** Files are decoded as text and matched with regular expressions.
- **ZIP handling** happens in memory, never extracted to disk. Rejected: path traversal (`..`, absolute paths, drive letters, backslash tricks), encrypted archives, more than 5,000 entries, more than 400 source files, archives over 10 MB, more than 30 MB decompressed, and compression ratios over 100× (zip bombs). Each member is read with a hard byte cap regardless of what its header claims. Symlinks, binaries, unsupported types and files over 1 MB are skipped and listed. `node_modules`, `.git`, `dist`, `build` and similar are ignored.
- **Secrets are masked everywhere**: snippets, evidence, code viewer, reports, repair prompts and AI payloads. Only masked copies of files are stored in SQLite; raw content exists only in memory during the scan.
- **No source or secrets in logs**: the error handler logs only exception types.
- **Headers**: strict CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`. CORS only for the local dev server.
- **Deployed URL scanning** (optional) blocks localhost, private, link-local, CGNAT, reserved, multicast and IPv6 ULA addresses, cloud metadata endpoints, internal TLDs, non-standard ports and URLs with credentials. It resolves DNS once and connects to the vetted IP (DNS-rebinding protection) while still verifying TLS for the hostname, re-validates every redirect (max 3), uses 6-second timeouts, a 1.5 MB size cap and a content-type allow-list, fetches at most 8 same-host scripts, and only sends GET requests. It requires the user to confirm authorization. Browser-visible findings are labelled separately.

## Evaluation

`app/evaluation.py` holds 25 planted vulnerable snippets (each expecting a specific rule) and 15 safe snippets (expecting no findings). The **Evaluation** page runs the scanner on them live. Current result: 25 / 25 detected, 0 missed, 0 false positives. These cases were written alongside the rules, so this demonstrates that rules behave as designed; it is not a measure of real-world accuracy.

## Project layout

```
backend/
  app/
    main.py          FastAPI routes, typed models, security headers
    service.py       scan lifecycle, rescan comparison, reports
    ingest.py        safe ZIP / file ingestion with limits
    scanner/
      rules.py       25 detection rules (add one by subclassing Rule)
      masking.py     secret patterns, placeholder logic, redaction
      engine.py      runs rules, builds findings
      scoring.py     score formula
      compare.py     before/after matching
    repair.py        fix-prompt builder, deterministic explanations
    ai.py            LLM provider abstraction, schema validation
    urlscan.py       SSRF-hardened browser-visible URL scan
    evaluation.py    synthetic labelled dataset
    db.py            SQLite storage
  tests/             57 pytest tests
frontend/            React + TypeScript + Vite + Tailwind + Lucide
demo/
  vulnerable/        Campus Bazaar with planted issues (synthetic credentials)
  fixed/             corrected version (2 issues remain, 1 regression introduced)
```

## Known limitations

- **Pattern-based, single-line analysis.** Rules look at one line plus a small window. Multi-line SQL strings, data flow across files, and framework-specific auth (e.g. Next.js middleware, Supabase RLS, Firebase rules) are not understood. "Route without visible auth" is therefore only a review candidate.
- **Taint tracking is shallow**: a few hops of simple assignments within one file.
- **Languages**: JavaScript/TypeScript (incl. JSX/TSX, Vue, Svelte), HTML, Python and config files. Other languages are not scanned.
- **No dependency (SCA) scanning** and no Semgrep integration in this build; the rule engine is designed so Semgrep results could be added as another rule source.
- **Secret detection** covers common provider formats and credential-named assignments. It does not verify whether a key is live, and high-entropy secrets under unusual names can be missed.
- **Rescan matching** treats a finding that moved more than 8 lines and changed text as resolved-plus-new.
- **Deployed URL scanning** was unit-tested for its blocking rules, but could not be exercised against live sites in the development sandbox, which only allows proxied outbound traffic. It does not run through HTTP proxies by design (that would bypass IP pinning), and pages rendered entirely by client-side JavaScript after load are seen only as their initial HTML and scripts.
- **AI explanations** were tested with mocked providers (success, invalid JSON, provider failure, secret masking). A real provider call was not made during development because no API key was configured.
- **Single-user, local tool**: no authentication or multi-tenant isolation. Do not expose it on a public network as-is.
- The evaluation dataset is small and written by the authors.
