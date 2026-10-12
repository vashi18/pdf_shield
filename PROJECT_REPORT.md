# PDFShield — Detailed Project Report

**Project:** PDFShield  
**Purpose:** Defensive static PDF malware analysis, OSINT investigation, threat-intelligence correlation, IOC exploration, and case/report management.  
**Checkpoint:** `f054c6b336dfc2bd7976df008cc8eecc6d0ee34b` — *Build PDFShield static analysis workspace*  
**Report status:** Verified against the current source and live Preview environment.

## 1. Executive summary

PDFShield is a local-first, evidence-led security workspace for inspecting suspicious PDF files without executing the document, embedded scripts, attachments, or extracted URLs. It combines:

- A responsive dark editorial cybersecurity dashboard
- Safe PDF validation, parsing, hashing, metadata extraction, and structural inspection
- Explainable heuristic risk scoring from 0–100
- Extracted IOC normalization and local threat-indicator correlation
- Consent-gated OSINT investigation history
- Trusted threat-feed configuration and manual synchronization
- IOC Explorer search/filter/pagination
- Case management and JSON/PDF/CSV report exports
- Persistent SQLAlchemy records and honest zero-state dashboard values

The application is delivered as a combined React frontend and FastAPI backend and is currently available through the managed Preview deployment link below.

## 2. Product links

### Live deployed Preview

**[Open PDFShield](https://3000-isuxnci37e8vwfnpxl1ji-6d0d2250.us4.manus.computer)**

This is the verified managed Preview URL. The project has not been published to a separate production domain because automatic publication is disabled and no explicit production publish was requested.

### Detailed report

This file is the detailed project report: `PROJECT_REPORT.md`.

### GitHub repository status

A public GitHub repository link is **not currently available**. The project configuration reports `git_repository.provider: manus`, and the local canonical remote is the private Manus-managed repository rather than GitHub. The GitHub connector exists in the account configuration but is currently disabled.

To provide a GitHub URL, a GitHub destination must first be connected or authorized. No GitHub repository was invented or exposed as a substitute.

## 3. Architecture

```text
Browser
  │
  ├── React 18 + TypeScript + Vite
  │     ├── React Router
  │     ├── Recharts
  │     ├── Framer Motion
  │     └── Lucide React
  │
  └── FastAPI application on port 3000
        ├── Upload validation and PDF static analysis
        ├── SQLAlchemy persistence
        ├── SQLite default storage
        ├── IOC normalization and correlation
        ├── OSINT consent boundary
        ├── Trusted feed synchronization
        ├── JSON/PDF/CSV report generation
        └── Static frontend serving
```

### Source structure

| Area | Responsibility |
|---|---|
| `frontend/src/App.tsx` | Workspace shell, navigation, dashboard, analyzer, OSINT, feeds, IOC, reports, and settings views |
| `frontend/src/lib/api.ts` | Typed browser-to-API client |
| `frontend/src/styles.css` | Dark editorial design system, responsive layout, accessibility focus states, reduced-motion behavior |
| `frontend/public/manus-routes.json` | Webdev route manifest |
| `backend/app/main.py` | FastAPI app, persistence flow, API endpoints, CORS, static serving |
| `backend/app/database.py` | SQLAlchemy engine/session and SQLite-first database selection |
| `backend/app/models.py` | Analyses, IOCs, threat feeds, indicators, sync history, OSINT records, cases, notes, and settings |
| `backend/app/schemas.py` | Request and response validation models |
| `backend/app/services/pdf_analyzer.py` | PDF signature validation, parsing, metadata, structure, actions, attachments, and IOC extraction |
| `backend/app/services/risk.py` | Explainable risk score and risk-class calculation |
| `backend/app/services/ioc.py` | IOC extraction, normalization, deduplication, and correlation helpers |
| `backend/app/services/feeds.py` | Trusted feed registry and feed URL safety validation |
| `backend/app/services/reports.py` | JSON, PDF, and CSV report serialization |
| `tests/test_services.py` | Automated service-level tests |
| `Dockerfile` | Self-contained frontend build and FastAPI production image |
| `.env.example` | Non-secret runtime configuration template |

## 4. Implemented functionality

### Dashboard and navigation

- Overview page titled **“Your threat intelligence workspace.”**
- Responsive sidebar with PDFShield wordmark, system status, collapse behavior, and seven working destinations:
  - Overview
  - Analyze PDF
  - OSINT Investigations
  - Threat Intelligence
  - IOC Explorer
  - Reports
  - Settings
- Global top bar with breadcrumbs, search affordance, notifications, and profile/settings affordance.
- Live backend-derived dashboard counters for PDFs, suspicious documents, extracted IOCs, and threat matches.
- Risk distribution and activity visualizations.
- Feed health and recent investigation surfaces.
- Honest zero-state behavior when no live records exist.

### Static PDF analysis

- Drag-and-drop and file-picker upload workflow.
- PDF extension and content-signature validation.
- Persistent default upload limit of **25 MB**, configurable in Settings.
- SHA-256 hash generation.
- Filename and size capture.
- Readability/parsing status.
- Page count and encryption status.
- Metadata extraction.
- Static inspection for JavaScript, `/JS`, embedded files, `/OpenAction`, `/AA`, `/URI`, `/Launch`, and related structural indicators.
- Text-derived URL, domain, and IP extraction.
- Explicit states for detected, not detected, and not inspected.
- Explanatory findings, evidence, risk reasons, limitations, and provenance.
- Downloadable JSON report, polished PDF report, and IOC CSV export.

### Risk scoring

Risk scoring is heuristic and transparent. It uses documented structural signals and produces:

- Score from 0 to 100
- Informational, Low, Medium, High, or Critical class
- Human-readable reasons and evidence
- Limitations explaining that static analysis cannot prove a document is benign or malicious

Threat-intelligence matches remain separate from structural findings and do not silently become malware verdicts.

### IOC Explorer and correlation

- Supported IOC types include URLs, domains, IP addresses, and hashes.
- Normalization and deduplication are performed before correlation.
- Exact/normalized matching against persisted threat indicators.
- Search, type filter, match filter, pagination, and copy/export affordances.
- Match details preserve source, tags, confidence, and provenance when available.

### OSINT investigations

- Investigation workspace for hashes, domains, URLs, and IP addresses.
- Explicit request-level consent plus persistent Settings consent gate.
- PDFs are never transmitted to external providers.
- Extracted URLs are never automatically visited.
- No-result, not-configured, and unavailable states are represented honestly.
- Provider keys are expected to remain server-side.

### Threat intelligence feeds

- Trusted feed registry with documentation and status.
- Feed enablement is explicit.
- URLs are checked against a trusted allowlist.
- Requests use bounded timeouts and no automatic redirects.
- Indicators are normalized and deduplicated.
- Sync history records running, success, disabled, blocked, and error states.
- Feed health is not reported as operational before a successful synchronization.

### Reports and cases

- Every uploaded analysis receives a unique analysis ID and case ID.
- Historical analyses are retained rather than silently overwritten.
- Case statuses include New, In Review, Resolved, and Archived in the UI model.
- Reports preserve timestamps, evidence provenance, risk reasons, IOC data, limitations, and source attribution.
- JSON, PDF, and CSV exports are available from analysis reports.

## 5. API surface

The interactive OpenAPI documentation is available at `/docs` on the deployed application.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health and timestamp |
| `GET` | `/api/dashboard/stats` | Persisted dashboard counters and feed health |
| `GET` | `/api/dashboard/activity` | Activity and risk-distribution data |
| `POST` | `/api/analyses` | Validate, statically inspect, persist, and return a PDF analysis |
| `GET` | `/api/analyses` | List historical analyses |
| `GET` | `/api/analyses/{analysis_id}` | Retrieve a single analysis |
| `GET` | `/api/analyses/{analysis_id}/report?format=json\|pdf\|csv` | Download an analysis report |
| `GET` | `/api/iocs` | Search, filter, and paginate IOCs |
| `GET` | `/api/iocs/{ioc_id}` | Retrieve IOC details |
| `POST` | `/api/osint/lookup` | Consent-gated OSINT lookup state |
| `GET` | `/api/osint/investigations` | List OSINT investigation history |
| `GET` | `/api/feeds` | List configured trusted feeds |
| `POST` | `/api/feeds/{feed_id}/sync` | Manually synchronize an enabled trusted feed |
| `GET` | `/api/feeds/{feed_id}/history` | Review feed sync history |
| `GET` | `/api/cases` | List case history |
| `GET` | `/api/cases/{case_id}` | Retrieve a case and related notes/analyses |
| `PATCH` | `/api/cases/{case_id}` | Update case status or analyst notes |
| `GET` | `/api/settings` | Read persistent application settings |
| `PATCH` | `/api/settings` | Persist upload, provider, consent, theme, and sync settings |

## 6. Security and privacy posture

- Uploaded PDFs are treated as untrusted input.
- No uploaded file is executed.
- Embedded scripts and attachments are not executed.
- Extracted URLs are not opened automatically.
- Feed URLs are restricted to trusted configured sources.
- External OSINT requires explicit consent.
- PDF contents are not transmitted to external providers.
- Upload sizes are bounded before analysis.
- Filenames are reduced to safe path names.
- API errors avoid exposing raw parser details to clients.
- CORS is restricted to configured origins.
- External feed calls use a bounded timeout and disabled automatic redirects.
- Secrets are represented only through server-side environment configuration.
- Risk and intelligence results are clearly separated.
- Missing threat matches are never presented as proof of safety.

## 7. Design system

PDFShield uses a dark editorial cyber-intelligence aesthetic rather than a neon hacker theme.

- Background: `#121113`
- Card surface: `#1A181B`
- Elevated surface: `#242125`
- Primary text: `#F4EFF3`
- Secondary text: `#A8A1A7`
- Signature dusty-rose accent: `#B58A9A`
- Warning amber: `#D4AD6A`
- Success sage: `#8EA68D`
- Danger red: `#C77D7D`
- Display type: DM Serif Display / Georgia fallback
- Body type: Inter / system sans fallback
- Technical type: IBM Plex Mono / system monospace fallback

The interface includes subtle grain, restrained glass treatment, hairline evidence rules, case-file metadata strips, responsive layouts, accessible focus states, and reduced-motion support.

## 8. Validation evidence

| Check | Result |
|---|---|
| Backend service tests | **5 passed** |
| Frontend TypeScript check | **Passed** |
| Frontend production build | **Passed** |
| Python bytecode compilation | **Passed** |
| `/api/health` public smoke test | **Passed** |
| `/manus-routes.json` public smoke test | **Passed** |
| Dashboard/settings zero-state smoke test | **Passed** |
| Real PDF upload smoke test | HTTP **201** |
| JSON report export smoke test | HTTP **200** |
| Public Preview response | **Healthy** |
| Clean delivered database state | **Zero-state verified** |

The final smoke-test records were removed before delivery so the live dashboard starts with honest zero-state values.

## 9. Runtime and deployment notes

- Default runtime port: `3000`
- Default database: SQLite file `pdfshield.db`
- Managed database mode is explicit and opt-in through `PDFSHIELD_USE_MANAGED_DB=true`.
- Default maximum upload size: 25 MB.
- Demo mode: off by default.
- External lookup consent: off by default.
- Threat feeds: configured but not operational until explicitly enabled and successfully synchronized.
- Auto-publish: disabled.
- Production container entry point: FastAPI/Uvicorn using `$PORT`, defaulting to 3000.

## 10. Known follow-up items

1. Connect and authorize a GitHub destination if a public GitHub repository link is required.
2. Configure provider keys and a consent policy before enabling live VirusTotal, AbuseIPDB, or other OSINT providers.
3. Configure and validate managed database connectivity before switching away from SQLite for a multi-instance deployment.
4. Add authentication before exposing the application to an untrusted public audience.
5. Add a production scheduler for non-overlapping feed synchronization if recurring sync is required.

## 11. Final delivery

- **Live Preview:** https://3000-isuxnci37e8vwfnpxl1ji-6d0d2250.us4.manus.computer
- **Checkpoint SHA:** `f054c6b336dfc2bd7976df008cc8eecc6d0ee34b`
- **GitHub URL:** Not available yet; no GitHub repository is connected.
