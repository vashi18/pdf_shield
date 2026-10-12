# PDFShield implementation plan

## Product scope

PDFShield is a defensive, local-first PDF static-analysis and threat-intelligence workspace. The first delivered version prioritizes a complete vertical slice over decorative mock data: real PDF upload and non-executing parsing, persisted analysis/case/IOC records, transparent risk scoring, local feed correlation, opt-in OSINT adapters, exportable reports, and a polished responsive dashboard. Demo mode is explicit and off by default; empty live datasets render as honest zero states.

The backend is a Python FastAPI service that owns parsing, persistence, exports, validation, and security boundaries. The frontend is a React/Vite/TypeScript client served by the same FastAPI process in Preview/production, with client-side routing for the seven requested workspaces. SQLite is the reliable local fallback for the requested SQLAlchemy data model; the schema is initialization-safe and can later be pointed at the managed database without changing API contracts.

## Architecture and project structure

- `frontend/` — Vite/React/TypeScript application, Tailwind-compatible CSS tokens, router, pages, reusable UI, API client, and typed view models.
  - `src/components/` — sidebar/top bar, stat cards, charts, upload dropzone, findings, IOC tables, drawers, toasts, and shared primitives.
  - `src/pages/` — Overview, Analyze PDF, OSINT, Threat Intelligence, IOC Explorer, Reports, and Settings.
  - `src/lib/` — API client, formatting, normalization helpers, and browser-safe types.
  - `src/styles/` — global design tokens, grain treatment, responsive rules, and accessible focus states.
  - `public/manus-routes.json` — complete page route manifest required by Webdev Preview.
- `backend/app/` — FastAPI application.
  - `main.py` — app factory, CORS, static frontend serving, API registration, health endpoint.
  - `database.py` — SQLAlchemy engine/session and safe schema initialization.
  - `models.py` — analyses, IOCs, threat feeds/indicators, sync history, OSINT lookups, cases, notes, and settings.
  - `schemas.py` — request/response validation models.
  - `services/pdf_analyzer.py` — content-signature validation, safe temporary handling, PyMuPDF/pypdf parsing, metadata, structure/action/attachment/URL extraction.
  - `services/risk.py` — configurable explainable scoring, classification, coverage, and limitations.
  - `services/ioc.py` — normalization, deduplication, extraction, correlation, and export formatting.
  - `services/feeds.py` — trusted feed registry, parser/validation, explicit sync history, and local lookup.
  - `services/osint.py` — provider adapters with consent gate, timeouts, errors, and honest no-result states.
  - `services/reports.py` — JSON/CSV/PDF report generation with provenance and limitations.
  - `routers/` — dashboard, analyses, IOCs, OSINT, feeds, cases, and settings endpoints.
- `tests/` — pytest coverage for file validation, hashing, metadata, JavaScript/attachment detection, IOC extraction/normalization, scoring, and feed parsing.
- `requirements.txt`, `frontend/package.json`, `frontend/tsconfig.json`, `frontend/vite.config.ts` — pinned runtime/toolchain dependencies.
- `Dockerfile` — self-contained production image that builds the frontend and runs FastAPI on `$PORT` (default 3000).
- `app.config.ts` — project logo metadata for checkpointing.
- `.env.example` — non-secret configuration names only.

## Design direction

- **Design movement:** dark editorial cyber-intelligence / dark academia, softened with restrained feminine mauve accents rather than neon terminal aesthetics.
- **Core principles:** evidence before drama; quiet hierarchy; editorial asymmetry; every state is explicit and explainable.
- **Color philosophy:** near-black plum surfaces keep attention on evidence; dusty rose marks the PDFShield identity; sage and amber communicate operational states without shouting; muted red is reserved for risk.
- **Layout paradigm:** a persistent command rail plus an asymmetric editorial canvas. Overview uses staggered cards and compact evidence columns instead of a centered admin grid. Detail workspaces use wide reading panes with narrow metadata rails.
- **Signature elements:** mauve hairline rules with numbered section labels; soft paper-grain overlay; “case-file” metadata strips using monospace labels and local timestamps.
- **Interaction philosophy:** every action gives a calm, reversible response. Drawers expose provenance; filters preserve context; destructive or external-sharing actions are explicit and never automatic.
- **Animation:** 160–240ms opacity/translate transitions, gentle card lift on hover, skeleton shimmer only while data is loading, and no essential information hidden behind motion. Respect `prefers-reduced-motion`.
- **Typography system:** `DM Serif Display` for editorial headings, `Inter` for body/UI, and `IBM Plex Mono` for hashes, IPs, URLs, IDs, and evidence snippets. Use a tight display scale and generous line-height in reading surfaces.
- **Brand essence:** “A quiet evidence desk for suspicious documents, built for analysts who need defensible answers.” Personality: precise, composed, observant.
- **Brand voice:** direct, careful, and evidence-led. Example lines: “Read the document without running it.” / “No match is not the same as safe.”
- **Wordmark/logo:** a compact shield outline split by a document fold, with a single mauve signal notch; the wordmark is set in a custom-feeling serif/sans pairing rather than a default logo font.
- **Signature brand color:** `#B58A9A` (dusty rose mauve), used sparingly for active navigation, evidence rules, and primary actions.

## Backend behavior

Uploaded files are accepted only when the declared size and PDF magic bytes/content are valid. Secure temp files are created with restrictive permissions and removed after parsing. No extracted URL is opened, no attachment is written out for execution, and no document script is executed. Parsing failures are represented as `not_inspected` evidence rather than optimistic negatives. The risk score is a transparent sum of structural signals and is clearly labeled as heuristic; feed reputation matches are shown in a separate intelligence section and only add a documented correlation signal.

The SQLite schema uses relationships, indexes, UTC timestamps, and unique constraints that avoid conflating repeated analyses. The feed engine ships with a trusted URLhaus CSV adapter configuration but does not report operational/count status until a sync succeeds. A manual sync is available; scheduled synchronization is represented by a safe service hook and can be enabled through settings without arbitrary PDF-controlled URLs. OSINT lookup is disabled until explicit consent and a provider is configured; URLhaus can be queried from trusted configuration, while VirusTotal and AbuseIPDB require server-side keys.

## Build and validation workflow

1. Install frontend and backend dependencies from the pinned manifests.
2. Configure host-managed diagnostics for TypeScript, JavaScript, Python, JSON, and CSS.
3. Implement the API and tests first, then the shared frontend shell and pages against typed API responses.
4. Build the frontend into `frontend/dist`; run FastAPI on `0.0.0.0:3000` so Preview can serve both API and SPA.
5. Run pytest, TypeScript build, and a clean production build; fix actionable diagnostics and runtime errors.
6. Verify `/api/health`, `/manus-routes.json`, the SPA shell, and core API behavior with a safe sample PDF generated in the test suite.
7. Commit to the canonical `main` branch, then publish only if explicitly requested; the current project keeps auto-publish disabled.
