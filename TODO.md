# PDFShield delivery outcomes

## 1. Responsive evidence-led application shell
- Provide a persistent responsive sidebar with PDFShield wordmark, system-status indicator, collapsible behavior, and working links for Overview, Analyze PDF, OSINT Investigations, Threat Intelligence, IOC Explorer, Reports, and Settings.
- Provide a global top bar with breadcrumbs, search, notifications, and profile/settings affordances.
- Use the specified dark editorial palette, serif display typography, clean sans body text, monospace technical identifiers, subtle grain, restrained shadows/glass, accessible focus states, keyboard navigation, responsive layouts, loading skeletons, toast notifications, and reduced-motion support.
- Serve and keep synchronized a valid `/manus-routes.json` manifest for all page routes.

## 2. Defensive PDF analysis vertical slice
- Accept PDF files through a picker and drag-and-drop, validate extension plus content signature, enforce a persistent default maximum upload size of 25 MB, and show progress/errors/status.
- Never execute uploaded documents, embedded scripts, attachments, or extracted URLs; use safe temporary files and clean them up.
- Persist original filename, size, SHA-256, readability/parsing status, metadata, page count, encryption status, structural/object indicators, JavaScript indicators, embedded attachments, OpenAction/additional actions, URI annotations, extracted URLs/domains/IPs, suspicious features, evidence, and analysis limitations.
- Handle malformed, encrypted, oversized, unsupported, and parser-failure inputs safely; distinguish detected, not detected, and not successfully inspected.
- Show a polished result with summary, copyable SHA-256, metadata, heuristic 0–100 risk score/classification/reasons, static findings separate from intelligence, extracted IOCs, evidence drawers/cards, limitations, and downloadable JSON.

## 3. Explainable correlation, OSINT, and feeds
- Keep risk scoring transparent and configurable with Informational/Low/Medium/High/Critical classes and explicit evidence; never claim a suspicious feature proves malware or that a missing match proves safety.
- Support normalized hashes, domains, URLs, and IP addresses; correlate extracted IOCs against locally persisted threat indicators with source/tags/confidence/first-last seen/match time/cached-current status.
- Provide an OSINT workspace with investigation history, provider/source attribution, timestamps, links, confidence/reputation labels, errors, rate limits, unavailable/no-result/cached states, and explicit external-lookup consent; never transmit PDFs or automatically visit extracted URLs.
- Provide trusted feed configuration, status, last successful sync, real persisted counts, error state, manual refresh, interval, docs, deduplication, validation, UTC storage/local display, non-overlapping sync, and SSRF-safe trusted URLs; never claim a feed is operational before a successful sync.

## 4. IOC explorer and case/report center
- Provide searchable/filterable/paginated IOC Explorer for hashes, domains, URLs, and IP addresses, with type/source/tag/match filters, timestamp sorting, detail drawer, related investigations, copy, and CSV/JSON export.
- Provide case history with unique case IDs, file details, timestamps, risk/reasons, extracted IOCs, OSINT results, feed matches, notes, statuses New/In Review/Resolved/Archived, status updates, historical analyses, JSON export, polished PDF export, and IOC CSV export.
- Include evidence provenance, source attribution, timestamps, analysis limitations, and no silent overwriting of historical reports.

## 5. Persistence, settings, API, and security boundaries
- Implement SQLAlchemy models/relationships/indexes/transactions for analyses, extracted IOCs, threat indicators, feed sources, sync history, OSINT lookups, cases, notes, and settings; store secrets only in environment/server configuration.
- Implement documented FastAPI endpoints covering health, dashboard stats/activity, analyses and reports, IOCs, OSINT lookups/investigations, feeds/sync/history, cases, and settings with validation and meaningful HTTP errors.
- Persist upload limit, enabled providers, external consent, feed/sync settings, retention, demo mode, theme, and application information; show honest zero states when live data is absent and label demo mode explicitly.
- Use restrictive CORS, safe error messages, output escaping, request timeouts, validation, rate limits where appropriate, protected analysis files, and no offensive exploitation or malware deployment functionality.

## 6. Automated verification and delivery
- Add automated tests for file validation, SHA-256 generation, PDF metadata extraction, JavaScript indicator detection, embedded-file detection, URL/IOC extraction, risk scoring, IOC normalization, and threat-feed parsing/correlation.
- Pass frontend build/type checks, backend tests, production build, health check, route manifest validation, and core API smoke checks.
- Provide a self-contained Dockerfile and `.env.example`; checkpoint intended source on canonical `main` without enabling auto-publish.
