# Phase 2 Architecture Baseline

## Existing Architecture Overview
The ThreatTrace AI MVP is an enterprise-grade cybersecurity email investigation platform. It consists of a decoupled frontend and backend.

### Frontend
- **Framework:** Next.js 15.5 App Router
- **UI/Styling:** React, Tailwind CSS v4, custom functional components (`src/components/ui/primitives.tsx`). (MUI has been completely removed.)
- **State/Fetching:** React Query (`@tanstack/react-query`).
- **Testing:** Vitest + React Testing Library (`npm run test`).
- **Type Checking:** TypeScript (`npm run typecheck`).
- **Key Modules:** 
  - `InvestigationDashboard.tsx` and 8 modular widgets handling Risk, Forensics, Timeline, Intel, IOC, Geo, Evidence, and Graph views.

### Backend
- **Framework:** FastAPI (Python 3.10+)
- **Database:** PostgreSQL (production) or SQLite (development/tests) via SQLAlchemy ORM.
- **Migrations:** Alembic.
- **Architecture Pattern:** Service Layer Pattern separating routing (`apps/api/src/api`), business logic (`apps/api/src/services`), data access (`apps/api/src/db`), and data models (`apps/api/src/models`, `apps/api/src/schemas`).
- **Testing:** Pytest with extensive unit and integration tests (`pytest`).
- **Type Checking & Linting:** Mypy and Ruff (`mypy src`, `ruff check src`).

## Existing Investigation Workflow
1. **Ingestion:** Upload `.eml` via UI -> `/v1/email/upload`. Creates `Case`.
2. **Parsing:** Extract body, headers, attachments (`/parse`).
3. **Detection:** Rule-based/AI heuristic threat classification and explainability (`/threat-analysis`).
4. **Forensics:** SPF/DKIM/DMARC verification and MTA relay extraction (`/header-forensics`).
5. **IOC Extraction:** IPs, domains, emails, hashes (`/iocs`).
6. **Threat Intelligence:** Cross-reference IOCs with AbuseIPDB, VirusTotal, etc. (`/threat-intel`).
7. **Geo Infrastructure:** MaxMind/Mock location mapping of origin IPs (`/geo-infrastructure`).
8. **Risk Scoring:** Deterministic weighted scoring mechanism aggregating signals into a 0-100 score (`/risk-assessment`).
9. **Graph:** Extracts relationships (e.g. `USES_DOMAIN`, `RESOLVES_TO`) storing in Neo4j or InMemory fallback (`/graph`).
10. **Evidence Integrity:** Compute SHA-256 custody hashes of evidence files (`/evidence`).
11. **Reporting:** Timeline aggregation (`/timeline`) and PDF generation (`/report/pdf`).

## Extension Points
- **Provider Interfaces:** New external tools must implement existing base provider classes (e.g., `GeoIPProvider`, `ThreatIntelProvider`, `ThreatGraphRepository`).
- **Service Interfaces:** New investigation stages can be added as isolated services inside `apps/api/src/services/`.
- **UI Widgets:** The dashboard naturally accepts new grid items that pull from new `/v1/email/{case_id}/...` endpoints.

## Prohibited Changes
- Do NOT rewrite the Next.js or FastAPI architectures.
- Do NOT migrate to alternative CSS frameworks or component libraries (keep pure Tailwind).
- Do NOT modify the deterministic risk scoring weights directly without explicit instruction.
- Do NOT remove or bypass the `Mock...` providers; external API calls must be wrapped in interfaces.
- Do NOT manually manipulate the database schema; always use Alembic migrations.
- Do NOT fake or fabricate threat intelligence or geolocation data.

## Existing API Contracts
- RESTful HTTP API.
- All investigation endpoints follow the `GET|POST /api/v1/email/{case_id}/[feature]` pattern.
- The UI handles loading states independently for each widget using React Query, expecting HTTP 503 or graceful errors on provider failure without crashing the dashboard.

## Existing Database Contracts
- Managed by Alembic in `apps/api/alembic`.
- Relational tables include `cases`, `emails`, `forensics`, `iocs`, `risk_assessments`, `threat_assessments`, `evidence_records`, etc.

## Existing Test Commands
- **Backend:** 
  - `pytest`
  - `mypy src`
  - `ruff check src`
- **Frontend:**
  - `npm run typecheck`
  - `npm run lint`
  - `npm run test`
  - `npm run build`

## Known Technical Debt
- Minor strict typing issues in the backend were discovered and resolved during baseline validation (e.g., Mypy strict validation of FastAPI exception handlers, `get_payload` byte parsing, and dict typing in Mock Geo Provider).
- Hardcoded fallback dummy values (e.g., "N/A") when parsed email values are missing.

## Known Limitations
- Current threat graph uses `InMemoryThreatGraphRepository` by default in development unless Neo4j is explicitly configured via environment variables.
- AI detection is heavily heuristic and rule-based (`HeuristicThreatDetector`), waiting for genuine Transformer/LLM integration.
- PDF generation may fail on environments lacking underlying system rendering capabilities if not fully mocked/isolated.
