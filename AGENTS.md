# ThreatTrace AI — AI Development Rules

## Project

ThreatTrace AI is a cybersecurity email investigation platform.

The MVP must support:

1. Email ingestion
2. Email parsing
3. AI threat detection
4. Email header forensics
5. SPF/DKIM/DMARC analysis
6. IOC extraction
7. IP/domain threat intelligence
8. Geo/infrastructure intelligence
9. Risk scoring
10. Investigation dashboard
11. Threat graph
12. PDF investigation report
13. Evidence hashing

The product must feel like a small SOC investigation platform, not merely a phishing classifier.

## CRITICAL DEVELOPMENT RULES

### Rule 1 — Never implement future features unless explicitly requested

Do not proactively add:

* blockchain
* Neo4j
* external threat intelligence APIs
* AI model training
* background workers
* Redis
* Kubernetes
* cloud deployment
* malware sandboxing
* unrelated refactoring

Only implement the feature explicitly requested in the current task.

### Rule 2 — Preserve working functionality

Before modifying existing functionality:

1. Inspect the existing implementation.
2. Identify public APIs.
3. Identify database schema dependencies.
4. Identify frontend dependencies.
5. Identify existing tests.
6. Do not change existing behavior unless required.

If a change could break an existing feature, stop and explain the risk before proceeding.

### Rule 3 — Small vertical slices

Each task must produce one small, testable increment.

Do not combine unrelated features.

### Rule 4 — Test before completion

Every implementation must include:

* unit tests where applicable
* API tests where applicable
* frontend tests where applicable
* regression tests for existing behavior
* lint/type checks
* build verification

Do not claim success without actually running the relevant commands.

### Rule 5 — No fake success

Never:

* create fake API responses and call the feature complete
* silently swallow exceptions
* return hardcoded production-looking data
* fabricate threat intelligence
* fabricate GeoIP information
* fabricate SPF/DKIM/DMARC results
* claim an attacker location from an IP

If an external service is unavailable, use an explicit adapter/mock and clearly mark it as development-only.

### Rule 6 — Security

Treat uploaded email files as untrusted input.

Never:

* execute attachments
* execute scripts found inside emails
* automatically open URLs
* trust HTML from uploaded emails
* expose uploaded files publicly
* log secrets
* commit API keys

Uploaded files must be validated and safely stored.

### Rule 7 — Database changes

Every schema modification must use Alembic migration.

Never manually modify the production schema.

### Rule 8 — API compatibility

Prefer additive API changes.

Do not rename/remove an existing API field merely because a cleaner design is preferred.

If a breaking change is absolutely necessary, explain it first.

### Rule 9 — Dependency discipline

Do not upgrade unrelated dependencies during a feature task.

Do not introduce a dependency if the standard library or an existing dependency can reasonably solve the problem.

Pin important dependencies.

### Rule 10 — Architecture

Use:

* FastAPI
* SQLAlchemy
* Alembic
* PostgreSQL
* Next.js
* React
* TypeScript

Use service-layer abstractions for:

* parsing
* threat detection
* threat intelligence
* GeoIP
* risk scoring
* report generation

External providers must be accessed through adapters.

Example:

ThreatIntelProvider
→ AbuseIPDBProvider
→ VirusTotalProvider
→ MockThreatIntelProvider

### Rule 11 — AI abstraction

AI detection must not be tightly coupled to the API layer.

Use:

ThreatDetector
→ RuleBasedThreatDetector
→ TransformerThreatDetector

The API should depend on the interface, not a specific model.

### Rule 12 — Explainability

Every threat classification must produce:

* classification
* confidence
* reasons
* model version

Never return only a score.

### Rule 13 — Risk scoring

Keep risk calculation deterministic.

Current MVP weighting:

* AI analysis: 40%
* Header forensics: 25%
* Domain reputation: 15%
* IP reputation: 10%
* URL analysis: 10%

Do not silently change these weights.

### Rule 14 — Geo terminology

Never display:

"Attacker location"

Use:

"Probable infrastructure origin"

GeoIP indicates infrastructure information, not necessarily the physical attacker.

### Rule 15 — Git

One feature = one branch.

Branch format:

feat/<number>-<feature-name>

Examples:

feat/04-email-upload
feat/07-ai-threat-detection

Commit only after tests pass.

Commit format:

feat(scope): short description

Examples:

feat(upload): add secure email upload endpoint
feat(parser): parse EML metadata and body
test(parser): add EML parser regression tests

### Rule 16 — Completion protocol

Before saying a task is complete, report:

1. Files changed
2. Features implemented
3. Tests added
4. Commands executed
5. Test results
6. Known limitations
7. Database migrations
8. API changes
9. Security considerations
10. Commit message

Do not move to the next feature automatically.

### Rule 17 — Stop conditions

STOP instead of guessing if:

* requirements conflict
* existing behavior is unclear
* a dependency is incompatible
* database migration is destructive
* an API breaking change is required
* credentials are missing
* an external service contract is unknown
* tests cannot be made reliable

Ask for a decision rather than inventing one.

### Rule 18 — No unnecessary refactoring

Do not refactor unrelated code during feature implementation.

If refactoring is useful, document it separately as technical debt.

### Rule 19 — Definition of Done

A feature is complete only when:

* implementation exists
* tests exist
* tests pass
* lint passes
* type checks pass
* build passes where applicable
* existing tests still pass
* migration works where applicable
* documentation is updated where necessary
* git diff has been reviewed

### Rule 20 — Preserve the MVP

Optimize for:

stability > correctness > simplicity > demo quality > extensibility

Do not optimize for theoretical enterprise architecture.

The goal is a reliable SIH MVP.
