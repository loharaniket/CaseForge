# ThreatTrace AI — Architecture Overview

## Monorepo Architecture

ThreatTrace AI is structured as a modular monorepo to maintain strict architectural separation between backend services, frontend presentation, shared contracts, and infrastructure orchestration.

```
ThreatTrace-AI/
├── apps/
│   ├── api/             # FastAPI backend microservice (Python 3.13)
│   └── web/             # Next.js React frontend (TypeScript, Node 22+)
├── packages/
│   └── contracts/       # Shared TypeScript contracts and API models
├── infrastructure/      # Docker Compose & database provisioning
├── docs/                # Architectural, database, and API specifications
├── samples/             # Sample forensic email test corpora
└── scripts/             # Developer environment provisioning scripts
```

## Core Architectural Principles

### 1. Service-Layer Abstraction
The API layer never contains business logic or direct provider calls. Business logic resides in dedicated services (`apps/api/src/services/`) that consume standard provider interfaces (`apps/api/src/providers/`).

### 2. Decoupled Provider Adapters
External integrations (Threat Intel, GeoIP, AI classification engines, and Report Generators) are encapsulated behind abstract interfaces:
* `ThreatDetectorProvider` → RuleBased, Transformer, Mock
* `ThreatIntelProvider` → VirusTotal, AbuseIPDB, Mock
* `GeoIPProvider` → MaxMind, Mock
* `ReportGeneratorProvider` → Weasyprint/PDF, Mock

This design ensures the system can run entirely offline or in air-gapped SOC environments using mock/local adapters.

### 3. Explainable AI Threat Classification
All AI threat classifications MUST output:
* Classification category (`phishing`, `spear_phishing`, `bec`, `malware`, `spam`, `benign`, `unknown`)
* Confidence score (`0.0` to `1.0`)
* Structured reasons/evidence list
* Model version tag

### 4. Deterministic Risk Scoring Formula
The MVP composite risk calculation uses strict deterministic weighting:
* AI Analysis: 40%
* Header Forensics: 25%
* Domain Reputation: 15%
* IP Reputation: 10%
* URL Analysis: 10%

### 5. Safe Evidence Handling
Raw email files are treated as untrusted binary streams. No attachments or scripts are ever executed or parsed without sandboxed sanitization. GeoIP indicators are explicitly labeled as "Probable infrastructure origin" rather than physical attacker coordinates.
