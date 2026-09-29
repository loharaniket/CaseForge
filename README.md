# CaseForge — Email Forensic Investigation Platform

CaseForge is a modular cybersecurity email forensics and investigation platform built for Security Operations Centers (SOC).

---

## Repository Structure

```
CaseForge/
├── apps/
│   ├── api/             # FastAPI Backend API (Python 3.13)
│   └── web/             # React 19 + Vite SPA Frontend Dashboard (TypeScript)
├── infrastructure/      # Docker Compose & PostgreSQL configuration
└── docs/                # Architecture, database, and API documentation
```

---

## Quick Start

### Prerequisites
* **Python**: 3.11+ (Python 3.13 recommended)
* **Node.js**: Node 20+ LTS (Node 22/24 recommended)
* **Docker & Docker Compose** (Optional for containerized PostgreSQL)

### 1. Environment Setup

Copy `.env.example` templates:
```bash
cp .env.example .env
cp apps/api/.env.example apps/api/.env
cp apps/web/.env.example apps/web/.env
```

### 2. Backend Setup (`apps/api`)

Install dependencies:
```bash
python -m pip install -r apps/api/requirements.txt -r apps/api/requirements-dev.txt
```

Run tests:
```bash
pytest apps/api/tests -v
```

Start the API development server:
```bash
python -m uvicorn apps.api.src.main:app --reload --port 8000
```
API Documentation will be accessible at: `http://localhost:8000/api/v1/docs`

### 3. Frontend Setup (`apps/web`)

Install dependencies:
```bash
npm --prefix apps/web install
```

Run build & type check:
```bash
npm --prefix apps/web run build
npm --prefix apps/web run typecheck
```

Start the Vite development server:
```bash
npm --prefix apps/web run dev
```
Access the dashboard at: `http://localhost:3000`

---

## Development Principles & Guidelines

Refer to [AGENTS.md](AGENTS.md) and [docs/architecture.md](docs/architecture.md) for strict rules governing incremental vertical slices, security protocols, AI model decoupling, and risk calculation weights.
