# AlertIQ — AI-Powered SIEM Alert Triage System

AlertIQ is a full-stack security operations tool that ingests raw security events, runs them through a 7-stage pipeline, and uses Claude AI to triage alerts into structured verdicts — so analysts spend time on real threats, not noise.

## What It Does

Raw security event comes in → normalized → deduplicated → pre-filtered → PII scrubbed → IP enriched → Claude AI triages → priority score (P1–P4) → analyst dashboard with live updates.

## Pipeline

| Step | Name | What It Does |
|------|------|--------------|
| 1 | Ingest & Normalize | Standardizes raw fields to ECS schema, deduplicates via MD5 hash (5-min window) |
| 2 | Pre-Filter | Suppresses noise (heartbeats, pings), throttles IP floods, auto-escalates CRITICAL events |
| 3 | PII Scrub | Strips emails, SSNs, phone numbers, tokens, passwords before AI sees the data |
| 4 | Enrichment | IP reputation via ip-api.com (geo, proxy/Tor flags), asset registry lookup |
| 5 | Claude AI Triage | Claude Sonnet 4.6 returns verdict, confidence score, severity, and recommended action |
| 6 | Score & Route | Priority score 0–100, routed to P1–P4 queue, MITRE ATT&CK technique tagged |
| 7 | Escalate & Notify | Slack webhook for P1/P2, WebSocket push to live dashboard, analyst TP/FP feedback loop |

## Tech Stack

- **Backend** — FastAPI, Python 3.12, PostgreSQL 16 (JSONB), psycopg3
- **AI** — Anthropic Claude Sonnet 4.6 (structured JSON output)
- **Frontend** — React, Vite, Tailwind CSS
- **Real-Time** — WebSockets
- **Auth** — JWT + RBAC (Analyst / Admin / Read-Only)
- **Deployment** — Docker Compose

## Running Locally

**Prerequisites:** Docker Desktop, Python 3.11+, Node 18+

```bash
# 1. Start PostgreSQL
docker run --name alertiq-postgres \
  -e POSTGRES_USER=alertiq \
  -e POSTGRES_PASSWORD=alertiq123 \
  -e POSTGRES_DB=alertiq \
  -p 5432:5432 -d postgres:16

# 2. Set up backend
cp .env.example .env   # fill in your values
python -m venv venv
venv/Scripts/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000

# 3. Set up frontend
cd frontend
npm install
npm run dev   # → http://localhost:3000
```

**Or with Docker Compose (full stack):**
```bash
docker compose up --build
# Backend: http://localhost:8000
# Dashboard: http://localhost:3000
```

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/alerts/ingest` | Ingest a raw security event |
| GET | `/alerts` | List alerts (JWT required) |
| GET | `/alerts/{id}` | Get alert detail |
| PATCH | `/alerts/{id}/verdict` | Submit analyst verdict |
| GET | `/alerts/stats` | Dashboard stats |
| POST | `/auth/register` | Register (first user = admin) |
| POST | `/auth/login` | Login → JWT token |
| WS | `/ws/alerts` | Live alert stream |

## Environment Variables

Copy `.env.example` to `.env` and fill in:

```
DATABASE_URL          PostgreSQL connection string
JWT_SECRET            Random secret for signing tokens
CORS_ORIGINS          Comma-separated allowed frontend origins
SLACK_WEBHOOK_URL     Optional — Slack alerts for P1/P2
DEDUP_WINDOW_SECONDS  Duplicate window (default 300)
```
