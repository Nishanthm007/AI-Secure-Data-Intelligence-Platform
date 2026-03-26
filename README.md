# AI Secure Data Intelligence Platform

> **Hackathon 2026** — AI Gateway · Scanner · Log Analyzer · Risk Engine

A full-stack security intelligence platform that ingests multi-source data (text, files, SQL, chat, logs), detects sensitive information and security risks, scores risk with a configurable engine, and generates AI-powered insights.

---

## Architecture

```
Input (Text / File / SQL / Log / Chat)
        ↓
  Validation & Parsing
        ↓
  Detection Engine
  ├── Regex Patterns  (15+ patterns: passwords, API keys, JWTs, AWS keys, PII…)
  ├── Log Analyzer    (line-by-line, brute-force detection, suspicious IP, debug leaks)
  └── AI Analysis     (OpenAI GPT-4o-mini or rule-based fallback)
        ↓
  Risk Engine         (score-based: critical=5, high=3, medium=2, low=1)
        ↓
  Policy Engine       (mask | block | allow)
        ↓
  Response            (findings, risk score, masked content, AI insights)
```

---

## Tech Stack

| Layer    | Technology                                   |
|----------|----------------------------------------------|
| Backend  | Python 3.11+, FastAPI, Uvicorn               |
| AI       | OpenAI GPT-4o-mini (rule-based fallback)     |
| Parsing  | pypdf, python-docx                           |
| Frontend | React 18, Vite, CSS Modules                  |

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Clone & Configure

```bash
cd backend
copy .env.example .env
# Edit .env — set OPENAI_API_KEY for AI insights (optional; works without it)
```

### 2. Start Everything (Windows)

```
start.bat
```

Or manually:

```bash
# Backend
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (new terminal)
cd frontend
npm install
npm run dev
```

### 3. Open

- **UI**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs

---

## API

### `POST /api/v1/analyze`
Analyze text / SQL / chat / log content.

```json
{
  "input_type": "log",
  "content": "2026-03-10 10:00:01 INFO password=admin123 api_key=sk-prod-xyz",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```

### `POST /api/v1/analyze/upload`
Upload a file (PDF, DOCX, TXT, LOG, SQL, CSV) via `multipart/form-data`.

---

## Detection Patterns

| Pattern | Risk |
|---------|------|
| Password in logs | Critical |
| AWS Access Key | Critical |
| Database connection string | Critical |
| Hard-coded secret | Critical |
| API key | High |
| JWT token | High |
| Bearer token | High |
| Stack trace | Medium |
| Brute-force attempt (≥5 fails) | High |
| Debug mode leak | Medium |
| Email address | Low |
| IP address | Low |

---

## Features

- **Multi-input**: Text · PDF · DOCX · TXT · LOG · SQL · Chat
- **Log Viewer**: Line-by-line highlighting with risk colour-coding
- **Drag & Drop**: File upload with drag-and-drop support
- **AI Insights**: Specific, actionable security recommendations
- **Risk Engine**: Weighted scoring with 4 severity levels
- **Policy Engine**: Mask / Block / Allow based on risk level
- **Observability**: `/api/v1/health` endpoint

---

## Sample Log

`sample_logs/app.log` contains a realistic log demonstrating:
- Plaintext passwords & API keys
- Brute-force login attempts
- Stack trace leaks
- JWT token exposure
- Database connection strings
- AWS key exposure
