# PhishScope — AI-Powered Phishing Detection & Threat Intelligence Platform

> **3-Tier ML Consensus Pipeline** · Flask · scikit-learn · SHAP · Ollama LLM · Playwright · Redis · SQLite/PostgreSQL

---

## Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [ML Pipeline Detail](#ml-pipeline-detail)
- [Scoring Formula](#scoring-formula)
- [Database Schema](#database-schema)
- [Tech Stack](#tech-stack)
- [Documentation](#documentation)

---

## Overview

PhishScope is an enterprise-grade phishing URL detection platform built for Security Operations Center (SOC) analysts. It accepts a raw or defanged URL, runs it through a three-tier machine learning consensus pipeline combined with live network intelligence, NLP content analysis, AI-assisted LLM review, and security header auditing — and returns a scored, fully explainable verdict.

**Core Capabilities:**
- Instant Tier 1 lexical classification (no network I/O, always available)
- Conditional Tier 2 HTML+URL stacking ensemble (runs when page is crawlable)
- Tier 3 SSL/DNS/WHOIS/Reputation network intelligence
- SHAP per-feature impact scores — explains every decision
- Ollama local LLM threat analyst summary (DeepSeek 1.5b)
- Playwright headless screenshot of the target page
- URLhaus + VirusTotal threat feed cross-reference
- Safe sandboxed HTML preview (all scripts stripped)
- PDF downloadable report via ReportLab
- Batch mode — paste a raw email/log blob, all URLs extracted automatically
- Full analyst workspace: notes, feedback, history, community labels

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER (Analyst UI)                     │
│  app.js · history_center.js · login.js · theme.js · app.css           │
└───────────────────────────────┬────────────────────────────────────────┘
                                │  POST /api/analyze
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    FLASK APPLICATION CORE  (app.py)                    │
│                                                                        │
│  before_request ──► attach request_id + perf_counter                  │
│  after_request  ──► inject CSP/HSTS/XFO headers + Prometheus metrics  │
│                                                                        │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────────┐   │
│  │  RateLimiter │  │  auth_required│  │  MetricsRegistry         │   │
│  │  Redis/Memory│  │  session check│  │  counters·gauges·timers  │   │
│  └──────────────┘  └───────────────┘  └──────────────────────────┘   │
└───────────────────────────────┬────────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    PhishingAnalyzer  (analysis.py)                     │
│                                                                        │
│  ① Redis cache lookup ──► return early on HIT                         │
│                                                                        │
│  ② _normalize_url()  _validate_url()                                  │
│                                                                        │
│  ③ TIER 1 ─────────────────────────────────────────────────────────   │
│     _extract_tier1_features()  →  12 lexical URL features             │
│     _run_tier1_model()         →  RandomForestClassifier.predict_proba│
│                                                                        │
│  ④ PARALLEL BLOCK 1 (ThreadPoolExecutor, 6 threads)                   │
│     ├── _crawl()              →  HTTP fetch + BeautifulSoup parse      │
│     ├── _analyze_ssl()        →  raw TLS socket + X.509 cert audit    │
│     ├── _analyze_dns()        →  dnspython A/MX/SPF/DMARC lookups     │
│     ├── _analyze_reputation() →  whois domain age + TLD scoring       │
│     └── _check_threat_intel() →  URLhaus + VirusTotal API             │
│                                                                        │
│  ⑤ _analyze_text()     NLP suspicious phrases + brand impersonation   │
│     _build_sandbox()   strip scripts/iframes/events for safe preview  │
│                                                                        │
│  ⑥ TIER 2 (if html_ok = True) ─────────────────────────────────────  │
│     _extract_model_features()  →  10 URL+HTML feature vector         │
│     _run_model()               →  StackingClassifier.predict_proba    │
│                                                                        │
│  ⑦ SecurityService.analyze()  →  CSP·HSTS·XFO·iframe·JS obfuscation  │
│                                                                        │
│  ⑧ NETWORK SCORE = 0.40·SSL + 0.30·DNS + 0.30·Reputation             │
│                                                                        │
│  ⑨ CONSENSUS ──────────────────────────────────────────────────────   │
│     html_ok=True:  0.55·T1 + 0.25·T2 + 0.10·Net + 0.10·Sec          │
│     html_ok=False: 0.75·T1 + 0.15·Net + 0.10·Sec                     │
│                                                                        │
│  ⑩ known_malicious override → floor score at 95.0                     │
│                                                                        │
│  ⑪ PARALLEL BLOCK 2                                                   │
│     ├── _capture_screenshot()    →  Playwright Chromium headless      │
│     ├── _analyze_with_ollama()   →  LLM prompt → structured JSON      │
│     └── _compute_shap()          →  mean-reference local contribution │
│                                                                        │
│  ⑫ _build_chart_assets()  →  Matplotlib gauge + bars + SHAP chart    │
│     Redis cache WRITE                                                  │
└───────────────────────────────┬────────────────────────────────────────┘
                                │  save to DB
                                ▼
┌───────────────────────────────────────────────────────────────────────┐
│              HistoryStore (storage.py)  SQLite / PostgreSQL           │
│   Tables: users · analysis_history · analysis_notes ·                │
│           analysis_feedback · background_jobs                         │
│   Job Locking:  FOR UPDATE SKIP LOCKED  (Postgres)                   │
│                 WAL-mode write transaction  (SQLite)                  │
└───────────────────────────────┬───────────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────────┐
│              EnrichmentQueue (enrichment_queue.py)                    │
│   Daemon thread · claim_job() · analyze_url() full · update_analysis()│
└───────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
PhishScope/
│
├── setup_and_run.bat                ← One-click Windows launcher
├── run_docker.bat                   ← Docker Compose launcher
├── docker-compose.yml
├── LICENSE
├── README.md
│
├── Model/
│   ├── 1/
│   │   ├── tier1_url_model.pkl      ← RandomForestClassifier (14.7 MB)
│   │   └── preprocessor.pkl         ← StandardScaler for Tier 1
│   ├── 2/
│   │   ├── final_ensemble.pkl       ← StackingClassifier (2.5 MB)
│   │   ├── preprocessor.pkl         ← Preprocessor for Tier 2
│   │   └── selected_features.txt    ← Ordered feature column names
│   └── 3/
│       └── network_intelligence.py  ← Hot-swap plugin (dynamic import)
│
├── flask_phishing_app/
│   ├── app.py                       ← Flask factory + all 14 routes
│   ├── config.py                    ← AppConfig dataclass (env vars)
│   ├── enrichment_queue.py          ← Background worker daemon
│   ├── metrics.py                   ← Prometheus registry
│   ├── rate_limit.py                ← Token-bucket (Redis/memory)
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .env.example
│   │
│   ├── services/
│   │   ├── analysis.py              ← PhishingAnalyzer (1756 lines)
│   │   ├── security_service.py      ← SecurityService (122 lines)
│   │   └── storage.py               ← HistoryStore (626 lines)
│   │
│   ├── static/
│   │   ├── app.css                  ← Full UI stylesheet (30 KB)
│   │   ├── app.js                   ← Dashboard controller (34 KB)
│   │   ├── history_center.js
│   │   ├── login.js
│   │   └── theme.js
│   │
│   └── templates/
│       ├── index.html               ← Analyst dashboard
│       ├── login.html
│       ├── about.html
│       ├── history_center.html
│       └── security_layers.html
│
├── docs/
│   ├── HLD_system_architecture.md   ← High-Level Design document
│   ├── LLD_function_reference.md    ← Full function-level LLD (every method)
│   └── deploysetup.md
│
├── scripts/
│   └── import_urls_to_history.py    ← Bulk URL importer (CSV/XLSX/TXT)
│
└── tests/
    ├── test_analysis_pipeline.py
    └── test_production_hardening.py
```

---

## Quick Start

### Windows — One Click

> **Requires Python 3.11 or 3.12** — install from [python.org](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"**.

```
1.  git clone https://github.com/rudrakadel/Phishing_URL_Lexical-EnsembleModel.git
2.  Double-click  setup_and_run.bat
3.  Browser opens automatically at  http://127.0.0.1:5000
4.  Login:  admin  /  admin
```

`setup_and_run.bat` automatically handles:
- Detecting and validating the Python virtual environment (recreates if broken or from another PC)
- Installing all packages from `requirements.txt`
- Installing Playwright Chromium browser (one-time, ~150 MB)
- Writing a portable `.env` with paths auto-detected for the current machine
- Starting the Flask development server

### Manual (Any OS)

```bash
git clone https://github.com/rudrakadel/Phishing_URL_Lexical-EnsembleModel.git
cd Phishing_URL_Lexical-EnsembleModel

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate.bat

# Install dependencies
pip install -r flask_phishing_app/requirements.txt
python -m playwright install chromium

# Configure
cp flask_phishing_app/.env.example flask_phishing_app/.env
# Edit .env — set FLASK_SECRET_KEY at minimum

# Run
cd flask_phishing_app
python app.py
```

### Docker

```bash
docker compose up --build
```

Access at `http://localhost:5000` — login: `admin / admin`

### Ollama AI Review (Optional)

```bash
# Install from https://ollama.com, then:
ollama pull deepseek-r1:1.5b

# App will auto-connect via:
# OLLAMA_URL=http://127.0.0.1:11434/api/generate
```

---

## Configuration

Copy `.env.example` → `.env` and configure:

```env
# App
APP_ENV=development
APP_ROLE=web                          # web | worker
APP_HOST=127.0.0.1
APP_PORT=5000
FLASK_SECRET_KEY=change-this-in-prod  # REQUIRED in production

# Auth
APP_REQUIRE_AUTH=1
APP_USERNAME=admin
APP_PASSWORD=admin

# Database — leave empty to auto-detect path from file location
DATABASE_URL=                         # e.g. postgresql://user:pass@host/db
REDIS_URL=                            # e.g. redis://localhost:6379/0

# ML Models — leave empty to auto-detect
PHISHING_MODEL_DIR=                   # absolute path to project root

# Enrichment worker
ENABLE_BACKGROUND_WORKER=1
WORKER_POLL_INTERVAL_SECONDS=2
WORKER_MAX_RETRIES=5
WORKER_STALE_AFTER_SECONDS=300

# Timeouts
REQUEST_TIMEOUT_SECONDS=5
EXTERNAL_TIMEOUT_SECONDS=4
OLLAMA_TIMEOUT_SECONDS=18
SCREENSHOT_TIMEOUT_MS=15000

# Ollama
OLLAMA_URL=http://127.0.0.1:11434/api/generate
OLLAMA_MODEL=deepseek-r1:1.5b

# Optional integrations
VT_API_KEY=                           # VirusTotal API key
GOOGLE_CLIENT_ID=                     # Google OAuth client ID
METRICS_TOKEN=                        # Token for /api/metrics endpoint
```

---

## API Reference

All API routes return JSON. Authentication uses Flask sessions (cookie-based).

### Authentication

```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "analyst1",
  "first_name": "Jane",
  "last_name": "Doe",
  "mobile": "9876543210",
  "password": "securepassword"
}
```

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "analyst1", "password": "securepassword" }
```

```http
POST /api/auth/google
Content-Type: application/json

{ "credential": "<google-id-token>" }
```

---

### Analysis

```http
POST /api/analyze
Content-Type: application/json

{ "url": "http://suspicious-login-paypa1.xyz/secure/account" }

# OR paste raw text / defanged URLs:
{ "text": "Check this link hxxps://evil[.]com/phish and hxxp://fake-bank[.]ru" }
```

**Response:**
```json
{
  "url": "http://suspicious-login-paypa1.xyz/secure/account",
  "verdict": "High Risk",
  "hybrid_score": 87.4,
  "tier1_score": 91.2,
  "tier2_score": 83.6,
  "network_score": 74.0,
  "security_score": 80.0,
  "components": {
    "ML": 83.6, "HTML": 75.0, "Headers": 80.0, "NLP": 60.0,
    "SSL": 40.0, "DNS": 70.0, "Reputation": 90.0, "URL": 88.0
  },
  "ml": { "available": true, "probability": 0.836, "prediction": "phishing" },
  "shap": {
    "available": true,
    "method": "mean-reference local contribution",
    "top_features": [
      { "feature": "phish_hints", "impact": 0.142, "value": 3.0 },
      { "feature": "domain_age", "impact": 0.118, "value": 12.0 }
    ]
  },
  "ollama": { "available": true, "summary": "...", "verdict_reasoning": "..." },
  "threat_intelligence": { "known_malicious": false, "sources": [] },
  "charts": { "gauge": "<base64-png>", "components": "<base64-png>", "shap": "<base64-png>" },
  "screenshot": { "available": true, "path": "/static/screenshots/screenshot-20250604.png" },
  "human_summary": "Classification: High Risk (87.4/100). Urgency language present in page text.",
  "analysis_id": 142,
  "enrichment": { "status": "complete" },
  "cache": { "hit": false, "ttl_seconds": 1800 },
  "analysis_duration_ms": 3241.7
}
```

---

```http
POST /api/batch
Content-Type: application/json

{ "urls": ["https://url1.com", "https://url2.com"] }
# OR
{ "text": "multi-line email body with URLs..." }
```

```http
GET  /api/analysis/<id>            # Poll enrichment status / fetch full result
POST /api/analysis/<id>/notes      # { "note": "Confirmed phishing — ticket #4521" }
POST /api/analysis/<id>/feedback   # { "helpful": true, "corrected_label": "phishing" }
GET  /api/report/<id>              # Download PDF threat report
GET  /api/history?limit=20         # Recent analyses list
GET  /api/health                   # System health + model status
GET  /api/metrics                  # Prometheus metrics (requires METRICS_TOKEN header)
```

---

## ML Pipeline Detail

### Tier 1 — Lexical URL Classifier

**Model:** `RandomForestClassifier` | **Accuracy:** 89.89% | **F1:** 90.57%

Runs on 12 URL-string features. No network I/O — always available even if the target is offline.

| Feature | Description |
|---|---|
| `length_url` | Total URL character count |
| `length_hostname` | Hostname character count |
| `nb_dots` | Count of `.` in URL |
| `nb_hyphens` | Count of `-` in URL |
| `nb_www` | Count of `www` occurrences |
| `ratio_digits_url` | Digit characters / total characters |
| `length_words_raw` | Count of alphanumeric tokens (excl. TLD) |
| `longest_words_raw` | Max token length (excl. TLD) |
| `longest_word_path` | Max word length in URL path |
| `phish_hints` | Count of keywords: `login`, `secure`, `verify`, `account`, `update`, `bank`, `otp`, `signin`, `password`, `auth`, `admin` |
| `nb_slash` | Count of `/` in URL |
| `shortest_word_host` | Min word length in registered hostname |

### Tier 2 — Hybrid URL + HTML Stacking Ensemble

**Model:** `StackingClassifier` | **Accuracy:** ~94.4%

Runs only when the page can be crawled (`html_ok = True`). Combines URL structure with crawled HTML signals.

| Feature | Source | Description |
|---|---|---|
| `nb_www` | URL | www occurrences |
| `longest_word_path` | URL | Max path token length |
| `phish_hints` | URL | Phishing keyword count |
| `nb_hyperlinks` | HTML crawl | Total `<a>` anchor count |
| `ratio_extHyperlinks` | HTML crawl | External link fraction |
| `domain_age` | WHOIS | Domain age in days |
| `web_traffic` | Proxy heuristic | `min(hyperlinks × 800, 500000)` |
| `google_index` | Heuristic | 1.0 if HTTPS + >5 links |
| `page_rank` | Heuristic | 0–10 composite score |
| `status_encoded` | **Fixed 0.5** | Neutralized (prevents HTTP status leakage) |

### Tier 3 — Network Intelligence (Hot-Swap Plugin)

Loaded dynamically via `importlib.util.spec_from_file_location` from `Model/3/network_intelligence.py`. Can be replaced on disk without modifying application code.

**Checks:** SSL certificate validity · Days to expiry · CN/SAN match · DNS A/MX/SPF/DMARC records · WHOIS domain age · TLD reputation

---

## Scoring Formula

### Per-Dimension Risk Scores (0–100)

```python
# URL Risk
score += 20  if not uses_https
score += 30  if uses_ip_address
score += 20  if "@" in url
score += 20  if shortening_service
score += 15  if double_slash
score += 15  if subdomain_count >= 3
score += 10  if url_length > 100
score += 10  if domain_entropy > 3.5

# SSL Risk
score  = 85  if not has_ssl          # immediate
score += 40  if is_expired
score += 25  if not cn_matches
score += 20  if days_until_expiry < 7
score += 15  if certificate_age_days < 30

# HTML Risk
score += 20  if login_form
score += 15  if iframe
score += 15  if suspicious_form_handler
score += 20  if ratio_external_links > 0.6
score += 10  if ratio_null_links > 0.5

# Security Layer (SecurityService)
score += 20  if not Content-Security-Policy header
score += 15  if not Strict-Transport-Security header
score += 15  if not X-Frame-Options header
score += 15  if <iframe> found in body
score += 15  if redirect_count > 2
score += 20  if JS obfuscation detected (eval/unescape/fromCharCode/hex/base64)
```

### Final Consensus

```python
# With HTML crawled:
final = (0.55 * tier1_score) + (0.25 * tier2_score) + (0.10 * network_score) + (0.10 * security_score)

# Without HTML (crawl failed):
final = (0.75 * tier1_score) + (0.15 * network_score) + (0.10 * security_score)

# Threat feed override:
if known_malicious:
    final = max(final, 95.0)
    verdict = "Known Malicious"
```

### Verdict Thresholds

| Score | Verdict |
|---|---|
| 0 – 39 | `Low Risk` |
| 40 – 64 | `Medium Risk` |
| 65 – 100 | `High Risk` |
| threat feed hit | `Known Malicious` |

---

## Database Schema

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    first_name    TEXT NOT NULL,
    last_name     TEXT,
    mobile        TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analysis_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    username       TEXT,
    auth_provider  TEXT,
    verdict        TEXT,
    risk_score     REAL,
    ml_probability REAL,
    cache_hit      BOOLEAN DEFAULT 0,
    payload        TEXT,           -- JSON blob (JSONB in PostgreSQL)
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analysis_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analysis_history(id),
    note        TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE analysis_feedback (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER REFERENCES analysis_history(id),
    normalized_url  TEXT NOT NULL,
    username        TEXT,
    helpful         BOOLEAN NOT NULL,
    corrected_label TEXT,
    note            TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE background_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',  -- pending|running|completed|failed|retry
    payload      TEXT NOT NULL,                    -- JSON (JSONB in PostgreSQL)
    attempts     INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 5,
    last_error   TEXT,
    not_before   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reserved_at  TIMESTAMP,
    worker_id    TEXT,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_history_created_at ON analysis_history(created_at DESC);
CREATE INDEX idx_history_username   ON analysis_history(username);
CREATE INDEX idx_jobs_status        ON background_jobs(status, not_before);
CREATE INDEX idx_users_username     ON users(username);
CREATE INDEX idx_users_mobile       ON users(mobile);
CREATE INDEX idx_feedback_url       ON analysis_feedback(normalized_url);
```

**PostgreSQL job claim** (concurrent worker-safe):
```sql
WITH claimed AS (
    SELECT id FROM background_jobs
    WHERE status IN ('pending', 'retry') AND not_before <= CURRENT_TIMESTAMP
    ORDER BY id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE background_jobs
SET status = 'running', attempts = attempts + 1,
    reserved_at = CURRENT_TIMESTAMP, worker_id = %s
WHERE id IN (SELECT id FROM claimed)
RETURNING id, kind, payload, attempts, max_attempts;
```

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Web Framework | Flask | ≥ 3.0 |
| ML — Tier 1 | scikit-learn `RandomForestClassifier` | 1.6.1 |
| ML — Tier 2 | scikit-learn `StackingClassifier` | 1.6.1 |
| Gradient Boost | XGBoost + LightGBM | 3.2 / 4.6 |
| Explainability | SHAP (custom mean-reference) | 0.49.1 |
| LLM Review | Ollama (DeepSeek 1.5b) | local |
| Screenshots | Playwright Chromium headless | 1.58.0 |
| Charts | Matplotlib Agg backend | 3.10.8 |
| PDF Reports | ReportLab | 4.4.10 |
| HTTP | requests + BeautifulSoup4 | 2.32 / 4.14 |
| DNS | dnspython | 2.8.0 |
| WHOIS | python-whois | 0.9.6 |
| TLD Parsing | tldextract | 5.3.1 |
| Database | SQLite / PostgreSQL (psycopg3) | — |
| Cache / Rate Limit | Redis | ≥ 5.0 |
| Auth | Flask session + Werkzeug bcrypt + Google OAuth2 | — |
| Threat Intel | URLhaus (abuse.ch) + VirusTotal API v3 | — |
| Metrics | Prometheus text format | v0.0.4 |
| Data Processing | pandas + numpy + scipy | 3.0 / 1.26 / 1.12 |

---

## Documentation

| Document | Description |
|---|---|
| [HLD — System Architecture](docs/HLD_system_architecture.md) | High-Level Design: dataflow diagrams, tier table, consensus weights, DB schema overview, API map |
| [LLD — Function Reference](docs/LLD_function_reference.md) | Low-Level Design: every function in every module with tags, argument types, return types, internal logic, and scoring tables |

---

## Running Tests

```bash
.venv\Scripts\python.exe -m unittest tests.test_analysis_pipeline -v
.venv\Scripts\python.exe -m unittest tests.test_production_hardening -v
```

---

## Bulk URL Import

```bash
# From Excel / CSV
.venv\Scripts\python.exe scripts\import_urls_to_history.py urls.xlsx --column url --username admin

# From plain text (one URL per line)
.venv\Scripts\python.exe scripts\import_urls_to_history.py urls.txt --username admin

# Full deep analysis (slower)
.venv\Scripts\python.exe scripts\import_urls_to_history.py urls.csv --column url --username admin --full
```

---

## License

MIT — see [LICENSE](LICENSE)
