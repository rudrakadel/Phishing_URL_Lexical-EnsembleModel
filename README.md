# PhishScope — AI-Powered Phishing Detection & Threat Intelligence Platform

> A 3-Tier Machine Learning consensus pipeline for real-time phishing URL detection, built with Flask, scikit-learn, Ollama LLM, Playwright, SHAP explainability, and full threat intelligence enrichment.

---

## Features

- **3-Tier ML Consensus Pipeline** — Tier 1 (RandomForest lexical), Tier 2 (StackingClassifier HTML+URL), Tier 3 (DNS/SSL/Reputation network intelligence)
- **SHAP Explainability** — Per-feature impact scores showing exactly why a URL was flagged
- **AI-Assisted Review** — Local Ollama LLM (DeepSeek 1.5b) generates a human-readable threat analyst summary
- **Live Network Intelligence** — SSL certificate audit, DNS/SPF/DMARC checks, WHOIS domain age, VirusTotal + URLhaus threat feeds
- **Security Header Audit** — CSP, HSTS, X-Frame-Options, cookie flags, JS obfuscation detection
- **Playwright Screenshots** — Headless Chromium captures a full-page screenshot without visiting the URL manually
- **Safe HTML Sandbox** — Strips all scripts, iframes, event handlers and renders a read-only page preview
- **PDF Reports** — Downloadable ReportLab threat report with SHAP tables
- **Batch Analysis** — Submit up to 50 URLs or paste an email/log blob — all URLs are extracted and analysed
- **History & Notes** — All past analyses stored in SQLite/PostgreSQL; analysts can add notes and feedback
- **Prometheus Metrics** — Built-in `/api/metrics` endpoint
- **One-Click Windows Launcher** — `setup_and_run.bat` handles venv, packages, Playwright, and startup automatically

---

## Architecture — 3-Tier Consensus Pipeline

```
RAW URL INPUT
     │
     ▼
┌─────────────────────────────┐
│  Tier 1 — Lexical Classifier│  RandomForest · 12 URL-string features
│  Accuracy: 89.89%  F1:90.57%│  Runs always — no network I/O required
└──────────────┬──────────────┘
               │
       ┌───────┼───────────────────┐
       ▼       ▼                   ▼
   _crawl()  _analyze_ssl()   _analyze_dns()
  HTML Fetch  TLS Certificate   A/MX/SPF/DMARC
       │
       ▼
┌─────────────────────────────┐
│  Tier 2 — Stacking Ensemble │  StackingClassifier · 10 URL+HTML features
│  Accuracy: ~94.4%           │  Runs only when page is crawlable
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Tier 3 — Network Score     │  0.40·SSL + 0.30·DNS + 0.30·Reputation
│  + SecurityService Audit    │  Headers · Iframes · JS Obfuscation
└──────────────┬──────────────┘
               │
               ▼
    CONSENSUS WEIGHTING
    With HTML:    55%·T1 + 25%·T2 + 10%·T3 + 10%·Security
    Without HTML: 75%·T1 + 15%·T3 + 10%·Security
               │
               ▼
         FINAL VERDICT
    Low Risk / Medium Risk / High Risk / Known Malicious
```

---

## Project Structure

```
PhishScope/
├── setup_and_run.bat            ← One-click Windows launcher (run this)
├── run_docker.bat               ← Docker Compose launcher
├── docker-compose.yml           ← Multi-container orchestration
├── LICENSE
├── README.md
│
├── Model/
│   ├── 1/                       ← Tier 1: RandomForest lexical classifier
│   │   ├── tier1_url_model.pkl
│   │   └── preprocessor.pkl
│   ├── 2/                       ← Tier 2: Stacking ensemble
│   │   ├── final_ensemble.pkl
│   │   ├── preprocessor.pkl
│   │   └── selected_features.txt
│   └── 3/                       ← Tier 3: Network intelligence plugin
│       └── network_intelligence.py
│
└── flask_phishing_app/
    ├── app.py                   ← Flask factory + all routes
    ├── config.py                ← Environment configuration
    ├── enrichment_queue.py      ← Background deep-analysis worker
    ├── metrics.py               ← Prometheus metrics registry
    ├── rate_limit.py            ← Redis/in-memory rate limiter
    ├── requirements.txt
    ├── Dockerfile
    ├── .env.example             ← Copy to .env and fill in secrets
    │
    ├── services/
    │   ├── analysis.py          ← PhishingAnalyzer — core engine (1756 lines)
    │   ├── security_service.py  ← Security header + JS obfuscation audit
    │   └── storage.py           ← HistoryStore — SQLite/PostgreSQL layer
    │
    ├── static/
    │   ├── app.css
    │   ├── app.js
    │   ├── history_center.js
    │   ├── login.js
    │   └── theme.js
    │
    └── templates/
        ├── index.html           ← Main analyst dashboard
        ├── login.html
        ├── about.html
        ├── history_center.html
        └── security_layers.html
```

---

## Quick Start — Windows (Recommended)

**Requirements:** Python 3.11 or 3.12 installed with *"Add python.exe to PATH"* ticked.

```
1. Download or clone this repository
2. Double-click  setup_and_run.bat
3. Wait for "STARTING PHISHSCOPE"
4. Open  http://127.0.0.1:5000
5. Login:  admin / admin
```

The launcher automatically:
- Detects and validates (or recreates) the Python virtual environment
- Installs all packages from `requirements.txt`
- Installs Playwright Chromium browser
- Writes a portable `.env` with paths auto-detected for the current machine
- Starts the Flask server

---

## Quick Start — Manual (Any OS)

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/PhishScope.git
cd PhishScope

# Create venv
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

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

Open `http://127.0.0.1:5000` — login with `admin / admin`.

---

## Quick Start — Docker

```bash
docker compose up --build
```

Or use the guided launcher:
```
Double-click run_docker.bat
```

---

## Configuration

Copy `.env.example` to `.env` and set these variables:

| Variable | Default | Description |
|---|---|---|
| `FLASK_SECRET_KEY` | *(required in prod)* | Session encryption key |
| `APP_USERNAME` | `admin` | Admin login username |
| `APP_PASSWORD` | `admin` | Admin login password |
| `DATABASE_URL` | SQLite auto-path | Postgres: `postgresql://user:pass@host/db` |
| `REDIS_URL` | *(none)* | Enable Redis caching + distributed rate limiting |
| `OLLAMA_URL` | `http://127.0.0.1:11434/api/generate` | Local Ollama endpoint |
| `OLLAMA_MODEL` | `deepseek-r1:1.5b` | Model name (must be pulled first) |
| `VT_API_KEY` | *(none)* | VirusTotal API key for threat intel |
| `GOOGLE_CLIENT_ID` | *(none)* | Enable Google One Tap login |

---

## AI Review — Ollama (Optional)

The AI threat summary panel requires a local Ollama instance:

```bash
# Install Ollama from https://ollama.com
# Then pull the model:
ollama pull deepseek-r1:1.5b
```

The system works fully without Ollama — a rule-based heuristic summary is shown instead.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Analyse a single URL — full pipeline |
| `POST` | `/api/batch` | Analyse up to 50 URLs or a text blob |
| `GET` | `/api/analysis/<id>` | Fetch stored result by ID (used for enrichment polling) |
| `POST` | `/api/analysis/<id>/notes` | Add analyst note |
| `POST` | `/api/analysis/<id>/feedback` | Submit helpful/unhelpful vote |
| `GET` | `/api/report/<id>` | Download PDF threat report |
| `GET` | `/api/history` | Recent analysis list |
| `POST` | `/api/auth/login` | Login (username or mobile) |
| `POST` | `/api/auth/register` | Register new account |
| `POST` | `/api/auth/google` | Google OAuth login |
| `GET` | `/api/health` | Health check — model status, DB, optional services |
| `GET` | `/api/metrics` | Prometheus metrics (requires `METRICS_TOKEN` header) |

---

## Running Tests

```bash
.venv\Scripts\python.exe -m unittest tests.test_analysis_pipeline -v
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Web Framework | Flask 3.x |
| Tier 1 ML | scikit-learn RandomForestClassifier |
| Tier 2 ML | scikit-learn StackingClassifier |
| Explainability | SHAP (mean-reference local contribution) |
| LLM Review | Ollama (DeepSeek 1.5b) |
| Screenshots | Playwright Chromium (headless) |
| Charts | Matplotlib (Agg backend) |
| PDF Reports | ReportLab |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Cache | Redis |
| Rate Limiting | In-memory / Redis INCR |
| Auth | Flask session + Werkzeug bcrypt + Google OAuth2 |
| Threat Intel | URLhaus (abuse.ch) + VirusTotal API v3 |
| Metrics | Prometheus text format |

---

## License

MIT — see [LICENSE](LICENSE)
