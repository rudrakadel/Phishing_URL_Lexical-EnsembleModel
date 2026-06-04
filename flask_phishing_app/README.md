# Flask Phishing URL Detection App

This app lives in its own folder and uses the 3-Tier Layered Consensus model artifacts present in the parent folder under `Model/` by default:

- `Model/1/` (Tier 1 RF Lexical model)
- `Model/2/` (Tier 2 Ensemble Hybrid model)
- `Model/3/` (Tier 3 Network intelligence model)

## Run

```bash
cd /root/Downloads/Phishing/flask_phishing_app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
python3 app.py
```

For a production-style local launch:

```bash
gunicorn -w 2 -b 0.0.0.0:5000 app:app
```

Run the background enrichment worker separately:

```bash
APP_ROLE=worker python3 run_worker.py
```

Recommended because your saved model needs matching ML libraries:

- `scikit-learn==1.6.1`
- `xgboost==3.2.0`
- `lightgbm==4.6.0`
- `joblib==1.5.3`
- `numpy==1.26.4`
- `pandas==3.0.1`
- `scipy==1.12.0`
- `shap==0.49.1`

## Model path

The app reads model files from the parent folder automatically. To point it somewhere else:

```bash
export PHISHING_MODEL_DIR=/absolute/path/to/model/files
```

## Features

- Login-first entry flow at `/login`
- Local registration with first name, optional last name, mobile number, username, and password validation
- Protected dashboard at `/dashboard`
- URL analysis endpoint: `POST /api/analyze`
- Batch analysis endpoint: `POST /api/batch`
- History endpoint: `GET /api/history`
- Health endpoint: `GET /api/health`
- Metrics endpoint: `GET /api/metrics` with `X-Metrics-Token`
- Optional login endpoints: `POST /api/auth/login`, `POST /api/auth/logout`
- Analyst notes endpoint: `POST /api/analysis/<id>/notes`
- PDF report endpoint: `GET /api/report/<id>`
- Sandboxed HTML preview with dangerous content stripped before rendering
- SHAP explanations and chart images
- Threat intelligence checks for URLhaus and optional VirusTotal
- Optional Playwright screenshot capture
- Optional Ollama HTML security review
- Portable paths with no hardcoded Windows directories
- Local writable runtime cache for `tldextract` and Matplotlib
- Durable background enrichment queue backed by the application database
- Redis-backed result cache and optional rate-limit storage
- PostgreSQL support through `DATABASE_URL`
- Structured request logging, request ids, rate limiting, and session hardening
- Footer links to phishing research archives

## Optional environment variables

```bash
export APP_ENV=production
export FLASK_DEBUG=0
export APP_REQUIRE_AUTH=1
export APP_USERNAME=admin
export APP_PASSWORD_HASH='pbkdf2:sha256:...'
export FLASK_SECRET_KEY=replace-me
export DATABASE_URL=postgresql://user:pass@localhost:5432/phishscope
export METRICS_TOKEN=replace-me
export RATE_LIMIT_ANALYZE_PER_WINDOW=30
export RATE_LIMIT_BATCH_PER_WINDOW=5
export RATE_LIMIT_LOGIN_PER_WINDOW=10
export RATE_LIMIT_NOTES_PER_WINDOW=30
export RATE_LIMIT_WINDOW_SECONDS=60
export BATCH_MAX_URLS=50
export ENABLE_BACKGROUND_WORKER=1
export WORKER_POLL_INTERVAL_SECONDS=2
export WORKER_MAX_RETRIES=5
export REQUEST_TIMEOUT_SECONDS=5
export EXTERNAL_TIMEOUT_SECONDS=4
export OLLAMA_TIMEOUT_SECONDS=18
export SCREENSHOT_TIMEOUT_MS=15000
export REDIS_URL=redis://localhost:6379/0
export OLLAMA_URL=http://127.0.0.1:11434/api/generate
export OLLAMA_MODEL=deepseek:1.5b
export VT_API_KEY=your_key
```

If you still want plain-text local credentials during development, `APP_PASSWORD` is still supported. For production, use `APP_PASSWORD_HASH`.

Default local fallback credentials for development:

```text
username: admin
password: admin
```

Generate a password hash with:

```bash
python3 generate_password_hash.py
```

## Docker Compose

From the repository root:

```bash
cp flask_phishing_app/.env.example flask_phishing_app/.env
docker compose up --build
```

This starts:

- `web`: Gunicorn Flask service
- `worker`: background enrichment worker
- `db`: PostgreSQL
- `redis`: Redis for caching and rate-limit coordination

## Systemd / Nginx

Reference deployment files are included:

- `deploy/systemd/phishscope-web.service`
- `deploy/systemd/phishscope-worker.service`
- `deploy/nginx/phishscope.conf`

They assume the app is installed under `/opt/phishscope/flask_phishing_app`.
