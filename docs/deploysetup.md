# Deploy Setup

This document covers:

- local Docker deployment
- hosted deployment for resume use
- the exact services this app needs

## Recommended hosted option

For this project, the cleanest resume-friendly deployment is:

- `Render` for the public web app
- `Render Background Worker` for enrichment jobs
- `Render Postgres` for history and jobs
- `Render Key Value` for Redis-compatible caching and rate limiting

Why this is a good fit:

- the app already supports separate `web` and `worker` roles
- it already supports `DATABASE_URL` and `REDIS_URL`
- it already ships with a Dockerfile and Gunicorn config
- Render supports Docker services, background workers, Postgres, and Redis-compatible key-value services

## What you need before deploying

1. Push this repo to GitHub.
2. Make sure these files are committed:
   - `flask_phishing_app/Dockerfile`
   - `flask_phishing_app/gunicorn.conf.py`
   - `flask_phishing_app/run_worker.py`
   - `docker-compose.yml`
3. Generate a password hash if you want auth enabled:

```bash
cd /root/Downloads/Phishing/flask_phishing_app
python3 generate_password_hash.py
```

4. Prepare production values for:
   - `FLASK_SECRET_KEY`
   - `APP_PASSWORD_HASH`
   - `METRICS_TOKEN`
   - `VT_API_KEY` if you want VirusTotal
   - `GOOGLE_CLIENT_ID` if you want Google login

## Local Docker run

From the repository root:

```bash
cd /root/Downloads/Phishing
cp flask_phishing_app/.env.example flask_phishing_app/.env
```

Edit [`flask_phishing_app/.env`](/root/Downloads/Phishing/flask_phishing_app/.env) and set at minimum:

- `FLASK_SECRET_KEY`
- `APP_PASSWORD_HASH` or `APP_PASSWORD`
- `METRICS_TOKEN`

Then start everything:

```bash
docker compose up --build
```

What starts:

- `web` at `http://localhost:5000`
- `worker` for background enrichment
- `db` for PostgreSQL
- `redis` for caching and rate limiting

Useful commands:

```bash
docker compose up --build
docker compose down
docker compose down -v
docker compose logs -f web
docker compose logs -f worker
```

## Hosted deployment on Render

### Architecture

Deploy these four services:

1. `phishscope-db`
   Type: Postgres

2. `phishscope-redis`
   Type: Key Value

3. `phishscope-web`
   Type: Web Service

4. `phishscope-worker`
   Type: Background Worker

### Step 1: Create Postgres

In Render:

1. Create a new `Postgres` database.
2. Put it in the same region you plan to use for the app.
3. After creation, copy the `internal database URL`.
4. You will use that value as `DATABASE_URL`.

### Step 2: Create Redis-compatible Key Value

In Render:

1. Create a new `Key Value` service.
2. Put it in the same region as the app and database.
3. Set its memory policy based on use:
   - caching only: `allkeys-lru`
   - job queues: `noeviction`
4. Copy the `internal URL`.
5. Use that value as `REDIS_URL`.

Because this app uses Redis for cache and rate-limit coordination, internal URL is the right choice when all services are on Render in the same region.

### Step 3: Create the web service

Create a new `Web Service` on Render and connect your GitHub repo.

Use these settings:

- Language: `Docker`
- Dockerfile Path: `flask_phishing_app/Dockerfile`
- Docker Context: repo root
- Branch: your main branch
- Auto-Deploy: enabled

Environment variables for the web service:

```text
APP_ENV=production
APP_ROLE=web
FLASK_DEBUG=0
FLASK_SECRET_KEY=your-secret
APP_REQUIRE_AUTH=1
APP_USERNAME=admin
APP_PASSWORD_HASH=your-generated-hash
DATABASE_URL=your-render-postgres-internal-url
REDIS_URL=your-render-key-value-internal-url
METRICS_TOKEN=your-random-token
ENABLE_BACKGROUND_WORKER=1
RATE_LIMIT_ANALYZE_PER_WINDOW=30
RATE_LIMIT_BATCH_PER_WINDOW=5
RATE_LIMIT_LOGIN_PER_WINDOW=10
RATE_LIMIT_NOTES_PER_WINDOW=30
RATE_LIMIT_WINDOW_SECONDS=60
BATCH_MAX_URLS=50
REQUEST_TIMEOUT_SECONDS=5
EXTERNAL_TIMEOUT_SECONDS=4
OLLAMA_TIMEOUT_SECONDS=18
SCREENSHOT_TIMEOUT_MS=15000
```

Optional variables:

```text
GOOGLE_CLIENT_ID=...
VT_API_KEY=...
OLLAMA_URL=http://host.docker.internal:11434/api/generate
OLLAMA_MODEL=deepseek-r1:1.5b
```

Notes:

- The Dockerfile already starts Gunicorn for the web service.
- The image already copies model artifacts into `/models`.
- If Ollama is not reachable from Render, leave it disabled or point `OLLAMA_URL` to another reachable host.

### Step 4: Create the background worker

Create a new `Background Worker` on Render using the same repo.

Use these settings:

- Language: `Docker`
- Dockerfile Path: `flask_phishing_app/Dockerfile`
- Docker Context: repo root
- Docker Command: `python run_worker.py`

Use the same environment variables as the web service, except:

```text
APP_ROLE=worker
```

The worker consumes durable enrichment jobs from the database-backed queue.

### Step 5: Verify deployment

After both services are live:

1. Open the web URL from Render.
2. Sign in.
3. Run a sample analysis.
4. Confirm that:
   - the first response returns quickly
   - enrichment later completes
   - history is stored
   - notes save correctly
   - `/api/health` returns healthy

For metrics:

```bash
curl -H "X-Metrics-Token: YOUR_TOKEN" https://your-app.onrender.com/api/metrics
```

## What to mention on your resume

Good resume phrasing:

- `Deployed a phishing URL detection platform with Flask, Gunicorn, Docker, PostgreSQL, Redis, and background workers.`
- `Built a two-stage analysis pipeline with fast synchronous scoring and asynchronous enrichment jobs.`
- `Production-hardened the service with rate limiting, secure sessions, health checks, metrics, structured logging, and containerized deployment.`
- `Designed a deployable multi-service architecture with web, worker, database, and cache layers.`

## Optional improvements before making it public

- add a custom domain
- add HTTPS-only cookie enforcement if not already set in production
- configure Render access controls for metrics
- disable Google login if not configured
- add branding screenshots to the repo README
- add a short demo video or GIF

## Official references used

- Render Docker: https://render.com/docs/docker
- Render deploy behavior: https://render.com/docs/deploys
- Render Blueprint spec: https://render.com/docs/blueprint-spec
- Render Postgres connection docs: https://render.com/docs/databases
- Render Key Value docs: https://render.com/redis
- Render background worker example: https://render.com/docs/deploy-sidekiq-worker
