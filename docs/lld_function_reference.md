# PhishScope — Complete Low-Level Design & Function Reference

> **Keywords**: Phishing Detection · URL Analysis · Machine Learning · Flask API · 3-Tier Consensus Architecture · Random Forest · Stacking Classifier · SHAP Explainability · Playwright Screenshot · Ollama LLM · Redis Cache · SQLite · PostgreSQL · DNS Intelligence · SSL/TLS Audit · NLP Text Analysis · Security Headers · JavaScript Obfuscation · Background Worker · Prometheus Metrics · Rate Limiting · JWT-less Session Auth · Google OAuth · VirusTotal · URLhaus Threat Intelligence

---

## Part 1 — Project Overview & Architecture

### What PhishScope Is

PhishScope is an **enterprise-grade, multi-model phishing URL detection and threat intelligence platform**. It accepts a raw URL or defanged text blob from an analyst, subjects it to a three-tier layered machine learning consensus pipeline combined with live network intelligence checks, client-side security audits, NLP content analysis, and AI-assisted review via a local Ollama language model, and returns a scored, explainable verdict alongside Matplotlib charts, a SHAP feature breakdown, a Playwright screenshot, and a downloadable PDF report.

**Primary Use Case**: Security Operations Center (SOC) analysts who need to triage suspicious URLs without clicking them, backed by machine learning decisions they can audit and override.

---

### Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **Web Framework** | Flask 3.x (Python) | HTTP server, session management, routing |
| **ML — Tier 1** | scikit-learn `RandomForestClassifier` | Fast lexical URL scoring (no network I/O) |
| **ML — Tier 2** | scikit-learn `StackingClassifier` | Hybrid URL + HTML stacked ensemble |
| **ML — Tier 3** | Dynamic Python module `network_intelligence.py` | DNS, SSL, WHOIS network scoring |
| **Explainability** | SHAP (mean-reference local contribution) | Per-feature impact scores |
| **AI Review** | Ollama (`deepseek:1.5b`) | LLM-assisted threat summary |
| **Visualization** | Matplotlib (Agg backend) | Risk gauge, component bars, SHAP chart |
| **Screenshot** | Playwright Chromium (headless) | Visual page capture |
| **Report** | ReportLab | PDF threat report generation |
| **Database** | SQLite (dev) / PostgreSQL (prod) | Persistent storage |
| **Cache** | Redis | Result caching (TTL: 1800s) |
| **Rate Limiting** | In-memory token bucket / Redis INCR | Per-actor per-endpoint request caps |
| **Auth** | Flask session + Werkzeug bcrypt + Google OAuth2 | Multi-provider authentication |
| **Observability** | Prometheus-format text metrics | Counter/gauge/histogram export |
| **Threat Intel** | URLhaus (abuse.ch) + VirusTotal API v3 | Known-malicious database cross-reference |

---

### 3-Tier Consensus Pipeline

The core scoring system uses **three independent, non-overlapping model tiers** combined through a dynamic weighted consensus formula. Tiers operate on different feature sets to prevent feature leakage.

```
┌──────────────────────────────────────────────────────────┐
│                       RAW URL INPUT                      │
└────────────────────────────┬─────────────────────────────┘
                             │
             ┌───────────────▼────────────────┐
             │    TIER 1 — Lexical Classifier  │   ← ALWAYS RUNS (no I/O)
             │    RandomForestClassifier       │
             │    12 URL-string features only  │
             │    Accuracy: 89.89%  F1: 90.57% │
             └───────────────┬────────────────┘
                             │  tier1_score (0–100)
     ┌───────────────────────┼────────────────────────┐
     │  (parallel threads)   │                        │
┌────▼───────┐         ┌─────▼──────┐           ┌────▼────┐
│  _crawl()  │         │_analyze_   │           │_analyze_│
│  HTML Fetch│         │ssl()       │           │dns()    │
│  & Parse   │         │TLS Audit   │           │A/MX/SPF │
└────┬───────┘         └─────┬──────┘           └────┬────┘
     │  html_ok?             │                        │
┌────▼───────┐               └──────────┬─────────────┘
│  TIER 2    │  (conditional on html_ok)│
│  Stacking  │                    ┌─────▼────────────────┐
│  Ensemble  │                    │ TIER 3 Network Score │
│  Accuracy: │                    │ 0.40·SSL + 0.30·DNS  │
│   94.4%    │                    │ + 0.30·Reputation    │
└────┬───────┘                    └─────┬────────────────┘
     │ tier2_score                      │ network_score
     └──────────────┬───────────────────┘
                    │
         ┌──────────▼──────────┐
         │  SecurityService    │  ← Headers + iframe + JS obfuscation
         │  .analyze()         │
         └──────────┬──────────┘
                    │ security_score
         ┌──────────▼──────────────────────────────┐
         │         CONSENSUS WEIGHTING              │
         │                                          │
         │  WITH HTML:                              │
         │  final = 0.55·T1 + 0.25·T2              │
         │        + 0.10·T3 + 0.10·Sec             │
         │                                          │
         │  WITHOUT HTML:                           │
         │  final = 0.75·T1 + 0.15·T3 + 0.10·Sec  │
         └──────────────────────────────────────────┘
```

**Verdict Thresholds**:

| Score Range | Verdict |
|---|---|
| 0 – 39 | `Low Risk` |
| 40 – 64 | `Medium Risk` |
| 65 – 100 | `High Risk` |
| (override) | `Known Malicious` — threat feed confirmed |

---

### Project File Map

```
Phishing/
├── Model/
│   ├── 1/  tier1_url_model.pkl · preprocessor.pkl
│   ├── 2/  final_ensemble.pkl · preprocessor.pkl · selected_features.txt
│   └── 3/  network_intelligence.py
├── flask_phishing_app/
│   ├── app.py               ← Flask factory + all routes (580 lines)
│   ├── config.py            ← AppConfig dataclass (117 lines)
│   ├── enrichment_queue.py  ← EnrichmentQueue worker (81 lines)
│   ├── metrics.py           ← MetricsRegistry Prometheus (44 lines)
│   ├── rate_limit.py        ← RateLimiter token-bucket (64 lines)
│   ├── run_worker.py        ← standalone worker entrypoint
│   ├── services/
│   │   ├── analysis.py      ← PhishingAnalyzer engine (1756 lines)
│   │   ├── security_service.py ← SecurityService (122 lines)
│   │   └── storage.py       ← HistoryStore DB layer (626 lines)
│   ├── static/              ← JS, CSS, screenshots, charts
│   └── templates/           ← Jinja2 HTML templates
├── docker-compose.yml
├── setup_and_run.bat
└── run_docker.bat
```

---

## Part 2 — Module: `config.py`

> **Keywords**: Environment Variables · Dataclass · Configuration Management · Production Validation · Secret Key · Session Lifetime · Rate Limit Tuning · Worker Configuration · Timeout Budgets

### `AppConfig` (dataclass, slots=True)

A frozen configuration snapshot created once at application startup. All 63 environment variables are read here and nowhere else, preventing scattered `os.getenv()` calls across the codebase.

---

#### `_env_bool(name: str, default: bool) → bool`

**Tags**: `env-var`, `boolean-parsing`, `config-helper`

Reads environment variable `name`. Interprets the strings `"1"`, `"true"`, `"yes"`, `"on"` (case-insensitive) as `True`. Returns `default` if the variable is unset. Used for all feature-flag-style settings like `APP_REQUIRE_AUTH`, `FLASK_DEBUG`, `ENABLE_BACKGROUND_WORKER`.

---

#### `_env_int(name: str, default: int) → int`

**Tags**: `env-var`, `integer-parsing`, `config-helper`

Reads environment variable `name` and converts to `int`. Returns `default` on missing or unparseable value. Used for numeric settings like `APP_PORT`, `RATE_LIMIT_ANALYZE_PER_WINDOW`, `SCREENSHOT_TIMEOUT_MS`.

---

#### `AppConfig.from_env(base_dir: Path, app_root: Path) → AppConfig`

**Tags**: `factory-method`, `environment-configuration`, `startup`

**Called by**: `create_app()` in `app.py` once per process start.

**What it configures**:

| Field | Env Var | Default | Purpose |
|---|---|---|---|
| `app_role` | `APP_ROLE` | `"web"` | Controls worker thread start |
| `model_dir` | `PHISHING_MODEL_DIR` | `app_root` | Path to `Model/` directory |
| `database_url` | `DATABASE_URL` | SQLite in `data/` | Connection string |
| `require_auth` | `APP_REQUIRE_AUTH` | `True` | Enforce session auth |
| `rate_limit_analyze` | `RATE_LIMIT_ANALYZE_PER_WINDOW` | 30 | Max analyze calls per minute |
| `rate_limit_batch` | `RATE_LIMIT_BATCH_PER_WINDOW` | 5 | Max batch calls per minute |
| `ollama_timeout_seconds` | `OLLAMA_TIMEOUT_SECONDS` | 30 | Max wait for LLM response |
| `screenshot_timeout_ms` | `SCREENSHOT_TIMEOUT_MS` | 15000 | Max Playwright page load |
| `worker_stale_after_seconds` | `WORKER_STALE_AFTER_SECONDS` | 300 | Reclaim crashed worker jobs |

#### `AppConfig.validate() → None`

**Tags**: `startup-validation`, `fail-fast`

Raises `RuntimeError` immediately if:
- `app_role` is not `"web"` or `"worker"` (invalid deployment mode)
- `env == "production"` and `secret_key` is empty (session security requirement)

---

## Part 3 — Module: `services/security_service.py`

> **Keywords**: Client-Side Security Audit · HTTP Security Headers · Content-Security-Policy · HSTS · X-Frame-Options · JavaScript Obfuscation Detection · eval() · unescape() · String.fromCharCode · Base64 Inline · Hex Encoding · Iframe Detection · Redirect Hop Analysis · Security Risk Scoring

### `SecurityService`

A stateless, dependency-free audit class. Operates entirely on the HTTP response already fetched by `PhishingAnalyzer._crawl()`. Produces a dedicated `security_score` (0–100, higher = more risk) that feeds into the final consensus formula as a separate fourth signal, independent of all three ML tiers.

**Design Philosophy**: The `SecurityService` score is intentionally kept outside the ML training loop. It audits client-side security hygiene — not phishing probability directly — giving analysts a separate compliance-oriented risk dimension.

---

#### `SecurityService.__init__(self) → None`

**Tags**: `stateless`, `no-op`

No state is initialized. The class is instantiated once in `PhishingAnalyzer._load_artifacts()` and reused across all analyses.

---

#### `SecurityService.check_obfuscation(self, html_content: str) → tuple[bool, list[str]]`

**Tags**: `static-analysis`, `javascript-obfuscation`, `regex-scanning`, `eval-detection`, `hex-encoding`, `base64-detection`, `script-block-analysis`

**Purpose**: Scans every `<script>...</script>` block extracted from the raw HTML for known JavaScript obfuscation techniques used by phishing kits to evade static analysis.

**Arguments**:
- `html_content` (str) — Raw HTML page content as a full string.

**Returns**: `(is_obfuscated: bool, findings: list[str])`
- `is_obfuscated`: `True` if any obfuscation pattern was found across any script block.
- `findings`: Human-readable list of specific detection strings (e.g. `"Script block 2: dynamic execution 'eval()' detected."`).

**Detection Patterns (per script block)**:

| Pattern | Technique Detected | Threshold |
|---|---|---|
| `eval(` or `eval (` | Dynamic code execution — used to run decoded payloads at runtime | Any occurrence |
| `unescape(` or `unescape (` | String decoding — classic obfuscation deobfuscation step | Any occurrence |
| `String.fromCharCode` | Character-code-based string construction — avoids string literals | Any occurrence |
| `\xNN` hex escapes | Hexadecimal character encoding — hides readable strings | > 15 matches |
| Long base64 strings `"[A-Za-z0-9+/]{80,}"` | Inline encoded payloads — hides scripts inside data URIs | > 3 matches |

**Internal Flow**:
1. Short-circuit if `html_content` is empty — returns `(False, [])`.
2. Compile regex `<script\b[^>]*>(.*?)</script>` with `re.DOTALL | re.IGNORECASE`.
3. For each extracted script block, run all 5 detection checks above.
4. Each hit appends a finding string with the block index prefix.
5. Return accumulated results.

**Risk Contribution**: If `is_obfuscated = True` → `+20 risk points` added in `SecurityService.analyze()`.

---

#### `SecurityService.analyze(self, headers: dict, html_content: str, redirect_count: int = 0) → dict`

**Tags**: `security-audit`, `header-analysis`, `csp-check`, `hsts-check`, `x-frame-options`, `iframe-detection`, `redirect-hops`, `risk-scoring`, `beautifulsoup`

**Purpose**: Computes a consolidated security risk score from six independent audit dimensions. This is the main entry point for the SecurityService.

**Arguments**:
- `headers` (dict) — Raw `requests.Response.headers` dict from the crawl.
- `html_content` (str) — Raw page HTML for iframe and JS scanning.
- `redirect_count` (int) — Count of HTTP redirects followed (from `response.history`).

**Returns**:
```python
{
    "security_score": float,           # 0–100 total risk (higher = riskier)
    "csp_present": bool,               # Content-Security-Policy header present
    "hsts_present": bool,              # Strict-Transport-Security header present
    "x_frame_options_present": bool,   # X-Frame-Options header present
    "has_iframe": bool,                # <iframe> or <frame> tag found in body
    "js_obfuscated": bool,             # Obfuscation patterns detected
    "redirect_count": int,             # Total HTTP redirect hops
    "security_findings": list[str]     # Human-readable finding strings
}
```

**Scoring Table**:

| Condition | Points Added | Reasoning |
|---|---|---|
| Missing `Content-Security-Policy` | +20 | No XSS protection policy |
| Missing `Strict-Transport-Security` | +15 | HTTPS not enforced on future visits |
| Missing `X-Frame-Options` | +15 | Clickjacking attack vector open |
| `<iframe>` or `<frame>` in body | +15 | Embedded malicious frame loading |
| `redirect_count > 2` | +15 | Suspicious redirect chain (cloaking) |
| JS Obfuscation detected | +20 | Hidden code execution patterns |

**Maximum possible score**: 100 (all conditions triggered).

**Internal Flow**:
1. Normalize all header keys to lowercase.
2. Check header key existence for CSP, HSTS, XFO.
3. Use `BeautifulSoup(html_content, "html.parser")` to search for `iframe` and `frame` tags.
4. Call `self.check_obfuscation(html_content)` to get `(js_obfuscated, obfuscation_findings)`.
5. Accumulate score and append finding strings per triggered condition.
6. For JS findings, include up to 3 specific sub-findings from `obfuscation_findings`.

---

## Part 4 — Module: `services/analysis.py`

> **Keywords**: PhishingAnalyzer · Machine Learning Inference · Feature Engineering · URL Normalization · HTTP Crawling · TLS Certificate Analysis · DNS Resolution · WHOIS Domain Age · Shannon Entropy · NLP Suspicious Phrases · Brand Impersonation · SHAP Feature Importance · Mean-Reference Contribution · ThreadPoolExecutor · Parallel Execution · Redis Caching · Playwright Headless Browser · Ollama LLM Prompt Engineering · ReportLab PDF · Matplotlib Charts · Risk Gauge · Component Breakdown · Heuristic Fallback · Threat Intelligence · URLhaus · VirusTotal

### `PhishingAnalyzer`

The central intelligence engine of PhishScope. A single long-lived object instantiated in `create_app()` and reused across all requests. Manages model artifact loading, all analysis sub-routines, caching, charting, screenshot capture, and PDF generation.

**Dependency Guard Pattern**: Every optional library (`shap`, `whois`, `playwright`, `reportlab`, `dns`, `redis`) is imported inside a `try/except` block at the module level. If the import fails, the variable is set to `None` and all functions that need it check `if library is None` and return graceful fallbacks. This means the system degrades gracefully without crashing.

---

#### `PhishingAnalyzer.__init__(self, BASE_DIR: Path, model_dir: Path) → None`

**Tags**: `initialization`, `startup`, `model-loading`, `directory-creation`, `redis-connection`, `matplotlib-config`, `tldextract-cache`

**Purpose**: Full initialization of the analyzer. Called once at Flask application startup.

**Initialization Sequence**:
1. **Path Setup**: Stores `base_dir`, resolves `model_dir` (also reads `PHISHING_MODEL_DIR` env var at runtime to allow Docker override).
2. **Service Config**: Reads `OLLAMA_URL`, `OLLAMA_MODEL`, `VT_API_KEY`, `REDIS_URL`, timeout settings from environment.
3. **Directory Creation**: Creates `static/screenshots/`, `runtime/tldextract-cache/`, `runtime/matplotlib/` using `mkdir(parents=True, exist_ok=True)`.
4. **Matplotlib Isolation**: Sets `MPLCONFIGDIR` env var to `runtime/matplotlib/` so matplotlib never writes to `~/.config/matplotlib` (prevents permission errors in Docker).
5. **TLD Extractor**: Calls `_build_tld_extractor()` — creates a `TLDExtract` instance with local cache.
6. **Redis Client**: Calls `_build_redis_client()` — connects to Redis or returns `None`.
7. **HTTP Session**: Creates a `requests.Session()` with `User-Agent: Mozilla/5.0 PhishScope/1.0`.
8. **Dependency Check**: Calls `_detect_missing_dependencies()`.
9. **Model Load**: Calls `_load_artifacts()` — loads all ML models synchronously. **Failure here is fatal** (raises immediately).
10. Sets `self.model_ready = True`.

---

#### `PhishingAnalyzer._patch_tree_model_compat(model: Any) → None` *(static)*

**Tags**: `pickle-compatibility`, `sklearn-version-compat`, `monotonic_cst`, `recursive-traversal`

**Purpose**: Injects missing `monotonic_cst = None` attribute on `DecisionTreeClassifier` and `DecisionTreeRegressor` objects pickled with scikit-learn < 1.4, making them loadable under sklearn ≥ 1.4 without `AttributeError`.

**Internal Logic**:
- Recursively visits model object graph via `estimators_`, `estimator_`, `base_estimator_`, `final_estimator_` attributes.
- Uses a `seen: set[int]` of `id()` values to prevent infinite recursion in self-referential model structures (e.g. stacked ensembles).
- Only modifies objects of class `DecisionTreeClassifier` or `DecisionTreeRegressor` that are missing the attribute.

**Side Effect**: Mutates model objects in-place.

---

#### `PhishingAnalyzer._detect_missing_dependencies(self) → list[str]`

**Tags**: `dependency-check`, `graceful-degradation`, `health-reporting`

Checks if `bs4`, `joblib`, `pandas`, `requests`, `tldextract` are importable. Returns a list of missing package names (empty list = all present). This list is exposed via the `/api/health` endpoint under `missing_dependencies`.

---

#### `PhishingAnalyzer._load_artifacts(self) → ModelArtifacts`

**Tags**: `model-loading`, `pickle-deserialization`, `joblib`, `dynamic-import`, `importlib`, `tier1`, `tier2`, `tier3`, `security-service-init`, `fail-fast`

**Purpose**: Loads all three ML model tiers from disk and initializes SecurityService. This is the only startup step that is permitted to fail with an unrecoverable error.

**Load Sequence**:

**Tier 1** (`Model/1/`):
- Loads `tier1_url_model.pkl` via `joblib.load()` → `self.tier1_model`.
- Loads `preprocessor.pkl` via `joblib.load()` → `self.tier1_preprocessor`.
- Applies `_patch_tree_model_compat(self.tier1_model)`.
- Raises `FileNotFoundError` if files missing, `RuntimeError` if deserialization fails.

**Tier 2** (`Model/2/`):
- Loads `final_ensemble.pkl` → `self.tier2_model`.
- Loads `preprocessor.pkl` → `self.tier2_preprocessor`.
- Reads `selected_features.txt` (newline-separated) → `self.tier2_selected_features: list[str]`.

**Tier 3** (`Model/3/`):
- Uses `importlib.util.spec_from_file_location("network_intelligence", path)` + `spec.loader.exec_module()` to dynamically import `network_intelligence.py`.
- Instantiates `NetworkIntelligenceAnalyzer()` → `self.network_analyzer`.
- **Hot-swap design**: The Tier 3 module is a detached plugin — it can be replaced on disk without modifying `analysis.py`.

**SecurityService**:
- Instantiates `SecurityService()` → `self.security_analyzer`.

**Returns**: `ModelArtifacts(model=tier2_model, preprocessor=tier2_preprocessor, selected_features=tier2_selected_features, errors=[])` for backward compatibility.

---

#### `PhishingAnalyzer._build_tld_extractor(self)`

**Tags**: `tldextract`, `tld-cache`, `domain-parsing`, `idempotent`

Creates `tldextract.TLDExtract(cache_dir=str(self.tld_cache_dir))`. The local cache prevents repeated HTTP requests to Mozilla's Public Suffix List. Returns `None` if `tldextract` is not installed.

---

#### `PhishingAnalyzer._build_redis_client(self)`

**Tags**: `redis`, `cache-backend`, `connection-test`, `optional-service`

Attempts `redis.Redis.from_url(self.redis_url)` then `client.ping()`. Returns the connected client on success. Returns `None` silently on any failure — Redis is optional and the system operates without it.

---

#### `PhishingAnalyzer._cache_key(self, normalized_url: str) → str`

**Tags**: `redis`, `cache-key`, `namespacing`

Returns `"phishing-analysis:v1:{normalized_url}"`. The `v1` version prefix allows cache invalidation by bumping the version when the analysis schema changes without flushing all Redis keys.

---

#### `PhishingAnalyzer._get_cached_result(self, normalized_url: str) → dict | None`

**Tags**: `redis`, `cache-hit`, `json-deserialization`, `performance`

Reads the Redis key for the normalized URL. On a hit, deserializes the JSON payload and injects `cache.hit = True` to inform the frontend. Returns `None` on any miss or Redis error (silently degrades).

---

#### `PhishingAnalyzer._set_cached_result(self, normalized_url: str, result: dict) → None`

**Tags**: `redis`, `cache-write`, `setex`, `ttl`

Serializes the result dict to JSON and stores with `SETEX` (TTL = `cache_ttl` seconds, default 1800). Silently swallows all exceptions to ensure analysis always completes even if Redis is unavailable.

---

#### `PhishingAnalyzer._request(self, method, url, timeout, **kwargs)`

**Tags**: `http-client`, `requests-session`, `timeout-enforcement`

Wrapper around `self.http.request()` (the shared `requests.Session`). Applies the default `request_timeout_seconds` if no explicit timeout is given. Falls back to module-level `requests` if session was not built.

---

#### `PhishingAnalyzer._normalize_url(self, raw_url: str) → str`

**Tags**: `url-normalization`, `http-prefix`, `preprocessing`

Strips leading/trailing whitespace. If the string does not start with `"http://"` or `"https://"`, prepends `"http://"`. This guarantees all downstream code receives a well-formed absolute URL for `urlparse()`.

---

#### `PhishingAnalyzer._validate_url(self, url: str) → dict`

**Tags**: `url-validation`, `hostname-check`, `at-symbol-detection`, `hyphen-detection`

Parses the URL with `urlparse`. Returns `{"valid": False, "error": "..."}` if `netloc` is empty (no hostname). Otherwise returns `{"valid": True, "warnings": [...]}` with non-fatal warnings for:
- Hostname > 50 characters (IDN or domain generation algorithm indicator).
- Hostname with > 2 hyphens (dash-stuffing trick).
- `@` symbol anywhere in URL (credential-embedding phishing technique).

---

#### `PhishingAnalyzer._registered_domain(self, host: str) → str`

**Tags**: `tldextract`, `registered-domain`, `public-suffix-list`, `eTLD+1`

Uses `tldextract` to return the eTLD+1 registered domain (e.g. `evil.co.uk` from `login.secure.evil.co.uk`). Falls back to the raw `host` string if tldextract is unavailable or raises an exception.

---

#### `PhishingAnalyzer._extract_tier1_features(self, url: str) → dict[str, float]`

**Tags**: `feature-engineering`, `lexical-url-features`, `tier1`, `random-forest`, `url-tokenization`, `phish-hints`, `digit-ratio`, `hostname-length`, `path-analysis`

**Purpose**: Computes the 12 numerical features used exclusively by the Tier 1 RandomForest. No network I/O — pure string computation.

**Feature Details**:

| Feature Name | Type | Computation | Phishing Signal |
|---|---|---|---|
| `length_url` | float | `len(url)` | Long URLs obscure the domain |
| `length_hostname` | float | `len(parsed.netloc)` | Longer hostnames are suspicious |
| `nb_dots` | float | `url.count('.')` | Many dots = many subdomains |
| `nb_hyphens` | float | `url.count('-')` | Hyphen-stuffing mimics brands |
| `nb_www` | float | `hostname.count('www')` | Multiple `www` is anomalous |
| `ratio_digits_url` | float | digits / total chars | High digit ratio = generated domain |
| `length_words_raw` | float | Count of alphanumeric tokens (excl. TLD) | Many tokens = verbose phishing path |
| `longest_words_raw` | float | Max token length (excl. TLD) | Long tokens hide brand misspellings |
| `longest_word_path` | float | Max word length in path+query | Long path tokens evade domain checks |
| `phish_hints` | float | Count of keywords: secure, login, account, verify, bank, update, signin, password, otp, admin, auth | Direct phishing vocabulary signals |
| `nb_slash` | float | `url.count('/')` | Many slashes = deep fake path |
| `shortest_word_host` | float | Min word length in registered hostname | Very short words = domain abbreviation |

**Internal Logic**: Uses `tldextract` to separate subdomain, domain, suffix so TLD words are excluded from word metrics (prevents `com`, `uk`, `org` from inflating word statistics).

---

#### `PhishingAnalyzer._run_tier1_model(self, features: dict[str, float]) → dict`

**Tags**: `tier1-inference`, `random-forest`, `sklearn`, `predict-proba`, `standardscaler`

**Purpose**: Runs the Tier 1 RandomForest inference pipeline against the 12 lexical features.

**Internal Flow**:
1. Constructs `pd.DataFrame([features], columns=FEATURE_LIST)` with fixed column order.
2. Calls `tier1_preprocessor.transform(input_df)` — applies the fitted `StandardScaler`.
3. Calls `tier1_model.predict(scaled)[0]` → integer label (0 = legitimate, 1 = phishing).
4. Calls `tier1_model.predict_proba(scaled)[0][1]` → probability of phishing class.
5. Returns `{"probability": float, "prediction": "phishing"|"legitimate"}`.

**Failure**: On any exception (e.g. shape mismatch, sklearn version incompatibility), returns `{"probability": 0.5, "prediction": "unknown"}` — a safe neutral prediction that won't bias the consensus score.

---

#### `PhishingAnalyzer._crawl(self, url: str, base_domain: str) → dict`

**Tags**: `http-crawl`, `html-fetch`, `beautifulsoup`, `anchor-parsing`, `external-link-ratio`, `null-link-ratio`, `login-form-detection`, `iframe-detection`, `suspicious-form-handler`, `redirect-tracking`, `content-type-check`

**Purpose**: Fetches the target URL and extracts all structural HTML signals needed by Tier 2 and NLP analysis.

**Arguments**:
- `url` — Normalized URL to fetch.
- `base_domain` — Registered domain, used to classify links as internal or external.

**Returns**:
```python
{
    "html_ok": bool,               # True if HTML was successfully fetched and parsed
    "html": str,                   # Full raw HTML content
    "title": str,                  # <title> tag text
    "status_code": int,            # HTTP response status code
    "response_headers": dict,      # Full response headers dict
    "hyperlinks": int,             # Total <a href> anchor count
    "ratio_external_links": float, # External anchors / total anchors
    "ratio_null_links": float,     # Null/void anchors / total anchors
    "login_form": bool,            # <input type="password"> found
    "iframe": bool,                # <iframe> or <frame> found
    "suspicious_form_handler": bool, # Form with blank/void action
    "redirect_count": int,         # len(response.history)
    "error": str | None            # Exception message if failed
}
```

**Anchor Classification**:
- **Null links**: `href=""`, `href="#"`, `href="javascript:void(0)"`, `href="javascript:;"` → common in credential-harvesting pages that disable navigation.
- **External links**: Resolved absolute URL has a different registered domain than `base_domain` → measures how much content loads from third parties.

**Suspicious Form Handler**: A `<form>` whose `action` is empty, `"#"`, or `"about:blank"` — common in phishing pages that submit credentials via JavaScript to avoid detection.

**Failure Mode**: Returns `html_ok = False` on non-HTML content-type, network timeout, connection error, or DNS failure. All downstream tiers handle `html_ok = False` gracefully.

---

#### `PhishingAnalyzer._analyze_ssl(self, hostname: str) → dict`

**Tags**: `ssl`, `tls`, `certificate`, `x509`, `subject-alt-name`, `expiry-check`, `cn-match`, `cert-age`

**Purpose**: Establishes a raw TLS connection to port 443 and extracts certificate metadata without using `requests`.

**Internal Flow**:
1. `ssl.create_default_context()` → standard CA verification.
2. `socket.create_connection((hostname, 443), timeout=...)` → TCP connection.
3. `ctx.wrap_socket(sock, server_hostname=hostname)` → TLS handshake.
4. `ssock.getpeercert()` → X.509 certificate dict.
5. Parses `notBefore` / `notAfter` strings with `datetime.strptime("%b %d %H:%M:%S %Y %Z")`.
6. Checks hostname match against `subjectAltName` DNS entries and `commonName`.

**Returns**:
```python
{
    "has_ssl": bool,
    "issuer": str,            # Organization name or Common Name
    "days_until_expiry": int,
    "is_expired": bool,
    "certificate_age_days": int, # Days since cert was issued
    "cn_matches": bool,       # Hostname matches cert
    "error": str | None
}
```

**Risk scored by** `_compute_ssl_risk()`:

| Condition | Risk Added |
|---|---|
| No SSL at all | 85.0 (base penalty) |
| Certificate expired | +40 |
| CN/SAN mismatch | +25 |
| Expiry < 7 days | +20 |
| Certificate age < 30 days | +15 |

---

#### `PhishingAnalyzer._analyze_dns(self, domain: str) → dict`

**Tags**: `dnspython`, `dns-resolution`, `a-record`, `mx-record`, `spf`, `dmarc`, `email-authentication`, `dns-health`

**Purpose**: Performs four DNS lookups to evaluate domain legitimacy and email security posture. Uses `dnspython` with a 4-second per-query lifetime.

**Lookups**:
1. `A` record → `has_a_record`, `ips: list[str]` — Does domain resolve to an IP?
2. `MX` record → `has_mx_record` — Does domain have legitimate mail servers?
3. `TXT` record → scans for `"v=spf1"` → `has_spf` — Email sender authentication.
4. `TXT` on `"_dmarc.{domain}"` → scans for `"v=dmarc1"` → `has_dmarc` — Email domain policy.

**Risk scored by** `_compute_dns_risk()`:

| Condition | Risk Added |
|---|---|
| No A record | +50 |
| No SPF record | +20 |
| No DMARC record | +20 |
| No MX record | +10 |

**Failure Handling**: Each lookup is in a separate `try/except`. Individual DNS failures don't abort the others.

---

#### `PhishingAnalyzer._analyze_reputation(self, domain: str) → dict`

**Tags**: `whois`, `domain-age`, `tld-reputation`, `hyphen-domain`, `long-domain`, `risk-factors`

**Purpose**: Domain age and structural reputation scoring using WHOIS data.

**Internal Logic**:
1. `whois.whois(domain)` → gets `creation_date` (may be a list; takes first item).
2. Computes `age_days = (now - creation_date).days`.
3. Builds `risk_factors` list based on:

| Factor | Risk Added |
|---|---|
| Domain age < 30 days | +40 |
| Domain age 30–180 days | +20 |
| Domain length > 30 chars | +10 |
| 3+ hyphens in domain | +10 |
| TLD in `.xyz`, `.top`, `.click`, `.work`, `.pw` | +30 |

**Returns**: `{"risk_score": int (0–100), "risk_factors": list[str], "domain_age_days": int|None}`

---

#### `PhishingAnalyzer._analyze_url_structure(self, url: str, hostname: str) → dict`

**Tags**: `url-structure-signals`, `ip-address-detection`, `url-shortener`, `at-symbol`, `double-slash`, `shannon-entropy`, `subdomain-depth`, `path-depth`

**Purpose**: Rule-based heuristic signal extraction from the URL structure. These signals feed `_compute_url_risk()`.

**Signals**:

| Signal | Value | How Computed |
|---|---|---|
| `uses_https` | bool | `parsed.scheme == "https"` |
| `uses_ip_address` | bool | `ipaddress.ip_address(hostname)` succeeds |
| `url_length` | int | `len(url)` |
| `subdomain_count` | int | Count of labels in `ext.subdomain.split(".")` |
| `path_depth` | int | Non-empty segments in `parsed.path.split("/")` |
| `has_at_symbol` | bool | `"@" in url` |
| `has_double_slash` | bool | `url.count("//") > 1` |
| `shortening_service` | bool | hostname in known shortener set (`bit.ly`, `tinyurl.com`, etc.) |
| `has_prefix_suffix` | bool | `"-" in ext.domain` |
| `domain_entropy` | float | Shannon entropy `H = -Σ p·log₂(p)` over character distribution |

**Risk scored by** `_compute_url_risk()`:

| Condition | Risk Added |
|---|---|
| No HTTPS | +20 |
| Raw IP address | +30 |
| @ symbol | +20 |
| URL shortener | +20 |
| Double slash | +15 |
| ≥ 3 subdomains | +15 |
| URL length > 100 | +10 |
| Domain entropy > 3.5 | +10 |
| Has prefix/suffix dash | +10 |

---

#### `PhishingAnalyzer._analyze_text(self, url: str, html_content: str, title: str) → dict`

**Tags**: `nlp`, `text-analysis`, `suspicious-phrases`, `brand-impersonation`, `credential-harvesting-language`, `beautifulsoup`, `visible-text-extraction`, `urgency-detection`

**Purpose**: NLP scan of visible page text for phishing language patterns and brand impersonation.

**SUSPICIOUS_PHRASES** (hardcoded list):
`"verify your account"`, `"confirm your identity"`, `"account suspended"`, `"immediate action required"`, `"click here to confirm"`, `"your account is at risk"`, `"unusual activity detected"`, `"enter your credentials"`, `"verify now"`, `"update your payment"`, `"password"`, `"otp"`

**KNOWN_BRANDS** detection:
`google → google.com`, `microsoft → microsoft.com`, `paypal → paypal.com`, `apple → apple.com`, `amazon → amazon.com`, `netflix → netflix.com`, `github → github.com`, `facebook → facebook.com`, `instagram → instagram.com`

**Internal Flow**:
1. Parse HTML with BeautifulSoup, decompose `<script>`, `<style>`, `<noscript>`.
2. Extract visible text with `soup.get_text(" ", strip=True)`, collapse whitespace.
3. Merge with `title` and lowercase.
4. Scan for all `SUSPICIOUS_PHRASES` → `suspicious: list[str]`.
5. Scan for `KNOWN_BRANDS` — if brand keyword appears and actual registered domain ≠ brand domain → `brand_impersonation = {brand, expected_domain}`.

**Risk Score**: `min(len(suspicious) × 12 + (35 if impersonation else 0), 100)`.

---

#### `PhishingAnalyzer._analyze_security_headers(self, headers: dict) → dict`

**Tags**: `http-security-headers`, `hsts`, `csp`, `x-frame-options`, `coop`, `coep`, `corp`, `referrer-policy`, `permissions-policy`, `cookie-flags`, `server-header-leakage`, `header-audit`

**Purpose**: Detailed 11-header security audit of the HTTP response. Separate from `SecurityService.analyze()` — this function produces a richer structured breakdown used by the UI, while `SecurityService.analyze()` produces the condensed score for the consensus formula.

**Headers Audited**:
HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP, Origin-Agent-Cluster, X-Permitted-Cross-Domain-Policies.

**Additional Checks**:
- `Server:` header exposed → version/stack fingerprinting leak.
- `Set-Cookie:` flags: `HttpOnly` (script access), `Secure` (HTTPS only), `SameSite` (CSRF protection).

**Risk Score**: `min(len(missing) × 12 + (8 if server exposed), 100)`.

---

#### `PhishingAnalyzer._extract_model_features(self, url, crawl, reputation) → dict[str, float]`

**Tags**: `feature-engineering`, `tier2-features`, `stacking-classifier`, `status-encoded-neutralization`, `page-rank-heuristic`, `web-traffic-proxy`

**Purpose**: Builds the multi-dimensional feature vector for the Tier 2 StackingClassifier. Combines lexical URL features with crawled HTML signals and reputation data.

**Features**:

| Feature | Source | Description |
|---|---|---|
| `nb_www` | URL | Count of `"www"` in netloc |
| `longest_word_path` | URL path | Max token length |
| `phish_hints` | URL | Count of phishing keyword matches |
| `nb_hyperlinks` | Crawl | Total `<a>` anchor count |
| `ratio_extHyperlinks` | Crawl | External link fraction |
| `domain_age` | WHOIS | Domain age in days |
| `web_traffic` | Proxy | `min(hyperlinks × 800, 500000)` — traffic proxy |
| `google_index` | Heuristic | 1.0 if HTTPS + >5 hyperlinks |
| `page_rank` | Heuristic | 0–10 score from HTTPS, links, domain age |
| `status_encoded` | **FIXED AT 0.5** | Neutralized transport status |

> **`status_encoded` Neutralization**: Earlier Tier 2 training incorrectly used HTTP response status code as a training feature. This created feature leakage — phishing sites can return `200 OK` and legitimate sites can return `403 Forbidden`. The value is fixed at `0.5` (neutral) so the model cannot be gamed via HTTP status manipulation.

---

#### `PhishingAnalyzer._status_to_encoded(self, status_code: int | None, html_ok: bool) → float`

**Tags**: `status-encoding`, `legacy-compat`, `neutralized`

Maps HTTP status codes to a float encoding used historically by the Tier 2 model. Present for backward compatibility but its output is overridden by the `status_encoded = 0.5` neutralization in `_extract_model_features()`.

---

#### `PhishingAnalyzer._run_model(self, features: dict[str, float]) → dict`

**Tags**: `tier2-inference`, `stacking-classifier`, `sklearn`, `predict-proba`, `feature-alignment`, `graceful-fallback`

**Purpose**: Runs Tier 2 StackingClassifier inference.

**Internal Flow**:
1. Builds `ml_input` dict aligned to `self.artifacts.selected_features` column order.
2. Creates `pd.DataFrame([ml_input], columns=ml_columns)`.
3. `self.artifacts.preprocessor.transform(frame)` → scaled array.
4. If model has `feature_names_in_` (sklearn ≥ 1.1), wraps transformed array back into named DataFrame to prevent column mismatch errors.
5. `model.predict(transformed)[0]` → label; `model.predict_proba(transformed)[0][1]` → probability.
6. Returns `{"available": True, "probability": float, "prediction": str, "features": dict}`.

**Failure**: Returns `{"available": False, "probability": 0.5, ...}` on model not ready, pandas unavailable, or any inference exception.

---

#### `PhishingAnalyzer._compute_shap(self, features: dict[str, float]) → dict`

**Tags**: `shap`, `explainability`, `feature-importance`, `mean-reference-contribution`, `local-explanation`, `model-transparency`

**Purpose**: Computes per-feature impact scores for the Tier 2 prediction using a custom mean-reference contribution method (avoids requiring the `shap` package for tree models with stacking estimators).

**Method — Mean-Reference Local Contribution**:
For each feature `f`:
1. Get `current_probability` = `model.predict_proba(actual_input)[0][1]`.
2. Create `reference_frame` = copy of input with feature `f` replaced by its training mean (`preprocessor.mean_[f]`).
3. Get `reference_probability` = `model.predict_proba(reference_frame)[0][1]`.
4. `impact[f] = current_probability - reference_probability`.
- Positive impact → feature increases phishing probability.
- Negative impact → feature decreases phishing probability.

**Returns**: Top 8 features sorted by `abs(impact)`:
```python
{
    "available": True,
    "estimator": "stacking-ensemble",
    "method": "mean-reference local contribution",
    "top_features": [
        {"feature": str, "impact": float, "abs_impact": float, "value": float, "reference_value": float},
        ...
    ]
}
```

---

#### `PhishingAnalyzer._analyze_with_ollama(self, url, html_content, headers, nlp, ml_result) → dict`

**Tags**: `llm`, `ollama`, `deepseek`, `prompt-engineering`, `json-structured-output`, `ai-review`, `threat-summary`, `connection-timeout-handling`

**Purpose**: Sends a structured multi-part prompt to the local Ollama LLM for AI-assisted threat analysis.

**Prompt Composition**:
- System instruction: Return strict JSON with 9 specific keys.
- URL being analyzed.
- Tier 2 ML prediction + probability + availability flag.
- Security header issues list from `headers.get("issues", [])`.
- NLP suspicious phrases list.
- First 3500 characters of HTML (whitespace-collapsed with `re.sub(r"\s+", " ", html)`).

**Ollama API Call**:
- `POST {OLLAMA_URL}` with `{"model": "deepseek:1.5b", "prompt": ..., "stream": False, "format": "json", "options": {"temperature": 0.1}}`.
- `temperature: 0.1` → near-deterministic output for structured JSON.
- `format: "json"` → forces Ollama to output valid JSON.

**Execution Gate** (`_should_run_ollama()`): Ollama is only invoked if:
- `html_ok = True` (page was fetched), AND
- At least one of: `ml_probability ≥ 0.55`, `header_risk_score ≥ 40`, `nlp_risk_score ≥ 20`.
This prevents wasting LLM tokens on clearly benign or unfetchable pages.

**Error Handling**:
- Connection refused → `"Ollama is not reachable on the configured local endpoint."`
- Read timeout → `"Ollama review timed out. The local model is busy or offline."`
- Other → Falls back to `_build_ollama_fallback()`.

---

#### `PhishingAnalyzer._build_ollama_fallback(self, url, headers, nlp, ml_result) → dict`

**Tags**: `heuristic-fallback`, `no-llm`, `rule-based-summary`, `graceful-degradation`

**Purpose**: Constructs a rule-based analyst summary when Ollama is unavailable, the page has no HTML, or Ollama invocation was gated off. Returns the same JSON shape as the live Ollama response so the frontend renders identically.

**Heuristic Logic**:
1. If ML available → states prediction label and confidence percentage.
2. If suspicious phrases found → lists top 4 phrases.
3. If brand impersonation detected → names the brand and flags domain mismatch.
4. If security header issues present → recommends manual investigation.
5. Always returns a non-empty `findings`, `recommendations`, `verdict_reasoning` list.

---

#### `PhishingAnalyzer._check_threat_intelligence(self, url: str, domain: str) → dict`

**Tags**: `threat-intelligence`, `urlhaus`, `abuse.ch`, `virustotal`, `api-v3`, `known-malicious`, `ioc-lookup`

**Purpose**: Cross-references the URL and domain against external threat intelligence feeds.

**Feed 1 — URLhaus (abuse.ch)**:
- `POST https://urlhaus-api.abuse.ch/v1/host/` with `host=<domain>`.
- Flagged if `query_status == "ok"` and `urls > 0`.
- Timeout: `external_timeout_seconds` (default 4s).

**Feed 2 — VirusTotal** (if `VT_API_KEY` set):
- `GET https://www.virustotal.com/api/v3/urls/{base64url}`.
- Flagged if `last_analysis_stats.malicious > 0` or `suspicious > 0`.

**Override Effect**: If either feed returns `known_malicious = True`, `analyze_url()` overrides `final_score = max(final_score, 95.0)` and sets `verdict = "Known Malicious"` regardless of ML scores.

---

#### `PhishingAnalyzer._build_sandbox(self, url: str, raw_html: str) → dict`

**Tags**: `sandbox`, `html-sanitization`, `xss-prevention`, `script-removal`, `event-handler-stripping`, `javascript-url-removal`, `meta-refresh-removal`, `form-disabling`, `pointer-events`

**Purpose**: Strips all active/dangerous HTML elements to produce a safe, read-only visual preview of the page without executing any scripts or enabling form submissions.

**Removed**:
- Tags: `<script>`, `<noscript>`, `<iframe>`, `<object>`, `<embed>`, `<base>`.
- `<meta http-equiv="refresh">` (auto-redirect).
- All `on*` event handler attributes (e.g. `onclick`, `onload`, `onmouseover`).
- `javascript:` href/src/action values.

**Added Safety**:
- All `<form>` elements get `action="#"` and `data-disabled="true"`.
- Password-containing forms get a visible red `sandbox-warning` badge.
- Injected `<style>` block sets `pointer-events: none !important` on all interactive elements.

---

#### `PhishingAnalyzer._capture_screenshot(self, url: str) → dict`

**Tags**: `playwright`, `chromium`, `headless-browser`, `screenshot`, `full-page`, `sandbox-flags`, `no-gpu`, `docker-compat`

**Purpose**: Captures a full-page screenshot using Playwright's Chromium headless browser.

**Chromium Launch Flags**: `--no-sandbox`, `--disable-setuid-sandbox`, `--disable-dev-shm-usage`, `--disable-gpu`, `--no-zygote` — all required for Docker/containerized environments.

**Viewport**: `1366 × 900` (standard laptop resolution).

**Navigation**: `page.goto(url, wait_until="domcontentloaded", timeout=screenshot_timeout_ms)` — waits for DOM load, not full network idle, to avoid hanging on pages with infinite background requests.

**Returns**: `{"available": True, "path": "/static/screenshots/{filename}.png"}` on success, or `{"available": False, "error": str}` on any failure.

---

#### `PhishingAnalyzer._chart_to_base64(self, fig) → str | None`

**Tags**: `matplotlib`, `base64-encoding`, `png`, `io.BytesIO`, `chart-serialization`

Saves a matplotlib figure to an in-memory `io.BytesIO` buffer as PNG at 110 DPI, closes the figure (prevents memory leak), and returns a base64-encoded string for direct embedding in JSON as a data URI.

---

#### `PhishingAnalyzer._chart_gauge(self, score: float) → str | None`

**Tags**: `risk-gauge`, `semicircle-chart`, `matplotlib`, `numpy`, `arc-plot`, `score-visualization`

Renders a semicircular gauge using `np.linspace(0, π, 80)` for arc segments and a dynamic color indicator needle. Three colored arcs: green (0–33%), orange (33–67%), red (67–100%). The needle position and color both reflect the score.

---

#### `PhishingAnalyzer._chart_components(self, scores: dict) → str | None`

**Tags**: `component-breakdown`, `bar-chart`, `matplotlib`, `color-coded-bars`

Renders a vertical bar chart of all numeric component scores. Bars are colored: green (< 40), orange (40–65), red (≥ 65). Non-numeric values (like `"Skipped"` for Tier 2 when HTML is unavailable) are filtered before rendering.

---

#### `PhishingAnalyzer._chart_shap(self, shap_result: dict) → str | None`

**Tags**: `shap-chart`, `horizontal-bar`, `feature-importance-visualization`, `positive-negative-impact`

Renders a horizontal bar chart of SHAP feature impacts. Positive-impact features (push toward phishing) are red; negative-impact features (push toward legitimate) are green. A vertical reference line at x=0 is drawn. Feature bars are displayed in descending absolute impact order.

---

#### `PhishingAnalyzer._build_chart_assets(self, scores, shap_result, hybrid_score) → dict`

**Tags**: `chart-orchestration`, `base64-charts`

Entry point for chart generation. Calls `_chart_gauge`, `_chart_components`, `_chart_shap` and packages results:
```python
{"gauge": "data:image/png;base64,...", "components": "...", "shap": "..."}
```

---

#### `PhishingAnalyzer._should_run_ollama(self, ml_result, header_analysis, nlp, crawl) → bool`

**Tags**: `ollama-gate`, `conditional-llm`, `performance-optimization`

Returns `True` only if page was crawled AND (ML probability ≥ 0.55 OR header risk ≥ 40 OR NLP risk ≥ 20). Prevents wasting LLM inference on clearly safe pages.

---

#### `PhishingAnalyzer._should_run_shap(self, ml_result: dict) → bool`

Returns `True` if `ml_result["available"] = True` (Tier 2 ran successfully). SHAP requires the Tier 2 model output.

---

#### `PhishingAnalyzer._generate_human_summary(self, verdict, hybrid, nlp, shap_result, threat_intel) → str`

**Tags**: `human-readable-summary`, `verdict-explanation`, `text-generation`, `threat-summary`

Builds a one-to-three sentence plain-English summary for the analysis result. Mentions:
- Verdict + score.
- Threat feed hits (if any).
- Brand impersonation (if detected).
- NLP urgency language (if present).
- Top 3 SHAP feature names (if available).

---

#### `PhishingAnalyzer._compute_html_risk(self, crawl: dict) → float`

**Tags**: `html-risk-scoring`, `login-form`, `iframe`, `external-link-ratio`, `null-link-ratio`

| Condition | Risk Added |
|---|---|
| `login_form = True` | +20 |
| `iframe = True` | +15 |
| `suspicious_form_handler = True` | +15 |
| `ratio_external_links > 0.6` | +20 |
| `ratio_external_links > 0.3` | +10 |
| `ratio_null_links > 0.5` | +10 |
| `html_ok = False` | +6 |

---

#### `PhishingAnalyzer._compute_ssl_risk(self, info: dict) → float`

**Tags**: `ssl-risk`, `certificate-expiry`, `cn-match`, `new-certificate`

No SSL → immediate 85.0. With SSL: expired cert +40, CN mismatch +25, <7 days to expiry +20, cert < 30 days old +15. Capped at 100.

---

#### `PhishingAnalyzer._compute_dns_risk(self, info: dict) → float`

**Tags**: `dns-risk`, `a-record`, `spf`, `dmarc`, `mx`

No A record +50, no SPF +20, no DMARC +20, no MX +10. Capped at 100.

---

#### `PhishingAnalyzer._compute_url_risk(self, signals: dict) → float`

**Tags**: `url-risk-scoring`, `https`, `ip-address`, `at-symbol`, `shortener`, `entropy`

No HTTPS +20, IP address +30, @ symbol +20, shortener +20, double slash +15, ≥3 subdomains +15, length >100 +10, high entropy +10, prefix/suffix +10. Capped at 100.

---

#### `PhishingAnalyzer._verdict_for_score(self, score: float) → str`

**Tags**: `verdict-mapping`, `threshold-based-classification`

Returns `"High Risk"` (≥65), `"Medium Risk"` (40–64), or `"Low Risk"` (<40). Overridden externally to `"Known Malicious"` if threat feeds confirm the URL.

---

#### `PhishingAnalyzer.analyze_url(self, raw_url: str) → dict` ⭐ **(Full Deep Analysis)**

**Tags**: `full-analysis`, `threaded-execution`, `ThreadPoolExecutor`, `consensus-scoring`, `cache-lookup`, `screenshot`, `ollama`, `shap`, `pdf-ready`

**Purpose**: The complete phishing analysis pipeline. Runs every analysis tier, enrichment, and visualization synchronously. Called directly by the `/api/analyze` endpoint and by the enrichment worker for background jobs.

**Execution Steps** (see main sequence diagram in Part 1 for full flow):

1. **Cache Check** → `_get_cached_result()`. Return early on hit (sub-millisecond response).
2. **Normalize + Validate** → `_normalize_url()` → `_validate_url()`. Return error dict on invalid URL.
3. **Tier 1** → `_extract_tier1_features()` → `_run_tier1_model()` → `tier1_score`.
4. **Parallel Block 1** (6-thread `ThreadPoolExecutor`):
   - `_crawl()` · `_analyze_ssl()` · `_analyze_dns()` · `_analyze_reputation()` · `_check_threat_intelligence()`
5. **Serial** → `_analyze_text()` · `_build_sandbox()`.
6. **Tier 2** (conditional): If `html_ok = True` → `_extract_model_features()` → `_run_model()` → `tier2_score`. Else → Tier 1 fallback.
7. **Security Layer** → `security_analyzer.analyze()` → `security_score`.
8. **Network Score** → `0.40·ssl + 0.30·dns + 0.30·reputation`.
9. **Consensus** → weighted formula → `final_score` → `_verdict_for_score()`.
10. **Override** → if `known_malicious` → `final_score = max(score, 95.0)`, verdict = `"Known Malicious"`.
11. **Parallel Block 2** (same executor):
    - `_capture_screenshot()` (if html_ok) · `_analyze_with_ollama()` (if gated) · `_compute_shap()` (if ml available)
12. **Charts** → `_build_chart_assets()`.
13. **Cache Write** → `_set_cached_result()`.
14. Returns full ~30-field result dict.

---

#### `PhishingAnalyzer.analyze_url_fast(self, raw_url: str) → dict` ⭐ **(Fast Path)**

**Tags**: `fast-analysis`, `reduced-latency`, `background-deferral`, `enrichment-pending`

**Purpose**: Reduced-latency variant for interactive UI requests. Runs Tier 1, crawl, SSL, DNS, Tier 2 (if html_ok), and SecurityService. Skips Ollama, Playwright, SHAP, WHOIS, threat intel. Returns immediately with `"enrichment": {"status": "pending"}`.

**Differences from `analyze_url()`**:
- Only 3 parallel threads (crawl, SSL, DNS) — no reputation or threat intel.
- Ollama, screenshot, SHAP all return deferred placeholders.
- `human_summary` is a fixed "Fast analysis completed" string.

**Use Case**: Called from the background worker's `_process_job()` to produce the initial partial result. The full `analyze_url()` then overwrites it.

---

#### `PhishingAnalyzer.generate_pdf_report(self, data: dict) → str | None`

**Tags**: `pdf-generation`, `reportlab`, `a4-layout`, `threat-report`, `shap-table`, `verdict-summary`

**Purpose**: Generates a formatted threat analysis PDF using ReportLab's Platypus layout engine.

**PDF Content**:
- Title paragraph in teal (`#0f766e`).
- `human_summary` body text.
- Summary table: URL, verdict, hybrid score, confidence, generated timestamp.
- SHAP top-5 features table with impact and raw values (if available).

**Returns**: Absolute filesystem path to the temp PDF file (from `tempfile.mkstemp()`), or `None` if ReportLab unavailable. The file is served and deleted by the `/api/report/<id>` route.

---

#### `PhishingAnalyzer._score_components(...)  /  _combine_risk_signals(...)` *(Internal helpers)*

**Tags**: `component-scoring`, `weighted-combination`, `offline-adjustment`, `known-malicious-override`

`_score_components()`: Packages all per-dimension risk scores into a single labeled dict.

`_combine_risk_signals()`: An alternative weighted combination method (used internally for consistency checking). Adjusts weights dynamically:
- If `html_ok = False` → reduces HTML/NLP/Headers weights.
- If `ml_result["available"] = False` → reduces ML weight from 0.30 to 0.12.
- If `known_malicious` → floor score at 95.0.

---

## Part 5 — Module: `services/storage.py`

> **Keywords**: HistoryStore · SQLite · PostgreSQL · psycopg · Parameterized Queries · Row-Level Locking · FOR UPDATE SKIP LOCKED · WAL Mode · Background Job Queue · Exponential Backoff · CRUD · JSONB · Analysis History · Analyst Notes · Feedback Aggregation · User Authentication · Password Hash

### `HistoryStore`

Database abstraction layer that supports both **SQLite** (default, zero-config) and **PostgreSQL** (production) through a unified interface. All SQL queries use parameterized inputs (`?` for SQLite, `%s` for Postgres) to prevent SQL injection.

---

#### `HistoryStore.__init__(self, database_url: str) → None`

**Tags**: `dual-database`, `url-parsing`, `placeholder-detection`

Detects database kind from the URL prefix. Sets `self.placeholder` to `"?"` (SQLite) or `"%s"` (Postgres). For SQLite, strips the `sqlite:///` prefix to get the filesystem path.

---

#### `HistoryStore._connect(self)`

**Tags**: `connection-factory`, `sqlite-wal`, `psycopg`, `parent-dir-creation`

Returns a live database connection. For SQLite: creates parent directories with `mkdir(parents=True, exist_ok=True)`, uses `timeout=30` for WAL-mode concurrent access. For Postgres: calls `psycopg.connect(self.database_url)`.

---

#### `HistoryStore._fetchall / _fetchone / _execute`

**Tags**: `query-helpers`, `connection-per-call`, `commit`

Thin wrappers that open a connection, execute parameterized SQL, commit (for `_execute`), and return results. Each call opens and closes its own connection — appropriate for SQLite's WAL mode where readers don't block writers.

---

#### `HistoryStore.init_db(self) → None`

**Tags**: `schema-creation`, `table-migration`, `idempotent`, `alter-table`, `index-creation`

Creates all five tables with `CREATE TABLE IF NOT EXISTS`. Runs column-addition migrations for `username`, `auth_provider`, `cache_hit`, `last_name`, `mobile` — these were added in later versions and existing databases need them patched without a full migration framework.

**Tables Created**:
1. `users` — Authentication identities.
2. `analysis_history` — Full analysis result blobs (JSON/JSONB payload).
3. `analysis_notes` — Analyst-appended notes per analysis.
4. `analysis_feedback` — Helpful/unhelpful votes and corrected labels.
5. `background_jobs` — Durable async task queue.

**Indexes**:
- `idx_history_created_at` — DESC index for recent-history pagination.
- `idx_history_username` — Per-user filtering.
- `idx_jobs_status_not_before` — Covered index for worker polling `WHERE status IN (...) AND not_before <= now()`.
- `idx_users_username / idx_users_mobile` — O(log n) login lookup.
- `idx_feedback_url` — Fast community feedback aggregation by URL.

---

#### `HistoryStore.save(self, result: dict, username, auth_provider) → int`

**Tags**: `analysis-persistence`, `json-serialization`, `jsonb`, `auto-increment`, `lastrowid`

Serializes the full result dict to JSON (`json.dumps(result, default=str)` — `default=str` handles datetime and Path objects). For SQLite, stores as `TEXT`; for Postgres, parses back to dict for native `JSONB` storage. Returns the auto-increment `analysis_id`.

---

#### `HistoryStore.update_analysis(self, analysis_id: int, result: dict) → None`

**Tags**: `background-enrichment-update`, `payload-overwrite`

Updates all indexed columns (`verdict`, `risk_score`, `ml_probability`, `cache_hit`) and the full `payload` blob for an existing analysis record. Called by the enrichment worker after completing the deep analysis.

---

#### `HistoryStore.get_analysis(self, analysis_id: int) → dict | None`

**Tags**: `analysis-retrieval`, `json-deserialization`, `notes-join`

Fetches a single analysis by primary key. Deserializes `payload` (already a dict for Postgres JSONB, `json.loads()` for SQLite TEXT). Attaches `notes = self.fetch_notes(analysis_id)` and `analysis_id` to the result dict before returning.

---

#### `HistoryStore.fetch_recent(self, limit, username) → list[dict]`

**Tags**: `history-pagination`, `user-scoped`, `order-by-id-desc`

Returns the N most recent analyses. If `username` is given, filters to that user's records. Returns light summary rows (no full payload) for the history sidebar.

---

#### `HistoryStore.enqueue_job(self, kind: str, payload: dict, max_attempts: int = 5) → int`

**Tags**: `job-queue`, `task-insertion`, `background-worker`

Inserts a new `background_jobs` row with `status = "pending"`. Returns the job ID. Called by `EnrichmentQueue.enqueue()`.

---

#### `HistoryStore.claim_job(self, worker_id: str, stale_after_seconds: int) → dict | None`

**Tags**: `distributed-locking`, `atomic-claim`, `for-update-skip-locked`, `stale-job-reclaim`, `concurrent-workers`

**The most complex method in the codebase.** Atomically selects and claims a pending job, handling concurrent workers safely.

**PostgreSQL Path** (`_claim_job_postgres`):
```sql
WITH claimed AS (
    SELECT id FROM background_jobs
    WHERE status IN ('pending', 'retry') AND not_before <= CURRENT_TIMESTAMP
    ORDER BY id ASC
    FOR UPDATE SKIP LOCKED   ← row-level lock, skips rows held by other workers
    LIMIT 1
)
UPDATE background_jobs SET status='running', attempts=attempts+1,
    reserved_at=CURRENT_TIMESTAMP, worker_id=%s
WHERE id IN (SELECT id FROM claimed)
RETURNING id, kind, payload, attempts, max_attempts
```

`FOR UPDATE SKIP LOCKED` enables **multiple worker processes** to poll simultaneously without blocking each other. Each worker sees a different pending row.

**SQLite Path** (`_claim_job_sqlite`):
- Uses a whole-database write transaction (SQLite WAL mode).
- Also reclaims stale `running` jobs where `reserved_at < (now - stale_after_seconds)` — handles crashed worker processes.
- Single-threaded safe — SQLite write lock ensures no two threads claim the same job.

---

#### `HistoryStore.complete_job(self, job_id: int) → None`

**Tags**: `job-completion`, `status-update`

Sets `status = "completed"` and `updated_at = CURRENT_TIMESTAMP`.

---

#### `HistoryStore.fail_job(self, job_id: int, error: str, retryable: bool) → None`

**Tags**: `job-failure`, `exponential-backoff`, `retry-queue`, `error-capture`

If `retryable = True` and `attempts < max_attempts` → `status = "retry"` with `not_before = now + 30 seconds` (fixed backoff — not exponential in current implementation). If at max attempts → `status = "failed"`. Stores up to 2000 characters of error message in `last_error`.

---

#### `HistoryStore.create_user / get_user_by_username / get_user_by_mobile / count_users`

**Tags**: `user-crud`, `bcrypt-hash`, `mobile-lookup`, `username-lookup`

Standard user management. Passwords stored as Werkzeug bcrypt hashes. Login supports both username and 10-digit mobile number as identifier.

---

#### `HistoryStore.save_note / fetch_notes`

**Tags**: `analyst-notes`, `append-only`, `per-analysis-id`

Append analyst free-text notes to a specific analysis. `fetch_notes()` returns all notes ordered by `id DESC`.

---

#### `HistoryStore.save_feedback / feedback_summary_for_url`

**Tags**: `community-feedback`, `helpful-voting`, `corrected-label`, `aggregation`

`save_feedback()` inserts a feedback row with `helpful` (bool), optional `corrected_label`, and optional `note`.

`feedback_summary_for_url()` aggregates up to 25 rows for a URL:
- Counts `helpful_count` and `not_helpful_count`.
- Groups corrected labels by frequency → `top_corrected_labels`.
- Returns 5 most recent individual feedback entries.
- Includes advisory caution: `"Community feedback is advisory only and may include malicious or low-quality submissions."`

---

#### `HistoryStore.healthcheck(self) → bool`

**Tags**: `health-check`, `db-connectivity`, `select-1`

Executes `SELECT 1` and verifies the result is `1`. Returns `True`/`False`. Used by `/api/health`.

---

#### `HistoryStore.count_pending_jobs(self) → int`

**Tags**: `queue-depth`, `prometheus-gauge`, `pending-count`

Counts rows in `background_jobs` where `status IN ('pending', 'retry')`. This value is updated as a Prometheus gauge after every HTTP response.

---

## Part 6 — Module: `enrichment_queue.py`

> **Keywords**: EnrichmentQueue · Background Worker · Daemon Thread · Job Polling · Distributed Queue · Claim-and-Process · Retry Logic · Prometheus Metrics · Worker ID · Threading Event · Graceful Shutdown

### `EnrichmentQueue`

Manages the background deep-analysis worker as a daemon thread. Continuously polls the database for pending jobs and processes them with the full `PhishingAnalyzer.analyze_url()` pipeline, then updates the stored result.

---

#### `EnrichmentQueue.__init__(self, history, analyzer, metrics, poll_interval_seconds, max_retries, stale_after_seconds) → None`

**Tags**: `dependency-injection`, `worker-id-generation`, `stop-event`

- Receives `HistoryStore`, `PhishingAnalyzer`, `MetricsRegistry` by injection.
- Generates unique `worker_id = "worker-{12-char-uuid-hex}"` per process instance — used in DB to track which worker owns each job.
- Creates `threading.Event` (`_stop`) for clean shutdown.

---

#### `EnrichmentQueue.start(self) → None`

**Tags**: `daemon-thread`, `idempotent-start`, `thread-name`

Creates and starts a `threading.Thread(target=self._run, name="enrichment-worker", daemon=True)`. Daemon flag ensures the thread dies when the Flask process exits (no cleanup needed). Idempotent — does nothing if thread is already alive.

---

#### `EnrichmentQueue.stop(self) → None`

**Tags**: `graceful-shutdown`, `stop-event`, `thread-join`

Sets `_stop` event (causes `_run()` loop to exit) and joins the thread with a 2-second timeout.

---

#### `EnrichmentQueue.enqueue(self, url: str, analysis_id: int) → int`

**Tags**: `job-creation`, `metrics-update`, `queue-depth-gauge`

Calls `HistoryStore.enqueue_job("enrich-analysis", {"url": url, "analysis_id": analysis_id})`. Increments `phishscope_jobs_enqueued_total` counter and updates `phishscope_jobs_pending` gauge.

---

#### `EnrichmentQueue._run(self) → None`

**Tags**: `worker-loop`, `polling`, `claim-job`, `sleep`, `metrics-recording`

**The main worker loop**:
```
while not _stop.is_set():
    job = history.claim_job(worker_id, stale_after_seconds)
    if not job:
        sleep(poll_interval_seconds)  # default: 2 seconds
        continue
    try:
        _process_job(job)
        history.complete_job(job.id)
        metrics.increment("phishscope_jobs_completed_total")
    except Exception:
        retryable = job.attempts < max_retries
        history.fail_job(job.id, error, retryable)
        metrics.increment("phishscope_jobs_failed_total")
    finally:
        metrics.observe("phishscope_job_duration", elapsed)
        metrics.gauge("phishscope_jobs_pending", pending_count)
```

---

#### `EnrichmentQueue._process_job(self, job: dict) → None`

**Tags**: `job-execution`, `full-analysis`, `result-overwrite`, `notes-preservation`

1. Extracts `analysis_id` and `url` from `job["payload"]`.
2. Loads current partial result from `HistoryStore.get_analysis(analysis_id)`.
3. Raises `RuntimeError` if record not found (database inconsistency).
4. Calls `PhishingAnalyzer.analyze_url(url)` — the full deep pipeline.
5. Attaches `analysis_id`, existing `notes`, and `{"enrichment": {"status": "complete"}}`.
6. Calls `HistoryStore.update_analysis(analysis_id, enriched)` — overwrites the partial fast-path result.

---

## Part 7 — Module: `rate_limit.py`

> **Keywords**: RateLimiter · Token Bucket · Fixed Window · Redis INCR · In-Memory Fallback · Thread-Safe · Per-Actor Buckets · Retry-After · 429 Too Many Requests

### `RateLimiter`

Thread-safe, dual-backend rate limiter. Uses Redis `INCR` + `EXPIRE` for distributed rate limiting when Redis is available, falling back to in-memory dict-based counting for single-process deployments.

---

#### `RateLimiter.__init__(self, window_seconds: int, redis_url: str) → None`

**Tags**: `fixed-window`, `redis-connection`, `in-memory-fallback`, `threading-lock`

Attempts Redis connection with `ping()`. Falls back silently to in-memory `_memory: dict[str, tuple[int, int]]` on failure.

---

#### `RateLimiter.check(self, bucket: str, limit: int) → RateLimitResult`

**Tags**: `rate-check`, `window-alignment`, `reset-calculation`

Aligns the current timestamp to a window boundary: `window_start = now - (now % window_seconds)`. Computes `reset_in = (window_start + window_seconds) - now`. Delegates to `_check_redis` or `_check_memory`.

Returns `RateLimitResult(allowed: bool, remaining: int, reset_in_seconds: int)`.

---

#### `RateLimiter._check_memory(self, bucket, limit, window_start, reset_in) → RateLimitResult`

**Tags**: `in-memory-counter`, `thread-lock`, `window-reset`

Under a `threading.Lock`: looks up `(count, window)` for bucket, resets count to 0 if window changed, increments count, stores updated value. Thread-safe for single-process multi-threaded Flask.

---

#### `RateLimiter._check_redis(self, bucket, limit, window_start, reset_in) → RateLimitResult`

**Tags**: `redis-incr`, `redis-expire`, `atomic-increment`, `distributed-safe`

Key format: `"rate-limit:{bucket}:{window_start}"`. Uses `INCR` (atomic) then `EXPIRE` on first increment (count == 1) to set TTL. On Redis failure, falls back to `_check_memory` (silent degradation).

---

## Part 8 — Module: `metrics.py`

> **Keywords**: MetricsRegistry · Prometheus · Counter · Gauge · Histogram Summary · Thread-Safe · render_prometheus · Observability · HTTP Request Metrics · Analysis Duration · Job Queue Depth

### `MetricsRegistry`

Lightweight Prometheus-compatible metrics collector. Stores counters, gauges, and timing summaries in thread-safe in-memory dicts. Renders to Prometheus text format via `/api/metrics`.

---

#### `MetricsRegistry.increment(self, name: str, amount: float = 1.0) → None`

**Tags**: `counter`, `thread-safe`, `event-counting`

Increments a named counter under `threading.Lock`. Used for: `phishscope_http_requests_total`, `phishscope_analysis_requests_total`, `phishscope_auth_success_total`, `phishscope_jobs_completed_total`, etc.

---

#### `MetricsRegistry.observe(self, name: str, value: float) → None`

**Tags**: `histogram`, `duration-recording`, `max-tracking`

Records a timing observation: increments `count`, adds to `sum`, updates `max`. Used for: `phishscope_http_request_duration`, `phishscope_fast_analysis_duration`, `phishscope_job_duration`.

---

#### `MetricsRegistry.gauge(self, name: str, value: float) → None`

**Tags**: `gauge`, `current-value`, `queue-depth`

Sets a named gauge to the current value. Used for `phishscope_jobs_pending` — updated after every request and job event.

---

#### `MetricsRegistry.render_prometheus(self) → str`

**Tags**: `prometheus-format`, `text-exposition`, `scrape-endpoint`

Renders all metrics to Prometheus text format (v0.0.4). Counters output as `# TYPE name counter` + `name value`. Gauges same pattern. Timers output as `_seconds_count`, `_seconds_sum`, `_seconds_max`.

---

## Part 9 — Module: `app.py`

> **Keywords**: Flask Factory · create_app · Session Management · Authentication Middleware · Rate Limiting Decorator · Input Sanitization · URL Extraction · Defanged URL Normalization · Before/After Request Hooks · Security Headers Injection · Prometheus Metrics Recording · Structured JSON Logging · Google OAuth · Werkzeug bcrypt · Batch Analysis · PDF Download · Community Feedback

### Flask Application Factory

All routes and helpers are defined inside `create_app() → Flask`. This factory pattern enables clean test isolation and environment-specific configuration.

---

#### `create_app() → Flask`

**Tags**: `factory-pattern`, `dependency-wiring`, `startup-sequence`

**Startup Sequence**:
1. `AppConfig.from_env()` → `config.validate()` (fail-fast check).
2. Flask app instantiation with `template_folder` and `static_folder`.
3. Session/cookie configuration applied to `app.config`.
4. `HistoryStore(database_url)` → `history.init_db()`.
5. `PhishingAnalyzer(BASE_DIR, model_dir)` — loads ML models (may raise).
6. `MetricsRegistry()` · `RateLimiter()` · `EnrichmentQueue()`.
7. Start enrichment worker daemon if `APP_ROLE=worker`.
8. Define all inner helpers and route handlers.
9. Return configured `Flask` app.

---

### Inner Helper Functions

#### `json_error(message, status) → Response`

**Tags**: `error-response`, `request-id-injection`

Returns `jsonify({"error": message, "request_id": g.request_id})` with the given HTTP status code. The `request_id` is included for distributed tracing correlation.

---

#### `read_json_dict() → dict`

**Tags**: `request-body-parsing`, `silent-parse`, `type-guard`

`request.get_json(silent=True)` returns `None` on parse failure. This wrapper also handles the case where the JSON root is not a dict (e.g. a JSON array) by returning `{}`.

---

#### `sanitize_url(value: str) → str`

**Tags**: `url-sanitization`, `length-check`, `security`

Strips whitespace. Raises `ValueError` if URL exceeds `config.url_max_length` (default 2048). Prevents extremely long input from overwhelming the analysis pipeline.

---

#### `sanitize_text_input(value: str) → str`

**Tags**: `text-sanitization`, `blob-input`, `length-check`

Like `sanitize_url` but allows longer inputs (up to `max(url_max_length × 20, 10000)` chars) to support free-text paste of email bodies or incident reports containing multiple URLs.

---

#### `extract_urls_from_text(value: str) → list[str]`

**Tags**: `url-extraction`, `defanging`, `hxxps-normalization`, `regex`, `deduplication`

Normalizes defanged URLs:
- `hxxps://` → `https://`
- `hxxp://` → `http://`

Then applies a broad regex matching `http://`, `https://`, `ftp://`, `www.` patterns and bare domain names. Strips trailing punctuation from matches. Deduplicates with `seen` set. Returns a list of normalized absolute URLs.

---

#### `sanitize_username / sanitize_first_name / sanitize_last_name / sanitize_mobile / sanitize_password`

**Tags**: `input-validation`, `character-allowlist`, `length-bounds`

| Function | Rules |
|---|---|
| `sanitize_username` | 3–40 chars, lowercase only, `[a-z0-9._-]` allowlist |
| `sanitize_first_name` | 2–40 chars, any printable |
| `sanitize_last_name` | 0–40 chars (optional), any printable |
| `sanitize_mobile` | Exactly 10 digits (strips non-digits first) |
| `sanitize_password` | Minimum 8 characters |

---

#### `finalize_analysis_result(result, raw_input, original_url, extracted_urls) → dict`

**Tags**: `result-enrichment`, `community-feedback-attach`, `input-url-normalization`

Attaches `input_url` (the original text the user typed), `extracted_urls` list (all URLs found in input), `community_feedback` from the DB, and `enrichment.status = "complete"`. Called just before saving to DB.

---

#### `current_actor() → str`

**Tags**: `rate-limit-key`, `actor-identification`, `session-or-ip`

Returns `"user:{username}"` for authenticated sessions or `"ip:{X-Forwarded-For|remote_addr}"` for unauthenticated requests. This key is used as the prefix for all rate limiter buckets, ensuring authenticated users and IPs are rate-limited independently.

---

#### `apply_rate_limit(bucket, limit) → Response | None`

**Tags**: `rate-limiting`, `429-response`, `retry-after-header`

Calls `rate_limiter.check(f"{bucket}:{current_actor()}", limit)`. On breach: returns a 429 JSON response with `{"error": "rate limit exceeded", "retry_in_seconds": N}` and `Retry-After: N` header. Returns `None` if allowed (middleware pattern).

---

#### `rate_limited(bucket, limit)` *(decorator factory)*

**Tags**: `decorator`, `view-wrapping`, `rate-limit-injection`

Returns a decorator that wraps a Flask view function with `apply_rate_limit()`. Used as `@rate_limited("analyze", config.rate_limit_analyze)`.

---

#### `auth_required` *(decorator)*

**Tags**: `authentication-guard`, `session-check`, `401-json`, `login-redirect`

Checks `session.get("authenticated")`. For API routes (`/api/`): returns `{"error": "authentication required"}` with 401. For page routes: redirects to `/login`. If `REQUIRE_AUTH = False`, passes all requests through.

---

#### `verify_legacy_password(password: str) → bool`

**Tags**: `bcrypt-verify`, `constant-time-compare`, `admin-fallback`

Checks the submitted password against `APP_PASSWORD_HASH` (bcrypt) if set, otherwise uses `secrets.compare_digest(expected, password)` for constant-time plain-text comparison. Supports admin accounts configured via environment variables rather than the user database.

---

### Request Lifecycle Hooks

#### `attach_request_context()` — `@app.before_request`

**Tags**: `request-id`, `trace-id`, `perf-counter`, `permanent-session`

On every request:
1. Generates or inherits `X-Request-ID` header → `g.request_id`.
2. Records `g.request_started = time.perf_counter()` for response time.
3. Sets `session.permanent = True` so sessions use `permanent_session_lifetime`.

---

#### `apply_security_headers(response)` — `@app.after_request`

**Tags**: `security-headers`, `csp`, `referrer-policy`, `permissions-policy`, `x-frame-options`, `structured-logging`, `prometheus-recording`

On every response:
1. Injects server-side security headers:
   - `X-Request-ID` — for distributed tracing
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: SAMEORIGIN`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Permissions-Policy: geolocation=(), microphone=(), camera=()`
   - `Content-Security-Policy` — restricts scripts to self + Google Accounts + Ollama local
2. Increments `phishscope_http_requests_total` counter.
3. Observes `phishscope_http_request_duration` with millisecond precision.
4. Updates `phishscope_jobs_pending` gauge.
5. Logs a structured JSON access log line with `request_id`, method, path, status, duration, remote addr.

---

### API Route Handlers

#### `POST /api/auth/register`

**Tags**: `user-registration`, `werkzeug-bcrypt`, `duplicate-check`, `session-creation`

Validates all fields through sanitize functions. Checks uniqueness of `username` and `mobile` in DB. Generates `generate_password_hash(password)` and calls `history.create_user()`. Creates an authenticated session immediately.

---

#### `POST /api/auth/login`

**Tags**: `login`, `mobile-or-username`, `bcrypt-verify`, `legacy-admin-fallback`, `auth-failure-metric`

Accepts `username` or `mobile` as identifier. Tries DB user lookup by mobile first (if identifier contains digits), then by username. Verifies with `check_password_hash()`. Falls back to legacy admin credentials via `verify_legacy_password()`. On success: creates session. On failure: increments `phishscope_auth_failure_total`.

---

#### `POST /api/auth/google`

**Tags**: `google-oauth`, `id-token-verification`, `google-auth-library`, `claims-parsing`

Verifies Google JWT using `google.oauth2.id_token.verify_oauth2_token()` against `GOOGLE_CLIENT_ID`. Extracts `email`, `given_name` from claims. Creates session without requiring a local user record.

---

#### `POST /api/analyze`

**Tags**: `url-analysis`, `fast-path`, `db-save`, `analysis-id`

1. `sanitize_text_input()` on `text` or `url` field.
2. `extract_urls_from_text()` → takes the first URL.
3. `analyzer.analyze_url(url)` (full pipeline — note: uses deep analysis not fast path here).
4. `finalize_analysis_result()` → `history.save()` → sets `analysis_id`.
5. Returns full result JSON.

---

#### `POST /api/batch`

**Tags**: `batch-analysis`, `url-deduplication`, `concurrent-processing`, `max-50-urls`

Accepts either `urls: [...]` array or `text: "..."` blob. Normalizes, deduplicates, caps at `batch_max_urls` (default 50). Runs `analyze_url()` for each URL sequentially. Returns `{"count": N, "items": [...]}`.

---

#### `GET /api/analysis/<id>`

**Tags**: `analysis-retrieval`, `community-feedback-attach`, `poll-endpoint`

Fetches analysis record from DB. Used by the frontend's `pollEnrichment()` function to check if the background worker has completed enrichment (polls until `enrichment.status == "complete"`).

---

#### `POST /api/analysis/<id>/notes`

**Tags**: `analyst-notes`, `rate-limited`, `length-check`

Validates note length against `config.note_max_length` (default 4000). Saves via `history.save_note()`. Returns all notes for the analysis.

---

#### `POST /api/analysis/<id>/feedback`

**Tags**: `feedback`, `corrected-label`, `community-data`, `rate-limited`

Validates `helpful` is a bool. Accepts optional `corrected_label` (≤80 chars) and `note`. Saves via `history.save_feedback()`. Returns aggregated feedback summary.

---

#### `GET /api/report/<id>`

**Tags**: `pdf-report`, `reportlab`, `send-file`, `temp-file`

Calls `analyzer.generate_pdf_report(result)` → gets temp PDF path → `flask.send_file(pdf_path, as_attachment=True, download_name="analysis-{id}.pdf")`.

---

#### `GET /api/health`

**Tags**: `health-check`, `model-status`, `db-status`, `worker-status`, `optional-services`

Returns:
- `model_ready`, `model_dir`, `missing_dependencies` — ML model state.
- `optional_services` — Ollama model name, VirusTotal configured, Redis available, Playwright available, ReportLab available, SHAP available.
- `database_ok` — `HistoryStore.healthcheck()`.
- `jobs_pending` — Current queue depth.
- `worker_enabled` / `worker_active_in_process` — Worker configuration.

---

#### `GET /api/metrics`

**Tags**: `prometheus`, `scrape-endpoint`, `metrics-token-auth`, `text-plain`

Protected by `METRICS_TOKEN` header check. Returns `MetricsRegistry.render_prometheus()` as `text/plain; version=0.0.4`.

---

## Part 10 — Data Flow Reference

### Full Analysis Result Structure (JSON)

The complete result dict returned by `analyze_url()` and stored in the database:

```python
{
    # Core identification
    "input_url": str,          # Raw URL as typed by the user
    "url": str,                # Normalized URL (http:// prefixed)
    "domain": str,             # Registered domain (eTLD+1)

    # Verdict
    "verdict": str,            # "Low Risk" / "Medium Risk" / "High Risk" / "Known Malicious"
    "prediction": str,         # "phishing" / "legitimate"
    "hybrid_score": float,     # Final consensus score 0–100
    "final_score": float,      # Same as hybrid_score (alias)
    "confidence": float,       # 100 - abs(tier1 - final) — agreement measure

    # Per-tier scores
    "tier1_score": float,      # Tier 1 RandomForest probability × 100
    "tier2_score": float,      # Tier 2 Stacking probability × 100 (0 if skipped)
    "network_score": float,    # 0.40·SSL + 0.30·DNS + 0.30·Reputation
    "security_score": float,   # SecurityService.analyze() score

    # Validation
    "validation": {"valid": bool, "warnings": list[str]},

    # All component scores
    "components": {
        "ML": float, "HTML": float, "Headers": float, "NLP": float,
        "SSL": float, "DNS": float, "Reputation": float, "URL": float,
        "Tier 1 (URL)": float, "Tier 2 (HTML)": float | "Skipped",
        "Network (Tier 3)": float, "Security Layer": float
    },

    # ML model output
    "ml": {"available": bool, "probability": float, "prediction": str, "features": dict},
    "selected_features": list[str],

    # Network intelligence
    "network": {
        "crawl": dict,            # html_ok, html, title, hyperlinks, etc.
        "ssl": dict,              # has_ssl, issuer, expiry, cn_matches
        "dns": dict,              # has_a_record, has_mx, has_spf, has_dmarc
        "reputation": dict,       # risk_score, risk_factors, domain_age_days
        "url_signals": dict,      # uses_https, uses_ip, shortener, entropy, etc.
        "security_headers": dict, # present, missing, issues, risk_score
        "explicit_security": dict # SecurityService result
    },

    # Content analysis
    "nlp": {"risk_score": float, "suspicious_phrases": list, "brand_impersonation": dict|None},
    "ollama": {"available": bool, "summary": str, "findings": list, ...},
    "threat_intelligence": {"known_malicious": bool, "sources": list, "details": dict},
    "sandbox": {"html": str, "removed": dict, "source_excerpt": str},

    # Visuals
    "screenshot": {"available": bool, "path": str|None, "error": str|None},
    "shap": {"available": bool, "top_features": list[dict], "method": str},
    "charts": {"gauge": str, "components": str, "shap": str},  # base64 PNGs

    # Summary
    "human_summary": str,

    # Metadata
    "model_ready": bool,
    "model_errors": list,
    "cache": {"hit": bool, "backend": str|None, "ttl_seconds": int},
    "analysis_duration_ms": float,
    "generated_at": str,        # ISO 8601 UTC timestamp
    "enrichment": {"status": "complete"|"pending"}
}
```

---

*PhishScope Platform — Complete LLD Function Reference*
*Generated from: `flask_phishing_app/` codebase — 7 modules, ~2,800 total lines of source*
