# PhishScope Context + Content

## Current State

PhishScope is a Flask-based phishing URL analysis dashboard located at:

```text
C:\Users\rudra\Videos\Phishing\Phishing
```

The project now has local git version control and startup restore snapshots.

Important commits:

```text
6173773 Baseline before startup and version-control improvements
1ce2179 Add robust launcher with restore snapshots
3859588 Fix IST greeting and authenticated navbar
3177f00 Round dashboard session card and fix IST greeting
c07c8c7 Constrain long detected URLs in composer
```

## How To Start

Run:

```text
START_PHISHSCOPE.bat
```

The launcher delegates to:

```text
setup_and_run.bat
scripts\launch_phishscope.ps1
```

Startup prompt:

```text
C - Create restore snapshot, then start
S - Start without snapshot
R - Restore a previous snapshot
L - List snapshots
Q - Quit
```

Use `C` before larger changes. Restore snapshots are stored in:

```text
.phishscope_versions
```

## Local URL

```text
http://127.0.0.1:5000
```

Default login:

```text
admin
admin
```

Health endpoints:

```text
http://127.0.0.1:5000/health
http://127.0.0.1:5000/ready
```

## Ollama

Ollama is installed and was verified reachable at:

```text
http://127.0.0.1:11434
```

Configured model:

```text
deepseek-r1:1.5b
```

The launcher attempts to start Ollama automatically if it is installed and not already running.

## UI Fixes Already Applied

- Dashboard greeting uses IST through `Asia/Kolkata`.
- Greeting ranges:
  - `05:00-11:59` Good morning
  - `12:00-16:59` Good afternoon
  - `17:00-21:59` Good evening
  - `22:00-04:59` Good night
- Dashboard session card and metric tiles are more rounded.
- The `Next Action` tile was replaced with live `IST Time`.
- Auth-aware navbar is shared across Dashboard, About, History, and Security Layers.
- Long detected URLs are constrained so the Analyze button does not shift.
- AI score text no longer has a gradient highlight; only the probability bar remains colored.
- History table URL text is explicitly dark in light mode.

## Key Files

```text
flask_phishing_app\app.py
flask_phishing_app\services\analysis.py
flask_phishing_app\services\storage.py
flask_phishing_app\static\app.css
flask_phishing_app\static\app.js
flask_phishing_app\static\nav.js
flask_phishing_app\static\history_center.js
flask_phishing_app\templates\index.html
flask_phishing_app\templates\history_center.html
scripts\launch_phishscope.ps1
docs\VERSION_CONTROL.md
```

## Verification Commands

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_production_hardening tests.test_analysis_pipeline
node --check .\flask_phishing_app\static\app.js
node --check .\flask_phishing_app\static\nav.js
```

## Viva / Project Interview Preparation

This section contains the most likely questions an external examiner may ask, based on the slide allocation and the actual PhishScope implementation.

## 1. Title & Introduction - Rudra Kadel

1. **Why did you choose this project?**
   - Phishing is a real-world security problem that affects email users, students, companies, banking users, and general internet users.
   - Many users cannot manually inspect URLs, SSL certificates, DNS records, or webpage content.
   - The project solves this by giving a fast, explainable phishing risk decision from a URL.

2. **What real-world problem does it solve?**
   - It helps detect suspicious URLs before a user clicks or trusts them.
   - It reduces manual effort for basic phishing triage.
   - It gives evidence such as URL structure, DNS, SSL, security headers, webpage content, screenshot, sandbox preview, and AI summary.

3. **What is the main objective of the project?**
   - To build an explainable phishing URL detection platform.
   - To combine machine learning with network intelligence and security checks.
   - To provide a usable dashboard where users can analyze one URL or multiple URLs and review saved results.

4. **Who are the target users?**
   - Security students.
   - SOC analysts or beginner security reviewers.
   - Teachers, evaluators, or small teams who want a local phishing analysis tool.
   - General users can benefit indirectly, but the current UI is mainly analyst-facing.

5. **What makes this project different from existing solutions?**
   - It does not only show a single score.
   - It uses a 3-tier structure: lexical ML, webpage/content ML, and network/security intelligence.
   - It includes local Ollama AI summary, SHAP explainability, screenshots, sandbox preview, history, notes, batch analysis, and PDF reporting.

6. **Can you summarize the project in one minute?**
   - PhishScope is a Flask-based phishing URL detection and threat intelligence platform. A user submits a suspicious URL. The system extracts URL features, runs trained ML models, fetches webpage and network signals, checks DNS, SSL, security headers, reputation, and content indicators, then generates an explainable verdict. The result includes risk score, confidence, evidence, AI-assisted explanation, screenshot, sandbox preview, and stored history for later review.

## 2. Technical Approach - Sagnik Pyne

1. **Why did you choose Python?**
   - Python has mature ML, data processing, web scraping, security, and automation libraries.
   - The trained models use scikit-learn, pandas, numpy, joblib, SHAP, and related Python tools.
   - Python made model loading, feature extraction, HTML parsing, DNS/SSL checks, report generation, and API integration easier than Java for this project.

2. **Why not Java?**
   - Java is strong for enterprise backend systems, but this project depends heavily on ML and data science workflows.
   - Python has simpler integration with scikit-learn, SHAP, pandas, BeautifulSoup, Playwright, and Ollama APIs.
   - In Java, we would need extra bridges or alternative ML libraries, increasing complexity without improving the core goal.

3. **Why Flask instead of Django?**
   - Flask is lightweight and suitable for a focused dashboard/API project.
   - Django would add more structure than needed, such as a full ORM/admin system.
   - Flask allowed direct control over routes, model loading, API responses, and local deployment.

4. **Why not React/Angular/Vue for the frontend?**
   - The project needed a functional analyst dashboard, not a large frontend application.
   - HTML templates plus JavaScript were enough for form handling, rendering analysis results, history, tabs, and dynamic UI updates.
   - A frontend framework could be added later if the UI grows, but it would increase setup complexity now.

5. **Why SQLite instead of MySQL/PostgreSQL?**
   - SQLite is easy for local setup and project demonstration.
   - It does not require a separate database server.
   - The code supports PostgreSQL-style deployment through `DATABASE_URL`, so scaling is still possible later.

6. **Why BeautifulSoup?**
   - BeautifulSoup is reliable for parsing fetched HTML.
   - It is useful for extracting title, forms, links, suspicious text, iframes, scripts, and visible content.
   - It is simpler than writing a custom parser and safer than regex-only HTML parsing.

7. **Why Playwright?**
   - Playwright can capture screenshots and inspect rendered pages in a browser-like environment.
   - Some phishing pages behave differently after rendering, so screenshots are useful evidence.
   - It supports headless Chromium, which works well for local automation.

8. **Why Ollama?**
   - Ollama runs local LLMs on the user's machine.
   - This avoids sending suspicious page content to a third-party AI API.
   - It provides human-readable threat summaries while keeping privacy better than cloud-only LLM integration.

9. **Why `deepseek-r1:1.5b`?**
   - It is already installed locally.
   - It is small enough to run on a normal machine.
   - It can produce useful reasoning summaries without requiring a large GPU.
   - Larger models may give better output but would increase memory, time, and setup requirements.

10. **Why not use a simpler AI API?**
    - A cloud AI API would be easier in some ways, but it raises privacy issues because URLs and page content may be sensitive.
    - A local Ollama model keeps analysis local.
    - The project still works without Ollama by using heuristic fallback summaries.

11. **Why use an NLP summary?**
    - Phishing is not only about URL structure; text content matters.
    - Suspicious phrases like "verify your account", "account suspended", "OTP", and "immediate action required" are useful signals.
    - The NLP summary helps explain why a page looks suspicious in human-readable terms.

12. **What alternatives did you have?**
    - Backend: Flask, Django, FastAPI, Java Spring Boot, Node.js Express.
    - Frontend: server-rendered HTML, React, Angular, Vue.
    - Database: SQLite, MySQL, PostgreSQL, MongoDB.
    - Parsing: BeautifulSoup, lxml, Selenium DOM extraction, regex.
    - Browser automation: Playwright, Selenium, Puppeteer.
    - AI summary: Ollama local models, OpenAI API, rule-based only.
    - Deployment: local Windows launcher, Docker, cloud VM, Render/Heroku-style hosting.

13. **Why these choices were practical**
    - Python + Flask + SQLite + local Ollama keeps setup simple.
    - The project demonstrates ML, security analysis, AI summary, and UI integration without requiring a heavy cloud stack.
    - The system remains extendable to PostgreSQL, Docker, cloud deployment, and browser extension formats.

## 3. Workflow & Impact - Parthib Dutta

1. **Explain the workflow step by step.**
   - User logs in.
   - User submits one URL or multiple URLs.
   - The app normalizes and validates URLs.
   - Tier 1 extracts lexical URL features and runs the first ML model.
   - The app fetches webpage content where possible.
   - Tier 2 uses HTML and URL features for deeper classification.
   - Tier 3 checks DNS, SSL, domain age, reputation, and security headers.
   - The final hybrid score and verdict are calculated.
   - The result is displayed with evidence, AI explanation, screenshots, sandbox preview, charts, and history.

2. **Why was batch analysis added?**
   - Real phishing investigations often involve many URLs from emails, logs, or reports.
   - Batch mode saves time by analyzing multiple URLs in one cycle.
   - It helps compare suspicious links from the same campaign.

3. **What is the practical impact?**
   - Saves manual inspection time.
   - Gives explainable evidence instead of only a black-box label.
   - Helps students and analysts understand phishing indicators.
   - Provides saved history and notes for repeated review.

4. **What assumptions were made?**
   - The URL can be safely fetched with timeouts.
   - The trained models are available locally.
   - Some external checks may fail because websites block bots or network access.
   - Ollama is optional and may not always be running.

5. **What are the current limitations?**
   - Model accuracy depends on training data quality.
   - Some phishing pages may block automated crawlers.
   - Local hardware affects AI summary and screenshot speed.
   - Current deployment is local-first, not yet a large multi-user SaaS platform.

6. **Can this become a browser extension for Gmail or Outlook?**
   - Yes, but it would need a browser extension frontend and a local or remote backend.
   - The extension could extract links from Gmail/Outlook pages and send them to the PhishScope API.
   - Privacy controls would be important because email links can contain personal tokens.
   - A safer design would ask the user before sending links and redact sensitive query parameters where possible.

7. **Should history be public?**
   - No. Analysis history can contain sensitive URLs, private tokens, email campaign links, internal domains, or user notes.
   - It should be private per user or restricted to authorized analysts.
   - Public sharing should only happen after sanitization.

## 4. Results - Sourav

1. **How did you evaluate the project?**
   - Unit tests for storage, configuration, rate limiting, and analysis pipeline.
   - Manual browser checks for login, dashboard, history, health endpoints, and UI behavior.
   - Functional checks with known domains and long URLs.
   - Health endpoints verify model readiness, database status, and optional services.

2. **What metrics matter?**
   - Model prediction and probability.
   - Hybrid risk score.
   - Confidence score.
   - Response time.
   - Number of successful analyses.
   - False positive and false negative behavior.
   - Whether evidence is understandable to the user.

3. **What datasets or test cases were used?**
   - Trained model artifacts under `Model/1` and `Model/2`.
   - Local tests include legitimate URLs such as Wikipedia.
   - Manual tests include long tracking URLs, suspicious-style URLs, and stored history records.

4. **How do you know the project is successful?**
   - It runs locally through a one-click launcher.
   - It loads ML models successfully.
   - It returns verdicts and evidence for URLs.
   - It stores history and notes.
   - Ollama, Playwright, SHAP, PDF reporting, and health checks are integrated.

5. **What would you improve with more time?**
   - More robust datasets and retraining.
   - More evaluation metrics and confusion matrix reports.
   - Better browser extension integration.
   - User roles and admin settings.
   - Stronger privacy controls for URL query parameters.
   - Cloud deployment with PostgreSQL and background workers.

## 5. References - Mrs. PB

1. **Which resources influenced the project?**
   - Phishing detection research papers.
   - Documentation for Flask, scikit-learn, SHAP, Playwright, BeautifulSoup, ReportLab, and Ollama.
   - Security best practices around HTTP headers, DNS, SSL, and phishing URL analysis.

2. **Why choose these references?**
   - They are directly related to phishing detection, web security, machine learning, and explainability.
   - Official documentation was used for implementation reliability.
   - Research papers help justify why URL, content, and network features are useful.

3. **Did the project use open-source libraries or APIs?**
   - Yes.
   - Flask for backend.
   - scikit-learn/joblib for ML.
   - pandas/numpy for data processing.
   - BeautifulSoup for HTML parsing.
   - Playwright for screenshots.
   - SHAP for explainability.
   - ReportLab for PDF reports.
   - tldextract, dnspython, python-whois, requests, and optional Ollama.

4. **How did the literature survey help?**
   - It showed that phishing detection improves when multiple signal types are combined.
   - It identified the gap between simple black-box scoring and explainable analyst-facing systems.

5. **How can the project adapt to new technology?**
   - Replace or retrain ML models.
   - Add new threat intelligence feeds.
   - Swap Ollama model with a stronger local model.
   - Add browser extension or cloud deployment.
   - Add better explainability and privacy redaction.

## Tier-by-Tier Architecture Explanation

PhishScope uses three tiers because phishing detection is not reliable from one signal alone. A URL may look normal but host suspicious content. A page may look clean but have suspicious DNS or SSL history. The tiers reduce dependence on one method.

### Tier 1 - Lexical URL Model

Purpose:

- Fast first-pass detection using only the URL string.
- Works even if the website cannot be fetched.

What it checks:

- URL length.
- Hostname length.
- Number of dots, hyphens, slashes, and `www`.
- Digit ratio.
- Suspicious words or phishing hints.
- Word lengths in host/path.

Why it exists:

- It is fast.
- It has no network dependency.
- It gives an immediate baseline risk score.

### Tier 2 - HTML + URL Ensemble Model

Purpose:

- Deeper classification when webpage content can be fetched.

What it checks:

- HTML/content-based features.
- Login forms.
- Link behavior.
- External links.
- Page structure.
- Combined URL and content signals.

Why it exists:

- Many phishing pages reveal risk through forms, wording, links, and HTML structure.
- URL-only detection can miss pages using realistic domains or tracking links.

### Tier 3 - Network and Security Intelligence

Purpose:

- Add infrastructure-level evidence.

What it checks:

- DNS records.
- SSL certificate presence and expiry.
- Domain age.
- Reputation signals.
- Security headers.
- SPF/DMARC/MX indicators where useful.

Why it exists:

- Phishing infrastructure often has weak DNS, weak certificate hygiene, missing headers, new domains, or suspicious reputation.
- These signals help explain the verdict beyond ML probability.

### Final Consensus

The final verdict combines:

- Tier 1 lexical model.
- Tier 2 HTML/content model where available.
- Tier 3 network/security score.
- Security header analysis.
- Heuristic and AI-assisted explanation.

This layered approach makes the result more defensible than a single model score.

## Most Probable Technical Questions

1. **Why did you create three tiers instead of one model?**
   - Because phishing signals come from different sources: URL structure, webpage content, and network infrastructure.
   - One model can fail if a page blocks crawling or if the URL looks normal.

2. **What happens if the webpage cannot be fetched?**
   - Tier 1 still works because it only needs the URL.
   - Tier 3 can still perform some network checks.
   - The system returns a fallback result instead of failing completely.

3. **Why is explainability important?**
   - A user needs to understand why a URL was flagged.
   - SHAP and evidence sections help justify the verdict.
   - This is important for academic evaluation and real security triage.

4. **Why did you add history?**
   - Analysts need to revisit previous checks.
   - History supports notes, feedback, and comparison.
   - It helps identify repeated campaigns or repeated false positives.

5. **Should history be encrypted or private?**
   - Yes, in production.
   - URLs can contain private tracking tokens or internal links.
   - Access should be authenticated and role-based.

6. **What security measures are implemented?**
   - Login/authentication.
   - Rate limiting.
   - Input validation and URL normalization.
   - Safe sandbox rendering.
   - Security headers.
   - Timeouts for external requests.
   - Local-only Ollama support for privacy.

7. **What are privacy concerns?**
   - URLs may include personal tokens.
   - Screenshots may capture sensitive pages.
   - History may expose private investigation data.
   - Public sharing should be disabled unless data is sanitized.

8. **Could attackers abuse this system?**
   - Yes, if public and unprotected, attackers could use it to test phishing URLs.
   - Rate limiting, authentication, logging, and access control reduce this risk.

9. **How would you scale it to 10,000 users?**
   - Use PostgreSQL instead of SQLite.
   - Move analysis jobs to background workers.
   - Add Redis queue/cache.
   - Deploy behind Nginx/Gunicorn.
   - Use cloud object storage for screenshots/reports.
   - Add role-based access and monitoring.

10. **Why not just use VirusTotal?**
    - VirusTotal is useful but external and reputation-based.
    - PhishScope adds local ML, HTML analysis, security headers, screenshots, sandbox preview, and explainability.
    - It can still integrate threat feeds as one layer.

11. **Why not make it only a browser extension?**
    - Browser extension is useful for Gmail/Outlook integration.
    - But ML models, screenshot capture, history, PDF generation, and analysis services are easier to manage in a backend.
    - A future extension can use this backend API.

12. **What is the biggest weakness of the project?**
    - Model quality depends on training data.
    - Some live websites block automated requests.
    - Local machine performance affects AI and screenshots.
    - More real-world validation is needed.

13. **What feature are you most proud of?**
    - The layered explainable verdict.
    - Batch analysis.
    - Local Ollama summary.
    - History and evidence retention.
    - One-click Windows startup with restore snapshots.

14. **What would version 2.0 include?**
    - Browser extension for Gmail/Outlook.
    - Better privacy redaction for URL parameters.
    - More datasets and retraining.
    - Multi-user roles.
    - Cloud deployment.
    - Admin settings page.
    - Better model evaluation dashboard.

15. **If one technology is removed, what alternative would you use?**
    - Flask removed: FastAPI.
    - SQLite removed: PostgreSQL.
    - BeautifulSoup removed: lxml or Playwright DOM extraction.
    - Playwright removed: Selenium.
    - Ollama removed: rule-based summaries or a cloud LLM API with privacy controls.
    - SHAP removed: feature importance or model-specific explanations.

## Common Questions Asked to Any Team Member

- What was your individual contribution to the project?
- What was the biggest challenge your team faced?
- What feature are you most proud of?
- What would you improve in version 2.0?
- If this project failed, what do you think would be the reason?
- How did you divide the work among team members?
- What did you learn from this project?
- If I remove one technology from your stack, what alternative would you use and why?
- What security measures have you implemented?
- If you had a budget of Rs. 10 lakh, how would you improve this project?

## Short Answers for Common Questions

**What was the biggest challenge?**

Integrating many different layers into one working flow: ML models, HTML crawling, DNS/SSL checks, screenshots, Ollama summaries, history, authentication, and UI rendering.

**What did you learn?**

How to combine machine learning with practical web security signals, how to make results explainable, and how to build a local full-stack security tool.

**Why is the project useful?**

It reduces the gap between a raw phishing score and an analyst-readable investigation report.


## Deep Technical Viva Answers

These answers are for stricter external viva questions where the examiner asks about exact implementation order, leakage, ensemble design, deployment, and limitations.

## 1. Exact End-to-End ML Pipeline

**Question:** What is the exact end-to-end pipeline: data source -> feature extraction -> preprocessing -> train/test split -> SMOTE -> model training -> evaluation -> deployment? Where does SMOTE sit relative to the split?

**Answer:**

In the current repository, the clearly available training script is:

```text
Model\1\train_tier1.py
```

That script trains the Tier 1 lexical URL model. Its actual order is:

1. Load dataset from one of these paths:

```text
phishing_dataset_3.csv
unnecessary\phishing_dataset_3.csv
unnecessary\datasets\phishing_dataset_3.csv
```

2. Normalize column names to lowercase.

3. Select Tier 1 URL-only features:

```text
length_url
length_hostname
nb_dots
nb_hyphens
nb_www
ratio_digits_url
length_words_raw
longest_words_raw
longest_word_path
phish_hints
nb_slash
shortest_word_host
```

4. Convert target labels:

```text
phishing -> 1
legitimate -> 0
1 -> 1
0 -> 0
```

5. Perform stratified train/test split:

```python
train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
```

6. Fit preprocessing only on training data:

```text
SimpleImputer(strategy="median")
StandardScaler()
```

7. Transform train and test separately:

```text
fit_transform(X_train)
transform(X_test)
```

8. Train model:

```text
RandomForestClassifier(
    n_estimators=250,
    max_depth=12,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
```

9. Evaluate on holdout test set:

```text
accuracy
F1 score
ROC-AUC
```

10. Save artifacts:

```text
Model\1\tier1_url_model.pkl
Model\1\preprocessor.pkl
```

**Important SMOTE clarification:**

The current `Model\1\train_tier1.py` does **not** use SMOTE. If SMOTE is used in future retraining, the correct order is:

```text
Load data
Extract features
Split into train/test
Fit imputer/scaler on train only
Apply SMOTE only to training data
Train model on resampled training data
Evaluate once on untouched test data
Save model/preprocessor
```

SMOTE must **not** be applied before train/test split. If SMOTE is applied before splitting, synthetic samples derived from training examples can leak into the test set and inflate metrics.

Correct defensible order:

```text
Raw dataset
-> feature selection
-> train/test split
-> fit preprocessing on X_train
-> transform X_train and X_test
-> SMOTE only on transformed X_train/y_train
-> model.fit(X_train_resampled, y_train_resampled)
-> model.predict(X_test_transformed)
```

For cross-validation, SMOTE should be inside an `imblearn.pipeline.Pipeline` so resampling happens independently inside each fold.

## 2. Flask + ML Ensemble + Gradio UI Setup

**Question:** What does the Flask + ML ensemble + Gradio UI setup actually look like? Which part serves the model, which part is the demo UI, and how do they talk?

**Answer:**

The current project uses **Flask**, not Gradio, as the working application UI and API.

Actual current structure:

```text
Browser UI
  -> Flask routes in flask_phishing_app\app.py
  -> PhishingAnalyzer in flask_phishing_app\services\analysis.py
  -> saved ML artifacts under Model\
  -> SQLite history database
  -> optional Ollama / Playwright / threat intelligence
```

There is no active Gradio app in the current repo.

The model serving flow is:

1. User opens:

```text
http://127.0.0.1:5000
```

2. User submits URL from the dashboard.

3. Frontend JavaScript calls Flask API:

```text
POST /api/analyze
POST /api/batch
```

4. Flask route calls:

```python
analyzer.analyze_url(url)
```

or:

```python
analyzer.analyze_url_fast(url)
```

5. `PhishingAnalyzer` loads and uses:

```text
Model\1\tier1_url_model.pkl
Model\1\preprocessor.pkl
Model\2\final_ensemble.pkl
Model\2\preprocessor.pkl
Model\2\selected_features.txt
Model\3\network_intelligence.py
```

6. Flask returns JSON to the dashboard.

7. The dashboard renders verdict, score, evidence, charts, AI summary, screenshot, sandbox preview, history, and notes.

If Gradio were added, it would be a separate demo UI that either imports the same `PhishingAnalyzer` class directly or calls the Flask API endpoints. For this project, the accurate viva answer is:

> The deployed/demo application is Flask-based. Flask serves both the UI and API. The ML ensemble is loaded inside the backend service layer, not served by a separate ML microservice. Gradio is not part of the current working app.

## 3. Final Feature List and Removed/Neutralized Features

**Question:** What is the final list of features used, and which ones were removed after the leakage fix?

**Answer:**

There are two model feature groups.

### Tier 1 Lexical URL Features

Tier 1 uses 12 URL-only features:

```text
length_url
length_hostname
nb_dots
nb_hyphens
nb_www
ratio_digits_url
length_words_raw
longest_words_raw
longest_word_path
phish_hints
nb_slash
shortest_word_host
```

These are legitimate because they are available immediately from the submitted URL at prediction time.

### Tier 2 Stacking Model Features

The saved Tier 2 model expects these 10 selected features:

```text
nb_www
longest_word_path
phish_hints
nb_hyperlinks
ratio_extHyperlinks
domain_age
web_traffic
google_index
page_rank
status_encoded
```

Runtime feature sources:

```text
nb_www              -> URL netloc
longest_word_path   -> URL path tokenization
phish_hints         -> suspicious keyword count in URL
nb_hyperlinks       -> crawled HTML anchor count
ratio_extHyperlinks -> fraction of external links
domain_age          -> WHOIS/reputation result
web_traffic         -> heuristic proxy from hyperlink count
google_index        -> heuristic HTTPS + hyperlink signal
page_rank           -> heuristic 0-10 trust-like score
status_encoded      -> fixed neutral value 0.5
```

The key leakage-related feature is:

```text
status_encoded
```

It was not removed from `selected_features.txt` because the saved Tier 2 model still expects that column. Instead, it is neutralized at runtime:

```python
"status_encoded": 0.5
```

This keeps the model input schema compatible while preventing HTTP status from dominating predictions.

## 4. Leakage Issue

**Question:** What was the leakage issue exactly? Was `status_encoded` a direct target leak? What replaced it?

**Answer:**

The leakage concern is around `status_encoded`.

The project documentation says the older Tier 2 setup used HTTP status encoding in a way that could poison the model. In phishing datasets, status-like columns can become strongly correlated with labels because of how the dataset was collected, not because the status is a reliable phishing property.

Example issue:

- Many collected phishing pages may be dead or return error codes.
- Many legitimate pages may return `200 OK`.
- The model may learn dataset collection artifacts instead of phishing behavior.

That is not a safe prediction-time feature because:

- A phishing page can return `200 OK`.
- A legitimate site can return `403`, `404`, bot-blocked, or timeout.
- HTTP status can depend on geography, bot protection, network, or headers.

So the runtime code neutralizes it:

```python
"status_encoded": 0.5
```

This means:

- It is still passed to the saved model because the model expects the column.
- It no longer carries actual HTTP status information.
- It cannot directly leak the label or overfit to crawler status artifacts.

Better future retraining:

- Remove `status_encoded` completely from training.
- Retrain Tier 2 with only legitimate prediction-time features.
- Replace it with defensible signals such as `html_fetch_success`, `redirect_count`, `has_login_form`, `external_link_ratio`, `domain_age_days`, `ssl_valid`, and `security_header_score`.

Feature legitimacy rule:

> A feature is legitimate only if it is available at prediction time and is not derived from the true label or dataset collection process.

## 5. Ensemble Algorithms and Combination Method

**Question:** Which algorithms make up the ensemble, and how are outputs combined?

**Answer:**

Tier 1 is separate:

```text
RandomForestClassifier
```

Tier 2 is a scikit-learn `StackingClassifier`.

The saved Tier 2 base estimators are:

```text
LogisticRegression(max_iter=2000)
RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1)
SVC(probability=True)
XGBClassifier(n_estimators=200, eval_metric="logloss")
LGBMClassifier(n_estimators=300, random_state=42)
```

The final meta-estimator is:

```text
LogisticRegression(max_iter=2000)
```

This is **stacking**, not simple voting.

How stacking works:

1. Each base learner produces a prediction/probability.
2. Those outputs become higher-level inputs to the final estimator.
3. The final Logistic Regression meta-model learns how to combine the base model outputs.

So the Tier 2 ensemble is:

```text
LR + RF + SVC + XGBoost + LightGBM -> Logistic Regression meta-learner
```

## 6. Hybrid Scoring

**Question:** What does hybrid scoring mean? Is it ensemble-of-models or ML + heuristic score?

**Answer:**

In PhishScope, "hybrid scoring" means a mix of ML scores and heuristic/security scores. It is not only the Tier 2 stacking ensemble.

There are two levels:

### Model Ensemble

Tier 2 itself is a model ensemble:

```text
StackingClassifier = multiple ML models combined by a meta-model
```

### Hybrid Final Score

The final `hybrid_score` combines:

```text
Tier 1 URL score
Tier 2 HTML/content score
Tier 3 network score
Security header score
```

When HTML is available:

```text
final_score = 0.55 * Tier1
            + 0.25 * Tier2
            + 0.10 * Network
            + 0.10 * Security
```

When HTML is not available:

```text
final_score = 0.75 * Tier1
            + 0.15 * Network
            + 0.10 * Security
```

This design lets the system still produce a verdict even when a webpage blocks crawling.

## 7. Current Performance Metrics

**Question:** What are the current performance metrics post-fix, and how do they compare to the old leaky model?

**Answer:**

The available repository gives clear Tier 1 training metrics through `Model\1\train_tier1.py`, which prints:

```text
Accuracy
F1 Score
ROC-AUC
```

The README describes Tier 1 approximately as:

```text
Accuracy: 89.89%
F1: 90.57%
```

The README describes Tier 2 approximately as:

```text
Accuracy: ~94.4%
```

However, the current repo does **not** include a Tier 2 retraining script or a metrics report showing exact post-leakage precision, recall, F1, and ROC-AUC after removing or neutralizing `status_encoded`.

So the defensible answer is:

> The old model likely had inflated performance because status-related features can correlate with labels due to dataset collection artifacts. In the current deployed runtime, `status_encoded` is neutralized to 0.5 to reduce leakage risk, but a full post-fix retraining/evaluation report is not present in this repository. The next proper step is to retrain Tier 2 without `status_encoded` and report accuracy, precision, recall, F1, ROC-AUC, and confusion matrix on an untouched holdout set.

Do not claim exact post-fix Tier 2 metrics unless they are generated from a retrained model.

## 8. Leakage Validation Strategy

**Question:** How did you validate there is no leakage this time?

**Answer:**

Current runtime leakage mitigation:

```text
status_encoded is fixed to 0.5 at prediction time
```

This prevents the runtime model from using actual HTTP status as a strong signal.

For training-time validation, the correct rigorous method should be:

1. Remove direct target-derived fields.
2. Remove dataset artifact fields.
3. Split before preprocessing and SMOTE.
4. Fit preprocessing only on training data.
5. Apply SMOTE only on training folds.
6. Evaluate on untouched holdout data.
7. Use cross-validation where each fold independently fits preprocessing and SMOTE.
8. Add domain-based split if possible so the same domain does not appear in both train and test.
9. Prefer temporal split for phishing datasets if timestamps are available.

Best answer:

> We mitigated the known runtime leakage by neutralizing `status_encoded`. For a publication-level validation, we should retrain Tier 2 after removing that feature entirely and validate using stratified holdout plus domain-level or temporal split. This would prove that performance comes from real phishing signals rather than collection artifacts.

## 9. Deployment / Demo Flow and Hosting Blocker

**Question:** Since you skipped live hosting in favor of a demo video + README, what does the deployed/demo flow look like and what was the blocker?

**Answer:**

Current demo flow:

1. User starts the project with:

```text
START_PHISHSCOPE.bat
```

2. Launcher runs:

```text
setup_and_run.bat
scripts\launch_phishscope.ps1
```

3. Launcher checks:

```text
Python
virtual environment
requirements
Playwright Chromium
Ollama availability
model files
restore snapshots
```

4. Flask starts locally at:

```text
http://127.0.0.1:5000
```

5. User logs in and submits URL.

6. Dashboard displays verdict, evidence, screenshots, AI summary, and history.

Specific hosting blockers:

- The app depends on local ML model files.
- It uses Playwright Chromium for screenshots, which needs browser/runtime support on the host.
- Ollama is local and not automatically available on normal cloud platforms.
- Some hosting platforms have memory/time limits unsuitable for model loading, screenshots, and crawling.
- SQLite is fine locally but should be PostgreSQL in production.
- Safe production deployment needs secrets, worker separation, queueing, file storage, and stricter abuse controls.

Defensible viva answer:

> We chose a local demo because this is a security analysis tool with local models, screenshots, and optional local LLM processing. Hosting it publicly without authentication, rate limits, privacy redaction, and abuse controls would be risky. The local demo proves the full pipeline while avoiding unsafe public exposure.

## 10. Known Limitations and Attack Scenarios

**Question:** What are known limitations or attack scenarios your model does not handle well?

**Answer:**

Known limitations:

1. **Fresh phishing domains**
   - Very new phishing pages may not appear in reputation feeds yet.

2. **Cloaking**
   - A phishing site may show harmless content to bots and malicious content to real users.

3. **JavaScript-heavy pages**
   - If content requires complex interaction, login, or delayed scripts, static extraction may miss signals.

4. **Bot blocking**
   - Sites may return `403`, CAPTCHA, or blank pages to automated requests.

5. **Compromised legitimate domains**
   - A real trusted domain can host a malicious page, making lexical and domain-age features less useful.

6. **URL shorteners and redirects**
   - Shorteners can hide final destinations.
   - Redirect chains need careful expansion with safety limits.

7. **Image-based phishing**
   - Pages that use images instead of text can bypass text/NLP phrase detection.

8. **Adversarial URL design**
   - Attackers can craft URLs to avoid obvious phishing keywords.

9. **Dataset drift**
   - Phishing tactics evolve, so old training data can become stale.

10. **Privacy-sensitive URLs**
    - URLs may contain tokens, email IDs, or tracking IDs.
    - History storage must be protected and should not be public.

11. **False positives**
    - Marketing links, email tracking URLs, and SSO redirects can look suspicious but be legitimate.

12. **False negatives**
    - Clean-looking pages with malicious intent may not trigger enough signals.

Strong closing answer:

> The model should be treated as a decision-support tool, not an absolute authority. It helps prioritize suspicious URLs and explain evidence, but final judgement should include analyst review, especially for high-impact cases.
