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

**What would you do with Rs. 10 lakh?**

Improve dataset quality, retrain models, deploy to cloud, add PostgreSQL and Redis workers, build a browser extension, add privacy redaction, improve UI/UX, and perform real-world testing.
