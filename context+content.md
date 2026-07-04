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

