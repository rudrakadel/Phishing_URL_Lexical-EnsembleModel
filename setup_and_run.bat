@echo off
setlocal EnableExtensions

:: Always run from the folder this bat file is in — no matter where it is on any PC
cd /d "%~dp0"
title PhishScope Setup and Launcher
color 0B

echo =================================================================
echo             PHISHSCOPE THREAT INTELLIGENCE SYSTEM
echo                  One-Click Windows Setup and Run
echo =================================================================
echo.

:: ── Paths (all relative to this bat file's location) ──────────────
set "PROJECT_DIR=%CD%"
set "APP_DIR=%PROJECT_DIR%\flask_phishing_app"
set "VENV_DIR=%PROJECT_DIR%\.venv"
set "REQ_FILE=%APP_DIR%\requirements.txt"
set "REQ_HASH_FILE=%VENV_DIR%\.requirements.sha256"
set "PLAYWRIGHT_MARKER=%VENV_DIR%\.playwright_chromium_installed"
set "APP_URL=http://127.0.0.1:5000"

echo [*] Running from:
echo     %PROJECT_DIR%
echo.

:: ── Check app.py exists ────────────────────────────────────────────
if not exist "%APP_DIR%\app.py" (
    color 0C
    echo [ERROR] Cannot find flask_phishing_app\app.py
    echo Make sure you run this bat file from inside the PhishScope folder.
    echo.
    pause
    exit /b 1
)

:: ── Check all model files exist ────────────────────────────────────
if not exist "%PROJECT_DIR%\Model\1\tier1_url_model.pkl"   goto missing_models
if not exist "%PROJECT_DIR%\Model\1\preprocessor.pkl"      goto missing_models
if not exist "%PROJECT_DIR%\Model\2\final_ensemble.pkl"    goto missing_models
if not exist "%PROJECT_DIR%\Model\2\preprocessor.pkl"      goto missing_models
if not exist "%PROJECT_DIR%\Model\2\selected_features.txt" goto missing_models
if not exist "%PROJECT_DIR%\Model\3\network_intelligence.py" goto missing_models
goto models_ok

:missing_models
color 0C
echo [ERROR] One or more ML model files are missing from the Model\ folder.
echo Make sure the entire PhishScope folder was copied, including Model\1\, Model\2\, Model\3\.
echo.
pause
exit /b 1

:models_ok
echo [OK] All model files found.
echo.

:: ── Find Python ────────────────────────────────────────────────────
echo [*] Checking Python installation...
set "PYTHON_CMD="

python --version >nul 2>&1
if "%errorlevel%"=="0" set "PYTHON_CMD=python"

if not defined PYTHON_CMD (
    py -3.12 --version >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=py -3.12"
)
if not defined PYTHON_CMD (
    py -3.11 --version >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=py -3.11"
)
if not defined PYTHON_CMD (
    py -3 --version >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=py -3"
)

if not defined PYTHON_CMD (
    color 0C
    echo [ERROR] Python 3.11 or 3.12 was not found on this PC.
    echo.
    echo  Download it from: https://www.python.org/downloads/
    echo  During install, tick "Add python.exe to PATH".
    echo.
    pause
    exit /b 1
)

%PYTHON_CMD% --version
echo.

:: ── Validate venv — detect broken venvs copied from another PC ─────
:: If venv exists but its python.exe does not actually run,
:: delete it so it gets recreated fresh for THIS machine.
if exist "%VENV_DIR%\Scripts\python.exe" (
    "%VENV_DIR%\Scripts\python.exe" --version >nul 2>&1
    if errorlevel 1 (
        echo [!] Found a virtual environment but it appears to be from a different PC.
        echo [*] Deleting broken venv and creating a fresh one for this machine...
        rmdir /s /q "%VENV_DIR%"
        if exist "%REQ_HASH_FILE%" del /f /q "%REQ_HASH_FILE%"
        if exist "%PLAYWRIGHT_MARKER%" del /f /q "%PLAYWRIGHT_MARKER%"
        echo [OK] Old venv removed.
        echo.
    ) else (
        echo [OK] Existing virtual environment is valid.
        echo.
    )
)

:: ── Create venv if it does not exist ──────────────────────────────
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    %PYTHON_CMD% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        color 0C
        echo [ERROR] Failed to create the virtual environment.
        echo Try moving the project folder to Desktop or Documents and run again.
        echo.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
    echo.
)

:: ── Activate venv ─────────────────────────────────────────────────
echo [*] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"
if errorlevel 1 (
    color 0C
    echo [ERROR] Could not activate the virtual environment.
    echo.
    pause
    exit /b 1
)

:: ── Install dependencies (skips if requirements.txt has not changed) ─
echo [*] Checking Python packages...
python -c "import hashlib,pathlib,sys; req=pathlib.Path(r'%REQ_FILE%'); marker=pathlib.Path(r'%REQ_HASH_FILE%'); h=hashlib.sha256(req.read_bytes()).hexdigest(); sys.exit(0 if marker.exists() and marker.read_text().strip()==h else 1)"
if errorlevel 1 (
    echo [*] Installing packages from requirements.txt - needs internet, takes a few minutes...
    python -m pip install --upgrade pip --quiet
    pip install -r "%REQ_FILE%"
    if errorlevel 1 (
        color 0C
        echo [ERROR] Package installation failed.
        echo Check your internet connection and run this file again.
        echo.
        pause
        exit /b 1
    )
    python -c "import hashlib,pathlib; req=pathlib.Path(r'%REQ_FILE%'); marker=pathlib.Path(r'%REQ_HASH_FILE%'); marker.write_text(hashlib.sha256(req.read_bytes()).hexdigest())"
    echo [OK] All packages installed.
) else (
    echo [OK] Packages already up to date.
)
echo.

:: ── Install Playwright Chromium browser ───────────────────────────
if not exist "%PLAYWRIGHT_MARKER%" (
    echo [*] Installing Playwright Chromium browser (one-time, ~150MB)...
    python -m playwright install chromium
    if errorlevel 1 (
        color 0E
        echo [WARNING] Playwright Chromium was not installed.
        echo Screenshots will be unavailable, but everything else works fine.
    ) else (
        echo ready > "%PLAYWRIGHT_MARKER%"
        echo [OK] Playwright Chromium ready.
    )
) else (
    echo [OK] Playwright Chromium already installed.
)
echo.

:: ── Create required directories ────────────────────────────────────
if not exist "%APP_DIR%\data"             mkdir "%APP_DIR%\data"             >nul 2>&1
if not exist "%APP_DIR%\runtime"          mkdir "%APP_DIR%\runtime"          >nul 2>&1
if not exist "%APP_DIR%\static\screenshots" mkdir "%APP_DIR%\static\screenshots" >nul 2>&1

:: ── Write a portable .env with correct paths for THIS machine ──────
:: This overwrites any stale hardcoded paths from a different PC.
echo [*] Writing configuration for this machine...
(
    echo APP_ENV=development
    echo APP_ROLE=web
    echo APP_HOST=127.0.0.1
    echo APP_PORT=5000
    echo FLASK_DEBUG=0
    echo FLASK_SECRET_KEY=dev-only-secret-key-change-for-production
    echo APP_REQUIRE_AUTH=1
    echo APP_USERNAME=admin
    echo APP_PASSWORD=admin
    echo DATABASE_URL=
    echo REDIS_URL=
    echo ENABLE_BACKGROUND_WORKER=1
    echo WORKER_POLL_INTERVAL_SECONDS=2
    echo WORKER_MAX_RETRIES=5
    echo WORKER_STALE_AFTER_SECONDS=300
    echo REQUEST_TIMEOUT_SECONDS=5
    echo EXTERNAL_TIMEOUT_SECONDS=4
    echo OLLAMA_TIMEOUT_SECONDS=18
    echo SCREENSHOT_TIMEOUT_MS=15000
    echo PHISHING_MODEL_DIR=
    echo OLLAMA_URL=http://127.0.0.1:11434/api/generate
    echo OLLAMA_MODEL=deepseek:1.5b
) > "%APP_DIR%\.env"

echo [OK] Configuration ready. Paths auto-detected for this machine.
echo.

:: ── Set env vars for this session ─────────────────────────────────
set "APP_ENV=development"
set "APP_ROLE=web"
set "APP_HOST=127.0.0.1"
set "APP_PORT=5000"
set "FLASK_DEBUG=0"
set "FLASK_SECRET_KEY=dev-only-secret-key-change-for-production"
set "APP_REQUIRE_AUTH=1"
set "APP_USERNAME=admin"
set "APP_PASSWORD=admin"
set "DATABASE_URL="
set "REDIS_URL="
set "ENABLE_BACKGROUND_WORKER=1"
set "PHISHING_MODEL_DIR="
set "OLLAMA_URL=http://127.0.0.1:11434/api/generate"
set "OLLAMA_MODEL=deepseek:1.5b"

:: ── Launch ────────────────────────────────────────────────────────
echo =================================================================
echo                    STARTING PHISHSCOPE
echo =================================================================
echo  URL      :  %APP_URL%
echo  Login    :  admin
echo  Password :  admin
echo.
echo  Keep this window open while using the app.
echo  Press Ctrl+C to stop the server.
echo =================================================================
echo.

start "" "%APP_URL%"
cd /d "%APP_DIR%"
python app.py

echo.
echo Server stopped.
pause
