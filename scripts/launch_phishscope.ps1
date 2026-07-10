Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$AppDir = Join-Path $ProjectDir "flask_phishing_app"
$VenvDir = Join-Path $ProjectDir ".venv"
$ReqFile = Join-Path $AppDir "requirements.txt"
$ReqHashFile = Join-Path $VenvDir ".requirements.sha256"
$PlaywrightMarker = Join-Path $VenvDir ".playwright_chromium_installed"
$VersionsDir = Join-Path $ProjectDir ".phishscope_versions"
$AppUrl = "http://127.0.0.1:5000"
$OllamaUrl = "http://127.0.0.1:11434"
$OllamaModel = "deepseek-r1:1.5b"
$script:LocalSecret = ""

function Write-Step($Message) {
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok($Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn($Message) {
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Fail($Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Robocopy($Source, $Destination, [switch]$Mirror) {
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $mode = if ($Mirror) { "/MIR" } else { "/E" }
    $args = @(
        $Source,
        $Destination,
        $mode,
        "/R:1",
        "/W:1",
        "/XD",
        ".git",
        ".venv",
        ".phishscope_versions",
        "dist",
        "unnecessary",
        "__pycache__",
        ".pytest_cache",
        "data",
        "runtime",
        "screenshots",
        "/XF",
        "*.pyc",
        "*.pyo",
        "*.log",
        "*.tmp"
    )
    & robocopy @args | Out-Null
    if ($LASTEXITCODE -ge 8) {
        Fail "File copy failed. Robocopy exit code: $LASTEXITCODE"
    }
}

function New-RestoreSnapshot {
    New-Item -ItemType Directory -Force -Path $VersionsDir | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $snapshot = Join-Path $VersionsDir $stamp
    Write-Step "Creating restore snapshot: $snapshot"
    Invoke-Robocopy -Source $ProjectDir -Destination $snapshot
    $manifest = @(
        "PhishScope restore snapshot",
        "Created: $(Get-Date -Format o)",
        "Source: $ProjectDir",
        "Restore behavior: source files are restored; runtime logs, virtualenv, git data, screenshots, dist, and legacy folders are excluded."
    )
    Set-Content -Path (Join-Path $snapshot "RESTORE_INFO.txt") -Value $manifest -Encoding UTF8
    Write-Ok "Restore snapshot created."
}

function Get-Snapshots {
    if (-not (Test-Path $VersionsDir)) {
        return @()
    }
    return @(Get-ChildItem -Path $VersionsDir -Directory | Sort-Object Name -Descending)
}

function Show-Snapshots {
    $snapshots = Get-Snapshots
    if ($snapshots.Count -eq 0) {
        Write-Warn "No restore snapshots found."
        return
    }
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host ("{0}. {1}" -f ($i + 1), $snapshots[$i].Name)
    }
}

function Restore-Snapshot {
    $snapshots = Get-Snapshots
    if ($snapshots.Count -eq 0) {
        Write-Warn "No restore snapshots found."
        return
    }

    Show-Snapshots
    $choice = Read-Host "Restore which snapshot number?"
    $index = 0
    if (-not [int]::TryParse($choice, [ref]$index) -or $index -lt 1 -or $index -gt $snapshots.Count) {
        Write-Warn "Invalid snapshot selection."
        return
    }

    $snapshot = $snapshots[$index - 1].FullName
    Write-Warn "This will overwrite current project files from snapshot '$($snapshots[$index - 1].Name)'."
    $confirm = Read-Host "Type RESTORE to continue"
    if ($confirm -ne "RESTORE") {
        Write-Warn "Restore cancelled."
        return
    }

    Invoke-Robocopy -Source $snapshot -Destination $ProjectDir -Mirror
    Write-Ok "Restore completed. Restart the launcher to run the restored version."
    exit 0
}

function Invoke-VersionPrompt {
    while ($true) {
        Write-Host ""
        Write-Host "Startup version control"
        Write-Host "C - Create restore snapshot, then start"
        Write-Host "S - Start without snapshot"
        Write-Host "R - Restore a previous snapshot"
        Write-Host "L - List snapshots"
        Write-Host "Q - Quit"
        $rawAnswer = Read-Host "Choose"
        if ($null -eq $rawAnswer) {
            exit 0
        }
        $answer = $rawAnswer.Trim().ToUpperInvariant()
        switch ($answer) {
            "C" { New-RestoreSnapshot; return }
            "S" { return }
            "R" { Restore-Snapshot }
            "L" { Show-Snapshots }
            "Q" { exit 0 }
            default { Write-Warn "Choose C, S, R, L, or Q." }
        }
    }
}

function Test-RequiredFiles {
    $required = @(
        (Join-Path $AppDir "app.py"),
        (Join-Path $ProjectDir "Model\1\tier1_url_model.pkl"),
        (Join-Path $ProjectDir "Model\1\preprocessor.pkl"),
        (Join-Path $ProjectDir "Model\2\final_ensemble.pkl"),
        (Join-Path $ProjectDir "Model\2\preprocessor.pkl"),
        (Join-Path $ProjectDir "Model\2\selected_features.txt"),
        (Join-Path $ProjectDir "Model\3\network_intelligence.py")
    )
    $missing = @($required | Where-Object { -not (Test-Path $_) })
    if ($missing.Count -gt 0) {
        Fail "Missing required files:`n$($missing -join "`n")"
    }
    Write-Ok "Required app and model files found."
}

function Find-Python {
    $commands = @(
        @("python"),
        @("py", "-3.12"),
        @("py", "-3.11"),
        @("py", "-3")
    )
    foreach ($cmd in $commands) {
        try {
            if ($cmd.Count -eq 1) {
                & $cmd[0] --version *> $null
            } else {
                & $cmd[0] $cmd[1] --version *> $null
            }
            if ($LASTEXITCODE -eq 0) {
                return ,$cmd
            }
        } catch {
        }
    }
    Fail "Python 3.11 or 3.12 was not found. Install Python and enable 'Add python.exe to PATH'."
}

function Invoke-Python($PythonCommand, [string[]]$Arguments) {
    if ($PythonCommand.Count -eq 1) {
        & $PythonCommand[0] @Arguments
    } else {
        & $PythonCommand[0] $PythonCommand[1] @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        Fail "Python command failed: $($Arguments -join ' ')"
    }
}

function Ensure-Venv {
    param([object[]]$PythonCommand)

    $venvPython = Join-Path $VenvDir "Scripts\python.exe"
    if (Test-Path $venvPython) {
        & $venvPython --version *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Existing virtual environment is valid."
            return $venvPython
        }

        Write-Warn "Existing virtual environment is broken. Recreating it."
        Remove-Item -LiteralPath $VenvDir -Recurse -Force
    }

    Write-Step "Creating virtual environment."
    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "venv", $VenvDir)
    Write-Ok "Virtual environment ready."
    return $venvPython
}

function Ensure-Packages {
    param([string]$PythonExe)

    Write-Step "Checking Python packages."
    $currentHash = (Get-FileHash -Path $ReqFile -Algorithm SHA256).Hash
    $storedHash = if (Test-Path $ReqHashFile) { (Get-Content $ReqHashFile -Raw).Trim() } else { "" }
    if ($currentHash -eq $storedHash) {
        Write-Ok "Packages already match requirements.txt."
        return
    }

    Write-Step "Installing packages from requirements.txt."
    & $PythonExe -m pip install --upgrade pip --quiet
    if ($LASTEXITCODE -ne 0) { Fail "pip upgrade failed." }
    & $PythonExe -m pip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) { Fail "Package installation failed." }
    Set-Content -Path $ReqHashFile -Value $currentHash -Encoding ASCII
    Write-Ok "Packages installed."
}

function Ensure-Playwright {
    param([string]$PythonExe)

    if (Test-Path $PlaywrightMarker) {
        Write-Ok "Playwright Chromium already installed."
        return
    }

    Write-Step "Installing Playwright Chromium browser."
    & $PythonExe -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Playwright Chromium was not installed. Screenshots may be unavailable."
        return
    }

    Set-Content -Path $PlaywrightMarker -Value "ready" -Encoding ASCII
    Write-Ok "Playwright Chromium ready."
}

function Test-OllamaApi {
    try {
        Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 3 | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Ensure-Ollama {
    $ollamaCommand = Get-Command "ollama" -ErrorAction SilentlyContinue
    if (-not $ollamaCommand) {
        Write-Warn "Ollama is not installed or not on PATH. AI review will use heuristic fallback."
        return
    }

    if (-not (Test-OllamaApi)) {
        Write-Step "Starting Ollama."
        Start-Process -FilePath $ollamaCommand.Source -ArgumentList "serve" -WindowStyle Hidden | Out-Null
        $deadline = (Get-Date).AddSeconds(20)
        while ((Get-Date) -lt $deadline) {
            if (Test-OllamaApi) {
                break
            }
            Start-Sleep -Seconds 2
        }
    }

    if (-not (Test-OllamaApi)) {
        Write-Warn "Ollama did not respond on $OllamaUrl. AI review will use heuristic fallback."
        return
    }

    $tags = Invoke-RestMethod -Uri "$OllamaUrl/api/tags" -TimeoutSec 5
    $availableModels = @($tags.models | ForEach-Object { $_.name })
    if ($availableModels -notcontains $OllamaModel) {
        Write-Warn "Configured Ollama model '$OllamaModel' is not installed. Installed models: $($availableModels -join ', ')"
        Write-Warn "Run: ollama pull $OllamaModel"
        return
    }

    Write-Ok "Ollama is reachable. Model selected: $OllamaModel"
}

function Write-LocalEnv {
    New-Item -ItemType Directory -Force -Path (Join-Path $AppDir "data") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $AppDir "runtime") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $AppDir "static\screenshots") | Out-Null

    $envPath = Join-Path $AppDir ".env"
    $secretBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($secretBytes)
    } finally {
        $rng.Dispose()
    }
    $secret = [Convert]::ToBase64String($secretBytes)
    $script:LocalSecret = $secret
    $content = @(
        "APP_ENV=development",
        "APP_ROLE=web",
        "APP_HOST=127.0.0.1",
        "APP_PORT=5000",
        "FLASK_DEBUG=0",
        "FLASK_SECRET_KEY=$secret",
        "APP_REQUIRE_AUTH=1",
        "APP_USERNAME=admin",
        "APP_PASSWORD=admin",
        "DATABASE_URL=",
        "REDIS_URL=",
        "ENABLE_BACKGROUND_WORKER=1",
        "WORKER_POLL_INTERVAL_SECONDS=2",
        "WORKER_MAX_RETRIES=5",
        "WORKER_STALE_AFTER_SECONDS=300",
        "BATCH_MAX_URLS=150",
        "REQUEST_TIMEOUT_SECONDS=5",
        "EXTERNAL_TIMEOUT_SECONDS=4",
        "OLLAMA_TIMEOUT_SECONDS=18",
        "SCREENSHOT_TIMEOUT_MS=15000",
        "PHISHING_MODEL_DIR=",
        "OLLAMA_URL=http://127.0.0.1:11434/api/generate",
        "OLLAMA_MODEL=$OllamaModel"
    )
    Set-Content -Path $envPath -Value $content -Encoding ASCII
    Write-Ok "Local .env written for this machine."
}

function Set-AppEnvironment {
    $env:APP_ENV = "development"
    $env:APP_ROLE = "web"
    $env:APP_HOST = "127.0.0.1"
    $env:APP_PORT = "5000"
    $env:FLASK_DEBUG = "0"
    $env:FLASK_SECRET_KEY = $script:LocalSecret
    $env:APP_REQUIRE_AUTH = "1"
    $env:APP_USERNAME = "admin"
    $env:APP_PASSWORD = "admin"
    $env:DATABASE_URL = ""
    $env:REDIS_URL = ""
    $env:ENABLE_BACKGROUND_WORKER = "1"
    $env:BATCH_MAX_URLS = "150"
    $env:PHISHING_MODEL_DIR = ""
    $env:OLLAMA_URL = "$OllamaUrl/api/generate"
    $env:OLLAMA_MODEL = $OllamaModel
}

Write-Host "================================================================="
Write-Host "            PHISHSCOPE THREAT INTELLIGENCE SYSTEM"
Write-Host "                  Windows Setup and Launcher"
Write-Host "================================================================="
Write-Host ""
Write-Host "Running from: $ProjectDir"

Invoke-VersionPrompt
Test-RequiredFiles
$pythonCommand = Find-Python
if ($pythonCommand.Count -eq 1) {
    $pythonDisplay = (& $pythonCommand[0] --version) -join " "
} else {
    $pythonDisplay = (& $pythonCommand[0] $pythonCommand[1] --version) -join " "
}
Write-Ok "Python found: $pythonDisplay"
$venvPython = Ensure-Venv -PythonCommand $pythonCommand
Ensure-Packages -PythonExe $venvPython
Ensure-Playwright -PythonExe $venvPython
Ensure-Ollama
Write-LocalEnv
Set-AppEnvironment

Write-Host ""
Write-Host "================================================================="
Write-Host "                    STARTING PHISHSCOPE"
Write-Host "================================================================="
Write-Host "URL      : $AppUrl"
Write-Host "Login    : admin"
Write-Host "Password : admin"
Write-Host "Health   : $AppUrl/health"
Write-Host ""
Write-Host "Keep this window open while using the app. Press Ctrl+C to stop."
Write-Host "================================================================="
Write-Host ""

Start-Process $AppUrl
Push-Location $AppDir
try {
    & $venvPython "app.py"
} finally {
    Pop-Location
}
