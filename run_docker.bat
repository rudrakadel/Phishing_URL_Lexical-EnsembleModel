@echo off
cd /d "%~dp0"
title PhishScope Docker Launcher
color 0A
echo =================================================================
echo             PHISHSCOPE THREAT INTELLIGENCE SYSTEM
echo                  Docker Automated Launcher
echo =================================================================
echo.

:: 1. Check if Docker is installed
echo [*] Checking if Docker is installed...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Docker is not installed or not running on your computer.
    echo Please download and install Docker Desktop from:
    echo https://www.docker.com/products/docker-desktop/
    echo.
    pause
    exit /b
)
echo [OK] Docker is installed.
echo.

:: 2. Check if Docker Daemon is running
echo [*] Verifying if Docker Desktop is running...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Docker Desktop is installed but NOT running.
    echo Please open the "Docker Desktop" application on your computer,
    echo wait for the Docker engine to start, and then try running this script again.
    echo.
    pause
    exit /b
)
echo [OK] Docker engine is running.
echo.

:: 3. Setup Configuration
echo [*] Setting up environment variables (.env)...
if not exist flask_phishing_app\.env (
    copy flask_phishing_app\.env.example flask_phishing_app\.env >nul
    echo [OK] Fresh .env configuration file created.
) else (
    echo [OK] Existing configuration detected.
)
echo.

:: 4. Launch Stack
echo =================================================================
echo               BUILDING AND RUNNING DOCKER CONTAINERS
echo =================================================================
echo [*] Spinning up PostgreSQL, Redis, Web App, and Worker...
echo [*] Opening http://localhost:5000 in your browser...
start http://localhost:5000

docker compose up --build
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Docker Compose failed to build or start.
)
pause
