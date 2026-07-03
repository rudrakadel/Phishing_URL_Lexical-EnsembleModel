@echo off
title Kill Development Servers

echo.
echo ==========================================
echo     KILLING DEVELOPMENT SERVERS
echo ==========================================
echo.

echo [1/6] Killing Python processes...
taskkill /F /IM python.exe >nul 2>&1
taskkill /F /IM pythonw.exe >nul 2>&1

echo [2/6] Killing Chrome / Chromium...
taskkill /F /IM chrome.exe >nul 2>&1
taskkill /F /IM msedge.exe >nul 2>&1

echo [3/6] Checking common development ports...

for %%p in (5000 7860 8000 8080 3000 8501) do (
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%%p ^| findstr LISTENING') do (
echo Killing PID %%a on port %%p
taskkill /F /PID %%a >nul 2>&1
)
)

echo [4/6] Cleaning orphaned processes...
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM uvicorn.exe >nul 2>&1

echo [5/6] Displaying remaining Python processes...
tasklist | findstr python

echo [6/6] Done.

echo.
echo ==========================================
echo ALL KNOWN DEV SERVERS TERMINATED
echo ==========================================
echo.

pause
