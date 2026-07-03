@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title PhishScope Setup and Launcher

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\launch_phishscope.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
    echo PhishScope launcher exited with code %EXIT_CODE%.
)
pause
exit /b %EXIT_CODE%
