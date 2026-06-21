@echo off
setlocal
title Network Incident Response Orchestrator

cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python was not found. Install Python or create .venv first.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

if not exist "ui\dist\index.html" (
    echo [INFO] UI bundle is missing. Building it now...
    where npm.cmd >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] npm was not found. Install Node.js, then run this file again.
        pause
        exit /b 1
    )
    call npm.cmd run build --workspace ui
    if errorlevel 1 (
        echo [ERROR] UI build failed.
        pause
        exit /b 1
    )
)

echo.
echo [INFO] Starting Network Incident Response Orchestrator...
echo [INFO] Open http://127.0.0.1:8000/operations
echo [INFO] Press Ctrl+C in this window to stop the project.
echo.

start "" "http://127.0.0.1:8000/operations"
%PYTHON% -m uvicorn app.web.server:app --host 127.0.0.1 --port 8000

endlocal
