@echo off
echo ==========================================================
echo          Starting Guardstack ASPM Platform...
echo ==========================================================

set SCRIPT_DIR=%~dp0
set WORKSPACE_ROOT=%SCRIPT_DIR%..
set PYTHONPATH=%WORKSPACE_ROOT%\.venv\Lib\site-packages;%WORKSPACE_ROOT%\backend

echo [1/2] Starting FastAPI Backend on http://127.0.0.1:8000...
start "Guardstack Backend" cmd /k "cd /d %WORKSPACE_ROOT%\backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo [2/2] Starting React Vite Frontend on http://127.0.0.1:5173...
start "Guardstack Frontend" cmd /k "cd /d %WORKSPACE_ROOT%\frontend && bun run dev"

echo Guardstack is running!
echo Dashboard: http://127.0.0.1:5173
echo API Docs:  http://127.0.0.1:8000/docs
