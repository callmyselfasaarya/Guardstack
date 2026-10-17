# Guardstack Local Development Launcher
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Starting Guardstack ASPM Platform...            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$WorkspaceRoot = (Get-Item $PSScriptRoot).Parent.FullName
$env:PYTHONPATH = "$WorkspaceRoot\.venv\Lib\site-packages;$WorkspaceRoot\backend"

Write-Host "`n[1/2] Starting FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Yellow
$BackendJob = Start-Process -FilePath "python" -ArgumentList "-m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload" -WorkingDirectory "$WorkspaceRoot\backend" -PassThru

Start-Sleep -Seconds 2

Write-Host "[2/2] Starting React Vite Frontend on http://127.0.0.1:5173..." -ForegroundColor Green
$FrontendJob = Start-Process -FilePath "bun" -ArgumentList "run dev" -WorkingDirectory "$WorkspaceRoot\frontend" -PassThru

Write-Host "`nGuardstack is live at:" -ForegroundColor Cyan
Write-Host "  -> Web Dashboard:  http://127.0.0.1:5173" -ForegroundColor Green
Write-Host "  -> API Docs:       http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "`nPress Ctrl+C to stop servers." -ForegroundColor Gray

try {
    Wait-Process -Id $BackendJob.Id, $FrontendJob.Id
} finally {
    Stop-Process -Id $BackendJob.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $FrontendJob.Id -Force -ErrorAction SilentlyContinue
}
