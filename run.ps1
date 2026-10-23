# One-command start for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
python -m pip install -q -r backend/requirements.txt
if (-not (Test-Path "frontend/dist/index.html")) {
  Push-Location frontend; npm install --no-audit --no-fund; npm run build; Pop-Location
}
Write-Host "PatchPilot AI running at http://localhost:8000  (API docs: /docs)"
Set-Location backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
