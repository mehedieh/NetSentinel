# Builds dist\NetSentinel.exe (portable; no Python needed on the target PC).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path ".venv\Scripts\python.exe")) { & "$root\setup.ps1" }
$py = "$root\.venv\Scripts\python.exe"
& $py -m pip install --upgrade -r requirements-dev.txt
& $py -m pytest -q
if ($LASTEXITCODE -ne 0) { Write-Error "Tests failed - not building." }
& $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build\work build\netsentinel.spec
Write-Host "`nBuilt: $root\dist\NetSentinel.exe" -ForegroundColor Green
