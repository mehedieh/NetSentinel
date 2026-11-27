# One-time setup: creates a virtual environment and installs/updates all packages.
# Usage (normal PowerShell, no admin needed):
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1            # required packages
#   powershell -ExecutionPolicy Bypass -File .\setup.ps1 -Optional  # + scapy, maxminddb
param([switch]$Optional)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = $null
foreach ($v in @("3.13", "3.12")) {
    try { & py "-$v" -c "import sys" 2>$null; if ($LASTEXITCODE -eq 0) { $py = @("py", "-$v"); break } } catch {}
}
if (-not $py) {
    Write-Host "Python 3.12 or 3.13 not found. Installing Python 3.13 with winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.13 --scope user --accept-package-agreements --accept-source-agreements
    $py = @("py", "-3.13")
}
Write-Host "Using: $(& $py[0] $py[1] --version)"
if (-not (Test-Path ".venv\Scripts\python.exe")) { & $py[0] $py[1] -m venv .venv }
$vpy = ".\.venv\Scripts\python.exe"
& $vpy -m pip install --upgrade pip
$req = if ($Optional) { "requirements-optional.txt" } else { "requirements.txt" }
& $vpy -m pip install --upgrade -r $req
& $vpy -c "import tkinter; tkinter.Tcl()" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nPython's Tcl/Tk component is missing - NetSentinel cannot open its window." -ForegroundColor Red
    Write-Host "Fix: Settings > Apps > Python 3.13 > Modify > tick 'tcl/tk and IDLE' > Install" -ForegroundColor Yellow
    Write-Host "  or: winget install -e --id Python.Python.3.13 --force" -ForegroundColor Yellow
    Write-Host "Then delete the .venv folder and run setup.bat again." -ForegroundColor Yellow
    exit 1
}
& $vpy main.py --check
Write-Host "`nSetup complete. Start with:  .\run.ps1" -ForegroundColor Green
if ($Optional) { Write-Host "Packet capture also needs Npcap: https://npcap.com" -ForegroundColor Yellow }
