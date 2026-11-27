# Launch NetSentinel. Missing/outdated packages are installed automatically on start.
#   .\run.ps1          standard user (least privilege)
#   .\run.ps1 -Admin   elevated (UAC prompt) for EStats, packet capture, firewall, DNS log
param([switch]$Admin)
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) { & "$PSScriptRoot\setup.ps1" }
$pyw = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$main = Join-Path $PSScriptRoot "main.py"
if ($Admin) { Start-Process -FilePath $pyw -ArgumentList "`"$main`"" -Verb RunAs -WorkingDirectory $PSScriptRoot }
else { & $pyw $main }
