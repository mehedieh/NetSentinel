# Launch NetSentinel. Missing/outdated packages are installed automatically on start.
#   .\run.ps1          standard user (least privilege)
#   .\run.ps1 -Admin   elevated (UAC prompt) for EStats, packet capture, firewall, DNS log
param([switch]$Admin)
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\python.exe")) { & "$PSScriptRoot\setup.ps1" }
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$main = Join-Path $PSScriptRoot "main.py"
if (-not (Test-Path $py)) { Write-Host "Setup did not complete (.venv missing). Run setup.bat and read its output." -ForegroundColor Red; exit 1 }
if ($Admin) {
    # Elevated console that stays open if NetSentinel exits with an error.
    $cmd = "Set-Location -LiteralPath '$PSScriptRoot'; & '$py' '$main'; if (`$LASTEXITCODE -ne 0) { Write-Host ''; Write-Host 'NetSentinel exited with an error (see above). Log: ' `$env:LOCALAPPDATA'\NetSentinel\logs' -ForegroundColor Red; Read-Host 'Press Enter to close' }"
    Start-Process powershell.exe -Verb RunAs -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $cmd)
} else {
    & $py $main
    if ($LASTEXITCODE -ne 0) { Write-Host "`nNetSentinel exited with code $LASTEXITCODE. Log: $env:LOCALAPPDATA\NetSentinel\logs" -ForegroundColor Red }
}
