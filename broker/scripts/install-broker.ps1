#Requires -RunAsAdministrator
<#
  Phase 3.1C operator step 1/3: publish the broker as a self-contained single-file exe, install it as
  a LocalSystem Windows service, provision the dedicated worker identity (account + random password in
  an LSA secret), the trusted roots, and the EXPLICIT trusted controller SID (hardening 4A), then start
  the service. Run from an ELEVATED PowerShell.

  -Controller names the single operator/controller account whose SID the broker will authorize (pipe
  ACL + exact impersonated-SID check). It defaults to the account running this script (a specific
  operator SID, printed below) — never "all administrators". Pass a different account or SID to override.
#>
param(
    [string]$Bin = (Join-Path $env:ProgramData 'CodeParley\broker\bin'),
    [string]$Controller = "$env:USERDOMAIN\$env:USERNAME",
    [string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$proj = Resolve-Path (Join-Path $PSScriptRoot '..\CodeParley.Broker')

# Make re-runnable: stop + remove any existing service so the published exe is not locked.
if (Get-Service CodeParleyBroker -ErrorAction SilentlyContinue) {
    Write-Host "existing service found; stopping + removing for a clean reinstall ..."
    Stop-Service CodeParleyBroker -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}
# Force-kill any lingering/stuck broker process + its child tree, so the published exe is unlocked.
Get-Process CodeParley.Broker -ErrorAction SilentlyContinue | ForEach-Object { & taskkill /PID $_.Id /T /F 2>$null | Out-Null }
if (Get-Service CodeParleyBroker -ErrorAction SilentlyContinue) { & sc.exe delete CodeParleyBroker | Out-Null; Start-Sleep -Seconds 2 }

New-Item -ItemType Directory -Force $Bin | Out-Null
Write-Host "publishing self-contained single-file broker to $Bin ..."
dotnet publish $proj -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o $Bin
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed ($LASTEXITCODE)" }

$exe = Join-Path $Bin 'CodeParley.Broker.exe'
if (-not (Test-Path $exe)) { throw "publish did not produce $exe" }

# Resolve + show the controller SID being granted, so the trust is explicit (not silent).
try { $sid = (New-Object System.Security.Principal.NTAccount($Controller)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
catch { if ($Controller -match '^S-1-') { $sid = $Controller } else { throw "cannot resolve controller '$Controller' to a SID: $($_.Exception.Message)" } }
Write-Host "trusted controller: $Controller  ($sid)"

Write-Host "installing service ...";   & $exe install                         ; if ($LASTEXITCODE -ne 0) { throw "install failed" }
Write-Host "provisioning worker + controller SID ..."; & $exe provision --controller $Controller ; if ($LASTEXITCODE -ne 0) { throw "provision failed" }
Write-Host "starting service ...";      Start-Service CodeParleyBroker
Get-Service CodeParleyBroker | Format-List Name, Status, StartType
Write-Host "`nBroker installed and running. Next: run proof-harness.ps1 (elevated)."
