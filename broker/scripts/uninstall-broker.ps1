#Requires -RunAsAdministrator
<#
  Phase 3.1C operator step 3/3: stop + remove the service, deprovision the worker identity (LSA secret
  + account) and the trusted controller config, and optionally purge the broker's ProgramData tree.
  Run from an ELEVATED PowerShell.
#>
param([switch]$Purge)
$ErrorActionPreference = 'Continue'
$brokerHome = Join-Path $env:ProgramData 'CodeParley\broker'
$exe = Join-Path $brokerHome 'bin\CodeParley.Broker.exe'

try { Stop-Service CodeParleyBroker -ErrorAction SilentlyContinue } catch {}
if (Test-Path $exe) { & $exe uninstall; & $exe deprovision }
else { & sc.exe delete CodeParleyBroker | Out-Null }

if ($Purge) { Remove-Item -Recurse -Force $brokerHome -ErrorAction SilentlyContinue }
Write-Host "uninstalled (Purge=$Purge)."
Write-Host "account removed = $(-not [bool](Get-LocalUser -Name 'cp-worker' -ErrorAction SilentlyContinue))"
Write-Host "service removed = $(-not [bool](Get-Service CodeParleyBroker -ErrorAction SilentlyContinue))"
