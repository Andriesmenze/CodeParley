#Requires -RunAsAdministrator
<#
  CodeParley Windows installer (Phase 6 Increment 2; contract §6.1, §6.3, §8 A-5). Run from an ELEVATED Windows
  PowerShell 5.1 (or PowerShell 7) as an administrator. It installs the custodian and the helper services and the
  engine runtime from the staged release artifacts, checking every one against the release manifest first; no .NET
  SDK or Node.js is needed on this machine.

    codeparley-installer.ps1 install          -Release <dir> -Operator <DOMAIN\admin> -Implementer <DOMAIN\user>
    codeparley-installer.ps1 upgrade          -Release <dir>          (backs the store up, migrates it; -Resume completes)
    codeparley-installer.ps1 upgrade -Resume
    codeparley-installer.ps1 rollback                                 (the kept previous build and the backup taken for it)
    codeparley-installer.ps1 rollback -AllowLegacyRollback            (DEVELOPMENT VMs only: into a script-installed build)
    codeparley-installer.ps1 uninstall                                (keeps the store, backups, group and grants)
    codeparley-installer.ps1 purge            -ConfirmStore <path of the store>   (removes everything it installed)
    codeparley-installer.ps1 grant-repository  -Path <repository>
    codeparley-installer.ps1 revoke-repository -Path <repository>
    codeparley-installer.ps1 status

  <dir> holds release-manifest.json and the artifacts it lists. The owner verifies the manifest's signature first
  (A-4/A-5); this script then verifies the size and SHA-256 of each artifact it installs, and the BUILD-ID inside.
  It puts the `code-parley` command on the machine's PATH (<ProgramFiles>\CodeParley\bin; a new terminal sees it). The
  engine runtime is approved by the operator afterwards (`code-parley setup --repo <repository> --runtime-git-path <the
  installed git.exe>`, elevated): the installer never approves anything on the operator's behalf.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('install', 'upgrade', 'rollback', 'uninstall', 'purge', 'grant-repository', 'revoke-repository', 'status')]
  [string]$Verb,
  [string]$Release,
  [string]$Operator,
  [string]$Implementer,
  [string]$Path,
  [string]$ConfirmStore,
  [switch]$Resume,
  [switch]$AllowLegacyRollback
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ProgramRoot = Join-Path $env:ProgramFiles 'CodeParley'
$DataRoot = Join-Path $env:ProgramData 'CodeParley'
$Store = Join-Path $DataRoot 'Custodian'
$Backups = Join-Path $DataRoot 'Custodian-backups'
$RecordPath = Join-Path $DataRoot 'install-record.json'
$MarkerPath = Join-Path $DataRoot 'restore-marker.json'
$CustodianService = 'CodeParleyCustodian'
$HelperService = 'CodeParleyHelper'
$ReadersGroup = 'CodeParley Repository Readers'
$EventSource = 'CodeParley.Custodian'
$Tar = Join-Path $env:SystemRoot 'System32\tar.exe'
$AdminOnly = @('/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F')

function Fail([string]$why) { throw "codeparley-installer: $why" }

# A native program, its stderr collected as text: under 'Stop', Windows PowerShell 5.1 turns a native program's stderr into
# a terminating error (a harmless "service not started" would abort an uninstall). The exit code stays in $LASTEXITCODE
# for the caller's explicit check.
function Run-Native {
  $exe = $args[0]
  $rest = @($args | Select-Object -Skip 1)
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { & $exe @rest 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
}
function Step([string]$what) { Write-Host "- $what" }

# ---- the install record (every item created, with hashes; administrator-only) ----

function Read-Record {
  if (-not (Test-Path -LiteralPath $RecordPath)) { return $null }
  return Get-Content -LiteralPath $RecordPath -Raw | ConvertFrom-Json
}

function Write-Record($record) {
  New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
  $json = $record | ConvertTo-Json -Depth 8
  [System.IO.File]::WriteAllText($RecordPath, $json, (New-Object System.Text.UTF8Encoding($false)))
  Run-Native icacls.exe $RecordPath /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' | Out-Null
}

function New-Record([string]$version, [string]$operator, [string]$implementer) {
  return [pscustomobject]@{
    schema = 'codeparley.install-record.v1'; version = $version; previousVersion = $null
    installedAt = (Get-Date).ToUniversalTime().ToString('o'); operator = $operator; implementer = $implementer
    legacyBin = $null; items = @(); repositories = @(); backups = @()
  }
}

function Add-Item($record, [string]$kind, [string]$name) {
  $record.items = @($record.items | Where-Object { -not ($_.kind -eq $kind -and $_.name -eq $name) }) + @([pscustomobject]@{ kind = $kind; name = $name })
}

# The `code-parley` command on the machine's PATH: always the installed build, in an administrator-owned directory.
function Set-Cli($record, [string]$version) {
  $bin = Join-Path $ProgramRoot 'bin'
  $engine = Join-Path $ProgramRoot "engine\$version"
  New-Item -ItemType Directory -Force -Path $bin | Out-Null
  [System.IO.File]::WriteAllText((Join-Path $bin 'code-parley.cmd'), "@echo off`r`n`"$engine\node.exe`" `"$engine\dist\cli\main.js`" %*`r`n", [System.Text.Encoding]::ASCII)
  $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($machine -split ';') -notcontains $bin) { [Environment]::SetEnvironmentVariable('Path', "$($machine.TrimEnd(';'));$bin", 'Machine') }
  Add-Item $record 'cli' $bin
}

function Remove-Cli {
  $bin = Join-Path $ProgramRoot 'bin'
  $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($machine -split ';') -contains $bin) { [Environment]::SetEnvironmentVariable('Path', (($machine -split ';') | Where-Object { $_ -ne $bin }) -join ';', 'Machine') }
  if (Test-Path -LiteralPath $bin) { Remove-Item -LiteralPath $bin -Recurse -Force }
}

# ---- artifacts: checked against the manifest before anything is installed (A-5) ----

function Read-Manifest([string]$dir) {
  if (-not $dir) { Fail '-Release <dir with release-manifest.json> is required' }
  $file = Join-Path $dir 'release-manifest.json'
  if (-not (Test-Path -LiteralPath $file)) { Fail "no release-manifest.json in $dir" }
  $m = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
  if ($m.schema -ne 'codeparley.release-manifest.v1') { Fail "$file is not a CodeParley release manifest" }
  Step "release $($m.version) from commit $($m.commit) (manifest SHA-256 $((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()))"
  if (-not $m.releaseCandidate) { Write-Warning 'this manifest is NOT a release candidate (a dry run: changes in the tree or an unverified commit)' }
  return $m
}

function Get-Artifact($manifest, [string]$dir, [string]$name) {
  $entry = @($manifest.artifacts | Where-Object { $_.name -eq $name })
  if ($entry.Count -ne 1) { Fail "the manifest lists no artifact $name" }
  $e = $entry[0]
  $file = Join-Path $dir $e.file
  if (-not (Test-Path -LiteralPath $file)) { Fail "$($e.file) is missing from $dir" }
  $size = (Get-Item -LiteralPath $file).Length
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
  if ($size -ne $e.size) { Fail "$($e.file) is $size bytes, the manifest says $($e.size); nothing was installed" }
  if ($sha -ne $e.sha256) { Fail "$($e.file) has SHA-256 $sha, the manifest says $($e.sha256); nothing was installed" }
  return [pscustomobject]@{ entry = $e; file = $file; sha256 = $sha }
}

function Expand-Artifact($artifact, [string]$dest) {
  if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Run-Native $Tar -xzf $artifact.file -C $dest
  if ($LASTEXITCODE -ne 0) { Fail "could not unpack $($artifact.file)" }
  $id = Get-Content -LiteralPath (Join-Path $dest 'BUILD-ID') -Raw | ConvertFrom-Json
  if ($id.commit -ne $artifact.entry.buildId.commit -or $id.version -ne $artifact.entry.buildId.version -or $id.artifact -ne $artifact.entry.name) {
    Remove-Item -LiteralPath $dest -Recurse -Force
    Fail "the BUILD-ID inside $($artifact.entry.file) does not match the manifest"
  }
}

# ---- services ----

function Get-ServicePath([string]$name) {
  $s = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
  if ($null -eq $s) { return $null }
  return $s.PathName
}

function Stop-CodeParley {
  foreach ($s in @($CustodianService, $HelperService)) {
    if (Get-Service $s -ErrorAction SilentlyContinue) { Stop-Service $s -Force -ErrorAction SilentlyContinue }
  }
}

function Set-ServicePolicy {
  # The custodian starts automatically at boot (not delayed: a delayed start left hooks without a custodian for about two
  # minutes after every boot) and is restarted twice after a crash, then left stopped (bounded). Its recovery still
  # completes before it accepts a request. The helper stays demand-started by the custodian.
  Run-Native sc.exe config $CustodianService start= auto | Out-Null
  Run-Native sc.exe failure $CustodianService reset= 86400 actions= restart/10000/restart/60000//0 | Out-Null
}

# sc.exe with a command line built here: Windows PowerShell 5.1 does not escape the quotes inside an argument that has a
# space, so a binary path with arguments ("<exe>" helper-service) would arrive mangled. Same form as HelperInstall.cs.
function Set-ServiceBinary([string]$service, [string]$imagePath) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo('sc.exe', ('config {0} binPath= "{1}"' -f $service, $imagePath.Replace('"', '\"')))
  $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
  $proc = [System.Diagnostics.Process]::Start($psi)
  $text = $proc.StandardOutput.ReadToEnd() + $proc.StandardError.ReadToEnd()
  $proc.WaitForExit()
  if ($proc.ExitCode -ne 0) { Fail "could not point $service at $imagePath (sc.exe $($proc.ExitCode): $($text.Trim()))" }
}

function Set-ServiceBinaries([string]$exe) {
  Set-ServiceBinary $CustodianService "`"$exe`""
  if (Get-Service $HelperService -ErrorAction SilentlyContinue) { Set-ServiceBinary $HelperService "`"$exe`" helper-service" }
}

function Invoke-Custodian([string]$exe, [string[]]$arguments) {
  $out = Run-Native $exe @arguments
  $code = $LASTEXITCODE
  return [pscustomobject]@{ code = $code; text = ($out | Out-String).Trim() }
}

function Get-StoreStatus([string]$exe) {
  $r = Invoke-Custodian $exe @('store-status')
  if ($r.code -ne 0) { Fail "store-status failed: $($r.text)" }
  return $r.text | ConvertFrom-Json
}

function Assert-StoreServable($status) {
  # L-1: the installer checks the store's format before it upgrades, rolls back or uninstalls.
  if ($status.kind -eq 'newer') { Fail "the store is format $($status.format), newer than this build ($($status.serves)): $($status.detail). Install the matching build, or roll back to it" }
  if ($status.kind -eq 'unreadable') { Fail "the store's format marker is unreadable: $($status.detail)" }
}

function CustodianExe([string]$version) { return Join-Path $ProgramRoot "custodian\$version\CodeParley.Custodian.exe" }

# ---- backups (L-4: SYSTEM and Administrators only; hashed; the last two kept) ----

# The store's review exports are locked to the custodian and the helper, not even administrators: an elevated installer
# reaches them only in backup mode (robocopy /B), which leaves their access lists as they are.
function Invoke-Robocopy([string[]]$arguments) {
  & robocopy.exe @arguments /B /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { Fail "robocopy failed (exit $LASTEXITCODE): $($arguments -join ' ')" }
}

# Removes a directory the store may have locked folders in.
function Clear-Locked([string]$dir) {
  if (-not (Test-Path -LiteralPath $dir)) { return }
  $empty = Join-Path $DataRoot ('.empty-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  New-Item -ItemType Directory -Force -Path $empty | Out-Null
  try { Invoke-Robocopy @($empty, $dir, '/MIR') } finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
  Remove-Item -LiteralPath $dir -Recurse -Force
}

function New-Backup($record, [string]$version, [int]$format) {
  New-Item -ItemType Directory -Force -Path $Backups | Out-Null
  Run-Native icacls.exe $Backups @AdminOnly | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $file = Join-Path $Backups "store-$stamp-$version.zip"
  $staging = Join-Path $Backups ('.staging-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  try {
    # The copy takes the backups folder's administrator-only access list.
    Invoke-Robocopy @($Store, $staging, '/E', '/COPY:DAT', '/DCOPY:T')
    [System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $file, [System.IO.Compression.CompressionLevel]::Optimal, $false)
  } catch {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    throw
  } finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
  }
  Run-Native icacls.exe $file /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' | Out-Null
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant()
  $record.backups = @($record.backups) + @([pscustomobject]@{ file = $file; sha256 = $sha; version = $version; storeFormat = $format; takenAt = (Get-Date).ToUniversalTime().ToString('o') })
  # Retention: the last two.
  $all = @($record.backups)
  if ($all.Count -gt 2) {
    foreach ($old in $all[0..($all.Count - 3)]) { Remove-Item -LiteralPath $old.file -Force -ErrorAction SilentlyContinue }
    $record.backups = $all[($all.Count - 2)..($all.Count - 1)]
  }
  Step "backed the store up to $file (SHA-256 $sha)"
  return $sha
}

# ---- verbs ----

function Install-CodeParley {
  $kept = Read-Record
  if ($kept -and $kept.version) { Fail 'CodeParley is already installed here; use upgrade (or uninstall first)' }
  if (Get-Service $CustodianService -ErrorAction SilentlyContinue) { Fail "a $CustodianService service exists without an install record (an earlier script install): use upgrade, which migrates it" }
  if (-not $Operator -or -not $Implementer) { Fail 'install needs -Operator <administrator account> and -Implementer <standard user account>' }
  if ($Operator -eq $Implementer) { Fail 'the operator must be a separate account from the implementer' }
  $m = Read-Manifest $Release
  $cust = Get-Artifact $m $Release 'custodian-windows-x64'
  $engine = Get-Artifact $m $Release 'engine-runtime-windows-x64'
  $record = New-Record $m.version $Operator $Implementer
  # After an uninstall the kept store, backups and grants stay on the record.
  if ($kept) { $record.items = @($kept.items); $record.repositories = @($kept.repositories); $record.backups = @($kept.backups) }
  $custDir = Join-Path $ProgramRoot "custodian\$($m.version)"
  $engineDir = Join-Path $ProgramRoot "engine\$($m.version)"
  Expand-Artifact $cust $custDir; Add-Item $record 'directory' $custDir
  Expand-Artifact $engine $engineDir; Add-Item $record 'directory' $engineDir
  $exe = CustodianExe $m.version
  if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) { [System.Diagnostics.EventLog]::CreateEventSource($EventSource, 'Application') }
  Add-Item $record 'event-source' $EventSource
  Write-Record $record
  $r = Invoke-Custodian $exe @('install'); if ($r.code -ne 0) { Fail "service install failed: $($r.text)" }
  Add-Item $record 'service' $CustodianService
  Set-ServicePolicy
  $r = Invoke-Custodian $exe @('provision', '--operator', $Operator, '--implementer', $Implementer); if ($r.code -ne 0) { Fail "provision failed: $($r.text)" }
  Add-Item $record 'store' $Store
  $r = Invoke-Custodian $exe @('install-helper'); if ($r.code -ne 0) { Fail "helper install failed: $($r.text)" }
  Add-Item $record 'service' $HelperService; Add-Item $record 'group' $ReadersGroup
  Set-Cli $record $m.version
  Write-Record $record
  Start-Service $CustodianService
  Step "installed CodeParley $($m.version); the custodian is $((Get-Service $CustodianService).Status)"
  Write-Host "Next: each protected repository - the implementer runs code-parley init --repo <repository>; an administrator runs this installer's grant-repository -Path <repository>; the operator, in an elevated terminal: code-parley setup --repo <repository> --home <the implementer's data home> --runtime `"$engineDir`" --runtime-git-path <the installed git.exe, e.g. C:\Program Files\Git\mingw64\bin\git.exe>"
  Write-Host "Each protected repository: codeparley-installer.ps1 grant-repository -Path <repository>"
}

function Upgrade-CodeParley {
  $record = Read-Record
  if ($Resume) {
    if (-not $record) { Fail 'nothing is installed by this installer to resume' }
    $exe = CustodianExe $record.version
    Stop-CodeParley
    $r = Invoke-Custodian $exe @('store-upgrade', '--resume')
    if ($r.code -ne 0) { Fail "the store upgrade did not complete: $($r.text). Repair it and run upgrade -Resume again, or rollback" }
    Start-Service $CustodianService
    Step "the store upgrade completed; the custodian is $((Get-Service $CustodianService).Status)"
    return
  }
  $m = Read-Manifest $Release
  $cust = Get-Artifact $m $Release 'custodian-windows-x64'
  $engine = Get-Artifact $m $Release 'engine-runtime-windows-x64'
  if (-not $record) {
    # The first upgrade of a script-installed custodian (the VM layout) migrates it, and records where it was.
    $legacy = Get-ServicePath $CustodianService
    if (-not $legacy) { Fail 'nothing is installed: use install' }
    $legacyExe = $legacy.Trim('"')
    $cfg = Get-Content -LiteralPath (Join-Path $Store 'custodian-config.json') -Raw | ConvertFrom-Json
    $record = New-Record 'legacy' $cfg.operatorAccount $cfg.implementerAccount
    $record.legacyBin = Split-Path -Parent $legacyExe
    Add-Item $record 'service' $CustodianService; Add-Item $record 'store' $Store
    if (Get-Service $HelperService -ErrorAction SilentlyContinue) { Add-Item $record 'service' $HelperService; Add-Item $record 'group' $ReadersGroup }
    Step "migrating the script-installed custodian at $legacyExe (recorded as the previous build)"
  } else {
    if ($record.version -eq $m.version) { Fail "CodeParley $($m.version) is already installed" }
    Assert-StoreServable (Get-StoreStatus (CustodianExe $record.version))
  }
  $custDir = Join-Path $ProgramRoot "custodian\$($m.version)"
  $engineDir = Join-Path $ProgramRoot "engine\$($m.version)"
  Expand-Artifact $cust $custDir
  Expand-Artifact $engine $engineDir
  $exe = CustodianExe $m.version
  $before = Get-StoreStatus $exe
  Assert-StoreServable $before
  Stop-CodeParley
  # A fresh (never started) store is served at the build's own format: its backup records the format that will be served.
  $fmt = if ($null -ne $before.format) { [int]$before.format } else { [int]$before.serves }
  # Nothing has changed yet if the backup fails: the service comes back as it was.
  try { $sha = New-Backup $record $record.version $fmt }
  catch {
    $why = $_.Exception.Message
    foreach ($d in @($custDir, $engineDir)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    Start-Service $CustodianService -ErrorAction SilentlyContinue
    Fail "the store backup failed, so nothing was upgraded and the service is running again: $why"
  }
  $record.previousVersion = $record.version
  $record.version = $m.version
  Add-Item $record 'directory' $custDir; Add-Item $record 'directory' $engineDir
  if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) { [System.Diagnostics.EventLog]::CreateEventSource($EventSource, 'Application') }
  Add-Item $record 'event-source' $EventSource
  Set-Cli $record $m.version
  Write-Record $record
  Set-ServiceBinaries $exe
  Set-ServicePolicy
  $r = Invoke-Custodian $exe @('store-upgrade', '--backup-sha256', $sha)
  if ($r.code -ne 0) { Fail "the store upgrade did not complete: $($r.text). The service stays stopped: run upgrade -Resume, or rollback" }
  # §6.3: the helper service belongs to the installation; an earlier script install without it gets it now.
  if (-not (Get-Service $HelperService -ErrorAction SilentlyContinue)) {
    $h = Invoke-Custodian $exe @('install-helper'); if ($h.code -ne 0) { Fail "helper install failed: $($h.text)" }
    Add-Item $record 'service' $HelperService; Add-Item $record 'group' $ReadersGroup
    Write-Record $record
    Step 'installed the helper service (the earlier installation had none)'
  }
  Remove-OldVersions $record
  Start-Service $CustodianService
  Step "upgraded to CodeParley $($m.version); the custodian is $((Get-Service $CustodianService).Status)"
  Write-Host "The engine runtime moved to ${engineDir}: the operator approves it again (code-parley setup --resume --repo <repository> --runtime `"$engineDir`" --runtime-git-path <git.exe>, elevated; code-parley status --repo <repository> shows what else is needed); protected reviews are refused until then. Reinstall the plugin from this release's plugin-windows archive."
}

# Only the installed build and the kept previous one stay (§6.3). Only directories this installer recorded are removed:
# anything else under the same parent (an administrator's own, or an earlier script layout's) is left as it is.
function Remove-OldVersions($record) {
  $keep = @((Join-Path $ProgramRoot "custodian\$($record.version)"), (Join-Path $ProgramRoot "engine\$($record.version)"))
  if ($record.previousVersion) { $keep += @((Join-Path $ProgramRoot "custodian\$($record.previousVersion)"), (Join-Path $ProgramRoot "engine\$($record.previousVersion)")) }
  foreach ($item in @($record.items | Where-Object { $_.kind -eq 'directory' })) {
    if ($keep -notcontains $item.name) {
      if (Test-Path -LiteralPath $item.name) { Remove-Item -LiteralPath $item.name -Recurse -Force }
      $record.items = @($record.items | Where-Object { $_.name -ne $item.name })
    }
  }
  Write-Record $record
}

function Rollback-CodeParley {
  $record = Read-Record
  if (-not $record -or -not $record.previousVersion) { Fail 'there is no kept previous build to roll back to' }
  $backup = @($record.backups | Where-Object { $_.version -eq $record.previousVersion }) | Select-Object -Last 1
  if (-not $backup) { Fail "there is no backup taken for $($record.previousVersion) (L-6: a rollback is only to the build that matches the backup)" }
  if (-not (Test-Path -LiteralPath $backup.file)) { Fail "the backup $($backup.file) is missing" }
  $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $backup.file).Hash.ToLowerInvariant()
  if ($sha -ne $backup.sha256) { Fail "the backup $($backup.file) has SHA-256 $sha, recorded $($backup.sha256): it is never restored" }
  $previousExe = if ($record.previousVersion -eq 'legacy') { Join-Path $record.legacyBin 'CodeParley.Custodian.exe' } else { CustodianExe $record.previousVersion }
  if (-not (Test-Path -LiteralPath $previousExe)) { Fail "the previous build $previousExe is missing" }
  # A rollback target must apply the restored epoch and serve the backup's store format; anything else is refused before
  # the store is touched. A script-installed (pre-restored-epoch) build is a development VM's only, never a release's.
  if ($record.previousVersion -eq 'legacy') {
    if (-not $AllowLegacyRollback) { Fail 'the previous build is a script-installed development custodian that does not apply the restored epoch: rolling back to it is not supported (development VMs only: -AllowLegacyRollback)' }
  } else {
    $serves = [int](Get-StoreStatus $previousExe).serves
    if ($null -eq $backup.storeFormat -or [int]$backup.storeFormat -ne $serves) { Fail "the backup holds store format $($backup.storeFormat), the previous build $($record.previousVersion) serves format ${serves}: it is not a compatible rollback target; nothing was changed" }
  }
  Stop-CodeParley
  Step "restoring the store from $($backup.file)"
  # The backup is unpacked first, into a staging directory INSIDE the store root (so it inherits the store's protected DACL);
  # only once that succeeded are the store's contents replaced by it. A backup that cannot be unpacked changes nothing.
  $staging = Join-Path $Store ('.restore-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  try { [System.IO.Compression.ZipFile]::ExtractToDirectory($backup.file, $staging) }
  catch {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
    Fail "the backup $($backup.file) could not be unpacked ($($_.Exception.Message)); the store is unchanged"
  }
  Clear-Locked (Join-Path $Store 'exports')
  Get-ChildItem -LiteralPath $Store -Force | Where-Object { $_.FullName -ne $staging -and -not ($record.legacyBin -and $_.FullName -eq $record.legacyBin) } | Remove-Item -Recurse -Force
  foreach ($child in Get-ChildItem -LiteralPath $staging -Force) {
    $dest = Join-Path $Store $child.Name
    if (Test-Path -LiteralPath $dest) { continue } # the kept legacy build directory
    Move-Item -LiteralPath $child.FullName -Destination $dest
  }
  Remove-Item -LiteralPath $staging -Recurse -Force
  # Without its session marker the restored store is recovered at the next start by any build, even one that does not
  # read restore markers (a store that holds records and no session marker always is).
  $session = Join-Path $Store 'session.json'
  if (Test-Path -LiteralPath $session) { Remove-Item -LiteralPath $session -Force }
  # L-5: the restore marker, administrator-written beside the store; the custodian applies the restored epoch once.
  $format = 2
  if ($record.previousVersion -ne 'legacy') { $format = (Get-StoreStatus $previousExe).format }
  else { Write-Warning 'the previous build is a script-installed custodian that does not read restore markers: it recovers the restored store as after a restart of the OS (grants suspended, approvals lapsed, loops paused, intents void), but it neither ends open runs nor voids unconsumed fix confirmations' }
  $marker = [pscustomobject]@{ restoreId = ('rst-' + [guid]::NewGuid().ToString('N').Substring(0, 16)); restoredAt = (Get-Date).ToUniversalTime().ToString('o'); backupSha256 = $sha; storeFormat = $format }
  [System.IO.File]::WriteAllText($MarkerPath, ($marker | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
  Run-Native icacls.exe $MarkerPath /inheritance:r /grant:r '*S-1-5-18:F' /grant:r '*S-1-5-32-544:F' /grant:r 'NT SERVICE\CodeParleyCustodian:R' | Out-Null
  Set-ServiceBinaries $previousExe
  $rolledFrom = $record.version
  $record.version = $record.previousVersion
  $record.previousVersion = $null
  Add-Item $record 'restore-marker' $MarkerPath
  if ($record.version -ne 'legacy') { Set-Cli $record $record.version } else { Remove-Cli }
  Write-Record $record
  Start-Service $CustodianService
  Step "rolled back from $rolledFrom to $($record.version) (restore $($marker.restoreId)); the custodian is $((Get-Service $CustodianService).Status)"
  Write-Host 'At its start the custodian ended every open protected run (restored), voided every unconsumed confirmation, suspended every grant and lapsed every approval: the operator re-confirms what is still wanted.'
}

function Remove-Installed($record, [switch]$Purge) {
  $exe = $null
  if ($record -and $record.version) { $exe = if ($record.version -eq 'legacy') { Join-Path $record.legacyBin 'CodeParley.Custodian.exe' } else { CustodianExe $record.version } }
  # L-1 before an uninstall (a purge removes the store whatever its format).
  if (-not $Purge -and $exe -and $record.version -ne 'legacy' -and (Test-Path -LiteralPath $exe)) { Assert-StoreServable (Get-StoreStatus $exe) }
  Stop-CodeParley
  if ($exe -and (Test-Path -LiteralPath $exe)) {
    if (Get-Service $HelperService -ErrorAction SilentlyContinue) { $null = Invoke-Custodian $exe @('uninstall-helper') }
    $null = Invoke-Custodian $exe @('uninstall')
  } else {
    foreach ($s in @($HelperService, $CustodianService)) { if (Get-Service $s -ErrorAction SilentlyContinue) { Run-Native sc.exe delete $s | Out-Null } }
  }
  Remove-Cli
  # The directories this installer recorded; their parents only when nothing else is left in them.
  if ($record) { foreach ($item in @($record.items | Where-Object { $_.kind -eq 'directory' })) { if (Test-Path -LiteralPath $item.name) { Remove-Item -LiteralPath $item.name -Recurse -Force } } }
  foreach ($d in @((Join-Path $ProgramRoot 'custodian'), (Join-Path $ProgramRoot 'engine'), $ProgramRoot)) {
    if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force)) { Remove-Item -LiteralPath $d -Force }
  }
  if ($record -and $record.legacyBin -and (Test-Path -LiteralPath $record.legacyBin)) { Remove-Item -LiteralPath $record.legacyBin -Recurse -Force }
  if ([System.Diagnostics.EventLog]::SourceExists($EventSource)) { [System.Diagnostics.EventLog]::DeleteEventSource($EventSource) }
}

function Uninstall-CodeParley {
  $record = Read-Record
  Remove-Installed $record
  if ($record) {
    $record.items = @($record.items | Where-Object { $_.kind -in @('store', 'group', 'restore-marker') })
    $record.version = $null; $record.previousVersion = $null; $record.legacyBin = $null
    Write-Record $record
  }
  Step 'uninstalled: the services, the binaries, the engine runtime and the event source are removed'
  Write-Host 'Kept (each removed by `codeparley-installer.ps1 purge -ConfirmStore <store>`):'
  Write-Host "  the protected store   $Store"
  Write-Host "  the backups           $Backups"
  Write-Host "  the group             $ReadersGroup"
  if ($record) { foreach ($r in @($record.repositories)) { Write-Host "  the repository grant  $($r.path)   (revoke: codeparley-installer.ps1 revoke-repository -Path `"$($r.path)`")" } }
}

function Purge-CodeParley {
  if ($ConfirmStore -ne $Store) { Fail "purge removes the protected store, its backups and every grant: confirm by naming the store exactly: -ConfirmStore `"$Store`"" }
  $record = Read-Record
  Remove-Installed $record -Purge
  $problems = @()
  if ($record) {
    foreach ($r in @($record.repositories)) {
      Run-Native icacls.exe $r.path /remove:g "$ReadersGroup" /T /C /Q | Out-Null
      if ($LASTEXITCODE -ne 0) { $problems += "the grant on $($r.path) (icacls exit $LASTEXITCODE)" }
      Remove-WalkGrant $r
    }
  }
  foreach ($p in @($Store, $Backups, $MarkerPath, $RecordPath)) {
    if (Test-Path -LiteralPath $p) {
      try {
        if ($p -eq $Store) { Clear-Locked (Join-Path $Store 'exports') }
        Remove-Item -LiteralPath $p -Recurse -Force
      } catch { $problems += "$p ($($_.Exception.Message))" }
    }
  }
  if (Get-LocalGroup -Name $ReadersGroup -ErrorAction SilentlyContinue) {
    try { Remove-LocalGroup -Name $ReadersGroup } catch { $problems += "the group $ReadersGroup ($($_.Exception.Message))" }
  }
  if ($problems.Count -gt 0) { Write-Warning ("purge could not remove: " + ($problems -join '; ')); exit 1 }
  Step 'purged: everything the installer created is removed'
}

# The custodian resolves a repository's identity by opening every folder on its path with read-attributes only. It gets
# that from the parent's listing, which a user profile does not give: the repository and each folder below the profile
# (or below the drive's top level) get read-attributes for the custodian's service SID, and the repository also
# read-control (the custodian checks the readers' grant on it), nothing else. The profile itself is not changed; the SID
# is used because the name stops resolving once the service is gone.
function Get-WalkedPaths([string]$full) {
  $users = Split-Path -Parent $env:PUBLIC
  $paths = @()
  $p = $full
  while ($true) {
    $parent = Split-Path -Parent $p
    if (-not $parent -or $parent -eq [System.IO.Path]::GetPathRoot($full) -or $parent -ieq $users) { break }
    $paths += $p
    $p = $parent
  }
  if ($paths.Count -eq 0) { $paths = @($full) }
  return $paths
}

function Remove-WalkGrant($entry) {
  if ($entry.PSObject.Properties['walked']) {
    foreach ($d in @($entry.walked)) { if (Test-Path -LiteralPath $d) { Run-Native icacls.exe $d /remove:g "*$($entry.custodianSid)" /C /Q | Out-Null } }
  }
}

function Grant-Repository {
  if (-not $Path) { Fail 'grant-repository needs -Path <repository>' }
  $record = Read-Record; if (-not $record) { Fail 'CodeParley is not installed by this installer' }
  $full = (Resolve-Path -LiteralPath $Path).ProviderPath
  Run-Native icacls.exe $full /grant "${ReadersGroup}:(OI)(CI)(RX)" | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "icacls could not grant $ReadersGroup read on $full" }
  $sid = ([System.Security.Principal.NTAccount]"NT SERVICE\$CustodianService").Translate([System.Security.Principal.SecurityIdentifier]).Value
  $walked = @(Get-WalkedPaths $full)
  foreach ($d in $walked) {
    $rights = if ($d -eq $full) { '(RA,RC)' } else { '(RA)' }
    Run-Native icacls.exe $d /grant "*${sid}:$rights" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "icacls could not grant the custodian read-attributes on $d" }
  }
  $record.repositories = @(@($record.repositories) | Where-Object { $_.path -ne $full }) + @([pscustomobject]@{ path = $full; grantedAt = (Get-Date).ToUniversalTime().ToString('o'); walked = $walked; custodianSid = $sid })
  Write-Record $record
  Step "granted $ReadersGroup read and traverse on $full, and the custodian read-attributes on $($walked.Count) folder(s) of its path (recorded)"
}

function Revoke-Repository {
  if (-not $Path) { Fail 'revoke-repository needs -Path <repository>' }
  $record = Read-Record; if (-not $record) { Fail 'CodeParley is not installed by this installer' }
  $full = (Resolve-Path -LiteralPath $Path).ProviderPath
  Run-Native icacls.exe $full /remove:g "$ReadersGroup" /T /C /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail "icacls could not remove the grant on $full" }
  foreach ($r in @($record.repositories | Where-Object { $_.path -eq $full })) { Remove-WalkGrant $r }
  $record.repositories = @(@($record.repositories) | Where-Object { $_.path -ne $full })
  Write-Record $record
  Step "revoked $ReadersGroup on $full"
}

function Show-Status {
  $record = Read-Record
  foreach ($s in @($CustodianService, $HelperService)) {
    $svc = Get-Service $s -ErrorAction SilentlyContinue
    if ($svc) { Write-Host ("{0,-22} {1,-9} {2}" -f $s, $svc.Status, (Get-ServicePath $s)) } else { Write-Host ("{0,-22} not installed" -f $s) }
  }
  if ($record) {
    Write-Host "installed version      $($record.version) (previous: $($record.previousVersion))"
    $exe = if ($record.version -eq 'legacy') { Join-Path $record.legacyBin 'CodeParley.Custodian.exe' } elseif ($record.version) { CustodianExe $record.version } else { $null }
    if ($exe -and (Test-Path -LiteralPath $exe)) { Write-Host "store                  $((Invoke-Custodian $exe @('store-status')).text)" }
    foreach ($b in @($record.backups)) { Write-Host "backup                 $($b.file) ($($b.version), SHA-256 $($b.sha256))" }
    foreach ($r in @($record.repositories)) { Write-Host "repository grant       $($r.path)" }
  } else { Write-Host 'no install record (not installed by this installer)' }
}

switch ($Verb) {
  'install' { Install-CodeParley }
  'upgrade' { Upgrade-CodeParley }
  'rollback' { Rollback-CodeParley }
  'uninstall' { Uninstall-CodeParley }
  'purge' { Purge-CodeParley }
  'grant-repository' { Grant-Repository }
  'revoke-repository' { Revoke-Repository }
  'status' { Show-Status }
}
