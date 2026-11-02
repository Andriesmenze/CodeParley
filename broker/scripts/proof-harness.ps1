#Requires -RunAsAdministrator
<#
  Phase 3.1C operator step 2/3: drive the stabilized Windows broker through its named-pipe IPC (as the
  elevated operator/controller) and exercise the common-contract behaviours, saving raw evidence.

  Covers: capability verification; a clean proof-battery run with broker-side write-denial verification;
  single-active admission (capacity_exceeded); broker Terminate; execution timeout (timed_out);
  detached-straggler cleanup (unclean); broker graceful shutdown (interrupted); simulated host crash
  recovery (lost); and exact-SID authorization (a non-controller elevated admin is refused at the pipe).

  Each step writes a JSON file into -OutDir; a summary.json + console table conclude. Run ELEVATED.
#>
param(
    [string]$OutDir = (Join-Path $PSScriptRoot ("proof-evidence-" + (Get-Date -Format 'yyyyMMddHHmmss'))),
    [string]$Bin = (Join-Path $env:ProgramData 'CodeParley\broker\bin'),
    [string]$Controller = "$env:USERDOMAIN\$env:USERNAME",
    [switch]$SkipAuthTest
)
$ErrorActionPreference = 'Stop'
$exe = Join-Path $Bin 'CodeParley.Broker.exe'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$results = [System.Collections.Generic.List[object]]::new()
function Record($name, $pass, $detail) { $results.Add([pscustomobject]@{ step = $name; pass = [bool]$pass; detail = "$detail" }); Write-Host ("[{0}] {1} -- {2}" -f $(if ($pass) { 'PASS' } else { 'FAIL' }), $name, $detail) }
function Save($name, $obj) { $obj | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $OutDir "$name.json") -Encoding UTF8 }

function Send-Broker([hashtable]$req, [switch]$ExpectConnectFail) {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'CodeParley.Broker',
        [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
    try {
        try { $pipe.Connect(5000) }
        catch { if ($ExpectConnectFail) { return [pscustomobject]@{ connectDenied = $true; error = $_.Exception.Message } } else { throw } }
        if ($ExpectConnectFail) { return [pscustomobject]@{ connectDenied = $false; note = 'connected unexpectedly' } }
        $sw = New-Object System.IO.StreamWriter($pipe); $sw.AutoFlush = $true
        $sr = New-Object System.IO.StreamReader($pipe)
        $sw.WriteLine(($req | ConvertTo-Json -Compress))
        $readTask = $sr.ReadLineAsync()
        if (-not $readTask.Wait(150000)) { throw "broker did not respond within 150s (op=$($req.op))" }
        return ($readTask.Result | ConvertFrom-Json)
    } finally { $pipe.Dispose() }
}

function Launch-AndWait($runId, $workload, $timeoutSec, $pollSeconds = 60) {
    $req = @{ version = 1; op = 'LaunchWorkload'; runId = $runId; workloadKey = $workload }
    if ($timeoutSec) { $req.timeoutSeconds = $timeoutSec }
    $launch = Send-Broker $req
    if (-not $launch.ok) { return $launch }
    $terminal = 'exited','timed_out','terminated','interrupted','unclean','failed','lost'
    $deadline = (Get-Date).AddSeconds($pollSeconds); $status = $null
    do {
        Start-Sleep -Seconds 2
        $status = Send-Broker @{ version = 1; op = 'GetStatus'; runId = $runId }
    } while (($status.state -notin $terminal) -and ((Get-Date) -lt $deadline))
    return $status
}

Write-Host "=== CodeParley Windows broker stabilization proof -> $OutDir ===`n"

# A. capability verification (runs inside the LocalSystem service via IPC).
try {
    $cap = Send-Broker @{ version = 1; op = 'Capabilities' }; Save 'A-capabilities' $cap
    $v = [bool]$cap.capabilities.verified
    Record 'A capabilities verified' $v ("verified=$($cap.capabilities.verified) controllerSid=$($cap.capabilities.ipc.controllerSid)")
} catch { Record 'A capabilities verified' $false $_.Exception.Message }

# B. clean proof-battery + broker-side write-denial verification.
try {
    $rid = 'proofb' + (Get-Date -Format 'yyyyMMddHHmmss')
    $st = Launch-AndWait $rid 'proof-battery' $null 90; Save 'B-proof-battery' $st
    $res = if ($st.resultJson) { $st.resultJson | ConvertFrom-Json } else { $null }
    $okState = $st.state -eq 'exited' -and [int]$st.exitCode -eq 0
    $toolingOk = $res -and $res.tooling.gitToplevel.ok -and $res.tooling.gitStatus.ok -and $res.tooling.nodeChildInNested.ok -and $res.tooling.npmNoop.ok
    $deniedOk = $res -and (-not $res.anyDeniedWriteSucceeded)
    $verif = $st.verification
    $brokerVerif = $verif -and $verif.deniedDirectoriesClean -and $verif.deniedFilesUnchanged -and ($verif.leaks.Count -eq 0)
    Record 'B exited+code0' $okState "state=$($st.state) exit=$($st.exitCode)"
    Record 'B tooling works' $toolingOk "git/node/npm nested all ok=$toolingOk"
    Record 'B worker: no denied write' $deniedOk "anyDeniedWriteSucceeded=$($res.anyDeniedWriteSucceeded)"
    Record 'B broker-verified denials' $brokerVerif "dirsClean=$($verif.deniedDirectoriesClean) filesUnchanged=$($verif.deniedFilesUnchanged) leaks=$($verif.leaks.Count)"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $rid } | Out-Null
} catch { Record 'B proof-battery' $false $_.Exception.Message }

# C. single-active admission + broker Terminate.
try {
    $a = 'liveA' + (Get-Date -Format 'yyyyMMddHHmmss')
    $la = Send-Broker @{ version = 1; op = 'LaunchWorkload'; runId = $a; workloadKey = 'lifecycle-tree' }
    Start-Sleep -Seconds 2
    $b = 'liveB' + (Get-Date -Format 'yyyyMMddHHmmss')
    $lb = Send-Broker @{ version = 1; op = 'LaunchWorkload'; runId = $b; workloadKey = 'lifecycle-tree' }
    Save 'C-single-active' @{ launchA = $la; launchB = $lb }
    Record 'C single-active rejects 2nd' (-not $lb.ok -and $lb.errorCode -eq 'capacity_exceeded') "B.errorCode=$($lb.errorCode)"
    $term = Send-Broker @{ version = 1; op = 'Terminate'; runId = $a }; Save 'C-terminate' $term
    Record 'C terminate' ($term.state -eq 'terminated') "A.state=$($term.state)"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $a } | Out-Null
    if ($lb.ok) { Send-Broker @{ version = 1; op = 'Cleanup'; runId = $b } | Out-Null }
} catch { Record 'C single-active/terminate' $false $_.Exception.Message }

# D. execution timeout (broker-enforced wall-clock limit).
try {
    $rid = 'timeout' + (Get-Date -Format 'yyyyMMddHHmmss')
    $st = Launch-AndWait $rid 'lifecycle-tree' 5 40; Save 'D-timeout' $st
    Record 'D timed_out' ($st.state -eq 'timed_out') "state=$($st.state)"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $rid } | Out-Null
} catch { Record 'D timeout' $false $_.Exception.Message }

# E. detached straggler -> unclean (main exits 0, descendant force-killed; never reported `exited`).
try {
    $rid = 'unclean' + (Get-Date -Format 'yyyyMMddHHmmss')
    $st = Launch-AndWait $rid 'lifecycle-detached' $null 40; Save 'E-unclean' $st
    Record 'E unclean (not exited)' ($st.state -eq 'unclean') "state=$($st.state)"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $rid } | Out-Null
} catch { Record 'E unclean' $false $_.Exception.Message }

# F. broker graceful shutdown while a run is active -> interrupted (recorded durably).
try {
    $rid = 'interrupt' + (Get-Date -Format 'yyyyMMddHHmmss')
    Send-Broker @{ version = 1; op = 'LaunchWorkload'; runId = $rid; workloadKey = 'lifecycle-tree' } | Out-Null
    Start-Sleep -Seconds 3
    Stop-Service CodeParleyBroker -Force; Start-Sleep -Seconds 2
    Start-Service CodeParleyBroker; Start-Sleep -Seconds 2
    $st = Send-Broker @{ version = 1; op = 'GetStatus'; runId = $rid }; Save 'F-interrupted' $st
    Record 'F interrupted (graceful stop)' ($st.state -eq 'interrupted') "state=$($st.state)"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $rid } | Out-Null
} catch { Record 'F interrupted' $false $_.Exception.Message }

# G. simulated host crash (ungraceful kill) -> lost + stale workspace removed on recovery.
try {
    $rid = 'lost' + (Get-Date -Format 'yyyyMMddHHmmss')
    Send-Broker @{ version = 1; op = 'LaunchWorkload'; runId = $rid; workloadKey = 'lifecycle-tree' } | Out-Null
    Start-Sleep -Seconds 3
    Get-Process CodeParley.Broker -ErrorAction SilentlyContinue | ForEach-Object { & taskkill /PID $_.Id /T /F 2>$null | Out-Null }
    Start-Sleep -Seconds 2
    Start-Service CodeParleyBroker; Start-Sleep -Seconds 2
    $st = Send-Broker @{ version = 1; op = 'GetStatus'; runId = $rid }; Save 'G-lost' $st
    $wsGone = -not (Test-Path (Join-Path $env:ProgramData "CodeParley\broker\work\$rid"))
    Record 'G lost (crash recovery)' ($st.state -eq 'lost') "state=$($st.state)"
    Record 'G stale workspace removed' $wsGone "workspaceGone=$wsGone"
    Send-Broker @{ version = 1; op = 'Cleanup'; runId = $rid } | Out-Null
} catch { Record 'G lost' $false $_.Exception.Message }

# H. exact-SID authorization: a non-controller elevated admin is refused at the pipe ACL.
if (-not $SkipAuthTest) {
    try {
        Stop-Service CodeParleyBroker -Force; Start-Sleep -Seconds 1
        & $exe provision --controller 'S-1-5-20' | Out-Null   # NETWORK SERVICE: a valid, non-operator SID
        Start-Service CodeParleyBroker; Start-Sleep -Seconds 2
        $denied = Send-Broker @{ version = 1; op = 'Ping' } -ExpectConnectFail
        Save 'H-unauthorized' $denied
        Record 'H non-controller admin denied' ([bool]$denied.connectDenied) "connectDenied=$($denied.connectDenied) ($($denied.error))"
    } catch { Record 'H unauthorized' $false $_.Exception.Message }
    finally {
        Stop-Service CodeParleyBroker -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1
        & $exe provision --controller $Controller | Out-Null
        Start-Service CodeParleyBroker -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2
        $ok = Send-Broker @{ version = 1; op = 'Ping' }
        Record 'H controller restored' ([bool]$ok.ok) "ping.ok=$($ok.ok)"
    }
}

$summary = [pscustomobject]@{
    host = $env:COMPUTERNAME; when = (Get-Date).ToString('o'); controller = $Controller
    passed = @($results | Where-Object pass).Count; total = $results.Count; results = $results
}
Save 'summary' $summary
Write-Host "`n==== $($summary.passed)/$($summary.total) checks passed ====`nEvidence bundle: $OutDir"
Write-Host "Send the bundle back for the HOST-CONTRACT-STABILIZED gate."
