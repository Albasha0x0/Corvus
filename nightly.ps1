# The nightly run of this machine: a full run of HEAD in the background worktree once the machine is idle (it holds
# the heavy lock), then the perf run in a worktree of its own, which is skipped when another full run holds or waits
# for the heavy lock by then. Opt-in: -Register adds a Windows scheduled task that runs this script daily; nothing registers it otherwise. Each step is logged to .git/corvus-nightly.log, the
# test output to .git/corvus-nightly.log.run.
# Usage:  ./nightly.ps1                         # one nightly run now (what the task runs)
#         ./nightly.ps1 -Register [-At 02:00]   # registers the task for the current user (-Strength routine|exhaustive|whole)
#         ./nightly.ps1 -Unregister             # removes it
# The task runs while the user is logged on and sees the user's environment variables (CORVUS_*, CORVUS_HEAVY_LOCK).
#Requires -Version 7.0
param(
    [switch]$Register,
    [switch]$Unregister,
    [string]$At = '02:00',
    [ValidateSet('routine', 'exhaustive', 'whole')][string]$Strength = 'whole',
    [string]$TaskName = 'Corvus nightly tests'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$gitDir = [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root)
$nightlyLog = Join-Path $gitDir 'corvus-nightly.log'
# The output of the night's test.ps1 calls, replaced each night.
$runLog = "$nightlyLog.run"

if ($Register -or $Unregister) {
    if (-not $IsWindows) { Write-Host 'The nightly task is a Windows scheduled task; use cron or a systemd timer elsewhere.' -ForegroundColor Red; exit 1 }
    if ($Unregister) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed the scheduled task '$TaskName'."
        exit 0
    }
    $pwsh = (Get-Process -Id $PID).Path
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -File `"$PSCommandPath`" -Strength $Strength" -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    # It starts once the machine has been idle for 10 minutes, waiting up to 4 hours for that, and keeps running when
    # the user returns; a night the machine was off starts when it is on again; a night still running when the next
    # starts keeps going.
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration (New-TimeSpan -Minutes 10) -IdleWaitTimeout (New-TimeSpan -Hours 4) `
        -DontStopOnIdleEnd -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 12)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "Registered '$TaskName': daily at $At once the machine is idle, a $Strength full run of $root, then the perf run. Log: $nightlyLog"
    exit 0
}

function Write-Nightly([string]$message) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm') $message"
    Add-Content -Path $nightlyLog -Value $line
    Write-Host $line
}

$commit = (git -C $root rev-parse --short HEAD).Trim()
$askedAt = Get-Date
Write-Nightly "start: $Strength full run of $commit"
# The night's run analyses 3 engine seeds cold again; push runs leave the check off.
$env:CORVUS_SEED_VALIDATE = '3'
$flags = @{ Full = $true; Background = $true }
if ($Strength -eq 'whole') { $flags.Whole = $true } elseif ($Strength -eq 'exhaustive') { $flags.Exhaustive = $true }
& (Join-Path $root 'test.ps1') @flags *> $runLog

# The night's run is the first background run started since it asked: one going then takes the request from the
# queue when it ends, on the newest commit queued. Push runs queued behind it are not waited for. A run's process
# starts the queued run after removing both files, so the wait also lasts while that process lives.
$running = Join-Path $gitDir 'corvus-background.json'
$queued = Join-Path $gitDir 'corvus-background.next'
$asked = $askedAt.ToUniversalTime().Ticks
$own = $null; $dispatcher = $null
function Get-RunProcess($record) {
    if ($record) { Get-Process -Id $record.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $record.started } }
}
while ($true) {
    if ($own) {
        if (-not (Get-RunProcess $own)) { break }
    }
    else {
        $record = Get-Content $running -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $alive = Get-RunProcess $record
        if ($record -and $record.started -ge $asked) { $own = $record; continue }
        if ($alive) { $dispatcher = $alive }
        elseif (-not (Test-Path $queued) -and -not ($dispatcher -and -not $dispatcher.HasExited)) { break }
    }
    Start-Sleep -Seconds 5
}
# The run's own record in the test history: corvus-background.result names the latest run, which may be a push run.
$ran = if ($own) {
    $since = $askedAt.ToString('yyyy-MM-dd HH:mm')
    Get-Content (Join-Path $gitDir 'corvus-test-history.jsonl') -ErrorAction SilentlyContinue | Where-Object { $_.Contains('"kind":"run"') } |
        ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.commit -and $own.commit.StartsWith($_.commit) -and $_.at -ge $since } | Select-Object -Last 1
}
$outcome = if ($ran) { "$($ran.commit) $(if ($ran.code -eq 0) { 'passed' } else { "FAILED (exit $($ran.code))" }) at $($ran.at)" }
    elseif ($own) { "$($own.commit.Substring(0, 8)) ended without a record in the test history" } else { 'no run started' }
Write-Nightly "full run: $outcome (asked on $commit at $($askedAt.ToString('yyyy-MM-dd HH:mm')))"

# The lock script's status names a holder "heavy: <name>" and a waiter "heavy waiting: <name>"; full runs are corvus-full-<pid>.
if ($env:CORVUS_HEAVY_LOCK -and (& $env:CORVUS_HEAVY_LOCK status | Where-Object { $_ -match '^heavy( waiting)?: corvus-full-' })) {
    Write-Nightly 'perf run skipped: another full run holds or waits for the heavy lock'
    exit 0
}
# The perf run builds in a worktree of its own on the commit the full run tested, so the checkout and the push runs'
# worktree stay free. Checking out the next night's commit there keeps bin/obj; a broken worktree is made again.
$tested = if ($own) { $own.commit } else { (git -C $root rev-parse HEAD).Trim() }
$bgRoot = if ($env:CORVUS_BACKGROUND_DIR) { $env:CORVUS_BACKGROUND_DIR } else { [IO.Path]::GetTempPath() }
$dir = Join-Path $bgRoot 'corvus-perf-worktree'
$reused = $false
if (Test-Path (Join-Path $dir '.git')) {
    git -C $dir checkout --quiet --detach --force $tested 2>$null
    if ($LASTEXITCODE -eq 0) { git -C $dir clean -fdq 2>$null; $reused = $LASTEXITCODE -eq 0 }
}
if (-not $reused) {
    if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    git -C $root worktree prune
    git -C $root worktree add --detach $dir $tested 2>$null | Out-Null
}
if ("$(git -C $dir rev-parse HEAD 2>$null)".Trim() -ne $tested) {
    Write-Nightly "perf run not run: $dir is not a worktree of $($tested.Substring(0, 8))"
    exit 1
}
& (Join-Path $dir 'test.ps1') -Perf *>> $runLog
$code = $LASTEXITCODE
Write-Nightly "perf run: $(if ($code -eq 0) { 'no regression confirmed' } else { "FAILED (exit $code)" })"
exit $code
