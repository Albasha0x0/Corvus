# The nightly run of this machine: a full run of HEAD in the background worktree once the machine is idle (it holds
# the heavy lock), then the perf run, which is skipped when another full run holds or waits for the heavy lock by
# then. Opt-in: -Register adds a Windows scheduled task that runs this script daily; nothing registers it otherwise. Each step is logged to .git/corvus-nightly.log, the
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
Write-Nightly "start: $Strength full run of $commit"
# The night's run analyses 3 engine seeds cold again; push runs leave the check off.
$env:CORVUS_SEED_VALIDATE = '3'
$flags = @{ Full = $true; Background = $true }
if ($Strength -eq 'whole') { $flags.Whole = $true } elseif ($Strength -eq 'exhaustive') { $flags.Exhaustive = $true }
& (Join-Path $root 'test.ps1') @flags *> $runLog

# The run and any run queued behind it end before the perf run.
& (Join-Path $root 'test.ps1') -Wait *>> $runLog
Write-Nightly "full run: $(Get-Content (Join-Path $gitDir 'corvus-background.result') -Raw -ErrorAction SilentlyContinue)"

# The lock script's status names a holder "heavy: <name>" and a waiter "heavy waiting: <name>"; full runs are corvus-full-<pid>.
if ($env:CORVUS_HEAVY_LOCK -and (& $env:CORVUS_HEAVY_LOCK status | Where-Object { $_ -match '^heavy( waiting)?: corvus-full-' })) {
    Write-Nightly 'perf run skipped: another full run holds or waits for the heavy lock'
    exit 0
}
& (Join-Path $root 'test.ps1') -Perf *>> $runLog
$code = $LASTEXITCODE
Write-Nightly "perf run: $(if ($code -eq 0) { 'no regression confirmed' } else { "FAILED (exit $code)" })"
exit $code
