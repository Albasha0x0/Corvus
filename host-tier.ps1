# Runs test.ps1 -HostTier on HEAD in its own worktree; the tier's classes run on the test host CORVUS_TEST_REMOTE
# names, and the families they pass are recorded.
# This machine only builds and reads results back, so the task has no idle condition.
# Log: .git/corvus-host-tier.log; test.ps1 output: .git/corvus-host-tier.log.run.
# Usage:  ./host-tier.ps1                         # one run now (what the task runs)
#         ./host-tier.ps1 -Register [-At 02:00]   # adds a daily scheduled task for the current user (opt-in)
#         ./host-tier.ps1 -Unregister             # removes it
# The task runs while the user is logged on and sees the user's environment variables (CORVUS_TEST_REMOTE).
#Requires -Version 7.0
param(
    [switch]$Register,
    [switch]$Unregister,
    [string]$At = '02:00',
    [string]$TaskName = 'Corvus host tier tests'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$gitDir = [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root)
$tierLog = Join-Path $gitDir 'corvus-host-tier.log'
$runLog = "$tierLog.run"

if ($Register -or $Unregister) {
    if (-not $IsWindows) { Write-Host 'The host tier task is a Windows scheduled task; use cron or a systemd timer elsewhere.' -ForegroundColor Red; exit 1 }
    if ($Unregister) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Removed the scheduled task '$TaskName'."
        exit 0
    }
    $pwsh = (Get-Process -Id $PID).Path
    $action = New-ScheduledTaskAction -Execute $pwsh -Argument "-NoProfile -File `"$PSCommandPath`"" -WorkingDirectory $root
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    # A night the machine was off starts when it is on again; a run still going when the next starts keeps going.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 8)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Write-Host "Registered '$TaskName': daily at $At, the host tier of $root on the test host. Log: $tierLog"
    exit 0
}

function Write-Tier([string]$message) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm') $message"
    Add-Content -Path $tierLog -Value $line
    Write-Host $line
}

$commit = (git -C $root rev-parse HEAD).Trim()
# One worktree serves every night: checking out the next commit keeps bin/obj, so the build for the keys is
# incremental. Untracked files go; a missing or broken worktree is made again.
$bgRoot = if ($env:CORVUS_BACKGROUND_DIR) { $env:CORVUS_BACKGROUND_DIR } else { [IO.Path]::GetTempPath() }
$dir = Join-Path $bgRoot 'corvus-tier-worktree'
$reused = $false
if (Test-Path (Join-Path $dir '.git')) {
    git -C $dir checkout --quiet --detach --force $commit 2>$null
    if ($LASTEXITCODE -eq 0) { git -C $dir clean -fdq 2>$null; $reused = $LASTEXITCODE -eq 0 }
}
if (-not $reused) {
    if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    git -C $root worktree prune
    git -C $root worktree add --detach $dir $commit | Out-Null
}
if ("$(git -C $dir rev-parse HEAD 2>$null)".Trim() -ne $commit) {
    Write-Tier "not run: $dir is not a worktree of $($commit.Substring(0, 8))"
    exit 1
}
Write-Tier "start: host tier of $($commit.Substring(0, 8))"
& (Join-Path $dir 'test.ps1') -HostTier *> $runLog
$code = $LASTEXITCODE
Write-Tier "host tier: $(if ($code -eq 0) { 'passed' } else { "FAILED (exit $code)" })"
exit $code
