# Runs the tests: the quick set by default. -Full adds slow, IDA and Ghidra tests (CORVUS_GHIDRA_DIR) and stamps a
# clean tree it passed on, so -Full -IfChanged and release.ps1 skip a repeat.
# Usage:  ./test.ps1                      # before each commit: the quick tests of the families changed since origin/main
#         ./test.ps1 -All                 # the whole quick set
#         ./test.ps1 -Full                # full suite (before a release or a gate run)
#         ./test.ps1 -Full -IfChanged     # full suite unless it already passed on this exact tree
#         ./test.ps1 -Full -Exhaustive    # every sweep input, not a quarter, and the Tier=Release tests (gates and releases)
#         ./test.ps1 -Affected            # quick set plus the slow tests of the families changed since origin/main (before a push)
#         ./test.ps1 -Filter <expr>       # any dotnet test filter, quick or full
#         ./test.ps1 -Full -Reuse         # only the families whose inputs changed since their last full pass (test-reuse.psm1)
#         ./test.ps1 -Full -Background    # after a push: -Reuse on HEAD (or -Commit) in its own worktree; returns at once
#                                         #   (-Exhaustive: patch release strength; -Whole: exhaustive without reuse)
#         ./test.ps1 -SecondGhidra        # the Engines tests with CORVUS_SECOND_GHIDRA_DIR, unless they passed on these inputs
#         ./test.ps1 -Status              # the last background run: passed / failed / running, its log, and run times;
#                                         #   the CI and release workflow results on GitHub (gh), unknown without gh
#         ./test.ps1 -Wait                # returns when the background run and any run queued behind it end: 0 passed, 1 not
#         ./test.ps1 -Perf                # the speed measurements with their budgets, alone on the machine (nightly, after -Full)
#         ./test.ps1 -Stamp               # records the last full run's passes when its recording step failed (same tree only)
#         ./test.ps1 -RemoteRun -Group sweep -Shard 0/2  # CI: one shard of a group a push run offloads (test-remote.psm1)
#         ./test.ps1 -Full -Coverage      # also collects line coverage (coverlet) and checks Ratchets/coverage.txt
#         ./test.ps1 -CoverageMap         # source files each family and slow class runs, for -Reuse (refreshed weekly)
#         ./test.ps1 -Mutation [-Target sqlite,pe]  # mutation testing of the core readers (Stryker.NET; tests/mutation.json),
#                                         #   surviving mutants checked against Ratchets/mutation-survivors.txt (gates and releases)
#Requires -Version 7.0
param(
    [switch]$Full,
    [switch]$All,
    [switch]$IfChanged,
    [switch]$Exhaustive,
    [switch]$Affected,
    [string]$Base = 'origin/main',
    [string]$Filter,
    [switch]$Background,
    [switch]$Status,
    [switch]$Reuse,
    [switch]$Whole,
    [switch]$SecondGhidra,
    [switch]$Coverage,
    [switch]$CoverageMap,
    [switch]$Mutation,
    [string[]]$Target,
    [switch]$Stamp,
    [switch]$Perf,
    [switch]$RemoteRun,
    [string]$Group = '',
    [string]$Shard = '0/1',
    [switch]$CrossPlatform,
    [string]$Commit,
    [switch]$Wait
)

$ErrorActionPreference = 'Stop'
$runClock = [Diagnostics.Stopwatch]::StartNew(); $buildSeconds = 0.0
$root = $PSScriptRoot
$tests = Join-Path $root 'tests/Corvus.Tests'
# The repository's own .git (shared by its worktrees): stamps and background results land there and are never committed.
$gitDir = [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root)
$result = Join-Path $gitDir 'corvus-background.result'
$log = Join-Path $gitDir 'corvus-background.log'
# Every run's test times (test-time.psm1): the last runs of each mode, and the report built from them.
$timeHistory = Join-Path $gitDir 'corvus-test-history.jsonl'
$timeReport = Join-Path $gitDir 'corvus-time-report.md'
# Test homes of earlier runs leave their deleted tools folders in an inherited PATH; past cmd's limit it finds no dotnet.
$tempRoot = [IO.Path]::GetTempPath()
$env:PATH = ($env:PATH -split [IO.Path]::PathSeparator | Where-Object {
    $_ -and -not ($_.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and -not (Test-Path $_)) }) -join [IO.Path]::PathSeparator

# A shell started before a CORVUS_* user variable was set (an agent's, an editor's) lacks it, and its engine and real-data
# tests skip; full and background runs take such variables from the user's environment.
function Import-UserTestVariables {
    if (-not $IsWindows) { return }
    $user = [Environment]::GetEnvironmentVariables('User')
    foreach ($name in $user.Keys) {
        if (($name -like 'CORVUS_*' -or $name -eq 'GHIDRA_INSTALL_DIR') -and -not [Environment]::GetEnvironmentVariable($name)) { Set-Item "env:$name" $user[$name] }
    }
}
if ($Full -or $Background -or $Perf) { Import-UserTestVariables }

# Test runs yield to the desktop: the builds, test hosts and engine workers they start inherit the lowered priority. The
# perf run keeps normal priority: it measures alone on the machine.
if (-not $Perf) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    Set-RunPriority
}
# MSBuild's worker nodes set their own priority, normal unless the build asks for low, so a lowered run asks for low.
$buildPriority = @(if ((Get-Process -Id $PID).PriorityClass -in 'BelowNormal', 'Idle') { '-lowPriority:true' })


# One shard of the offloaded classes, as the CI offload job runs it: results in TestResults/offload.trx. Classes are
# dealt by the seconds recorded in Support/offload-seconds.json (Save-OffloadSeconds rebuilds it from offload results).
if ($RemoteRun) {
    Import-Module (Join-Path $root 'test-remote.psm1') -Force
    $index, $count = $Shard -split '/' | ForEach-Object { [int]$_ }
    $recorded = Read-OffloadSeconds (Join-Path $tests 'Support/offload-seconds.json')
    $classes = @(Get-RemoteShard @(Get-RemoteClasses $tests $Group -CrossPlatform:$CrossPlatform) $index $count $recorded)
    if (-not $classes) { Write-Host "Shard $Shard of $(if ($Group) { $Group } else { 'every group' }) has no class."; exit 0 }
    Write-Host "Shard $Shard of $(if ($Group) { $Group } else { 'every group' }): $($classes -join ', ')"
    $env:CORVUS_ALL_TESTS = '1'; $env:CORVUS_SWEEP = if ($Exhaustive) { 'exhaustive' } else { $null }
    & dotnet test $tests --nologo @buildPriority -c Release --filter (Get-ClassFilter $classes $Exhaustive.IsPresent (Get-MixedClasses $tests)) --logger 'trx;LogFileName=offload.trx' `
        --results-directory (Join-Path $root 'TestResults') --blame-hang --blame-hang-timeout 30m --blame-hang-dump-type mini
    exit $LASTEXITCODE
}

if ($Status) {
    # The offload line covers the offloaded classes only; the CI test jobs
    # and the release build report here.
    Import-Module (Join-Path $root 'test-remote.psm1') -Force
    $showWorkflows = { Get-WorkflowStatus $root | ForEach-Object { Write-Host $_ } }
    if (-not (Test-Path $result)) { Write-Host 'No background run yet.'; & $showWorkflows; exit 0 }
    $text = (Get-Content $result -Raw).Trim()
    # A killed run, or one whose worktree broke, leaves "running" and its record behind.
    $record = Join-Path $gitDir 'corvus-background.json'
    if ($text -match ' running since ' -and (Test-Path $record)) {
        $run = Get-Content $record -Raw | ConvertFrom-Json
        $alive = Get-Process -Id $run.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $run.started }
        if (-not $alive) { $text = "$($run.commit.Substring(0, 8)) not running (pid $($run.pid) gone, no result)" }
    }
    Write-Host $text
    if (Test-Path $log) { Get-Content $log -Tail 5 | Where-Object { $_ -match '\[FAIL\]|Passed!|Failed!|Stamped' } | ForEach-Object { Write-Host "  $_" } }
    Import-Module (Join-Path $root 'test-time.psm1') -Force
    Get-IoStalls "$log.io" | ForEach-Object { Write-Host "  Slow samples: $_" }
    $dumps = @(Get-ChildItem (Join-Path $gitDir 'corvus-stalls') -File -ErrorAction SilentlyContinue)
    if ($dumps) { Write-Host "  Worker thread dumps: $($dumps.Count) in $(Join-Path $gitDir 'corvus-stalls')" }
    if (Test-Path "$log.previous") {
        $before = Get-Content "$log.previous"
        Write-Host "Previous: $(($before | Select-Object -Last 1) -replace '^Result: ', '')"
        $before | Where-Object { $_ -match '\[FAIL\]|Failed!' } | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
    }
    $times = @(Get-TimeSummary $timeHistory)
    if ($times) { Write-Host "Run times ($timeReport):"; $times | ForEach-Object { Write-Host "  $_" } }
    $misses = Join-Path $gitDir 'corvus-selection-misses.txt'
    if (Test-Path $misses) { Write-Host "Last selection miss: $(Get-Content $misses -Tail 1)" }
    Get-RemoteStatus $gitDir | ForEach-Object { Write-Host "Offload $_" }
    & $showWorkflows
    if (Get-DeferredStatus $gitDir) { Write-Host "Classes left for the nightly run: $(Get-DeferredStatus $gitDir)" }
    $nightly = Join-Path $gitDir 'corvus-nightly.log'
    if (Test-Path $nightly) { Write-Host "Nightly ($nightly): $(Get-Content $nightly -Tail 1)" }
    $verdicts = Join-Path $gitDir 'corvus-perf-verdicts.json'
    if (Test-Path $verdicts) {
        $last = Get-Content $verdicts -Raw | ConvertFrom-Json
        Write-Host "Perf run at $($last.at) on $($last.commit): $(if ($last.over) { "over budget: $($last.over -join ', ')" } else { 'every measurement within budget' })"
    }
    exit 0
}

# Starts timing a run: samples machine load, logs permit waits, and points the collection orderer at the history.
function Start-RunTiming([string]$mode) {
    $env:CORVUS_TEST_HISTORY = $timeHistory; $env:CORVUS_TEST_MODE = $mode
    Import-Module (Join-Path $root 'test-time.psm1') -Force
    $script:loadJob = try { Start-MachineLoad } catch { $null }
    $env:CORVUS_PERMIT_LOG = Join-Path $tempRoot "corvus-permits-$PID.tsv"
    Remove-Item $env:CORVUS_PERMIT_LOG -ErrorAction SilentlyContinue
}

# Builds the test project and adds its seconds to $buildSeconds.
function Invoke-TestBuild {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    & dotnet build $tests --nologo @buildPriority -v q
    $script:buildSeconds += $clock.Elapsed.TotalSeconds
}

# Quick runs start alone classes in their own test process beside the parallel ones, since what they need alone is
# per process. Receive-AloneRun waits for the job.
function Start-AloneRun([string]$filter, [string]$resultsDir, [string[]]$more = @()) {
    Start-ThreadJob -ArgumentList $tests, $buildPriority, $filter, $resultsDir, $more -ScriptBlock {
        param($tests, $priority, $filter, $resultsDir, $more)
        & dotnet test $tests --nologo @priority --no-build --filter $filter --logger 'trx;LogFileName=alone.trx' --results-directory $resultsDir @more 2>&1
        "exit=$LASTEXITCODE"
    }
}

# Waits for a Start-AloneRun job, prints its output, joins its results into $trx and returns its exit code.
function Receive-AloneRun($job, [string]$trx, [string]$resultsDir) {
    $lines = @(Receive-Job $job -Wait -AutoRemoveJob)
    $lines | Select-Object -SkipLast 1 | Out-Host
    Import-Module (Join-Path $root 'test-remote.psm1') -Force
    Join-TrxFiles $trx @($trx, (Join-Path $resultsDir 'alone.trx'))
    if ("$($lines[-1])" -match '^exit=(-?\d+)$') { [int]$Matches[1] } else { 1 }
}

# Records a run's TRX times in the history and report. Timing never fails a run: errors are printed only.
function Save-RunTimes([string]$trx, [string]$mode, [int]$code, [hashtable]$extra = @{}) {
    try {
        # The wait for the heavy lock is recorded on its own, not as run time.
        $wall = $runClock.Elapsed.TotalSeconds - $(if ($extra.heavyWait) { $extra.heavyWait } else { 0 })
        $endJob = try { Start-MachineLoad } catch { $null }
        $context = [ordered]@{ mode = $mode; commit = (git -C $root rev-parse --short HEAD).Trim(); at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); code = $code; wall = [math]::Round($wall, 1) }
        $context.loadStart = if ($script:loadJob) { Receive-Job $script:loadJob -Wait -AutoRemoveJob } else { $null }
        $context.loadEnd = if ($endJob) { Receive-Job $endJob -Wait -AutoRemoveJob } else { $null }
        $context.heavyWait = $null; $context.permits = $null
        if ($env:CORVUS_PERMIT_LOG -and (Test-Path $env:CORVUS_PERMIT_LOG)) {
            # Seconds waited per resource (or set of resources a class takes together).
            $context.permits = [ordered]@{}
            foreach ($permitWait in Import-Csv $env:CORVUS_PERMIT_LOG -Delimiter "`t" -Header resources, seconds, collection | Group-Object resources | Sort-Object Name) {
                $context.permits[$permitWait.Name] = [math]::Round(($permitWait.Group | Measure-Object { [double]::Parse($_.seconds, [cultureinfo]::InvariantCulture) } -Sum).Sum, 1)
            }
        }
        foreach ($name in $extra.Keys) { $context[$name] = $extra[$name] }
        Write-Host (Save-TestTimes $trx $context $timeHistory $timeReport)
    }
    catch { Write-Host "Recording the run times failed: $_" -ForegroundColor Yellow }
    finally {
        # Later test runs of this script (a failure rerun) log no waits.
        if ($env:CORVUS_PERMIT_LOG) { Remove-Item $env:CORVUS_PERMIT_LOG -ErrorAction SilentlyContinue; Remove-Item Env:CORVUS_PERMIT_LOG }
    }
}

# A permit wait ends 5 min (-Full) or 30 s short of the run's hang limit
# (30 min, 2 min), so a busy machine skips the collection before the hang
# dump ends the run.
$permitMaxWait = if ($Full) { '00:25:00' } else { '00:01:30' }

# Names the classes a permit wait left unrun and returns them; empty when none.
function Get-NotRun([string]$trx) {
    $notRun = @(if (Test-Path $trx) { Get-PermitSkips $trx })
    if ($notRun) { Write-Host "Not run, their permits held elsewhere past the wait limit: $($notRun -join ', '); their families stay unrecorded." -ForegroundColor Yellow }
    $notRun
}

# Perf run: Perf=Timing tests with budgets enforced, one at a time, under the heavy lock and every permit.
# Over budget counts only when most of 5 samples are; past 1.5x Ratchets/perf-baseline.txt (median of 5) regresses.
# Fails only when the previous perf run flagged the same test too, so one slow run is reported, two in a row fail.
# Other processes over 25% of the machine in over a tenth of the 10 s samples: partial, no verdict, exit 3.
$perfVerdicts = Join-Path $gitDir 'corvus-perf-verdicts.json'
if ($Perf) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    Import-Module (Join-Path $root 'test-time.psm1') -Force
    $lockName = "corvus-perf-$PID"
    $lockClock = [Diagnostics.Stopwatch]::StartNew()
    $heavy = Enter-HeavyLock $lockName
    Write-Host 'Waiting for every test permit on the machine.'
    $permits = Enter-AllPermits (Get-PermitCounts (Join-Path $tests 'Support/MachinePermits.cs'))
    $waited = [math]::Round($lockClock.Elapsed.TotalSeconds, 1)
    $saved = $env:CORVUS_PERF, $env:CORVUS_ALL_TESTS, $env:CORVUS_PERMITS_HELD
    $results = Join-Path $tempRoot "corvus-trx-perf-$PID"
    $loadLog = Join-Path $tempRoot "corvus-perf-load-$PID.log"
    $loadSampler = $null
    # Ends the run when other work loaded the machine: its timings neither confirm nor clear a verdict.
    function Exit-IfContended([string[]]$over) {
        $contention = Get-PerfContention $loadLog
        if (-not $contention) { Write-Host 'Perf run: the machine load is unknown (no sample).' -ForegroundColor Yellow; return }
        if (-not $contention.Partial) { Write-Host "Perf run: $($contention.Text)."; return }
        Write-Host "Perf run partial: $($contention.Text); no verdict recorded." -ForegroundColor Yellow
        if ($over) { Write-Host "Over budget while the machine was busy: $($over -join ', ')." -ForegroundColor Yellow }
        exit 3
    }
    try {
        $env:CORVUS_PERF = '1'; $env:CORVUS_ALL_TESTS = '1'; $env:CORVUS_PERMITS_HELD = '1'
        $serial = @('--', 'xUnit.MaxParallelThreads=1', 'xUnit.ParallelizeTestCollections=false')
        Start-RunTiming 'perf'
        $loadSampler = try { Start-LoadSampler $loadLog } catch { $null }
        $perfFilter = if ($Filter) { "Perf=Timing&($Filter)" } else { 'Perf=Timing' }
        & dotnet test $tests --nologo @buildPriority --filter $perfFilter --logger 'trx;LogFileName=full.trx' --results-directory $results @serial
        $code = $LASTEXITCODE
        $trx = Join-Path $results 'full.trx'
        $contention = Get-PerfContention $loadLog
        Save-RunTimes $trx 'perf' $code @{ heavyWait = $waited; partial = [bool]$contention.Partial; otherLoad = $contention.Text }
        $failed = @(if (Test-Path $trx) { Get-FailedTests $trx })
        if ($code -ne 0 -and -not $failed) { Write-Host "The perf run failed (exit $code) with no failed test to sample again." -ForegroundColor Red; exit $code }
        Exit-IfContended $failed
        $sample = 1
        $samples = [Collections.Generic.List[string]]::new()
        if (Test-Path $trx) { $samples.Add($trx) }
        $over = @(Get-PerfOverBudget $failed {
            param($pending)
            $script:sample++
            $out = Join-Path $results "sample-$script:sample"
            & dotnet test $tests --nologo @buildPriority --no-build --filter (($pending | ForEach-Object { "FullyQualifiedName~$_" }) -join '|') `
                --logger 'trx;LogFileName=sample.trx' --results-directory $out @serial | Out-Host
            $sampleTrx = Join-Path $out 'sample.trx'
            # A sample that wrote no results counts as over budget for every test in it.
            if (Test-Path $sampleTrx) { $samples.Add($sampleTrx); Get-FailedTests $sampleTrx } else { $pending }
        })
        # The baseline comparison runs in the test assembly, which reads the baselines the way the tests do.
        $assembly = Get-ChildItem (Join-Path $tests 'bin') -Recurse -Filter 'Corvus.Tests.dll' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        function Get-Regressions { if ($samples.Count) { & dotnet exec $assembly.FullName --perf-regressions @samples } }
        $candidates = @(Get-Regressions | Where-Object { $_ -like "test`t*" } | ForEach-Object { ($_ -split "`t")[1] })
        for ($extra = 2; $extra -le 5 -and $candidates; $extra++) {
            $out = Join-Path $results "baseline-$extra"
            & dotnet test $tests --nologo @buildPriority --no-build --filter (($candidates | ForEach-Object { "FullyQualifiedName~$_" }) -join '|') `
                --logger 'trx;LogFileName=sample.trx' --results-directory $out @serial | Out-Host
            if (Test-Path (Join-Path $out 'sample.trx')) { $samples.Add((Join-Path $out 'sample.trx')) }
        }
        $regressed = @(Get-Regressions | Where-Object { $_ -like "regressed`t*" } | ForEach-Object { $f = $_ -split "`t"; [pscustomobject]@{ Name = $f[1]; Text = $f[2] } })
        foreach ($r in $regressed) { Write-Host "Past 1.5 times its baseline: $($r.Text)." -ForegroundColor Yellow }
        $flagged = @($over) + @($regressed | ForEach-Object { "baseline:$($_.Name)" })
        Exit-IfContended $flagged
        $confirmed = @(Update-PerfVerdicts $perfVerdicts $flagged (git -C $root rev-parse --short HEAD).Trim())
        $once = @($flagged | Where-Object { $_ -notin $confirmed })
        if ($failed -and -not $over) { Write-Host "Over budget once, within it in most of 5 samples: $($failed -join ', ')." -ForegroundColor Yellow }
        if ($once) { Write-Host "Over budget or past the baseline for the first run in a row (the next perf run confirms or clears it): $($once -join ', ')." -ForegroundColor Yellow }
        if ($confirmed) { Write-Host "Over budget or past the baseline in two perf runs in a row: $($confirmed -join ', ')." -ForegroundColor Red; exit 1 }
        Write-Host 'Perf run: no regression confirmed.'
        exit 0
    }
    finally {
        $env:CORVUS_PERF, $env:CORVUS_ALL_TESTS, $env:CORVUS_PERMITS_HELD = $saved
        if ($loadSampler) { Stop-Job $loadSampler; Remove-Job $loadSampler -Force }
        Remove-Item $loadLog -ErrorAction SilentlyContinue
        if (Test-Path $results) { Remove-Item -Recurse -Force $results }
        Exit-AllPermits $permits
        if ($heavy) { Exit-HeavyLock $lockName }
    }
}

# Mutation testing: one Stryker.NET run (CORVUS_STRYKER, else PATH) over the tests/mutation.json targets.
# Stryker compiles the whole project per run, so targets share one; MutationTests checks survivors per target.
if ($Mutation) {
    $stryker = if ($env:CORVUS_STRYKER) { $env:CORVUS_STRYKER } else { (Get-Command dotnet-stryker -ErrorAction SilentlyContinue).Source }
    if (-not $stryker) { Write-Host 'Mutation testing skipped: Stryker.NET not found (dotnet tool install -g dotnet-stryker, or set CORVUS_STRYKER).' -ForegroundColor Yellow; exit 0 }
    $table = Get-Content (Join-Path $root 'tests/mutation.json') -Raw | ConvertFrom-Json -AsHashtable
    $names = if ($Target) { $Target -split ',' } else { @($table.targets.Keys | Sort-Object) }
    $missing = @($names | Where-Object { -not $table.targets[$_] })
    if ($missing) { Write-Host "No mutation target $($missing -join ', ') in tests/mutation.json." -ForegroundColor Red; exit 2 }
    $out = Join-Path ([IO.Path]::GetTempPath()) "corvus-mutation-$PID"
    New-Item -ItemType Directory -Force $out | Out-Null
    $project = Join-Path $root 'src/Corvus'
    $config = [ordered]@{}
    foreach ($key in $table.options.Keys) { $config[$key] = $table.options[$key] }
    # Stryker resolves paths from the mutated project's folder.
    $config['test-projects'] = @($config['test-projects'] | ForEach-Object { [IO.Path]::GetRelativePath($project, (Join-Path $root $_)).Replace('\', '/') })
    $config['mutate'] = @($names | ForEach-Object { $table.targets[$_].mutate } | ForEach-Object { $_ -replace '^src/Corvus/', '' })
    $config['test-case-filter'] = ($names | ForEach-Object { $table.targets[$_].tests }) -join '|'
    $file = Join-Path $out 'stryker-config.json'
    Set-Content $file (@{ 'stryker-config' = $config } | ConvertTo-Json -Depth 5)
    Write-Host "Mutation targets: $($names -join ', ')"
    Push-Location $project
    try { & $stryker --config-file $file --output (Join-Path $out 'run') --skip-version-check }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { Write-Host "Stryker failed ($LASTEXITCODE); output in $out." -ForegroundColor Red; exit $LASTEXITCODE }
    $env:CORVUS_MUTATION_REPORT = $out
    try { & dotnet test $tests --nologo @buildPriority --filter 'FullyQualifiedName~MutationTests' -p:CORVUS_ALL_TESTS=1 }
    finally { Remove-Item Env:CORVUS_MUTATION_REPORT }
    $code = $LASTEXITCODE
    $summary = Join-Path $out 'summary.txt'
    if (Test-Path $summary) { Get-Content $summary | ForEach-Object { Write-Host $_ } }
    if ($code -eq 0) { Remove-Item -Recurse -Force $out } else { Write-Host "Reports kept in $out." }
    exit $code
}

# Background run: a full run of HEAD in a kept worktree of its own; its stamp counts for -IfChanged and release.ps1.
# A request while a run is going is queued: one run then starts on the newest queued commit at the strongest strength,
# so runs always finish and pushes in between share one run.
$running = Join-Path $gitDir 'corvus-background.json'
$lastPassed = Join-Path $gitDir 'corvus-background.passed'
$queued = Join-Path $gitDir 'corvus-background.next'

# Waits while a run is live or queued; the last run's process starts the queued one after removing both files, so the
# wait also lasts while that process lives.
if ($Wait) {
    $dispatcher = $null
    while ($true) {
        $run = Get-Content $running -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        $alive = if ($run) { Get-Process -Id $run.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $run.started } }
        if ($alive) { $dispatcher = $alive }
        elseif (-not (Test-Path $queued) -and -not ($dispatcher -and -not $dispatcher.HasExited)) { break }
        Start-Sleep -Seconds 5
    }
    $text = if (Test-Path $result) { (Get-Content $result -Raw).Trim() } else { 'No background run yet.' }
    Write-Host $text
    exit $(if ($text -match ' passed at ') { 0 } else { 1 })
}

if ($Background) {
    # The pre-push hook names the pushed commit, as HEAD may hold unpushed commits. $commit is $Commit (case-insensitive).
    $named = $Commit
    $commit = (git -C $root rev-parse "$(if ($named) { $named } else { 'HEAD' })^{commit}" 2>$null)
    if ($LASTEXITCODE -ne 0) { Write-Host "No commit '$named' here." -ForegroundColor Red; exit 2 }
    $commit = "$commit".Trim()
    if (-not $named -and (git -C $root status --porcelain)) { Write-Host 'Uncommitted changes are not part of the background run (it tests HEAD).' }
    $strength = if ($Whole) { 'whole' } elseif ($Exhaustive) { 'exhaustive' } else { 'routine' }
    $previous = if (Test-Path $running) { Get-Content $running -Raw | ConvertFrom-Json } else { $null }
    $process = if ($previous) { Get-Process -Id $previous.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $previous.started } } else { $null }
    if ($process) {
        Import-Module (Join-Path $root 'test-reuse.psm1') -Force
        $asked = Save-QueuedRun $queued $strength $commit
        Write-Host "A run on $($previous.commit.Substring(0, 8)) is going; queued: a run on $($commit.Substring(0, 8)) ($asked) when it ends (./test.ps1 -Status)."
        exit 0
    }
    # CORVUS_BACKGROUND_DIR: where the worktrees go, such as a folder the antivirus does not scan.
    $bgRoot = if ($env:CORVUS_BACKGROUND_DIR) { $env:CORVUS_BACKGROUND_DIR } else { [IO.Path]::GetTempPath() }
    # One reused worktree keeps packages and bin/obj for incremental builds; a missing or broken one is made again.
    $dir = Join-Path $bgRoot 'corvus-bg-worktree'
    $reusedTree = $false
    if (Test-Path (Join-Path $dir '.git')) {
        git -C $dir checkout --quiet --detach --force $commit 2>$null
        if ($LASTEXITCODE -eq 0) { git -C $dir clean -fdq 2>$null; $reusedTree = $LASTEXITCODE -eq 0 }
    }
    if (-not $reusedTree) {
        if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
        git -C $root worktree prune
        git -C $root worktree add --detach $dir $commit | Out-Null
    }
    $checkedOut = git -C $dir rev-parse HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or "$checkedOut".Trim() -ne $commit) {
        Write-Host "The background run did not start: $dir is not a worktree of $commit (git worktree add failed)." -ForegroundColor Red
        exit 1
    }
    # Routine by default; release strength records the passes a release takes.
    $flags = '-Full' + $(if ($Whole) { ' -Exhaustive' } elseif ($Exhaustive) { ' -Exhaustive -Reuse' } else { ' -Reuse' })
    $short = $commit.Substring(0, 8)
    # Keep the previous run's log and result readable for -Status.
    if (Test-Path $log) {
        Move-Item -Force $log "$log.previous"
        if (Test-Path $result) { Add-Content -Path "$log.previous" -Value "Result: $((Get-Content $result -Raw).Trim())" }
    }
    Set-Content -Path $result -Value "$short running since $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -NoNewline
    # Thread dumps of engine workers stopped for time stay next to the log.
    $stalls = Join-Path $gitDir 'corvus-stalls'
    # File open times and disk and memory counters every 10 s, so a stalled run shows its window.
    $permitDir = Join-Path $tempRoot 'corvus-test-data/permits'
    New-Item -ItemType Directory -Force $permitDir | Out-Null
    # A whole run refreshes a coverage map over 6 days old (-Reuse drops it at 7) while its record keeps pushes queued.
    $script = @"
Set-Location '$dir'
`$env:CORVUS_STALL_DIR = '$stalls'
`$env:CORVUS_TEST_PUSH_RUN = '1'
Import-Module ./test-time.psm1
`$sampler = Start-IoSampler '$log.io' @('$permitDir', '$tempRoot')
& ./test.ps1 $flags *> '$log'
`$code = `$LASTEXITCODE
Stop-Job `$sampler; Remove-Job `$sampler -Force
Set-Content -Path '$result' -Value ('$short ' + `$(if (`$code -eq 0) { 'passed' } else { 'FAILED (exit ' + `$code + ')' }) + ' at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')) -NoNewline
if (`$code -eq 0) { Set-Content -Path '$lastPassed' -Value '$commit' -NoNewline }
`$map = '$(Join-Path $gitDir 'corvus-coverage-map.json')'
if ('$strength' -eq 'whole' -and (-not (Test-Path `$map) -or (Get-Item `$map).LastWriteTime -lt (Get-Date).AddDays(-6))) { & ./test.ps1 -CoverageMap *> '$log.coverage' }
if ((Get-Content '$running' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json).pid -eq `$PID) { Remove-Item '$running' }
Set-Location '$root'
if (Test-Path '$queued') {
    Import-Module '$root/test-reuse.psm1'
    `$next = Read-QueuedRun '$queued'; Remove-Item '$queued'
    `$strength = @{ Full = `$true; Background = `$true }
    if (`$next.Strength -eq 'whole') { `$strength.Whole = `$true } elseif (`$next.Strength -eq 'exhaustive') { `$strength.Exhaustive = `$true }
    if (`$next.Commit) { `$strength.Commit = `$next.Commit }
    & '$root/test.ps1' @strength
}
"@
    $scriptFile = Join-Path $gitDir 'corvus-background.ps1'
    Set-Content -Path $scriptFile -Value $script
    if ($IsWindows) {
        # Created by WMI, outside the caller's job object: a terminal or agent shell that closes its job would end the run.
        $startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{
            ShowWindow = [uint16]0; EnvironmentVariables = [string[]](Get-ChildItem env: | ForEach-Object { "$($_.Name)=$($_.Value)" }) }
        $created = Invoke-CimMethod Win32_Process -MethodName Create -Arguments @{
            CommandLine = "pwsh -NoProfile -File `"$scriptFile`""; CurrentDirectory = $root; ProcessStartupInformation = $startup }
        if ($created.ReturnValue -ne 0) { Write-Host "The background run did not start (Win32_Process.Create returned $($created.ReturnValue))." -ForegroundColor Red; exit 1 }
        $started = Get-Process -Id $created.ProcessId
    }
    else { $started = Start-Process nohup -ArgumentList @('pwsh', '-NoProfile', '-File', $scriptFile) -RedirectStandardOutput /dev/null -PassThru }
    $record = [ordered]@{ pid = $started.Id; started = $started.StartTime.ToUniversalTime().Ticks; commit = $commit; dir = $dir; strength = $strength }
    Set-Content -Path $running -Value ($record | ConvertTo-Json) -NoNewline
    Write-Host "Full suite started in the background on $short ($dir); ./test.ps1 -Status shows the result."
    exit 0
}

# The test family a changed file belongs to; '*' is shared code (every family), null a file no test reads.
function Get-Family([string]$path) {
    $p = $path -replace '\\', '/'
    switch -Regex ($p) {
        '^src/Corvus/(Tools|Services)/Shared/' { return '*' }
        '^src/Corvus/(Tools|Services)/(Dotnet|DotnetEdits|NativeAnalysis|Engines|NativeEdits|Builds|Containers|Mobile|Dumps|AotMetadata|NativeAot|Session|Web)/' { return $Matches[2] }
        '^src/Corvus/Services/Analysis/' { return 'Containers' }
        '^src/Corvus/Services/AotBuild/' { return 'AotMetadata' }
        '^src/Corvus/Services/Mobile/' { return 'Mobile' }
        '^src/Corvus/Services/Simplify/' { return 'DotnetEdits' }
        '^src/Corvus/Native/Providers/' { return 'Engines' }
        '^src/Corvus/Native/(Annotations|Patching)/' { return 'NativeEdits' }
        '^src/Corvus/Native/Diff/' { return 'Builds' }
        '^src/Corvus/Native/(Dump|Live)/' { return 'Dumps' }
        '^src/Corvus/Native/NativeAot/' { return 'NativeAot' }
        '^src/Corvus/Native/' { return 'NativeAnalysis', 'NativeFormats' }
        '^src/' { return '*' }                                   # Core, Mcp, Setup, Relay, the project file
        '^tests/Corvus\.Tests/(Support|ContractSweepData)/' { return '*' }
        '^tests/Corvus\.Tests/(Ratchets|ProtocolSamples|TokenCorpus)/' { return 'Contract' }
        '^tests/Corvus\.Tests/PipelineSamples/' { return 'DotnetEdits' }
        '^tests/Corvus\.Tests/NativeAotSample/' { return 'NativeAot' }
        '^tests/Corvus\.Tests/([^/]+)/' { return $Matches[1] }
        '^tests/' { return '*' }                                 # the test project file, runsettings, fixtures
        default { return 'Contract' }                            # docs, scripts, README: the doc and contract tests
    }
}

# The top-level test classes of a family folder; a filter on ".Name" also takes their nested classes (Name+Nested).
function Get-FamilyClasses([string]$family) {
    $dir = Join-Path $tests $family
    if (-not (Test-Path $dir)) { return @() }
    Get-ChildItem $dir -Recurse -Filter *.cs | ForEach-Object {
        [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^public (?:sealed |abstract |partial )*class (\w+)') | ForEach-Object { $_.Groups[1].Value }
    } | Sort-Object -Unique
}

# Commit gate: quick tests of the families changed since $Base (by the coverage map where known) plus Contract.
# Shared code runs the whole quick set.
if (-not ($Full -or $All -or $Affected -or $Filter -or $Coverage -or $CoverageMap -or $SecondGhidra -or $Background)) {
    $changed = @(git -C $root diff --name-only $Base) + @(git -C $root ls-files --others --exclude-standard) | Where-Object { $_ } | Sort-Object -Unique
    if (-not $changed) { Write-Host "Nothing changed since ${Base}; ./test.ps1 -All runs the whole quick set."; exit 0 }
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $coveredBy = Read-CoverageMap (Join-Path $gitDir 'corvus-coverage-map.json')
    # Files outside src/ and tests/ go to the families whose tests read repository files.
    $readers = @(Get-RootReaders $tests)
    $families = @(@($changed | ForEach-Object {
        if ($coveredBy -and $coveredBy[$_]) { $coveredBy[$_] } elseif ($_ -notmatch '^(src|tests)/') { $readers } else { Get-Family $_ } }) + 'Contract' | Sort-Object -Unique)
    if ($families -notcontains '*') {
        $classes = @($families | ForEach-Object { Get-FamilyClasses $_ } | Sort-Object -Unique)
        $quickFilter = 'Speed!=Slow&(' + (($classes | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|') + ')'
        if ($quickFilter.Length -lt 24000) {
            Write-Host "Changed since ${Base}: $($changed.Count) files; quick tests of $($families -join ', ')."
            $results = Join-Path $tempRoot "corvus-trx-$PID"
            Start-RunTiming 'quick'
            $savedMaxWait = $env:CORVUS_PERMIT_MAX_WAIT
            $env:CORVUS_PERMIT_MAX_WAIT = $permitMaxWait
            # A failed build leaves the split and --no-build out: the test command builds again and names the errors.
            Invoke-TestBuild
            $built = $LASTEXITCODE -eq 0
            $alone = if ($built) { @(Get-AloneClasses $tests | Where-Object { ($_ -replace '\+.*$', '') -in $classes }) } else { @() }
            $aloneJob = $null
            if ($alone) {
                $split = Get-AloneFilters $quickFilter $alone
                $aloneJob = Start-AloneRun $split.Alone (Join-Path $results 'alone')
                & dotnet test $tests --nologo @buildPriority --no-build --filter $split.Rest --logger 'trx;LogFileName=full.trx' --results-directory $results
            }
            else {
                $noBuild = @(if ($built) { '--no-build' })
                & dotnet test $tests --nologo @buildPriority @noBuild --filter $quickFilter --logger 'trx;LogFileName=full.trx' --results-directory $results
            }
            $code = $LASTEXITCODE
            if ($aloneJob) { $aloneCode = Receive-AloneRun $aloneJob (Join-Path $results 'full.trx') (Join-Path $results 'alone'); if ($code -eq 0) { $code = $aloneCode } }
            $env:CORVUS_PERMIT_MAX_WAIT = $savedMaxWait
            Save-RunTimes (Join-Path $results 'full.trx') 'quick' $code @{ build = if ($built) { [math]::Round($buildSeconds, 1) } else { $null } }
            Get-NotRun (Join-Path $results 'full.trx') | Out-Null
            if (Test-Path $results) { Remove-Item -Recurse -Force $results }
            exit $code
        }
    }
    Write-Host "Changed since ${Base}: $($changed.Count) files, shared code among them: the whole quick set runs."
}

if ($Affected) {
    $changed = @(git -C $root diff --name-only $Base) + @(git -C $root ls-files --others --exclude-standard) | Where-Object { $_ }
    $families = @($changed | ForEach-Object { Get-Family $_ } | Sort-Object -Unique)
    Write-Host "Changed since ${Base}: $($changed.Count) files; families: $(if ($families) { $families -join ', ' } else { 'none' })"
    if ($families -contains '*') { $Full = $true; Write-Host 'Shared code changed: the full suite runs.' }
    else {
        $classes = @($families | ForEach-Object { Get-FamilyClasses $_ } | Sort-Object -Unique)
        $Full = $true
        $Filter = (@('Speed!=Slow') + ($classes | ForEach-Object { "FullyQualifiedName~.$_" })) -join '|'
        Write-Host "Quick set plus $($classes.Count) test classes of the changed families."
    }
}

# The clean tree a full run passed on and its sweep mode, kept in .git; a dirty tree has no hash worth recording.
function Get-CleanTree {
    if (git -C $root status --porcelain) { return $null }
    return (git -C $root rev-parse 'HEAD^{tree}').Trim()
}
# "<tree> <mode>", with " reused" when reused family passes made up part of it.
$treeStamp = Join-Path $gitDir 'corvus-full-suite.stamp'
# Every whole-suite pass on a clean tree, newest last: release.ps1 ships on the newest one on its history.
$fullPasses = Join-Path $gitDir 'corvus-full-passes.txt'
function Write-TreeStamp([string]$tree, [string]$mode, [bool]$reused) {
    $value = "$tree $mode" + $(if ($reused) { ' reused' } else { '' })
    Set-Content -Path $treeStamp -Value $value -NoNewline
    Add-FullPass $fullPasses (git -C $root rev-parse HEAD).Trim() $value
    Write-Host "Stamped $value."
}
# The last whole-suite run's results and what recording them needs, so -Stamp can record them without a rerun.
$lastRun = Join-Path $gitDir 'corvus-last-run.json'
$lastTrx = Join-Path $gitDir 'corvus-last-run.trx'


if ($Full -and $IfChanged) {
    $tree = Get-CleanTree
    $have = if (Test-Path $treeStamp) { (Get-Content $treeStamp -Raw).Trim() } else { '' }
    $done = if ($Exhaustive) { $have -in "$tree exhaustive", "$tree exhaustive reused" } else { $have -like "$tree *" }
    if ($tree -and $done) {
        Write-Host "The full suite already passed on tree $tree; skipped."
        exit 0
    }
}

# Full runs on a clean tree record each passed family's input key; -Reuse runs only families whose key changed.
$familyStamps = Join-Path $gitDir 'corvus-family-stamps.json'
$selectionMisses = Join-Path $gitDir 'corvus-selection-misses.txt'
$coverageMapFile = Join-Path $gitDir 'corvus-coverage-map.json'
$mode = if ($Exhaustive) { 'exhaustive' } else { 'sampled' }
$familyKeys = $null; $built = $false
$wholeSuite = $Full -and -not $Filter


# Records the saved run's passes (a run whose recording step failed), for the tree it ran on only.
if ($Stamp) {
    if (-not ((Test-Path $lastRun) -and (Test-Path $lastTrx))) { Write-Host 'No saved full run to record.' -ForegroundColor Red; exit 2 }
    $run = Get-Content $lastRun -Raw | ConvertFrom-Json -AsHashtable
    $tree = Get-CleanTree
    if ($tree -ne $run.tree) { Write-Host "The saved run was on tree $($run.tree); this tree is $(if ($tree) { $tree } else { 'not clean' }). Run the suite again." -ForegroundColor Red; exit 2 }
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    Import-Module (Join-Path $root 'test-remote.psm1') -Force
    # Classes the run keyed on their own, by their 'class:<name>' keys.
    $own = @{}; foreach ($name in $run.keys.Keys | Where-Object { $_ -like 'class:*' }) { $own[$name.Substring(6)] = $true }
    $classes = Split-ClassMap (Get-ClassMap $tests) $own
    $passed = @(Get-UndeferredFamilies @(Get-PassedFamilies $lastTrx $classes $run.code) $classes @($run.deferred))
    Save-FamilyPasses $familyStamps $passed $run.keys $run.mode $run.commit
    Write-Host "Recorded $($run.mode) passes for $($passed.Count) families from the run of $($run.at)."
    if ($run.code -ne 0) { Write-Host "The saved run failed (exit $($run.code)): the tree is not stamped." -ForegroundColor Red; exit 1 }
    if (Get-PermitSkips $lastTrx) { Write-Host 'The saved run left collections unrun (permit wait): the tree is not stamped.' -ForegroundColor Yellow; exit 0 }
    Write-TreeStamp $tree $run.mode $run.reused
    exit 0
}

# Engines tests on a second Ghidra, keyed like a family: unchanged inputs skip; a retry runs only the failures.
$secondStamp = Join-Path $gitDir 'corvus-second-ghidra.json'

# Writes the first three lines of each named test's failure message in a TRX file.
function Write-FailureMessages([string]$trx, [string[]]$names) {
    $messages = Get-FailureMessages $trx
    foreach ($test in $names | Where-Object { $messages[$_] }) {
        Write-Host "  $test`: $((($messages[$test] -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 3) -join ' | ')"
    }
}
function Invoke-SecondGhidra {
    if (-not $env:CORVUS_SECOND_GHIDRA_DIR) { Write-Host 'Engine tests on a second Ghidra skipped: CORVUS_SECOND_GHIDRA_DIR is not set.' -ForegroundColor Yellow; return 0 }
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $filter = ((Get-ClassMap $tests)['Engines'] | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|'
    $key = $null; $last = $null
    if (Get-CleanTree) {
        $environment = Get-RunEnvironment @{ CORVUS_GHIDRA_DIR = $env:CORVUS_SECOND_GHIDRA_DIR }
        $key = (Get-FamilyKeys @(git -C $root ls-tree -r HEAD) @('Engines') @(Get-RootReaders $tests) $environment (Read-CoverageMap $coverageMapFile))['Engines']
        $last = if (Test-Path $secondStamp) { Get-Content $secondStamp -Raw | ConvertFrom-Json } else { $null }
        if ($last.key -ne $key) { $last = $null }
    }
    if ($last -and -not $last.failed) { Write-Host "Engine tests on the second Ghidra passed on these inputs ($($last.commit)); skipped."; return 0 }
    if ($last) {
        $filter = ($last.failed | ForEach-Object { "FullyQualifiedName~$_" }) -join '|'
        Write-Host "Engine tests on the second Ghidra: rerunning the $(@($last.failed).Count) that failed on these inputs."
    }
    $results = Join-Path $tempRoot "corvus-trx-second-$PID"
    # CORVUS_TEST_ENGINE=ghidra skips IDA-only tests, which another Ghidra cannot change.
    $saved = $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS, $env:CORVUS_TEST_ENGINE
    $env:CORVUS_GHIDRA_DIR = $env:CORVUS_SECOND_GHIDRA_DIR; $env:CORVUS_ALL_TESTS = '1'; $env:CORVUS_TEST_ENGINE = 'ghidra'
    try { & dotnet test $tests --nologo @buildPriority --filter $filter --logger 'trx;LogFileName=second.trx' --results-directory $results | Out-Host; $code = $LASTEXITCODE }
    finally { $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS, $env:CORVUS_TEST_ENGINE = $saved }
    $trx = Join-Path $results 'second.trx'
    # Keep failure causes in the log and a saved copy; the results folder is removed below.
    if ($code -ne 0 -and (Test-Path $trx)) {
        Write-FailureMessages $trx @(Get-FailedTests $trx)
        $failedRun = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$((git -C $root rev-parse --short HEAD).Trim())-second"
        Save-FailedRun (Join-Path $gitDir 'corvus-failed-runs') $failedRun @($trx)
        Write-Host "Results kept in $(Join-Path $gitDir "corvus-failed-runs/$failedRun.trx")."
    }
    if ($key) {
        # A failure no test is blamed for (a crashed host) keeps no record, so everything runs next time.
        $failed = if (Test-Path $trx) { @(Get-FailedTests $trx) } else { @() }
        if ($code -eq 0 -or $failed) {
            $record = [ordered]@{ key = $key; failed = $(if ($code -eq 0) { @() } else { $failed }); commit = (git -C $root rev-parse --short HEAD).Trim(); at = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
            Set-Content -Path $secondStamp -Value ($record | ConvertTo-Json -Depth 3) -NoNewline
        }
        elseif (Test-Path $secondStamp) { Remove-Item $secondStamp }
    }
    if (Test-Path $results) { Remove-Item -Recurse -Force $results }
    return $code
}
if ($SecondGhidra) { exit (Invoke-SecondGhidra) }

# One instrumented run per family records the source files its tests ran; failures are ignored, only what ran counts.
# Slow classes (30 s or more in the last full run) get their own run, so -Reuse keys each on its own files.
# Read-CoverageMap drops the map after a week.
if ($CoverageMap) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    & dotnet build $tests --nologo @buildPriority -v q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $slow = @(Get-SlowClasses (Join-Path $gitDir 'corvus-last-run.trx'))
    $families = [ordered]@{}; $classes = [ordered]@{}
    function Get-MapFiles([string]$name, [string[]]$classNames) {
        $out = Join-Path $tempRoot "corvus-map-$PID-$name"
        $filter = ($classNames | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|'
        & dotnet test $tests --nologo @buildPriority --no-build --filter $filter --results-directory $out --collect 'XPlat Code Coverage' -- `
            'DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include=[corvus]*' | Out-Null
        $report = Get-ChildItem $out -Recurse -Filter coverage.cobertura.xml -ErrorAction SilentlyContinue | Select-Object -First 1
        $result = if ($report) { [pscustomobject]@{ Files = @(Get-CoveredFiles $report.FullName $root) } } else { $null }
        Write-Host "$name`: $(if ($result) { "$($result.Files.Count) source files" } else { 'no report' })"
        if (Test-Path $out) { Remove-Item -Recurse -Force $out }
        return $result
    }
    $saved = $env:CORVUS_ALL_TESTS; $env:CORVUS_ALL_TESTS = '1'
    try {
        foreach ($family in $classMap.Keys | Sort-Object) {
            $own = if (Test-AlwaysRunFolder $family) { @() } else { @($classMap[$family] | Where-Object { $_ -in $slow }) }
            foreach ($class in $own) {
                # A class without a report stays with its family.
                if ($run = Get-MapFiles $class @($class)) { $classes[$class] = [ordered]@{ family = $family; files = $run.Files } }
            }
            $rest = @($classMap[$family] | Where-Object { -not $classes[$_] })
            # A family without a report keeps the folder rules for every file.
            if (-not $rest) { $families[$family] = @() }
            elseif ($run = Get-MapFiles $family $rest) { $families[$family] = $run.Files }
        }
    }
    finally { $env:CORVUS_ALL_TESTS = $saved }
    $record = [ordered]@{ commit = (git -C $root rev-parse --short HEAD).Trim(); at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); families = $families; classes = $classes }
    Set-Content -Path $coverageMapFile -Value ($record | ConvertTo-Json -Depth 4) -NoNewline
    Write-Host "Coverage map: $coverageMapFile"
    exit 0
}

if ($wholeSuite -and (Get-CleanTree)) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    $treeLines = @(git -C $root ls-tree -r HEAD)
    $readers = @(Get-RootReaders $tests)
    # Classes the coverage map ran on their own are keyed, run and recorded on their own, as 'class:<name>'.
    $classCoverage = Read-ClassCoverage $coverageMapFile
    if ($classCoverage.Count) {
        $classMap = Split-ClassMap $classMap $classCoverage
        $coveredBy = Add-ClassTestScopes (Read-CoverageMap $coverageMapFile -Classes) $classCoverage @($treeLines | ForEach-Object { $_.Substring($_.IndexOf("`t") + 1) })
        $readers += @($classCoverage.Keys | Where-Object { $classCoverage[$_].family -in $readers } | ForEach-Object { "class:$_" })
    }
    else { $coveredBy = Read-CoverageMap $coverageMapFile }
    # The tools found outside the settings come from the test assembly's own table, so it is built first.
    Invoke-TestBuild | Out-Null
    $built = $LASTEXITCODE -eq 0
    $familyKeys = Get-FamilyKeys $treeLines @($classMap.Keys) $readers (Get-RunEnvironment -tools (Get-LocatedTools $tests)) $coveredBy
    if (-not $coveredBy) { Write-Host 'No coverage map from the last week (./test.ps1 -CoverageMap): shared code keys every family.' }
    if ($Reuse) {
        $stamps = if (Test-Path $familyStamps) { Get-Content $familyStamps -Raw | ConvertFrom-Json } else { $null }
        $stale = Get-StaleFamilies $familyKeys $stamps $Exhaustive.IsPresent
        $Filter = Get-ReuseFilter $stale $classMap
        $kept = @($classMap.Keys | Where-Object { $_ -notin $stale } | Sort-Object)
        if ($Filter) { Write-Host "Reusing the $mode passes of $($kept -join ', '); running $($stale -join ', ') and the always-run classes." }
        else { Write-Host 'No family pass to reuse: the full suite runs.' }
    }
}
elseif ($Reuse) { Write-Host 'Reuse needs a clean tree and the whole suite: nothing is reused.' }

# Engine tests skip silently without their engine; a full run names the missing ones before and after it runs.
$missingEngines = @()
if ($Full) {
    if (-not ($env:CORVUS_GHIDRA_DIR -or $env:GHIDRA_INSTALL_DIR)) { $missingEngines += 'Ghidra (set CORVUS_GHIDRA_DIR)' }
    $idaUser = @($env:IDAUSR -split [IO.Path]::PathSeparator | Where-Object { $_ }) +
        $(if ($IsWindows) { Join-Path $env:APPDATA 'Hex-Rays/IDA Pro' } else { Join-Path $HOME '.idapro' })
    if (-not $env:CORVUS_IDA_DIR -and -not ($idaUser | Where-Object { Test-Path (Join-Path $_ 'ida-config.json') })) { $missingEngines += 'IDA (set CORVUS_IDA_DIR)' }
    if ($missingEngines) { Write-Host "Engine tests will be skipped: $($missingEngines -join ', ')." -ForegroundColor Yellow }
}

$arguments = @('test', $tests, '--nologo') + $buildPriority
if ($built) { $arguments += '--no-build' }
# Tier=Release tests run at release strength only, or with a command-line filter or coverage (the floors count them).
$runFilter = if ($Full -and -not $Exhaustive -and -not $Coverage -and -not $PSBoundParameters.ContainsKey('Filter')) { if ($Filter) { "($Filter)&Tier!=Release" } else { 'Tier!=Release' } } else { $Filter }
# Offload sends engine-free heavy classes to the CI offload jobs and runs the rest here; without a target all run here.
$offload = if ($wholeSuite -and -not $Coverage) { Import-Module (Join-Path $root 'test-remote.psm1') -Force; Get-OffloadTarget $root $Exhaustive.IsPresent } else { $null }
$offloadHandle = $null; $sent = @(); $offloadRecord = $null; $offloadClock = $null
if ($offload) {
    $candidates = @(Get-RemoteClasses $tests); $mixed = @(Get-MixedClasses $tests)
    $sent = if ($Filter) { @([regex]::Matches($Filter, 'FullyQualifiedName~\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -in $candidates }) } else { $candidates }
    $offloadRecord = [ordered]@{ target = $offload.Name; commit = (git -C $root rev-parse --short HEAD).Trim(); at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); classes = $sent.Count; state = 'running'; seconds = $null; note = $null }
    if ($sent) {
        $offloadClock = [Diagnostics.Stopwatch]::StartNew()
        $offloadHandle = Start-Offload $offload (git -C $root rev-parse HEAD).Trim() (Join-Path $root 'test-remote.psm1')
        $runFilter = Get-LocalFilter $runFilter $sent $mixed
        Write-Host "Offloading $($sent.Count) classes to $($offload.Name); the rest run here."
    }
    else { $offloadRecord.state = 'idle'; $offloadRecord.note = 'no class to send' }
    Save-RemoteRecord $gitDir $offloadRecord
}
# Push runs leave the nightly group's classes to the nightly run: they need an unloaded machine or real data, or run
# longest.
$deferred = @()
if ($wholeSuite -and -not $Coverage -and $Reuse) {
    Import-Module (Join-Path $root 'test-remote.psm1') -Force
    $deferred = @(Get-RemoteClasses $tests -Group nightly)
    if ($deferred) { $runFilter = Get-LocalFilter $runFilter $deferred; Write-Host "Left for the nightly run: $($deferred.Count) classes." }
}
if ($runFilter) { $arguments += @('--filter', $runFilter) }
$results = Join-Path ([IO.Path]::GetTempPath()) "corvus-trx-$PID"
$arguments += @('--logger', 'trx;LogFileName=full.trx', '--results-directory', $results)
# The history keeps each mode apart: the commit gate, a push's reusing run, a whole run, and runs of a chosen filter.
$runMode = if ($Affected -or $PSBoundParameters.ContainsKey('Filter')) { 'filter' } elseif (-not $Full) { 'quick' } elseif ($Reuse) { 'push' } else { 'full' }
$timing = @{}
if ($Reuse -and $familyKeys) { $timing.reused = @($kept).Count; $timing.families = $classMap.Count }
# A test past its hang limit ends the run with a dump in .git/corvus-hang-<time>.
# Limits: 2 min quick (slowest 41 s), 30 min full (slowest 27 min).
$hangLimit = if ($Full) { '30m' } else { '120s' }
# Full runs dump the heap to find a stuck awaited task; quick runs take a mini dump, enough to name a slow test.
$hangDump = if ($Full) { 'full' } else { 'mini' }
$arguments += @('--blame-hang', '--blame-hang-timeout', $hangLimit, '--blame-hang-dump-type', $hangDump)
$quarantineFile = Join-Path $tests 'Ratchets/quarantine.txt'
# Coverage floors are set by whole-suite runs, so a partial run is never checked against them.
if ($Coverage) {
    if (-not $Full -or $Filter -or $Reuse) { Write-Host 'Coverage needs the whole suite: -Full without -Filter, -Affected or -Reuse.' -ForegroundColor Red; exit 2 }
    $familyKeys = $null   # an instrumented run records no family passes and stamps no tree
    $arguments += @('--collect', 'XPlat Code Coverage', '--',
        'DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include=[corvus]*')
}
$saved = $env:CORVUS_ALL_TESTS; $savedSweep = $env:CORVUS_SWEEP; $savedMaxWait = $env:CORVUS_PERMIT_MAX_WAIT
try {
    if ($Full) { $env:CORVUS_ALL_TESTS = '1' }
    $env:CORVUS_PERMIT_MAX_WAIT = $permitMaxWait
    $env:CORVUS_SWEEP = if ($Exhaustive) { 'exhaustive' } else { $null }
    $tree = if ($wholeSuite -and -not $Coverage) { Get-CleanTree } else { $null }
    # A whole-suite run waits for a quiet machine and keeps it quiet until it ends, unless it is a push run (-Reuse).
    $heavyLock = "corvus-full-$PID"
    if ($wholeSuite) {
        Import-Module (Join-Path $root 'test-reuse.psm1') -Force
        $lockClock = [Diagnostics.Stopwatch]::StartNew()
        $heavy = Enter-RunLock $heavyLock $Reuse.IsPresent
        if ($heavy) { $timing.heavyWait = [math]::Round($lockClock.Elapsed.TotalSeconds, 1) }
    }
    Start-RunTiming $runMode
    if ($runMode -eq 'quick' -and -not $built) {
        Invoke-TestBuild
        if ($LASTEXITCODE -eq 0) { $built = $true; $arguments += '--no-build' }
    }
    $aloneJob = $null
    if ($runMode -eq 'quick' -and $built -and -not $Coverage -and $arguments -notcontains '--filter') {
        $alone = @(Get-AloneClasses $tests)
        if ($alone) {
            $split = Get-AloneFilters $null $alone
            $arguments += @('--filter', $split.Rest)
            # The run-alone classes are few, so their host's full dump stays small.
            $aloneJob = Start-AloneRun $split.Alone (Join-Path $results 'alone') @('--blame-hang', '--blame-hang-timeout', $hangLimit, '--blame-hang-dump-type', 'full')
        }
    }
    & dotnet @arguments
    $code = $LASTEXITCODE
    $trx = Join-Path $results 'full.trx'
    if ($aloneJob) { $aloneCode = Receive-AloneRun $aloneJob $trx (Join-Path $results 'alone'); if ($code -eq 0) { $code = $aloneCode } }
    if ($offloadHandle) {
        # Remote results join the local ones; a class that failed, proved less or has no results there reruns here.
        $got = Receive-Offload $offloadHandle (Join-Path $results 'offload')
        $offloadRecord.seconds = [math]::Round($offloadClock.Elapsed.TotalSeconds, 1)
        $here = @(); $notes = @()
        if (-not $got.Started) { $here = $sent; $offloadRecord.state = 'not run there'; $notes += "$($got.Note); its classes ran here" }
        else {
            $fastest = Get-FastestClassSeconds $timeHistory
            $here = @(Get-RerunClasses $got $sent $lastTrx $mixed $trx $fastest)
            $offloadRecord.state = if ($got.Failed) { "failed on $($offload.Name)" } else { 'passed' }
            if ($got.Note -notmatch '^run \d+$') { $notes += $got.Note }
            if ($got.Trx) {
                Copy-Item $got.Trx (Join-Path $gitDir "corvus-remote/$(Get-TargetFileName $offload.Name).trx") -Force
                # A target may run more classes than were sent; only the sent ones count.
                Join-TrxFiles $trx @($trx, $got.Trx) (@($here) + @($candidates | Where-Object { $_ -notin $sent })) $mixed
            }
        }
        $hereTrx = Join-Path $results 'here/here.trx'
        if ($here) {
            Write-Host "Running here what $($offload.Name) did not prove: $($here.Count) classes."
            & dotnet test $tests --nologo @buildPriority --no-build --filter (Get-ClassFilter $here ($runFilter -notmatch 'Tier!=Release') $mixed) --logger 'trx;LogFileName=here.trx' --results-directory (Join-Path $results 'here') | Out-Host
            if ($LASTEXITCODE -ne 0 -and $code -eq 0) { $code = $LASTEXITCODE }
            Join-TrxFiles $trx @($trx, $hereTrx) @() $mixed
        }
        if ($got.Started) {
            if ($got.Failed) { $notes += Get-FailedThereNote $got.Failed $(if ($here) { $hereTrx }) $offload.Name }
            $rest = @($here | Where-Object { $_ -notin @($got.Failed | ForEach-Object Class) })
            if ($rest) { $notes += "no full result there, ran here: $($rest -join ', ')" }
        }
        $offloadRecord.note = if ($notes) { $notes -join '; ' } else { $null }
        $timing.offload = "$($offloadRecord.state)$(if ($offloadRecord.note) { "; $($offloadRecord.note)" })"
        Save-RemoteRecord $gitDir $offloadRecord
        Write-Host "Offload $($offload.Name): $($offloadRecord.state)$(if ($offloadRecord.note) { "; $($offloadRecord.note)" })."
    }
    if ($wholeSuite -and -not $Coverage) { Save-DeferredClasses $gitDir (git -C $root rev-parse --short HEAD).Trim() $deferred }
    # Instrumented runs are slower throughout and are not timed.
    if (-not $Coverage) {
        $timing.build = if ($built) { [math]::Round($buildSeconds, 1) } else { $null }
        Save-RunTimes $trx $runMode $code $timing
    }
    $recordFailed = $false
    # A run that left collections unrun proved no full pass of the tree.
    $notRun = @(Get-NotRun $trx)
    if ($familyKeys -and (Test-Path $trx)) {
        $commit = (git -C $root rev-parse --short HEAD).Trim()
        # Saved before recording, so a failed recording step costs no rerun (-Stamp).
        Copy-Item $trx $lastTrx -Force
        $run = [ordered]@{ tree = $tree; mode = $mode; reused = [bool]$Filter; code = $code; keys = $familyKeys; commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); deferred = $deferred }
        Set-Content -Path $lastRun -Value ($run | ConvertTo-Json -Depth 3) -NoNewline
        try {
            $passed = @(Get-UndeferredFamilies @(Get-PassedFamilies $trx $classMap $code) $classMap $deferred)
            # A run that reused nothing checks the selection: a failure under a recorded pass's key is a miss.
            if (-not $Filter) {
                $before = if (Test-Path $familyStamps) { Get-Content $familyStamps -Raw | ConvertFrom-Json } else { $null }
                $misses = @(Get-SelectionMisses @(Get-FailedTests $trx) $classMap $familyKeys $before)
                if ($misses) {
                    Add-Content -Path $selectionMisses -Value "$commit $(Get-Date -Format 'yyyy-MM-dd HH:mm') $($misses -join ' ')"
                    Write-Host "Selection would have missed failures in $($misses -join ', '): passes on these inputs were recorded ($selectionMisses)." -ForegroundColor Red
                }
            }
            Save-FamilyPasses $familyStamps $passed $familyKeys $mode $commit
            Write-Host "Recorded $mode passes for $($passed.Count) families."
        }
        catch {
            $recordFailed = $true
            Write-Host "Recording the passes failed ($_); the results are kept: ./test.ps1 -Stamp records them without a rerun." -ForegroundColor Red
        }
    }
    if (Test-Path $trx) {
        Import-Module (Join-Path $root 'test-reuse.psm1') -Force
        $failed = @(Get-FailedTests $trx)
        # Quarantined tests run and are reported, but their failures alone do not fail a run that completed.
        $split = Split-Quarantined $failed (Read-Quarantine $quarantineFile) (Get-Date)
        if ($split.Quarantined) { Write-Host "Quarantined tests that failed ($quarantineFile): $($split.Quarantined -join ', ')." -ForegroundColor Yellow }
        if ($code -ne 0 -and $failed -and -not $split.Blocking -and (Test-RunCompleted $trx)) { $code = 0 }
        # A full run reruns each failed test once, only to label it; the run stays failed.
        if ($Full -and $code -ne 0 -and $split.Blocking -and -not $Coverage) {
            $again = @($split.Blocking | Select-Object -First 25)
            $rerun = Join-Path $results 'rerun'
            & dotnet test $tests --nologo @buildPriority --no-build --filter (($again | ForEach-Object { "FullyQualifiedName~$_" }) -join '|') `
                --logger 'trx;LogFileName=rerun.trx' --results-directory $rerun | Out-Host
            $rerunTrx = Join-Path $rerun 'rerun.trx'
            $passedAgain = $null
            if ((Test-Path $rerunTrx) -and (Test-RunCompleted $rerunTrx)) { $passedAgain = @(Get-PassedTests $rerunTrx) }
            $labels = @(Get-FailureLabels $again $passedAgain)
            if ($split.Blocking.Count -gt $again.Count) { $labels += "$($split.Blocking.Count - $again.Count) more failed test(s) not rerun (the rerun takes 25)" }
            Set-Content -Path (Join-Path $gitDir 'corvus-last-run-labels.txt') -Value $labels
            Write-Host "Failures after one rerun (the run stays failed):`n  $($labels -join "`n  ")" -ForegroundColor Red
            # Keep failure causes in the log and a saved copy, since the next run replaces the TRX.
            Write-FailureMessages $trx $split.Blocking
            $failedRun = "$(Get-Date -Format 'yyyyMMdd-HHmmss')-$((git -C $root rev-parse --short HEAD).Trim())"
            Save-FailedRun (Join-Path $gitDir 'corvus-failed-runs') $failedRun @($trx, $rerunTrx)
            Write-Host "Results kept in $(Join-Path $gitDir "corvus-failed-runs/$failedRun.trx")."
        }
    }
    $dumps = @(Get-ChildItem $results -Recurse -Include '*.dmp', 'Sequence_*.xml' -ErrorAction SilentlyContinue)
    if ($dumps) {
        $kept = Join-Path $gitDir "corvus-hang-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        New-Item -ItemType Directory -Force $kept | Out-Null
        $dumps | Copy-Item -Destination $kept
        Write-Host "A test ran past its hang limit ($hangLimit): dump and test sequence in $kept." -ForegroundColor Red
        # Full dumps (over 100 MB) stay in the newest three hang folders; older ones keep their test sequence.
        Get-ChildItem $gitDir -Directory -Filter 'corvus-hang-*' | Sort-Object Name -Descending | Select-Object -Skip 3 |
            ForEach-Object { Get-ChildItem $_.FullName -Filter '*.dmp' | Where-Object Length -gt 100MB | Remove-Item -Force -ErrorAction SilentlyContinue }
    }
    if ($Coverage) {
        $reports = @(Get-ChildItem $results -Recurse -Filter coverage.cobertura.xml -ErrorAction SilentlyContinue)
        if (-not $reports) { Write-Host 'No coverage report was written.' -ForegroundColor Red; if ($code -eq 0) { $code = 1 } }
        else {
            $rate = ([xml](Get-Content $reports[0].FullName -Raw)).coverage.'line-rate'
            Write-Host ("Line coverage of corvus: {0:0.0}%" -f (100 * [double]::Parse($rate, [cultureinfo]::InvariantCulture)))
            # Kept in .git for a report tool or a later floor check (CORVUS_COVERAGE_REPORT=<file>).
            Copy-Item $reports[0].FullName (Join-Path $gitDir 'corvus-coverage.cobertura.xml') -Force
            Write-Host "Report: $(Join-Path $gitDir 'corvus-coverage.cobertura.xml')"
            # Instrumentation can fail timing budgets; the plain full run gates those, this run gates the floors.
            if ($code -ne 0) { Write-Host 'Some tests failed under coverage instrumentation (timing budgets are expected to); the floor check decides this run.' -ForegroundColor Yellow }
            $env:CORVUS_COVERAGE_REPORT = $results
            try { & dotnet test $tests --nologo @buildPriority --no-build --filter 'FullyQualifiedName~CoverageFloorTests' }
            finally { Remove-Item Env:CORVUS_COVERAGE_REPORT }
            $code = $LASTEXITCODE
        }
    }
    if (Test-Path $results) { Remove-Item -Recurse -Force $results }
    if ($missingEngines) { Write-Host "Engine tests were skipped: $($missingEngines -join ', ')." -ForegroundColor Yellow }
    if ($code -ne 0) { exit $code }
    if ($tree -and -not $recordFailed -and -not $notRun) {
        try { Write-TreeStamp $tree $mode ([bool]$Filter) }
        catch { Write-Host "Stamping the tree failed ($_); the results are kept: ./test.ps1 -Stamp records them without a rerun." -ForegroundColor Red }
    }
    if ($wholeSuite -and -not $Coverage -and $env:CORVUS_SECOND_GHIDRA_DIR) {
        $code = Invoke-SecondGhidra
        if ($code -ne 0) { exit $code }
    }
}
finally {
    $env:CORVUS_ALL_TESTS = $saved; $env:CORVUS_SWEEP = $savedSweep; $env:CORVUS_PERMIT_MAX_WAIT = $savedMaxWait
    if ($heavy) { Exit-HeavyLock $heavyLock }
}
