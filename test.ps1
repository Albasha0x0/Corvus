# Runs the tests. The quick set by default; -Full runs everything (slow, IDA and Ghidra tests; set CORVUS_GHIDRA_DIR for
# Ghidra) and, on a clean tree, stamps the tree it passed on, so a later -Full -IfChanged (or release.ps1) skips a repeat.
# Usage:  ./test.ps1                      # before each commit: the quick tests of the families changed since origin/main
#         ./test.ps1 -All                 # the whole quick set
#         ./test.ps1 -Full                # full suite (before a release or a gate run)
#         ./test.ps1 -Full -IfChanged     # full suite unless it already passed on this exact tree
#         ./test.ps1 -Full -Exhaustive    # every sweep input, not a quarter, and the Tier=Release tests (gates and releases)
#         ./test.ps1 -Affected            # quick set plus the slow tests of the families changed since origin/main (before a push)
#         ./test.ps1 -Filter <expr>       # any dotnet test filter, quick or full
#         ./test.ps1 -Full -Reuse         # only the families whose inputs changed since their last full pass (test-reuse.psm1)
#         ./test.ps1 -Full -Background    # after a push: -Reuse on the committed HEAD in a worktree of its own; returns at once
#                                         #   (-Exhaustive: release strength, the passes a patch release takes;
#                                         #   -Whole: exhaustive without reuse, the pass a minor release gates on)
#         ./test.ps1 -SecondGhidra        # the Engines tests with CORVUS_SECOND_GHIDRA_DIR, unless they passed on these inputs
#         ./test.ps1 -Status              # the last background run: passed / failed / running, and its log
#         ./test.ps1 -Stamp               # records the last full run's passes when its recording step failed (same tree only)
#         ./test.ps1 -Full -Coverage      # also collects line coverage (coverlet) and checks Ratchets/coverage.txt
#         ./test.ps1 -CoverageMap         # which source files each family's tests run (weekly): -Reuse keys families on them
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
    [switch]$Stamp
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$tests = Join-Path $root 'tests/Corvus.Tests'
# The repository's own .git (shared by its worktrees): stamps and background results land there and are never committed.
$gitDir = [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root)
$result = Join-Path $gitDir 'corvus-background.result'
$log = Join-Path $gitDir 'corvus-background.log'
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
if ($Full -or $Background) { Import-UserTestVariables }

if ($Status) {
    if (-not (Test-Path $result)) { Write-Host 'No background run yet.'; exit 0 }
    $text = (Get-Content $result -Raw).Trim()
    # A run that ended without writing its result (killed, or its worktree
    # broke) leaves "running" and its record behind.
    $record = Join-Path $gitDir 'corvus-background.json'
    if ($text -match ' running since ' -and (Test-Path $record)) {
        $run = Get-Content $record -Raw | ConvertFrom-Json
        $alive = Get-Process -Id $run.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $run.started }
        if (-not $alive) { $text = "$($run.commit.Substring(0, 8)) not running (pid $($run.pid) gone, no result)" }
    }
    Write-Host $text
    if (Test-Path $log) { Get-Content $log -Tail 5 | Where-Object { $_ -match '\[FAIL\]|Passed!|Failed!|Stamped' } | ForEach-Object { Write-Host "  $_" } }
    $dumps = @(Get-ChildItem (Join-Path $gitDir 'corvus-stalls') -File -ErrorAction SilentlyContinue)
    if ($dumps) { Write-Host "  Worker thread dumps: $($dumps.Count) in $(Join-Path $gitDir 'corvus-stalls')" }
    if (Test-Path "$log.previous") {
        $before = Get-Content "$log.previous"
        Write-Host "Previous: $(($before | Select-Object -Last 1) -replace '^Result: ', '')"
        $before | Where-Object { $_ -match '\[FAIL\]|Failed!' } | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
    }
    exit 0
}

# Mutation testing: one Stryker.NET run (CORVUS_STRYKER, else dotnet-stryker on PATH) over the files and tests of the
# targets in tests/mutation.json, which holds every Stryker option. Stryker compiles the whole project once per run
# whatever is mutated, so targets share one run; MutationTests splits the report per target and checks the survivors.
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
    try { & dotnet test $tests --nologo --filter 'FullyQualifiedName~MutationTests' -p:CORVUS_ALL_TESTS=1 }
    finally { Remove-Item Env:CORVUS_MUTATION_REPORT }
    $code = $LASTEXITCODE
    $summary = Join-Path $out 'summary.txt'
    if (Test-Path $summary) { Get-Content $summary | ForEach-Object { Write-Host $_ } }
    if ($code -eq 0) { Remove-Item -Recurse -Force $out } else { Write-Host "Reports kept in $out." }
    exit $code
}

# A full run on the committed HEAD in a worktree of its own, so building and testing here continue meanwhile. The worktree
# is removed when the run ends; its stamp counts for -IfChanged and release.ps1 (same tree). A request while a run is
# going is queued: when the run ends, one run starts on the newest commit, at the strongest strength asked meanwhile,
# so runs always finish and pushes in between share one run.
$running = Join-Path $gitDir 'corvus-background.json'
$lastPassed = Join-Path $gitDir 'corvus-background.passed'
$queued = Join-Path $gitDir 'corvus-background.next'
if ($Background) {
    $commit = (git -C $root rev-parse HEAD).Trim()
    if (git -C $root status --porcelain) { Write-Host 'Uncommitted changes are not part of the background run (it tests HEAD).' }
    $strength = if ($Whole) { 'whole' } elseif ($Exhaustive) { 'exhaustive' } else { 'routine' }
    $previous = if (Test-Path $running) { Get-Content $running -Raw | ConvertFrom-Json } else { $null }
    $process = if ($previous) { Get-Process -Id $previous.pid -ErrorAction SilentlyContinue | Where-Object { $_.StartTime.ToUniversalTime().Ticks -eq $previous.started } } else { $null }
    if ($process) {
        $order = 'routine', 'exhaustive', 'whole'
        $asked = if (Test-Path $queued) { (Get-Content $queued -Raw).Trim() } else { 'routine' }
        if ($order.IndexOf($strength) -gt $order.IndexOf($asked)) { $asked = $strength }
        Set-Content -Path $queued -Value $asked -NoNewline
        Write-Host "A run on $($previous.commit.Substring(0, 8)) is going; queued: a run on the newest commit ($asked) when it ends (./test.ps1 -Status)."
        exit 0
    }
    # CORVUS_BACKGROUND_DIR: where the worktrees go, e.g. a folder the antivirus does not scan (script fixtures)
    $bgRoot = if ($env:CORVUS_BACKGROUND_DIR) { $env:CORVUS_BACKGROUND_DIR } else { [IO.Path]::GetTempPath() }
    $dir = Join-Path $bgRoot "corvus-bg-$($commit.Substring(0, 8))"
    if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    git -C $root worktree add --detach $dir $commit | Out-Null
    $checkedOut = git -C $dir rev-parse HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or "$checkedOut".Trim() -ne $commit) {
        Write-Host "The background run did not start: $dir is not a worktree of $commit (git worktree add failed)." -ForegroundColor Red
        exit 1
    }
    # Routine by default; release strength records the passes a release takes.
    $flags = '-Full' + $(if ($Whole) { ' -Exhaustive' } elseif ($Exhaustive) { ' -Exhaustive -Reuse' } else { ' -Reuse' })
    $short = $commit.Substring(0, 8)
    # the previous run's log and result stay readable (-Status) after the next run starts
    if (Test-Path $log) {
        Move-Item -Force $log "$log.previous"
        if (Test-Path $result) { Add-Content -Path "$log.previous" -Value "Result: $((Get-Content $result -Raw).Trim())" }
    }
    Set-Content -Path $result -Value "$short running since $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -NoNewline
    # Thread dumps of engine workers stopped for time stay next to the log.
    $stalls = Join-Path $gitDir 'corvus-stalls'
    # Below-normal priority, inherited by the test hosts and engine workers, keeps the machine responsive meanwhile.
    $script = @"
(Get-Process -Id `$PID).PriorityClass = 'BelowNormal'
Set-Location '$dir'
`$env:CORVUS_STALL_DIR = '$stalls'
& ./test.ps1 $flags *> '$log'
`$code = `$LASTEXITCODE
Set-Content -Path '$result' -Value ('$short ' + `$(if (`$code -eq 0) { 'passed' } else { 'FAILED (exit ' + `$code + ')' }) + ' at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')) -NoNewline
if (`$code -eq 0) { Set-Content -Path '$lastPassed' -Value '$commit' -NoNewline }
if ((Get-Content '$running' -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json).pid -eq `$PID) { Remove-Item '$running' }
Set-Location '$root'
git worktree remove --force '$dir'
if (Test-Path '$queued') {
    `$next = (Get-Content '$queued' -Raw).Trim(); Remove-Item '$queued'
    `$strength = @{ Full = `$true; Background = `$true }
    if (`$next -eq 'whole') { `$strength.Whole = `$true } elseif (`$next -eq 'exhaustive') { `$strength.Exhaustive = `$true }
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
        '^src/Corvus/(Tools|Services)/(Dotnet|DotnetEdits|NativeAnalysis|Engines|NativeEdits|Builds|Containers|Mobile|Dumps|Il2Cpp|NativeAot|Session|Web)/' { return $Matches[2] }
        '^src/Corvus/Services/Analysis/' { return 'Containers' }
        '^src/Corvus/Services/Il2CppRaw/' { return 'Il2Cpp' }
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

# The commit gate: the quick tests of the families a change touches (committed since $Base, uncommitted and untracked),
# by the coverage map where it knows a file, plus the contract tests; shared code runs the whole quick set. The full
# run after the push (the pre-push hook) runs everything.
if (-not ($Full -or $All -or $Affected -or $Filter -or $Coverage -or $CoverageMap -or $SecondGhidra -or $Background)) {
    $changed = @(git -C $root diff --name-only $Base) + @(git -C $root ls-files --others --exclude-standard) | Where-Object { $_ } | Sort-Object -Unique
    if (-not $changed) { Write-Host "Nothing changed since ${Base}; ./test.ps1 -All runs the whole quick set."; exit 0 }
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $coveredBy = Read-CoverageMap (Join-Path $gitDir 'corvus-coverage-map.json')
    # files outside src/ and tests/ (docs, scripts) go to the families whose tests read repository files
    $readers = @(Get-RootReaders $tests)
    $families = @(@($changed | ForEach-Object {
        if ($coveredBy -and $coveredBy[$_]) { $coveredBy[$_] } elseif ($_ -notmatch '^(src|tests)/') { $readers } else { Get-Family $_ } }) + 'Contract' | Sort-Object -Unique)
    if ($families -notcontains '*') {
        $classes = @($families | ForEach-Object { Get-FamilyClasses $_ } | Sort-Object -Unique)
        $quickFilter = 'Speed!=Slow&(' + (($classes | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|') + ')'
        if ($quickFilter.Length -lt 24000) {
            Write-Host "Changed since ${Base}: $($changed.Count) files; quick tests of $($families -join ', ')."
            & dotnet test $tests --nologo --filter $quickFilter
            exit $LASTEXITCODE
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

# The tree a full run passed on, and whether its sweeps were exhaustive, kept in .git so it is never committed. Only a
# clean tree has a hash worth recording.
function Get-CleanTree {
    if (git -C $root status --porcelain) { return $null }
    return (git -C $root rev-parse 'HEAD^{tree}').Trim()
}
# "<tree> <mode>", with " reused" when reused family passes made up part of it; the whole-suite stamp names the last tree
# an exhaustive run passed on without reuse (release.ps1: a minor release gates on it).
$treeStamp = Join-Path $gitDir 'corvus-full-suite.stamp'
$wholeStamp = Join-Path $gitDir 'corvus-whole-suite.stamp'
function Write-TreeStamp([string]$tree, [string]$mode, [bool]$reused) {
    $value = "$tree $mode" + $(if ($reused) { ' reused' } else { '' })
    Set-Content -Path $treeStamp -Value $value -NoNewline
    if ($mode -eq 'exhaustive' -and -not $reused) { Set-Content -Path $wholeStamp -Value $tree -NoNewline }
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

# Per-family passes: every full run on a clean tree records which families passed under which input key (SDK, OS build,
# engine settings and the family's files; test-reuse.psm1), and -Reuse runs only the families whose key changed.
$familyStamps = Join-Path $gitDir 'corvus-family-stamps.json'
$coverageMapFile = Join-Path $gitDir 'corvus-coverage-map.json'
$mode = if ($Exhaustive) { 'exhaustive' } else { 'sampled' }
$familyKeys = $null
$wholeSuite = $Full -and -not $Filter

# Records the saved run's passes (a run whose recording step failed), for the tree it ran on only.
if ($Stamp) {
    if (-not ((Test-Path $lastRun) -and (Test-Path $lastTrx))) { Write-Host 'No saved full run to record.' -ForegroundColor Red; exit 2 }
    $run = Get-Content $lastRun -Raw | ConvertFrom-Json -AsHashtable
    $tree = Get-CleanTree
    if ($tree -ne $run.tree) { Write-Host "The saved run was on tree $($run.tree); this tree is $(if ($tree) { $tree } else { 'not clean' }). Run the suite again." -ForegroundColor Red; exit 2 }
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $passed = Get-PassedFamilies $lastTrx (Get-ClassMap $tests) $run.code
    Save-FamilyPasses $familyStamps $passed $run.keys $run.mode $run.commit
    Write-Host "Recorded $($run.mode) passes for $($passed.Count) families from the run of $($run.at)."
    if ($run.code -ne 0) { Write-Host "The saved run failed (exit $($run.code)): the tree is not stamped." -ForegroundColor Red; exit 1 }
    Write-TreeStamp $tree $run.mode $run.reused
    exit 0
}

# The Engines tests again with a second Ghidra (the oldest supported, say), keyed like a family with that Ghidra in the
# settings: unchanged inputs skip it, and a retry under the same key runs only the tests that failed.
$secondStamp = Join-Path $gitDir 'corvus-second-ghidra.json'
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
    # CORVUS_TEST_ENGINE=ghidra: the IDA-only tests skip; another Ghidra version cannot change them
    $saved = $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS, $env:CORVUS_TEST_ENGINE
    $env:CORVUS_GHIDRA_DIR = $env:CORVUS_SECOND_GHIDRA_DIR; $env:CORVUS_ALL_TESTS = '1'; $env:CORVUS_TEST_ENGINE = 'ghidra'
    try { & dotnet test $tests --nologo --filter $filter --logger 'trx;LogFileName=second.trx' --results-directory $results | Out-Host; $code = $LASTEXITCODE }
    finally { $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS, $env:CORVUS_TEST_ENGINE = $saved }
    $trx = Join-Path $results 'second.trx'
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

# One instrumented run per family records the source files its tests ran; failures do not matter here (timing budgets
# fail under instrumentation), only what ran. Read-CoverageMap drops the map after a week.
if ($CoverageMap) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    & dotnet build $tests --nologo -v q
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $families = [ordered]@{}
    $saved = $env:CORVUS_ALL_TESTS; $env:CORVUS_ALL_TESTS = '1'
    try {
        foreach ($family in $classMap.Keys | Sort-Object) {
            $out = Join-Path $tempRoot "corvus-map-$PID-$family"
            $filter = ($classMap[$family] | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|'
            & dotnet test $tests --nologo --no-build --filter $filter --results-directory $out --collect 'XPlat Code Coverage' -- `
                'DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include=[corvus]*' | Out-Null
            $report = Get-ChildItem $out -Recurse -Filter coverage.cobertura.xml -ErrorAction SilentlyContinue | Select-Object -First 1
            # a family without a report keeps the folder rules for every file
            if ($report) { $families[$family] = @(Get-CoveredFiles $report.FullName $root) }
            Write-Host "$family`: $(if ($report) { "$($families[$family].Count) source files" } else { 'no report' })"
            if (Test-Path $out) { Remove-Item -Recurse -Force $out }
        }
    }
    finally { $env:CORVUS_ALL_TESTS = $saved }
    $record = [ordered]@{ commit = (git -C $root rev-parse --short HEAD).Trim(); at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); families = $families }
    Set-Content -Path $coverageMapFile -Value ($record | ConvertTo-Json -Depth 4) -NoNewline
    Write-Host "Coverage map: $coverageMapFile"
    exit 0
}

if ($wholeSuite -and (Get-CleanTree)) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    $coveredBy = Read-CoverageMap $coverageMapFile
    $familyKeys = Get-FamilyKeys @(git -C $root ls-tree -r HEAD) @($classMap.Keys) @(Get-RootReaders $tests) (Get-RunEnvironment) $coveredBy
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

$arguments = @('test', $tests, '--nologo')
# Measurements, accuracy oracles and the largest inputs (Tier=Release) run at release strength only; a filter given
# on the command line and coverage runs (the floors count them) keep them.
$runFilter = if ($Full -and -not $Exhaustive -and -not $Coverage -and -not $PSBoundParameters.ContainsKey('Filter')) { if ($Filter) { "($Filter)&Tier!=Release" } else { 'Tier!=Release' } } else { $Filter }
if ($runFilter) { $arguments += @('--filter', $runFilter) }
$results = Join-Path ([IO.Path]::GetTempPath()) "corvus-trx-$PID"
if ($familyKeys) { $arguments += @('--logger', 'trx;LogFileName=full.trx', '--results-directory', $results) }
# Coverage floors are set by whole-suite runs, so a partial run is never checked against them.
if ($Coverage) {
    if (-not $Full -or $Filter -or $Reuse) { Write-Host 'Coverage needs the whole suite: -Full without -Filter, -Affected or -Reuse.' -ForegroundColor Red; exit 2 }
    if (-not $familyKeys) { $arguments += @('--results-directory', $results) }
    $familyKeys = $null   # an instrumented run records no family passes and stamps no tree
    $arguments += @('--collect', 'XPlat Code Coverage', '--',
        'DataCollectionRunSettings.DataCollectors.DataCollector.Configuration.Include=[corvus]*')
}
$saved = $env:CORVUS_ALL_TESTS; $savedSweep = $env:CORVUS_SWEEP
try {
    if ($Full) { $env:CORVUS_ALL_TESTS = '1' }
    $env:CORVUS_SWEEP = if ($Exhaustive) { 'exhaustive' } else { $null }
    $tree = if ($wholeSuite -and -not $Coverage) { Get-CleanTree } else { $null }
    # A whole-suite run waits for a quiet machine and keeps it quiet until it ends.
    $heavyLock = "corvus-full-$PID"
    if ($wholeSuite) { Import-Module (Join-Path $root 'test-reuse.psm1') -Force; $heavy = Enter-HeavyLock $heavyLock }
    & dotnet @arguments
    $code = $LASTEXITCODE
    $trx = Join-Path $results 'full.trx'
    $recordFailed = $false
    if ($familyKeys -and (Test-Path $trx)) {
        $commit = (git -C $root rev-parse --short HEAD).Trim()
        # saved before recording, so a recording step that fails costs no rerun (-Stamp)
        Copy-Item $trx $lastTrx -Force
        $run = [ordered]@{ tree = $tree; mode = $mode; reused = [bool]$Filter; code = $code; keys = $familyKeys; commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
        Set-Content -Path $lastRun -Value ($run | ConvertTo-Json -Depth 3) -NoNewline
        try {
            $passed = Get-PassedFamilies $trx $classMap $code
            Save-FamilyPasses $familyStamps $passed $familyKeys $mode $commit
            Write-Host "Recorded $mode passes for $($passed.Count) families."
        }
        catch {
            $recordFailed = $true
            Write-Host "Recording the passes failed ($_); the results are kept: ./test.ps1 -Stamp records them without a rerun." -ForegroundColor Red
        }
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
            # Instrumentation slows every test, so timing budgets can fail here; the plain full run gates them, this run gates the floors.
            if ($code -ne 0) { Write-Host 'Some tests failed under coverage instrumentation (timing budgets are expected to); the floor check decides this run.' -ForegroundColor Yellow }
            $env:CORVUS_COVERAGE_REPORT = $results
            try { & dotnet test $tests --nologo --no-build --filter 'FullyQualifiedName~CoverageFloorTests' }
            finally { Remove-Item Env:CORVUS_COVERAGE_REPORT }
            $code = $LASTEXITCODE
        }
    }
    if (Test-Path $results) { Remove-Item -Recurse -Force $results }
    if ($missingEngines) { Write-Host "Engine tests were skipped: $($missingEngines -join ', ')." -ForegroundColor Yellow }
    if ($code -ne 0) { exit $code }
    if ($tree -and -not $recordFailed) {
        try { Write-TreeStamp $tree $mode ([bool]$Filter) }
        catch { Write-Host "Stamping the tree failed ($_); the results are kept: ./test.ps1 -Stamp records them without a rerun." -ForegroundColor Red }
    }
    if ($wholeSuite -and -not $Coverage -and $env:CORVUS_SECOND_GHIDRA_DIR) {
        $code = Invoke-SecondGhidra
        if ($code -ne 0) { exit $code }
    }
}
finally {
    $env:CORVUS_ALL_TESTS = $saved; $env:CORVUS_SWEEP = $savedSweep
    if ($heavy) { Exit-HeavyLock $heavyLock }
}
