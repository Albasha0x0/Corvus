# Runs the tests. The quick set by default; -Full runs everything (slow, IDA and Ghidra tests; set CORVUS_GHIDRA_DIR for
# Ghidra) and, on a clean tree, stamps the tree it passed on, so a later -Full -IfChanged (or release.ps1) skips a repeat.
# Usage:  ./test.ps1                      # quick set (before each commit)
#         ./test.ps1 -Full                # full suite (before a release or a gate run)
#         ./test.ps1 -Full -IfChanged     # full suite unless it already passed on this exact tree
#         ./test.ps1 -Full -Exhaustive    # the real-image sweeps take every input, not a quarter (gates and releases)
#         ./test.ps1 -Affected            # quick set plus the slow tests of the families changed since origin/main (before a push)
#         ./test.ps1 -Filter <expr>       # any dotnet test filter, quick or full
#         ./test.ps1 -Full -Reuse         # only the families whose inputs changed since their last full pass (test-reuse.psm1)
#         ./test.ps1 -Full -Background    # after a push: exhaustive with -Reuse on the committed HEAD in a worktree of its own;
#                                         #   returns at once (-Sampled: the routine quarter of the sweeps, no reuse;
#                                         #   -Whole: exhaustive without reuse, the pass a minor release gates on)
#         ./test.ps1 -SecondGhidra        # the Engines tests with CORVUS_SECOND_GHIDRA_DIR, unless they passed on these inputs
#         ./test.ps1 -Status              # the last background run: passed / failed / running, and its log
#         ./test.ps1 -Full -Coverage      # also collects line coverage (coverlet) and checks Ratchets/coverage.txt
#         ./test.ps1 -Mutation [-Target sqlite,pe]  # mutation testing of the core readers (Stryker.NET; tests/mutation.json),
#                                         #   surviving mutants checked against Ratchets/mutation-survivors.txt (gates and releases)
#Requires -Version 7.0
param(
    [switch]$Full,
    [switch]$IfChanged,
    [switch]$Exhaustive,
    [switch]$Affected,
    [string]$Base = 'origin/main',
    [string]$Filter,
    [switch]$Background,
    [switch]$Status,
    [switch]$Reuse,
    [switch]$Sampled,
    [switch]$Whole,
    [switch]$SecondGhidra,
    [switch]$Coverage,
    [switch]$Mutation,
    [string[]]$Target
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

if ($Status) {
    if (-not (Test-Path $result)) { Write-Host 'No background run yet.'; exit 0 }
    Write-Host (Get-Content $result -Raw).Trim()
    if (Test-Path $log) { Get-Content $log -Tail 5 | Where-Object { $_ -match '\[FAIL\]|Passed!|Failed!|Stamped' } | ForEach-Object { Write-Host "  $_" } }
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
# is removed when the run ends; its stamp counts for -IfChanged and release.ps1 (same tree).
if ($Background) {
    $commit = (git -C $root rev-parse HEAD).Trim()
    if (git -C $root status --porcelain) { Write-Host 'Uncommitted changes are not part of the background run (it tests HEAD).' }
    $dir = Join-Path ([IO.Path]::GetTempPath()) "corvus-bg-$($commit.Substring(0, 8))"
    if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    git -C $root worktree add --detach $dir $commit | Out-Null
    # Release strength by default, so its family passes let a patch release skip what this run proved.
    $flags = '-Full' + $(if ($Sampled) { '' } elseif ($Whole) { ' -Exhaustive' } else { ' -Exhaustive -Reuse' })
    $short = $commit.Substring(0, 8)
    Set-Content -Path $result -Value "$short running since $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -NoNewline
    $script = @"
Set-Location '$dir'
& ./test.ps1 $flags *> '$log'
`$code = `$LASTEXITCODE
Set-Content -Path '$result' -Value ('$short ' + `$(if (`$code -eq 0) { 'passed' } else { 'FAILED (exit ' + `$code + ')' }) + ' at ' + (Get-Date -Format 'yyyy-MM-dd HH:mm')) -NoNewline
Set-Location '$root'
git worktree remove --force '$dir'
"@
    # -WindowStyle exists on Windows only; elsewhere nohup keeps the run past the terminal.
    $start = @{ FilePath = 'pwsh'; ArgumentList = @('-NoProfile', '-Command', $script) }
    if ($IsWindows) { $start.WindowStyle = 'Hidden' }
    else { $start.FilePath = 'nohup'; $start.ArgumentList = @('pwsh') + $start.ArgumentList; $start.RedirectStandardOutput = '/dev/null' }
    Start-Process @start | Out-Null
    Write-Host "Full suite started in the background on $short ($dir); ./test.ps1 -Status shows the result."
    exit 0
}

# The test family a changed file belongs to; '*' is shared code (every family), null a file no test reads.
function Get-Family([string]$path) {
    $p = $path -replace '\\', '/'
    switch -Regex ($p) {
        '^src/Corvus/(Tools|Services)/Shared/' { return '*' }
        '^src/Corvus/(Tools|Services)/(Dotnet|DotnetEdits|NativeAnalysis|Engines|NativeEdits|Builds|Containers|Mobile|Dumps|Il2Cpp|NativeAot|Session)/' { return $Matches[2] }
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
$stamp = Join-Path $gitDir 'corvus-full-suite.stamp'
$wholeStamp = Join-Path $gitDir 'corvus-whole-suite.stamp'

if ($Full -and $IfChanged) {
    $tree = Get-CleanTree
    $have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { '' }
    $done = if ($Exhaustive) { $have -in "$tree exhaustive", "$tree exhaustive reused" } else { $have -like "$tree *" }
    if ($tree -and $done) {
        Write-Host "The full suite already passed on tree $tree; skipped."
        exit 0
    }
}

# Per-family passes: every full run on a clean tree records which families passed under which input key (SDK, OS build,
# engine settings and the family's files; test-reuse.psm1), and -Reuse runs only the families whose key changed.
$familyStamps = Join-Path $gitDir 'corvus-family-stamps.json'
$mode = if ($Exhaustive) { 'exhaustive' } else { 'sampled' }
$familyKeys = $null
$wholeSuite = $Full -and -not $Filter

# The inputs every family key shares: SDK, OS build and the settings, with $override in place of the current values.
function Get-RunEnvironment([hashtable]$override = @{}) {
    $os = if ($IsWindows) { $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; "windows $($v.CurrentBuild).$($v.UBR)" } else { uname -srm }
    $values = @{}
    Get-ChildItem env: | Where-Object { ($_.Name -like 'CORVUS_*' -and $_.Name -notin 'CORVUS_ALL_TESTS', 'CORVUS_SWEEP', 'CORVUS_UPDATE_DOCS') -or $_.Name -eq 'JAVA_HOME' } |
        ForEach-Object { $values[$_.Name] = $_.Value }
    foreach ($name in $override.Keys) { $values[$name] = $override[$name] }
    $settings = $values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" }
    (@("sdk $(dotnet --version)", $os) + $settings) -join "`n"
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
        $key = (Get-FamilyKeys @(git -C $root ls-tree -r HEAD) @('Engines') @(Get-RootReaders $tests) $environment)['Engines']
        $last = if (Test-Path $secondStamp) { Get-Content $secondStamp -Raw | ConvertFrom-Json } else { $null }
        if ($last.key -ne $key) { $last = $null }
    }
    if ($last -and -not $last.failed) { Write-Host "Engine tests on the second Ghidra passed on these inputs ($($last.commit)); skipped."; return 0 }
    if ($last) {
        $filter = ($last.failed | ForEach-Object { "FullyQualifiedName~$_" }) -join '|'
        Write-Host "Engine tests on the second Ghidra: rerunning the $(@($last.failed).Count) that failed on these inputs."
    }
    $results = Join-Path $tempRoot "corvus-trx-second-$PID"
    $saved = $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS
    $env:CORVUS_GHIDRA_DIR = $env:CORVUS_SECOND_GHIDRA_DIR; $env:CORVUS_ALL_TESTS = '1'
    try { & dotnet test $tests --nologo --filter $filter --logger 'trx;LogFileName=second.trx' --results-directory $results | Out-Host; $code = $LASTEXITCODE }
    finally { $env:CORVUS_GHIDRA_DIR, $env:CORVUS_ALL_TESTS = $saved }
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

if ($wholeSuite -and (Get-CleanTree)) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    $familyKeys = Get-FamilyKeys @(git -C $root ls-tree -r HEAD) @($classMap.Keys) @(Get-RootReaders $tests) (Get-RunEnvironment)
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
if ($Filter) { $arguments += @('--filter', $Filter) }
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
    & dotnet @arguments
    $code = $LASTEXITCODE
    $trx = Join-Path $results 'full.trx'
    if ($familyKeys -and (Test-Path $trx)) {
        $passed = Get-PassedFamilies $trx $classMap $code
        $all = if (Test-Path $familyStamps) { Get-Content $familyStamps -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
        $commit = (git -C $root rev-parse --short HEAD).Trim()
        foreach ($family in $passed) {
            # A sampled pass never replaces an exhaustive one on the same key.
            if ($all[$family] -and $all[$family].key -eq $familyKeys[$family] -and $all[$family].mode -eq 'exhaustive') { continue }
            $all[$family] = [ordered]@{ key = $familyKeys[$family]; mode = $mode; commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
        }
        $temp = "$familyStamps.tmp"
        Set-Content -Path $temp -Value ($all | ConvertTo-Json -Depth 3) -NoNewline
        Move-Item -Force $temp $familyStamps
        Write-Host "Recorded $mode passes for $($passed.Count) families."
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
    if ($tree) {
        $value = "$tree $mode" + $(if ($Filter) { ' reused' } else { '' })
        Set-Content -Path $stamp -Value $value -NoNewline
        if ($Exhaustive -and -not $Filter) { Set-Content -Path $wholeStamp -Value $tree -NoNewline }
        Write-Host "Stamped $value."
    }
    if ($wholeSuite -and -not $Coverage -and $env:CORVUS_SECOND_GHIDRA_DIR) {
        $code = Invoke-SecondGhidra
        if ($code -ne 0) { exit $code }
    }
}
finally { $env:CORVUS_ALL_TESTS = $saved; $env:CORVUS_SWEEP = $savedSweep }
