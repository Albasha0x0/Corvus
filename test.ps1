# Runs the tests. The quick set by default; -Full runs everything (slow, IDA and Ghidra tests; set CORVUS_GHIDRA_DIR for
# Ghidra) and, on a clean tree, stamps the tree it passed on, so a later -Full -IfChanged (or release.ps1) skips a repeat.
# Usage:  ./test.ps1                      # quick set (before each commit)
#         ./test.ps1 -Full                # full suite (before a release or a gate run)
#         ./test.ps1 -Full -IfChanged     # full suite unless it already passed on this exact tree
#         ./test.ps1 -Full -Exhaustive    # the real-image sweeps take every input, not a quarter (gates and releases)
#         ./test.ps1 -Affected            # quick set plus the slow tests of the families changed since origin/main (before a push)
#         ./test.ps1 -Filter <expr>       # any dotnet test filter, quick or full
#         ./test.ps1 -Full -Reuse         # only the families whose inputs changed since their last full pass (test-reuse.psm1)
#         ./test.ps1 -Full -Background    # the full suite on the committed HEAD in a worktree of its own; returns at once
#         ./test.ps1 -Status              # the last background run: passed / failed / running, and its log
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
    [switch]$Reuse
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$tests = Join-Path $root 'tests/Corvus.Tests'
# The repository's own .git (shared by its worktrees): stamps and background results land there and are never committed.
$gitDir = [IO.Path]::GetFullPath((git -C $root rev-parse --git-common-dir).Trim(), $root)
$result = Join-Path $gitDir 'corvus-background.result'
$log = Join-Path $gitDir 'corvus-background.log'

if ($Status) {
    if (-not (Test-Path $result)) { Write-Host 'No background run yet.'; exit 0 }
    Write-Host (Get-Content $result -Raw).Trim()
    if (Test-Path $log) { Get-Content $log -Tail 5 | Where-Object { $_ -match '\[FAIL\]|Passed!|Failed!|Stamped' } | ForEach-Object { Write-Host "  $_" } }
    exit 0
}

# A full run on the committed HEAD in a worktree of its own, so building and testing here continue meanwhile. The worktree
# is removed when the run ends; its stamp counts for -IfChanged and release.ps1 (same tree).
if ($Background) {
    $commit = (git -C $root rev-parse HEAD).Trim()
    if (git -C $root status --porcelain) { Write-Host 'Uncommitted changes are not part of the background run (it tests HEAD).' }
    $dir = Join-Path ([IO.Path]::GetTempPath()) "corvus-bg-$($commit.Substring(0, 8))"
    if (Test-Path $dir) { git -C $root worktree remove --force $dir 2>$null; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    git -C $root worktree add --detach $dir $commit | Out-Null
    $flags = '-Full' + $(if ($Exhaustive) { ' -Exhaustive' } else { '' }) + $(if ($Reuse) { ' -Reuse' } else { '' })
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
    Start-Process pwsh -ArgumentList '-NoProfile', '-Command', $script -WindowStyle Hidden | Out-Null
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
$stamp = Join-Path $gitDir 'corvus-full-suite.stamp'

if ($Full -and $IfChanged) {
    $tree = Get-CleanTree
    $want = if ($Exhaustive) { "$tree exhaustive" } else { $null }
    $have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { '' }
    if ($tree -and ($have -eq $want -or (-not $Exhaustive -and $have -like "$tree *"))) {
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
if ($wholeSuite -and (Get-CleanTree)) {
    Import-Module (Join-Path $root 'test-reuse.psm1') -Force
    $classMap = Get-ClassMap $tests
    $os = if ($IsWindows) { $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; "windows $($v.CurrentBuild).$($v.UBR)" } else { uname -srm }
    $settings = Get-ChildItem env: | Where-Object { ($_.Name -like 'CORVUS_*' -and $_.Name -notin 'CORVUS_ALL_TESTS', 'CORVUS_SWEEP', 'CORVUS_UPDATE_DOCS') -or $_.Name -eq 'JAVA_HOME' } |
        Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }
    $environment = (@("sdk $(dotnet --version)", $os) + $settings) -join "`n"
    $familyKeys = Get-FamilyKeys @(git -C $root ls-tree -r HEAD) @($classMap.Keys) @(Get-RootReaders $tests) $environment
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

$arguments = @('test', $tests, '--nologo')
if ($Filter) { $arguments += @('--filter', $Filter) }
$results = Join-Path ([IO.Path]::GetTempPath()) "corvus-trx-$PID"
if ($familyKeys) { $arguments += @('--logger', 'trx;LogFileName=full.trx', '--results-directory', $results) }
$saved = $env:CORVUS_ALL_TESTS; $savedSweep = $env:CORVUS_SWEEP
try {
    if ($Full) { $env:CORVUS_ALL_TESTS = '1' }
    $env:CORVUS_SWEEP = if ($Exhaustive) { 'exhaustive' } else { $null }
    $tree = if ($wholeSuite -and -not $Filter) { Get-CleanTree } else { $null }
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
    if (Test-Path $results) { Remove-Item -Recurse -Force $results }
    if ($code -ne 0) { exit $code }
    if ($tree) { $value = "$tree $mode"; Set-Content -Path $stamp -Value $value -NoNewline; Write-Host "Stamped $value." }
}
finally { $env:CORVUS_ALL_TESTS = $saved; $env:CORVUS_SWEEP = $savedSweep }
