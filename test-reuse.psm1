# Per-family reuse of full-suite passes (test.ps1 -Reuse): which families a change touches, each family's input key,
# which families must run again, and which passed in a run's TRX results.

# Test folders whose classes always run: cross-cutting contract tests and shared helpers.
$script:AlwaysRunFolders = 'Contract', 'Support', 'ContractSweepData'
# Flaky under load (OI-T1): a pass on another machine state proves little, so they always run.
$script:AlwaysRunClasses = 'McpProtocolTests', 'DeadlineTests', 'ConcurrencyTests', 'CallDeadlineTests', 'TokenEstimateCalibrationTests', 'ReanalyzeNativeTests'

# The family a tracked file belongs to for reuse: a family name, '*' (every family) or 'root' (the families whose tests
# read repository files). Stricter than test.ps1's Get-Family: only a family's own Tools/Services folders are its own.
function Get-ReuseScope([string]$path) {
    $p = $path -replace '\\', '/'
    switch -Regex ($p) {
        '^src/Corvus/(Tools|Services)/Shared/' { return '*' }
        '^src/Corvus/(Tools|Services)/(Dotnet|DotnetEdits|NativeAnalysis|Engines|NativeEdits|Builds|Containers|Mobile|Dumps|Il2Cpp|NativeAot|Session|Web)/' { return $Matches[2] }
        '^tests/Corvus\.Tests/(Support|ContractSweepData)/' { return '*' }
        '^tests/Corvus\.Tests/(Ratchets|ProtocolSamples|TokenCorpus)/' { return 'Contract' }
        '^tests/Corvus\.Tests/PipelineSamples/' { return 'DotnetEdits' }
        '^tests/Corvus\.Tests/NativeAotSample/' { return 'NativeAot' }
        '^tests/Corvus\.Tests/([^/]+)/' { return $Matches[1] }
        '^(src|tests)/' { return '*' }
        default { return 'root' }
    }
}

# Top-level test classes per test folder: @{ family = @(classes) }.
function Get-ClassMap([string]$testsDir) {
    $map = @{}
    foreach ($dir in Get-ChildItem $testsDir -Directory | Where-Object Name -notin 'bin', 'obj') {
        $classes = Get-ChildItem $dir.FullName -Recurse -Filter *.cs | ForEach-Object {
            [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^public (?:sealed |abstract |partial |static )*class (\w+)') | ForEach-Object { $_.Groups[1].Value }
        } | Sort-Object -Unique
        if ($classes) { $map[$dir.Name] = @($classes) }
    }
    return $map
}

# Test classes whose summed duration in a TRX file is at least $minSeconds: the ones worth a coverage run and a reuse
# key of their own (a few slow classes hold most of a full run's time).
function Get-SlowClasses([string]$trxPath, [double]$minSeconds = 30) {
    if (-not (Test-Path $trxPath)) { return @() }
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $classOf[$test.Node.id] = ($test.Node.TestMethod.className -split '\.')[-1] -replace '\+.*$', ''
    }
    $seconds = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        if (-not $result.Node.duration) { continue }
        $class = $classOf[$result.Node.testId]
        $seconds[$class] = $seconds[$class] + [TimeSpan]::Parse($result.Node.duration, [cultureinfo]::InvariantCulture).TotalSeconds
    }
    @($seconds.Keys | Where-Object { $seconds[$_] -ge $minSeconds } | Sort-Object)
}

# Whether a test folder's classes always run (-Reuse never skips them).
function Test-AlwaysRunFolder([string]$family) { $family -in $script:AlwaysRunFolders }

# Families whose tests read files outside src/ and tests/ (docs, scripts, workflows), found by their use of RepoRoot().
function Get-RootReaders([string]$testsDir) {
    Get-ChildItem $testsDir -Directory | Where-Object Name -notin 'bin', 'obj' | Where-Object {
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | Select-String -SimpleMatch 'RepoRoot()' -List | Select-Object -First 1
    } | ForEach-Object Name
}

# The inputs every family key shares: SDK, OS build and the settings, with $override in place of the current values.
function Get-RunEnvironment([hashtable]$override = @{}) {
    $os = if ($IsWindows) { $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; "windows $($v.CurrentBuild).$($v.UBR)" } else { uname -srm }
    $values = @{}
    Get-ChildItem env: | Where-Object { ($_.Name -like 'CORVUS_*' -and $_.Name -notin 'CORVUS_ALL_TESTS', 'CORVUS_SWEEP', 'CORVUS_UPDATE_DOCS', 'CORVUS_BACKGROUND_DIR', 'CORVUS_HEAVY_LOCK') -or $_.Name -eq 'JAVA_HOME' } |
        ForEach-Object { $values[$_.Name] = $_.Value }
    foreach ($name in $override.Keys) { $values[$name] = $override[$name] }
    $settings = $values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" }
    (@("sdk $(dotnet --version)", $os) + $settings) -join "`n"
}

# One key per family from `git ls-tree -r` lines ("<mode> blob <sha>\t<path>") and an environment string. With a
# coverage map (Read-CoverageMap), a source file the families' tests ran keys only those families.
function Get-FamilyKeys([string[]]$treeLines, [string[]]$families, [string[]]$rootReaders, [string]$environment, [hashtable]$coverage = $null) {
    $own = @{}; $shared = [System.Text.StringBuilder]::new(); $root = [System.Text.StringBuilder]::new()
    foreach ($line in $treeLines) {
        $tab = $line.IndexOf("`t"); if ($tab -lt 0) { continue }
        $entry = $line
        $path = $line.Substring($tab + 1)
        $scopes = if ($coverage -and $coverage[$path]) { $coverage[$path] } else { Get-ReuseScope $path }
        switch ($scopes) {
            '*' { [void]$shared.AppendLine($entry) }
            'root' { [void]$root.AppendLine($entry) }
            default { if (-not $own[$_]) { $own[$_] = [System.Text.StringBuilder]::new() }; [void]$own[$_].AppendLine($entry) }
        }
    }
    $keys = @{}
    foreach ($family in $families) {
        $text = "$environment`n$shared`n$(if ($rootReaders -contains $family) { $root } else { '' })`n$($own[$family])"
        $keys[$family] = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($text)))
    }
    return $keys
}

# The map test.ps1 -CoverageMap writes, as a hashtable; $null when there is none or it is older than $maxDays (calls
# added since would be missed; the folder rules then apply).
function Read-MapFile([string]$file, [int]$maxDays) {
    if (-not (Test-Path $file)) { return $null }
    $map = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable
    if ([datetime]::ParseExact($map.at, 'yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) -lt (Get-Date).AddDays(-$maxDays)) { return $null }
    return $map
}

# Which source files each family's tests ran, as @{ path = @(families) }; $null without a current map. A class mapped
# on its own (Read-ClassCoverage) counts for its family, or with -Classes for itself as 'class:<name>' (Split-ClassMap).
function Read-CoverageMap([string]$file, [int]$maxDays = 7, [switch]$Classes) {
    $map = Read-MapFile $file $maxDays
    if (-not $map) { return $null }
    $byPath = @{}
    foreach ($family in $map.families.Keys) { foreach ($path in $map.families[$family]) { $byPath[$path] = @($byPath[$path]) + $family | Where-Object { $_ } } }
    if ($map.classes) {
        foreach ($class in $map.classes.Keys) {
            $scope = if ($Classes) { "class:$class" } else { $map.classes[$class].family }
            foreach ($path in $map.classes[$class].files) { $byPath[$path] = @($byPath[$path]) + $scope | Where-Object { $_ } | Sort-Object -Unique }
        }
    }
    return $byPath
}

# The classes mapped on their own, as @{ class = @{ family; files } }; empty without a current map or with an older map.
function Read-ClassCoverage([string]$file, [int]$maxDays = 7) {
    $map = Read-MapFile $file $maxDays
    if (-not $map -or -not $map.classes) { return @{} }
    return $map.classes
}

# A class map with each class mapped on its own moved out of its family into a family of its own, 'class:<name>', so the
# reuse functions key, filter and record it like a family.
function Split-ClassMap([hashtable]$classMap, [hashtable]$classCoverage) {
    $split = @{}
    foreach ($family in $classMap.Keys) {
        $rest = @($classMap[$family] | Where-Object { -not $classCoverage[$_] })
        if ($rest) { $split[$family] = $rest }
        foreach ($class in $classMap[$family] | Where-Object { $classCoverage[$_] }) { $split["class:$class"] = @($class) }
    }
    return $split
}

# Coverage scopes with the test files of each class mapped on its own: every file of its family's test folder keys the
# family and each such class of it (a class may use any helper or fixture of its folder).
function Add-ClassTestScopes([hashtable]$coverage, [hashtable]$classCoverage, [string[]]$paths) {
    $scoped = @{} + $coverage
    $byFamily = @{}
    foreach ($class in $classCoverage.Keys) { $byFamily[$classCoverage[$class].family] = @($byFamily[$classCoverage[$class].family]) + "class:$class" | Where-Object { $_ } }
    foreach ($path in $paths) {
        if ($path -match '^tests/Corvus\.Tests/([^/]+)/' -and $byFamily[$Matches[1]]) { $scoped[$path] = @($Matches[1]) + $byFamily[$Matches[1]] }
    }
    return $scoped
}

# The repository paths of the source files with a line hit in a coverlet Cobertura report.
function Get-CoveredFiles([string]$reportPath, [string]$repoRoot) {
    [xml]$report = Get-Content $reportPath -Raw
    $sources = @($report.coverage.sources.source | ForEach-Object { "$_" })
    $repo = [IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    @($report.SelectNodes('//class') | Where-Object { [double]::Parse($_.'line-rate', [cultureinfo]::InvariantCulture) -gt 0 } | ForEach-Object {
        $name = $_.filename
        $full = if ([IO.Path]::IsPathRooted($name)) { $name } else { $sources | ForEach-Object { Join-Path $_ $name } | Where-Object { Test-Path $_ } | Select-Object -First 1 }
        if ($full) { $full = [IO.Path]::GetFullPath($full) }
        if ($full -and $full.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) { $full.Substring($repo.Length) -replace '\\', '/' }
    } | Sort-Object -Unique)
}

# Families that must run: no stamp, a different key, or a sampled pass when an exhaustive one is needed.
function Get-StaleFamilies([hashtable]$keys, $stamps, [bool]$exhaustive) {
    @($keys.Keys | Where-Object {
        $s = if ($stamps) { $stamps.$_ } else { $null }
        -not $s -or $s.key -ne $keys[$_] -or ($exhaustive -and $s.mode -ne 'exhaustive') -or $_ -in $script:AlwaysRunFolders
    } | Sort-Object)
}

# The dotnet test filter for the stale families plus the always-run classes; $null when everything must run.
function Get-ReuseFilter([string[]]$stale, [hashtable]$classMap) {
    if (@($classMap.Keys | Where-Object { $_ -notin $stale }).Count -eq 0) { return $null }
    $classes = @($stale | ForEach-Object { $classMap[$_] }) + $script:AlwaysRunClasses | Where-Object { $_ } | Sort-Object -Unique
    $filter = ($classes | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|'
    if ($filter.Length -gt 24000) { return $null }   # the command line limit; running everything is the safe answer
    return $filter
}

# Families whose every executed test passed in a TRX file; empty when a failure is not attributed to a known class, or
# when the run failed (a leak guard, a crashed host) with no failed test to blame.
function Get-PassedFamilies([string]$trxPath, [hashtable]$classMap, [int]$exitCode = 0) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $familyOf = @{}; foreach ($f in $classMap.Keys) { foreach ($c in $classMap[$f]) { $familyOf[$c] = $f } }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $class = ($test.Node.TestMethod.className -split '\.')[-1] -replace '\+.*$', ''
        $classOf[$test.Node.id] = $class
    }
    $ran = @{}; $failed = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $family = $familyOf[$classOf[$result.Node.testId]]
        $outcome = $result.Node.outcome
        if ($outcome -eq 'NotExecuted') { continue }
        if (-not $family) { if ($outcome -ne 'Passed') { return @() } else { continue } }
        $ran[$family] = $true
        if ($outcome -ne 'Passed') { $failed[$family] = $true }
    }
    if ($exitCode -ne 0 -and $failed.Count -eq 0) { return @() }
    @($ran.Keys | Where-Object { -not $failed[$_] } | Sort-Object)
}

# Records the families a run passed in the stamps file -Reuse reads; a sampled pass never replaces an exhaustive one on the same key.
function Save-FamilyPasses([string]$stampsPath, [string[]]$passed, [hashtable]$keys, [string]$mode, [string]$commit) {
    $stamps = if (Test-Path $stampsPath) { Get-Content $stampsPath -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
    foreach ($family in $passed) {
        if ($stamps[$family] -and $stamps[$family].key -eq $keys[$family] -and $stamps[$family].mode -eq 'exhaustive') { continue }
        $stamps[$family] = [ordered]@{ key = $keys[$family]; mode = $mode; commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm') }
    }
    $temp = "$stampsPath.tmp"
    Set-Content -Path $temp -Value ($stamps | ConvertTo-Json -Depth 3) -NoNewline
    Move-Item -Force $temp $stampsPath
}

# Whether every changed path (git's forward-slash form) is documentation outside src/ and tests/: such a change leaves
# every family key but those of the families reading repository files, so a whole pass before it holds for the rest.
function Test-DocsOnly([string[]]$paths) {
    $paths = @($paths | Where-Object { $_ })
    $paths.Count -gt 0 -and -not ($paths | Where-Object { $_ -match '^(src|tests)/' -or -not ($_ -match '^docs/' -or $_ -match '\.md$') })
}

# The tests that did not pass in a TRX file, as "Class+Nested.Method" names a dotnet test filter matches.
function Get-FailedTests([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $nameOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $nameOf[$test.Node.id] = "$($test.Node.TestMethod.className).$($test.Node.TestMethod.name)"
    }
    @(Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns | Where-Object { $_.Node.outcome -notin 'Passed', 'NotExecuted' } |
        ForEach-Object { $nameOf[$_.Node.testId] } | Sort-Object -Unique)
}

# Takes the machine-wide heavy lock a whole-suite run holds, so lanes' engine loops and load generators wait for it.
# CORVUS_HEAVY_LOCK names a script taking `heavy <name> -OwnerPid <pid>` (waits, then holds the lock exclusively) and
# `release <name>`; unset, there is no lock. Returns whether the lock was taken.
function Enter-HeavyLock([string]$name) {
    if (-not $env:CORVUS_HEAVY_LOCK) { return $false }
    Write-Host "Waiting for the heavy lock ($env:CORVUS_HEAVY_LOCK)."
    & $env:CORVUS_HEAVY_LOCK heavy $name -OwnerPid $PID | Out-Host
    return $true
}

# Releases the heavy lock taken by Enter-HeavyLock.
function Exit-HeavyLock([string]$name) {
    if ($env:CORVUS_HEAVY_LOCK) { & $env:CORVUS_HEAVY_LOCK release $name | Out-Host }
}

Export-ModuleMember -Function Enter-HeavyLock, Exit-HeavyLock, Get-RunEnvironment, Get-ReuseScope, Get-ClassMap, Get-SlowClasses, Test-AlwaysRunFolder, Read-ClassCoverage, Split-ClassMap, Add-ClassTestScopes, Get-RootReaders, Get-FamilyKeys, Read-CoverageMap, Get-CoveredFiles, Get-StaleFamilies, Get-ReuseFilter, Get-PassedFamilies, Save-FamilyPasses, Test-DocsOnly, Get-FailedTests
