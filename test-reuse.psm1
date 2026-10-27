# Per-family reuse of full-suite passes (test.ps1 -Reuse): family input keys, stale families, and passes from TRX.

# How a test run lowers its priority on each OS, and the CORVUS_TEST_PRIORITY value that keeps it at normal priority.
$script:RunPriority = @{ Windows = 'BelowNormal'; Nice = 10; Normal = 'normal' }

# Test folders whose classes always run: cross-cutting contract tests and shared helpers.
$script:AlwaysRunFolders = 'Contract', 'Support', 'ContractSweepData'
# Flaky under load: a pass under another machine state proves little, so they always run.
$script:AlwaysRunClasses = 'McpProtocolTests', 'DeadlineTests', 'ConcurrencyTests', 'CallDeadlineTests', 'TokenEstimateCalibrationTests', 'ReanalyzeNativeTests'

# A tracked file's reuse scope: a family, '*' (every family) or 'root' (families that read repository files).
# Stricter than test.ps1's Get-Family: only a family's own Tools/Services folders count.
function Get-ReuseScope([string]$path) {
    $p = $path -replace '\\', '/'
    switch -Regex ($p) {
        '^src/Corvus/(Tools|Services)/Shared/' { return '*' }
        '^src/Corvus/(Tools|Services)/(Dotnet|DotnetEdits|NativeAnalysis|Engines|NativeEdits|Builds|Containers|Mobile|Dumps|AotMetadata|NativeAot|Session|Web)/' { return $Matches[2] }
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

# Test classes whose summed TRX duration is at least $minSeconds, worth their own coverage run and reuse key.
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

# State of a path a setting names, so an in-place change changes every key; $null when the path does not exist.
# A file: size and write time. A folder: up to 20000 entries three levels deep, by relative name, size and write time.
# Subfolder write times are left out: they move shortly after a file changes, so two reads in a row would differ.
function Get-PathStamp([string]$value) {
    if (-not $value -or $value.IndexOfAny([IO.Path]::GetInvalidPathChars()) -ge 0) { return $null }
    try {
        $item = Get-Item -LiteralPath $value -Force -ErrorAction Stop
        if (-not $item.PSIsContainer) { return "$($item.Length) $($item.LastWriteTimeUtc.Ticks)" }
        $options = [IO.EnumerationOptions]@{ RecurseSubdirectories = $true; MaxRecursionDepth = 2; IgnoreInaccessible = $true; AttributesToSkip = [IO.FileAttributes]::ReparsePoint }
        $lines = [Collections.Generic.List[string]]::new()
        foreach ($entry in $item.EnumerateFileSystemInfos('*', $options)) {
            if ($lines.Count -ge 20000) { break }
            $name = $entry.FullName.Substring($item.FullName.Length)
            $lines.Add($(if ($entry -is [IO.FileInfo]) { "$name|$($entry.Length)|$($entry.LastWriteTimeUtc.Ticks)" } else { $name }))
        }
        $lines.Sort([StringComparer]::Ordinal)
        return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($lines -join "`n"))).Substring(0, 16)
    }
    catch { return $null }
}

# Inputs every family key shares: SDK, OS build, settings with their paths' state, and $tools; $override replaces
# current values.
function Get-RunEnvironment([hashtable]$override = @{}, [string[]]$tools = @()) {
    $os = if ($IsWindows) { $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; "windows $($v.CurrentBuild).$($v.UBR)" } else { uname -srm }
    $values = @{}
    # CORVUS_ANNOTATIONS_DIR is a test run's own folder (a7a9d20d), written while the run goes: run state, not an input.
    Get-ChildItem env: | Where-Object { ($_.Name -like 'CORVUS_*' -and $_.Name -notin 'CORVUS_ALL_TESTS', 'CORVUS_SWEEP', 'CORVUS_UPDATE_DOCS', 'CORVUS_BACKGROUND_DIR', 'CORVUS_HEAVY_LOCK', 'CORVUS_PERMIT_LOG', 'CORVUS_TEST_HISTORY', 'CORVUS_TEST_MODE', 'CORVUS_STALL_DIR', 'CORVUS_PERMITS_HELD', 'CORVUS_TEST_PRIORITY', 'CORVUS_SEED_VALIDATE', 'CORVUS_ANNOTATIONS_DIR') -or $_.Name -in 'JAVA_HOME', 'GHIDRA_INSTALL_DIR' } |
        ForEach-Object { $values[$_.Name] = $_.Value }
    # The IDA install the tests find without CORVUS_IDA_DIR: the one IDA's own configuration names.
    $idaConfig = if ($IsWindows) { Join-Path "$env:APPDATA" 'Hex-Rays/IDA Pro/ida-config.json' } else { Join-Path $HOME '.idapro/ida-config.json' }
    if (-not $values['CORVUS_IDA_DIR'] -and (Test-Path $idaConfig)) {
        try { $values['ida-config'] = (Get-Content $idaConfig -Raw | ConvertFrom-Json).Paths.'ida-install-dir' } catch { }
    }
    foreach ($name in $override.Keys) { $values[$name] = $override[$name] }
    $settings = $values.Keys | Sort-Object | ForEach-Object { "$_=$($values[$_])" + $(if ($stamp = Get-PathStamp $values[$_]) { " @$stamp" }) }
    (@("sdk $(dotnet --version)", $os) + $settings + $tools) -join "`n"
}

# Lowers $processId (default: this one) to BelowNormal or nice 10, inherited by children; skipped when
# CORVUS_TEST_PRIORITY is 'normal'; failures are ignored.
function Set-RunPriority([int]$processId = $PID) {
    if ($env:CORVUS_TEST_PRIORITY -eq $RunPriority.Normal) { return }
    try {
        if ($IsWindows) { (Get-Process -Id $processId).PriorityClass = $RunPriority.Windows }
        else { & renice $RunPriority.Nice -p $processId *> $null }
    }
    catch { }
}

# The newest build of the test assembly under $testsDir/bin; $null when it is not built.
function Get-BuiltTestAssembly([string]$testsDir) {
    Get-ChildItem (Join-Path $testsDir 'bin') -Recurse -Filter 'Corvus.Tests.dll' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

# Where the test assembly finds each external tool, one line per tool (LocatedTools.cs); none when it is not built.
function Get-LocatedTools([string]$testsDir) {
    $assembly = Get-BuiltTestAssembly $testsDir
    if (-not $assembly) { return @() }
    @(& dotnet exec $assembly.FullName --located-tools 2>$null | Where-Object { $_ -like 'tool *' })
}

# Test classes whose collection runs alone, as "Outer+Nested" names; none when the test assembly is not built.
function Get-AloneClasses([string]$testsDir) {
    $assembly = Get-BuiltTestAssembly $testsDir
    if (-not $assembly) { return @() }
    @(& dotnet exec $assembly.FullName --alone-classes 2>$null | Where-Object { $_ -like 'class *' } | ForEach-Object { $_.Substring(6) })
}

# Splits $filter (empty: every test) into Rest without the $alone classes and Alone with only them.
# Terms match the class between dots, so DeadlineTests excludes CallDeadlineTests.
function Get-AloneFilters([string]$filter, [string[]]$alone) {
    $base = if ($filter) { "($filter)&" } else { '' }
    [pscustomobject]@{
        Rest = $base + (($alone | ForEach-Object { "FullyQualifiedName!~.$_." }) -join '&')
        Alone = $base + '(' + (($alone | ForEach-Object { "FullyQualifiedName~.$_." }) -join '|') + ')'
    }
}

# One key per family from `git ls-tree -r` lines and an environment string; with a coverage map, a source file keys
# only the families whose tests ran it.
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

# The test.ps1 -CoverageMap map as a hashtable; $null when missing or older than $maxDays (folder rules apply then).
function Read-MapFile([string]$file, [int]$maxDays) {
    if (-not (Test-Path $file)) { return $null }
    $map = Get-Content $file -Raw | ConvertFrom-Json -AsHashtable
    if ([datetime]::ParseExact($map.at, 'yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) -lt (Get-Date).AddDays(-$maxDays)) { return $null }
    return $map
}

# Source files each family's tests ran, as @{ path = @(families) }; $null without a current map. A class mapped on
# its own counts for its family, or with -Classes as 'class:<name>'.
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

# A class map with each separately mapped class moved into its own family, 'class:<name>'.
function Split-ClassMap([hashtable]$classMap, [hashtable]$classCoverage) {
    $split = @{}
    foreach ($family in $classMap.Keys) {
        $rest = @($classMap[$family] | Where-Object { -not $classCoverage[$_] })
        if ($rest) { $split[$family] = $rest }
        foreach ($class in $classMap[$family] | Where-Object { $classCoverage[$_] }) { $split["class:$class"] = @($class) }
    }
    return $split
}

# Coverage scopes plus test files: each file of a family's test folder keys the family and its separately mapped
# classes, which may use any helper in the folder.
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

# Families whose every executed test passed in a TRX file; empty when a failure has no known class or the run failed
# with no failed test to blame.
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

# Families that failed under the key of their recorded pass: selection misses. Always-run folders never count.
function Get-SelectionMisses([string[]]$failedTests, [hashtable]$classMap, [hashtable]$keys, $stamps) {
    if (-not $stamps) { return @() }
    $familyOf = @{}; foreach ($f in $classMap.Keys) { foreach ($c in $classMap[$f]) { $familyOf[$c] = $f } }
    $failed = @($failedTests | ForEach-Object { $familyOf[($_ -split '\.')[-2] -replace '\+.*$', ''] } | Where-Object { $_ } | Sort-Object -Unique)
    @($failed | Where-Object { $_ -notin $script:AlwaysRunFolders -and $stamps.$_ -and $stamps.$_.key -eq $keys[$_] })
}

# Records passed families in the stamps file; a sampled pass never replaces an exhaustive one on the same key.
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

# Whether every changed path is documentation outside src/ and tests/, which changes only the 'root' families' keys.
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

# Each failed test's first failure message, keyed as Get-FailedTests names it; tests without one are left out.
function Get-FailureMessages([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $nameOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $nameOf[$test.Node.id] = "$($test.Node.TestMethod.className).$($test.Node.TestMethod.name)"
    }
    $messages = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns | Where-Object { $_.Node.outcome -notin 'Passed', 'NotExecuted' }) {
        $name = $nameOf[$result.Node.testId]
        $message = $result.Node.Output.ErrorInfo.Message
        if ($name -and $message -and -not $messages.ContainsKey($name)) { $messages[$name] = [string]$message }
    }
    $messages
}

# Copies a failed run's results into $folder as $name, keeping the newest $keep; the next run replaces the last TRX.
function Save-FailedRun([string]$folder, [string]$name, [string[]]$files, [int]$keep = 10) {
    New-Item -ItemType Directory -Force $folder | Out-Null
    $n = 0
    foreach ($file in $files | Where-Object { $_ -and (Test-Path $_) }) {
        Copy-Item $file (Join-Path $folder "$name$(if ($n++) { "-$n" }).trx") -Force
    }
    $runs = @(Get-ChildItem $folder -Filter '*.trx' | Group-Object { ($_.BaseName -split '-')[0..2] -join '-' } | Sort-Object Name -Descending)
    $runs | Select-Object -Skip $keep | ForEach-Object { $_.Group | Remove-Item -Force }
}

# The tests that passed in a TRX file (every result of the name passed), named as Get-FailedTests names them.
function Get-PassedTests([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $nameOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $nameOf[$test.Node.id] = "$($test.Node.TestMethod.className).$($test.Node.TestMethod.name)"
    }
    $results = @(Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns | ForEach-Object { [pscustomobject]@{ Name = $nameOf[$_.Node.testId]; Outcome = $_.Node.outcome } })
    @($results | Group-Object Name | Where-Object { -not ($_.Group | Where-Object Outcome -ne 'Passed') } | ForEach-Object Name | Sort-Object)
}

# Whether a TRX run ended normally: no aborted, timed-out or errored result and no aborted run (a crashed or hung host).
function Test-RunCompleted([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $summary = $trx.TestRun.ResultSummary
    $counters = $summary.Counters
    $summary.outcome -ne 'Aborted' -and [int]$counters.aborted -eq 0 -and [int]$counters.timeout -eq 0 -and [int]$counters.error -eq 0
}

# Labels each failed test after one rerun ($passedAgain $null: rerun incomplete); labels never change a verdict.
function Get-FailureLabels([string[]]$failed, [string[]]$passedAgain) {
    @($failed | ForEach-Object {
        if ($null -eq $passedAgain) { "$_`: failed (rerun did not complete)" }
        elseif ($_ -in $passedAgain) { "$_`: failed, passed on rerun (suspected flaky)" }
        else { "$_`: failed" }
    })
}

# Quarantine list: "test | owner | issue | yyyy-MM-dd (fix-by date)" lines, '#' comments. Empty for a missing file;
# throws on a malformed line.
function Read-Quarantine([string]$path) {
    if (-not (Test-Path $path)) { return @() }
    $number = 0
    @(foreach ($line in Get-Content $path) {
        $number++
        $text = $line.Trim()
        if (-not $text -or $text.StartsWith('#')) { continue }
        $fields = @($text -split '\|' | ForEach-Object { $_.Trim() })
        $until = [datetime]::MinValue
        if ($fields.Count -ne 4 -or @($fields | Where-Object { -not $_ }).Count -gt 0 -or
            -not [datetime]::TryParseExact($fields[3], 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$until)) {
            throw "$path line ${number}: expected 'test | owner | issue | yyyy-MM-dd', got '$text'"
        }
        [pscustomobject]@{ Test = $fields[0]; Owner = $fields[1]; Issue = $fields[2]; Until = $until }
    })
}

# Splits failed tests into Blocking and Quarantined (an entry dated $today or later); expired entries cover nothing.
function Split-Quarantined([string[]]$failed, $entries, [datetime]$today) {
    $covered = @{}
    foreach ($entry in $entries) { if ($entry.Until -ge $today.Date) { $covered[$entry.Test] = $true } }
    [pscustomobject]@{
        Blocking = @($failed | Where-Object { -not $covered.ContainsKey($_) })
        Quarantined = @($failed | Where-Object { $covered.ContainsKey($_) })
    }
}

# Takes the machine-wide heavy lock; returns whether it was taken. CORVUS_HEAVY_LOCK names a script taking
# `heavy <name> -OwnerPid <pid>` (waits, then holds it) and `release <name>`; unset means no lock.
function Enter-HeavyLock([string]$name) {
    if (-not $env:CORVUS_HEAVY_LOCK) { return $false }
    Write-Host "Waiting for the heavy lock ($env:CORVUS_HEAVY_LOCK)."
    & $env:CORVUS_HEAVY_LOCK heavy $name -OwnerPid $PID | Out-Host
    return $true
}

# The run queued in $file as @{ Strength; Commit }: routine with no commit when nothing is queued; an older file
# without a commit gives no commit (the run tests HEAD).
function Read-QueuedRun([string]$file) {
    $strength, $commit = if (Test-Path $file) { "$(Get-Content $file -Raw)".Trim() -split '\s+', 2 } else { 'routine', '' }
    @{ Strength = $(if ($strength) { $strength } else { 'routine' }); Commit = "$commit" }
}

# Queues a run of $commit at the strongest strength asked; a later commit replaces the queued one, so pushes in
# between share one run of the newest commit.
function Save-QueuedRun([string]$file, [string]$strength, [string]$commit) {
    $order = 'routine', 'exhaustive', 'whole'
    $asked = (Read-QueuedRun $file).Strength
    if ($order.IndexOf($strength) -gt $order.IndexOf($asked)) { $asked = $strength }
    Set-Content -Path $file -Value "$asked $commit" -NoNewline
    $asked
}

# Whole-suite heavy lock: runs without reuse wait for it; push runs take none, as permits bound them. True when taken.
function Enter-RunLock([string]$name, [bool]$reuse) {
    if ($reuse) { return $false }
    Enter-HeavyLock $name
}

# Appends a whole-suite pass ("<commit> <tree> <mode>[ reused] <time>") to the ledger, keeping its last 200 lines.
function Add-FullPass([string]$ledger, [string]$commit, [string]$stamp) {
    $lines = @(if (Test-Path $ledger) { Get-Content $ledger }) + "$commit $stamp $(Get-Date -Format 'yyyy-MM-ddTHH:mm')"
    Set-Content -Path $ledger -Value ($lines | Select-Object -Last 200)
}

# Newest full pass on HEAD's history: the ledger's newest ancestor commit, else the legacy last-pass file; else $null.
function Get-FullPass([string]$repo, [string]$ledger, [string]$legacyFile) {
    $candidates = @(if (Test-Path $ledger) { Get-Content $ledger | Where-Object { $_ } | ForEach-Object { ($_ -split ' ')[0] } })
    [array]::Reverse($candidates)
    if (Test-Path $legacyFile) { $candidates += (Get-Content $legacyFile -Raw).Trim() }
    foreach ($commit in $candidates) {
        git -C $repo merge-base --is-ancestor $commit HEAD 2>$null
        if ($LASTEXITCODE -eq 0) { return $commit }
    }
    return $null
}

# Releases the heavy lock taken by Enter-HeavyLock.
function Exit-HeavyLock([string]$name) {
    if ($env:CORVUS_HEAVY_LOCK) { & $env:CORVUS_HEAVY_LOCK release $name | Out-Host }
}

Export-ModuleMember -Function Add-FullPass, Get-FullPass, Read-QueuedRun, Save-QueuedRun, Enter-RunLock, Get-SelectionMisses, Get-PathStamp, Get-LocatedTools, Get-AloneClasses, Get-AloneFilters, Set-RunPriority, Enter-HeavyLock, Exit-HeavyLock, Get-RunEnvironment, Get-ReuseScope, Get-ClassMap, Get-SlowClasses, Test-AlwaysRunFolder, Read-ClassCoverage, Split-ClassMap, Add-ClassTestScopes, Get-RootReaders, Get-FamilyKeys, Read-CoverageMap, Get-CoveredFiles, Get-StaleFamilies, Get-ReuseFilter, Get-PassedFamilies, Save-FamilyPasses, Test-DocsOnly, Get-FailedTests, Get-FailureMessages, Save-FailedRun, Get-PassedTests, Test-RunCompleted, Get-FailureLabels, Read-Quarantine, Split-Quarantined
