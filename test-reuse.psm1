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

# Families whose tests read files outside src/ and tests/ (docs, scripts, workflows), found by their use of RepoRoot().
function Get-RootReaders([string]$testsDir) {
    Get-ChildItem $testsDir -Directory | Where-Object Name -notin 'bin', 'obj' | Where-Object {
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | Select-String -SimpleMatch 'RepoRoot()' -List | Select-Object -First 1
    } | ForEach-Object Name
}

# One key per family from `git ls-tree -r` lines ("<mode> blob <sha>\t<path>") and an environment string.
function Get-FamilyKeys([string[]]$treeLines, [string[]]$families, [string[]]$rootReaders, [string]$environment) {
    $own = @{}; $shared = [System.Text.StringBuilder]::new(); $root = [System.Text.StringBuilder]::new()
    foreach ($line in $treeLines) {
        $tab = $line.IndexOf("`t"); if ($tab -lt 0) { continue }
        $entry = $line
        switch (Get-ReuseScope $line.Substring($tab + 1)) {
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

Export-ModuleMember -Function Get-ReuseScope, Get-ClassMap, Get-RootReaders, Get-FamilyKeys, Get-StaleFamilies, Get-ReuseFilter, Get-PassedFamilies
