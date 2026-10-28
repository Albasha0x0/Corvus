# Offloaded test classes for whole-suite runs: which classes run elsewhere, the local filter, and joining the results.
# Without a usable target every class runs here.

# The classes a run sends: engine-free heavy classes (sweeps, matrices, round trips, reference comparisons, the full
# contract matrix, discovery at every thread count).
$script:RemotePatterns = '*SweepTests', '*MatrixTests', 'PipelineRoundTripTests', '*OracleTests', '*ComparisonTests', '*CompareTests',
    'ContractSweepFullTests', 'ParallelDiscoveryTests'
# Groups: sweep, ghidra and live are CI offload jobs; the nightly group's classes stay here and push runs leave them to
# the nightly run.
$script:Groups = 'sweep', 'ghidra', 'live', 'nightly'
$script:NightlyGroup = 'nightly'
# Nightly only: the Program Files sweep (over 30 min on a runner) and classes that need an unloaded machine.
$script:NightlyClasses = 'NativeToolSweepTests', 'DevRelayRealServerTests', 'DeadlineTests', 'StreamedSummaryMemoryTests'
# Folders whose classes go only as the ghidra group (by their Ghidra facts).
$script:EngineFolders = 'Engines'
# Attributes that keep a class's file here: the live real-data facts.
$script:LocalAttributes = 'LiveRealDataFact'
# Real-data facts: their file's classes join the nightly group; never to GitHub.
$script:DataAttribute = 'RequiresRealDataFact'
# An IDA fact given real-data variables reads real data too.
$script:IdaDataFact = '\[IdaFact\(\s*[^)\s]'
# Classes whose inputs are this machine's own: client-edition System32, local dumps and data folders, and RISC-V.
$script:LocalClasses = 'NativeLinkSweepTests', 'MinidumpSweepTests', 'FirmwareComparisonTests', 'InstallerComparisonTests',
    'DependencyListerComparisonTests', 'IsaEngineTests'
# A class under this share of its last local time (when at least the given seconds) proved less there and reruns here.
$script:ShortShare = 0.2
$script:ShortFloorSeconds = 30
# Where a run keeps each target's record and results, under the repository's .git.
$script:RecordFolder = 'corvus-remote'
# The nightly group's classes the last push run left to the nightly run, under the repository's .git.
$script:DeferredFile = 'corvus-nightly-deferred.txt'
# Set to 0 to run every class here.
$script:OffloadVariable = 'CORVUS_TEST_OFFLOAD'
# Set by the background push run: its commit is on its way to origin, so its CI run is coming.
$script:PushRunVariable = 'CORVUS_TEST_PUSH_RUN'
# Stands in for the gh command line in the tests (a .ps1).
$script:GhVariable = 'CORVUS_TEST_GH'
# The workflow and the job name prefix of the CI offload job (.github/workflows/ci.yml); its TRX artifacts share it.
$script:Workflow = 'ci.yml'
$script:OffloadJob = 'offload'
$script:ReleaseWorkflow = 'release.yml'
# Seconds each gh call of -Status may take; past it the workflow's result is
# unknown.
$script:StatusCallSeconds = 10
# Seconds for the commit's CI run to appear (push runs start before the push lands), minutes for offload jobs.
$script:RunAppearSeconds = 120
$script:RunFinishMinutes = 120
$script:PollSeconds = 15

# Top-level *Tests classes in $text as @{ Class; Ida; Ghidra }; Ghidra counts only facts a routine run includes, as
# offloads never run the release tier.
function Get-ClassEngines([string]$text) {
    $declarations = @([regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+Tests)\b'))
    $release = 'Trait\("Tier",\s*"Release"\)'
    for ($i = 0; $i -lt $declarations.Count; $i++) {
        $start = $declarations[$i].Index
        $end = if ($i + 1 -lt $declarations.Count) { $declarations[$i + 1].Index } else { $text.Length }
        $body = $text.Substring($start, $end - $start)
        # The class's own attributes: the lines of brackets right above its declaration.
        $above = @($text.Substring(0, $start) -split '\r?\n')
        $header = @(for ($j = $above.Count - 2; $j -ge 0 -and $above[$j].Trim() -match '^(\[|//)'; $j--) { $above[$j] }) -join "`n"
        # A fact's attributes run from the end of the member before it to the next member's declaration.
        $ghidra = $header -notmatch $release -and @([regex]::Matches($body, '\[GhidraFact\b') | Where-Object {
            $from = $body.LastIndexOfAny([char[]]'{};', $_.Index) + 1
            $to = $body.IndexOf('public ', $_.Index); if ($to -lt 0) { $to = $body.Length }
            $body.Substring($from, $to - $from) -notmatch $release
        }).Count -gt 0
        [pscustomobject]@{ Class = $declarations[$i].Groups[1].Value; Ida = $body -match '\[IdaFact\b'; Ghidra = $ghidra }
    }
}

# *Tests classes of $testsDir as @{ Class; Group; Mixed }, grouped nightly, live, ghidra or sweep. IDA-only classes,
# real data with IDA facts, live real data and local classes stay here; with -CrossPlatform, Windows-only too.
function Get-RemoteEntries([string]$testsDir, [switch]$CrossPlatform) {
    $local = '\[(' + ($script:LocalAttributes -join '|') + $(if ($CrossPlatform) { '|WindowsFact' }) + ')\b'
    Get-ChildItem $testsDir -Directory | Where-Object { $_.Name -notin 'bin', 'obj' } | ForEach-Object {
        $folder = $_.Name
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | ForEach-Object {
            $text = Get-Content $_.FullName -Raw
            if ($text -match $local) { return }
            $ida = $text -match '\[IdaFact\b'; $ghidra = $text -match '\[GhidraFact\b'
            if ($text -match ('\[' + $script:DataAttribute + '\b') -or $text -match $script:IdaDataFact) {
                if ($ida) { return }
                [regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+Tests)\b') | ForEach-Object { $_.Groups[1].Value } |
                    Where-Object { $_ -notin $script:LocalClasses } |
                    ForEach-Object { [pscustomobject]@{ Class = $_; Group = $script:NightlyGroup; Mixed = $false } }
                return
            }
            foreach ($class in Get-ClassEngines $text) {
                $name = $class.Class
                # GitHub has no IDA, so an IDA-only class runs here.
                if ($class.Ida -and -not $class.Ghidra) { continue }
                $of = if ($folder -eq 'Live') { 'live' } elseif ($class.Ghidra) { 'ghidra' } elseif ($folder -notin $script:EngineFolders) { 'sweep' } else { continue }
                if (-not ($name -in $script:NightlyClasses -or ($name -notin $script:LocalClasses -and ($of -ne 'sweep' -or ($script:RemotePatterns | Where-Object { $name -like $_ }))))) { continue }
                [pscustomobject]@{ Class = $name; Group = $(if ($name -in $script:NightlyClasses) { $script:NightlyGroup } else { $of }); Mixed = $class.Ida }
            }
        }
    }
}

# Classes of one group, or (empty) every group a run sends: all but nightly. Sorted; throws for an unknown group.
function Get-RemoteClasses([string]$testsDir, [string]$Group = '', [switch]$CrossPlatform) {
    if ($Group -and $Group -notin $script:Groups) { throw "Unknown offload group '$Group' (one of $($script:Groups -join ', '))." }
    @(Get-RemoteEntries $testsDir -CrossPlatform:$CrossPlatform |
        Where-Object { if ($Group) { $_.Group -eq $Group } else { $_.Group -ne $script:NightlyGroup } } |
        ForEach-Object Class | Sort-Object -Unique)
}

# The sent classes that use both engines: their Ghidra tests run there and their IDA tests here, joined per test. Sorted.
function Get-MixedClasses([string]$testsDir) {
    @(Get-RemoteEntries $testsDir | Where-Object Mixed | ForEach-Object Class | Sort-Object -Unique)
}

# Shard $index (0-based) of $count over $classes. With $seconds, longest first to the least-loaded shard (ties: lower
# shard; unrecorded: 1 s); without, dealt in name order. Deterministic on every machine.
function Get-RemoteShard([string[]]$classes, [int]$index, [int]$count, [hashtable]$seconds) {
    if (-not $seconds) { return @(for ($i = $index; $i -lt $classes.Count; $i += $count) { $classes[$i] }) }
    $load = [double[]]::new($count)
    $mine = foreach ($class in $classes | Sort-Object @{ Expression = { if ($seconds.ContainsKey($_)) { [double]$seconds[$_] } else { 1.0 } }; Descending = $true }, { $_ }) {
        $least = 0
        for ($i = 1; $i -lt $count; $i++) { if ($load[$i] -lt $load[$least]) { $least = $i } }
        $load[$least] += if ($seconds.ContainsKey($class)) { [double]$seconds[$class] } else { 1.0 }
        if ($least -eq $index) { $class }
    }
    @($mine | Sort-Object)
}

# The platform offload seconds are recorded under: windows, linux or macos, as this machine is.
function Get-OffloadPlatform { if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'macos' } else { 'linux' } }

# The record at $path (platform -> class -> seconds), empty when the file is missing; $null when it is unreadable.
function Read-OffloadRecord([string]$path) {
    if (-not (Test-Path $path)) { return @{} }
    try { Get-Content $path -Raw | ConvertFrom-Json -AsHashtable } catch { $null }
}

# Recorded seconds per class on $platform, else the longest on other platforms; $null when $path is missing or
# unreadable.
function Read-OffloadSeconds([string]$path, [string]$platform = (Get-OffloadPlatform)) {
    if (-not (Test-Path $path)) { return $null }
    $record = Read-OffloadRecord $path
    if ($null -eq $record) { return $null }
    $seconds = @{}
    foreach ($other in @($record.Keys | Where-Object { $_ -ne $platform })) {
        foreach ($class in $record[$other].Keys) { $seconds[$class] = [math]::Max([double]$record[$other][$class], [double]$seconds[$class]) }
    }
    if ($record[$platform]) { foreach ($class in $record[$platform].Keys) { $seconds[$class] = $record[$platform][$class] } }
    $seconds
}

# Records per class under $platform the median summed seconds over $trxPaths (whole, at least 1); other entries keep.
function Save-OffloadSeconds([string[]]$trxPaths, [string]$path, [string]$platform = (Get-OffloadPlatform)) {
    $runs = @{}
    foreach ($trx in $trxPaths) { foreach ($c in Get-ClassOutcomes $trx) { $runs[$c.Class] = @($runs[$c.Class]) + $c.Seconds | Where-Object { $null -ne $_ } } }
    $record = Read-OffloadRecord $path
    if ($null -eq $record) { $record = @{} }
    $old = if ($record[$platform]) { $record[$platform] } else { @{} }
    $seconds = [ordered]@{}
    foreach ($class in @($runs.Keys) + @($old.Keys) | Sort-Object -Unique) {
        if (-not $runs[$class]) { $seconds[$class] = $old[$class]; continue }
        $sorted = @($runs[$class] | Sort-Object)
        $median = if ($sorted.Count % 2) { $sorted[($sorted.Count - 1) / 2] } else { ($sorted[$sorted.Count / 2 - 1] + $sorted[$sorted.Count / 2]) / 2 }
        $seconds[$class] = [math]::Max(1, [int][math]::Round($median))
    }
    $record[$platform] = $seconds
    $sortedRecord = [ordered]@{}
    foreach ($name in $record.Keys | Sort-Object) { $sortedRecord[$name] = $record[$name] }
    Set-Content -Path $path -Value ($sortedRecord | ConvertTo-Json -Depth 3)
}

# A dotnet test filter that runs $filter (everything when empty) without $classes, keeping the tests other than the
# Ghidra ones (trait Engine=ghidra) of those in $mixed.
function Get-LocalFilter([string]$filter, [string[]]$classes, [string[]]$mixed = @()) {
    $parts = @($classes | Where-Object { $_ -notin $mixed } | ForEach-Object { "FullyQualifiedName!~.$_" })
    $split = @($classes | Where-Object { $_ -in $mixed } | ForEach-Object { "FullyQualifiedName!~.$_" })
    if ($split) { $parts += "(Engine!=ghidra|$($split -join '&'))" }
    $without = $parts -join '&'
    if (-not $without) { return $filter }
    if ($filter) { return "($filter)&$without" }
    return $without
}

# A dotnet test filter for $classes, at routine strength (no Tier=Release tests) unless $releaseTier; of those in $mixed
# only the tests other than the IDA ones (trait Engine=ida), which ran here already.
function Get-ClassFilter([string[]]$classes, [bool]$releaseTier, [string[]]$mixed = @()) {
    $filter = ($classes | ForEach-Object { if ($_ -in $mixed) { "(FullyQualifiedName~.$_&Engine!=ida)" } else { "FullyQualifiedName~.$_" } }) -join '|'
    if ($releaseTier) { return $filter }
    "($filter)&Tier!=Release"
}

# Per class of a TRX file: whether any of its tests was skipped (NotExecuted) or failed, and its summed test seconds.
function Get-ClassOutcomes([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) { $classOf[$test.Node.id] = ($test.Node.TestMethod.className -split '\.')[-1] -replace '\+.*$', '' }
    $skipped = @{}; $failed = @{}; $seconds = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $class = $classOf[$result.Node.testId]
        $skipped[$class] = [bool]$skipped[$class] -or $result.Node.outcome -eq 'NotExecuted'
        $failed[$class] = [bool]$failed[$class] -or $result.Node.outcome -in 'Failed', 'Error', 'Timeout', 'Aborted'
        $seconds[$class] = [double]$seconds[$class] + $(if ($result.Node.duration) { [TimeSpan]::Parse($result.Node.duration, [cultureinfo]::InvariantCulture).TotalSeconds } else { 0 })
    }
    $skipped.Keys | ForEach-Object { [pscustomobject]@{ Class = $_; Skipped = $skipped[$_]; Failed = $failed[$_]; Seconds = $seconds[$_] } }
}

# Per test of a TRX file: @{ Key; Class; Outcome }, the key being its class and test name.
function Get-TestOutcomes([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) { $classOf[$test.Node.id] = $test.Node.TestMethod.className }
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $full = $classOf[$result.Node.testId]
        [pscustomobject]@{ Key = "$full|$($result.Node.testName)"; Class = ($full -split '\.')[-1] -replace '\+.*$', ''; Outcome = $result.Node.outcome }
    }
}

# Classes of $classes with a test skipped both in $remoteTrx and in $hereTrx (or absent there) that ran in $lastTrx
# (the last local whole run). Sorted; empty without $lastTrx.
function Get-SkippedOnBoth([string]$remoteTrx, [string]$hereTrx, [string]$lastTrx, [string[]]$classes) {
    if (-not ($classes -and (Test-Path $lastTrx))) { return @() }
    $ran = @{}; foreach ($t in Get-TestOutcomes $lastTrx) { if ($t.Outcome -ne 'NotExecuted') { $ran[$t.Key] = $true } }
    $here = @{}; if (Test-Path $hereTrx) { foreach ($t in Get-TestOutcomes $hereTrx) { if ($t.Outcome -ne 'NotExecuted') { $here[$t.Key] = $true } } }
    @(Get-TestOutcomes $remoteTrx | Where-Object { $_.Class -in $classes -and $_.Outcome -eq 'NotExecuted' -and -not $here[$_.Key] -and $ran[$_.Key] } |
        ForEach-Object Class | Sort-Object -Unique)
}

# Per class, the fewest summed seconds of passed tests in any push or whole run in $historyFile
# (corvus-test-history.jsonl); a run that skipped the class adds nothing. Empty when the file is absent.
function Get-FastestClassSeconds([string]$historyFile) {
    $sums = @{}
    if (-not (Test-Path $historyFile)) { return $sums }
    $pattern = '^\{"kind":"test","run":"([^"]+)","mode":"(?:push|full)","name":"(?:[^"\\]|\\.)*","class":"([^"+]+)[^"]*","start":([-\d.eE]+),"end":([-\d.eE]+),"outcome":"Passed"'
    foreach ($line in [IO.File]::ReadLines($historyFile)) {
        if ($line -notmatch $pattern) { continue }
        $key = "$($Matches[2])`t$($Matches[1])"
        $sums[$key] = [double]$sums[$key] + [double]$Matches[4] - [double]$Matches[3]
    }
    $fastest = @{}
    foreach ($key in $sums.Keys) {
        $class = $key.Split("`t")[0]
        if (-not $fastest.ContainsKey($class) -or $sums[$key] -lt $fastest[$class]) { $fastest[$class] = $sums[$key] }
    }
    $fastest
}

# Classes that prove less in $remoteTrx than in $localTrx: a test skipped there, or far less time. The local time is
# the lower of the last run and $fastest, since a loaded machine would make an idle runner look short.
function Get-ProvedLessThere([string]$remoteTrx, [string]$localTrx, [hashtable]$fastest = @{}) {
    $before = @{}; if (Test-Path $localTrx) { foreach ($c in Get-ClassOutcomes $localTrx) { $before[$c.Class] = $c } }
    @(Get-ClassOutcomes $remoteTrx | Where-Object {
        $here = $before[$_.Class]
        $seconds = if (-not $here) { 0 } elseif ($fastest.ContainsKey($_.Class)) { [math]::Min($here.Seconds, $fastest[$_.Class]) } else { $here.Seconds }
        ($_.Skipped -and -not ($here -and $here.Skipped)) -or ($seconds -ge $script:ShortFloorSeconds -and $_.Seconds -lt $seconds * $script:ShortShare)
    } | ForEach-Object Class | Sort-Object -Unique)
}

# Sent classes that rerun here: failed there, proved less there, or have no results there. Sorted; empty when the
# remote half covered every class.
function Get-RerunClasses($got, [string[]]$sent, [string]$localTrx, [string[]]$mixed = @(), [string]$hereTrx = '', [hashtable]$fastest = @{}) {
    $there = @{}; if ($got.Trx) { foreach ($c in Get-ClassOutcomes $got.Trx) { $there[$c.Class] = $true } }
    $ranHere = if (Test-Path $localTrx) { @(Get-ClassOutcomes $localTrx | ForEach-Object Class) } else { $null }
    $missing = @($sent | Where-Object { -not $there[$_] -and ($null -eq $ranHere -or $_ -in $ranHere) })
    $short = if ($got.Trx) { @(Get-ProvedLessThere $got.Trx $localTrx $fastest | Where-Object { $_ -notin $mixed }) } else { @() }
    $both = if ($got.Trx) { @(Get-SkippedOnBoth $got.Trx $hereTrx $localTrx $mixed) } else { @() }
    @(@($got.Failed | ForEach-Object Class) + $short + $both + $missing | Where-Object { $_ -in $sent } | Sort-Object -Unique)
}

# One line per class that failed on $target and how its rerun here ($hereTrx) ended, joined with "; ":
# "<class> failed on <target> (<platforms>), passed here" (or "failed here", "not run here"). Empty when none failed.
function Get-FailedThereNote($failed, [string]$hereTrx, [string]$target) {
    $here = @{}; if ($hereTrx -and (Test-Path $hereTrx)) { foreach ($c in Get-ClassOutcomes $hereTrx) { $here[$c.Class] = $c } }
    (@($failed) | Group-Object Class | Sort-Object Name | ForEach-Object {
        $outcome = if (-not $here[$_.Name]) { 'not run here' } elseif ($here[$_.Name].Failed) { 'failed here' } else { 'passed here' }
        "$($_.Name) failed on $target ($((@($_.Group.Platform) | Sort-Object -Unique) -join ', ')), $outcome"
    }) -join '; '
}

# Joins $sources into one TRX at $target, dropping $dropClasses after the first source. $mergeClasses keep one result
# per test (failed over passed over skipped). An aborted source makes the run aborted.
function Join-TrxFiles([string]$target, [string[]]$sources, [string[]]$dropClasses = @(), [string[]]$mergeClasses = @()) {
    $present = @($sources | Where-Object { $_ -and (Test-Path $_) })
    if (-not $present) { return }
    $ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    [xml]$merged = Get-Content $present[0] -Raw
    $m = [Xml.XmlNamespaceManager]::new($merged.NameTable); $m.AddNamespace('t', $ns)
    foreach ($source in $present | Select-Object -Skip 1) {
        [xml]$other = Get-Content $source -Raw
        $o = [Xml.XmlNamespaceManager]::new($other.NameTable); $o.AddNamespace('t', $ns)
        $drop = @{}
        foreach ($test in $other.SelectNodes('//t:UnitTest', $o)) {
            if ((($test.TestMethod.className -split '\.')[-1] -replace '\+.*$', '') -in $dropClasses) { $drop[$test.id] = $true }
        }
        if ($mergeClasses) { Merge-TrxTests $merged $m $other $o $mergeClasses $drop }
        foreach ($part in @(@('//t:TestDefinitions', '//t:TestDefinitions/t:UnitTest', 'id'), @('//t:Results', '//t:Results/t:UnitTestResult', 'testId'), @('//t:TestEntries', '//t:TestEntries/t:TestEntry', 'testId'))) {
            $parent = $merged.SelectSingleNode($part[0], $m)
            if (-not $parent) { continue }
            foreach ($node in $other.SelectNodes($part[1], $o)) { if (-not $drop[$node.GetAttribute($part[2])]) { [void]$parent.AppendChild($merged.ImportNode($node, $true)) } }
        }
        $into = $merged.SelectSingleNode('//t:ResultSummary/t:Counters', $m); $from = $other.SelectSingleNode('//t:ResultSummary/t:Counters', $o)
        if ($into -and $from) { foreach ($a in $from.Attributes) { $into.SetAttribute($a.Name, [string]([int]$into.GetAttribute($a.Name) + [int]$a.Value)) } }
        $summary = $merged.SelectSingleNode('//t:ResultSummary', $m); $theirs = $other.SelectSingleNode('//t:ResultSummary', $o)
        if ($summary -and $theirs -and $theirs.outcome -in 'Aborted', 'Failed' -and $summary.outcome -ne 'Aborted') { $summary.SetAttribute('outcome', $theirs.outcome) }
    }
    # The outcome counters follow the joined results, so dropped results are not counted.
    $counters = $merged.SelectSingleNode('//t:ResultSummary/t:Counters', $m)
    if ($counters) {
        $outcomes = @($merged.SelectNodes('//t:Results/t:UnitTestResult', $m) | ForEach-Object { $_.GetAttribute('outcome') })
        $skipped = @($outcomes | Where-Object { $_ -eq 'NotExecuted' }).Count
        $counters.SetAttribute('total', [string]$outcomes.Count)
        $counters.SetAttribute('executed', [string]($outcomes.Count - $skipped))
        $counters.SetAttribute('passed', [string]@($outcomes | Where-Object { $_ -eq 'Passed' }).Count)
        $counters.SetAttribute('failed', [string]@($outcomes | Where-Object { $_ -eq 'Failed' }).Count)
        $counters.SetAttribute('notExecuted', [string]$skipped)
    }
    $merged.Save($target)
}

# For each test of $mergeClasses in $other that $merged holds too: marks it in $drop when its result there ranks no
# higher (failed over passed over skipped), else removes the one in $merged.
function Merge-TrxTests([xml]$merged, $m, [xml]$other, $o, [string[]]$mergeClasses, [hashtable]$drop) {
    $rank = { param($outcome) switch ($outcome) { 'NotExecuted' { 1 } 'Passed' { 2 } default { 3 } } }
    $mine = @{}
    foreach ($t in Get-TrxTests $merged $m) { if ($t.Class -in $mergeClasses) { $mine[$t.Key] = $t } }
    foreach ($t in Get-TrxTests $other $o) {
        if ($t.Class -notin $mergeClasses -or $drop[$t.Id] -or -not $mine[$t.Key]) { continue }
        $old = $mine[$t.Key]
        if ((& $rank $t.Result.outcome) -le (& $rank $old.Result.outcome)) { $drop[$t.Id] = $true; continue }
        foreach ($node in $old.Result, $old.Test, $merged.SelectSingleNode("//t:TestEntries/t:TestEntry[@testId='$($old.Id)']", $m)) { if ($node) { [void]$node.ParentNode.RemoveChild($node) } }
    }
}

# The tests of a TRX document with a result: @{ Id; Key; Class; Test; Result }, the key being its class and test name.
function Get-TrxTests([xml]$trx, $ns) {
    $results = @{}; foreach ($r in $trx.SelectNodes('//t:Results/t:UnitTestResult', $ns)) { $results[$r.testId] = $r }
    foreach ($test in $trx.SelectNodes('//t:TestDefinitions/t:UnitTest', $ns)) {
        $result = $results[$test.id]
        if (-not $result) { continue }
        $full = $test.TestMethod.className
        [pscustomobject]@{ Id = $test.id; Key = "$full|$($result.testName)"; Class = ($full -split '\.')[-1] -replace '\+.*$', ''; Test = $test; Result = $result }
    }
}

# The file name a target's record and results take in the record folder.
function Get-TargetFileName([string]$name) { $name -replace '[^\w.-]', '_' }

# Of the families in $passed, those whose classes in $classMap include none of $deferred: a family whose class did not
# run records no pass. Sorted.
function Get-UndeferredFamilies([string[]]$passed, [hashtable]$classMap, [string[]]$deferred = @()) {
    @($passed | Where-Object { $family = $_; -not @($classMap[$family] | Where-Object { $_ -in $deferred }) } | Sort-Object)
}

# Saves the classes a push run left to the nightly run, as "<commit> at <time>: <classes>" in
# <gitDir>/corvus-nightly-deferred.txt for -Status; no class removes the file.
function Save-DeferredClasses([string]$gitDir, [string]$commit, [string[]]$classes) {
    $file = Join-Path $gitDir $script:DeferredFile
    if (-not $classes) { Remove-Item $file -ErrorAction SilentlyContinue; return }
    Set-Content -Path $file -Value "$commit at $(Get-Date -Format 'yyyy-MM-dd HH:mm'): $($classes -join ', ')" -NoNewline
}

# The line Save-DeferredClasses wrote, or $null when the last push run left nothing.
function Get-DeferredStatus([string]$gitDir) {
    $file = Join-Path $gitDir $script:DeferredFile
    if (Test-Path $file) { (Get-Content $file -Raw).Trim() } else { $null }
}

# Saves the record -Status shows for a target: <gitDir>/corvus-remote/<name>.json.
function Save-RemoteRecord([string]$gitDir, [System.Collections.IDictionary]$record) {
    $folder = Join-Path $gitDir $script:RecordFolder
    New-Item -ItemType Directory -Force $folder | Out-Null
    Set-Content -Path (Join-Path $folder "$(Get-TargetFileName $record.target).json") -Value ($record | ConvertTo-Json -Depth 3) -NoNewline
}

# One line per target that took part in a run: "<target>: <state> on <commit> at <time> (<n> classes, <s> s); <note>".
function Get-RemoteStatus([string]$gitDir) {
    Get-ChildItem (Join-Path $gitDir $script:RecordFolder) -Filter *.json -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
        $r = Get-Content $_.FullName -Raw | ConvertFrom-Json
        # The run reads the offloaded results only after its own tests end, so "running" covers both halves.
        $state = if ($r.state -eq 'running') { 'running (results joined when the local tests end)' } else { $r.state }
        "$($r.target): $state on $($r.commit) at $($r.at) ($($r.classes) classes$(if ($null -ne $r.seconds) { ", $($r.seconds) s" }))$(if ($r.note) { "; $($r.note)" })"
    }
}

# The offload target as @{ Name; Kind; Repository }, or $null: GitHub for a routine run on origin's main. Release
# strength runs here. CORVUS_TEST_OFFLOAD=0 turns it off.
function Get-OffloadTarget([string]$repo, [bool]$releaseTier) {
    if ([Environment]::GetEnvironmentVariable($script:OffloadVariable) -in '0', 'false', 'off') { return $null }
    if ([Environment]::GetEnvironmentVariable($script:PushRunVariable) -ne '1') {
        git -C $repo merge-base --is-ancestor HEAD origin/main 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
    }
    if (-not $releaseTier) { Get-GitHubTarget $repo }
}

# The GitHub target of $repo, @{ Name; Kind; Repository }, or $null without the gh command line, without the offload
# job in ci.yml at HEAD, or with an origin outside github.com.
function Get-GitHubTarget([string]$repo) {
    if (-not ([Environment]::GetEnvironmentVariable($script:GhVariable) -or (Get-Command gh -ErrorAction SilentlyContinue))) { return $null }
    $workflow = git -C $repo show "HEAD:.github/workflows/$script:Workflow" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not ($workflow -match "^  ${script:OffloadJob}:")) { return $null }
    $url = (git -C $repo remote get-url origin 2>$null) -join ''
    if ($url -notmatch 'github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$') { return $null }
    @{ Name = 'github'; Kind = 'github'; Repository = $Matches[1] }
}

# Starts the remote half on $target; returns a handle for Receive-Offload. GitHub runs the offload job on push by
# itself, so the handle waits for that run.
function Start-Offload($target, [string]$commit, [string]$module) {
    switch ($target.Kind) {
        'github' {
            Start-ThreadJob -ArgumentList $module, $target.Repository, $commit -ScriptBlock {
                param($module, $repository, $commit)
                Import-Module $module
                Wait-GitHubRun $repository $commit
            }
        }
        default { throw "Unknown offload target kind '$($target.Kind)'." }
    }
}

# Waits for the remote half: @{ Started; Trx; Failed; Note } as Receive-GitHubRun returns it.
function Receive-Offload($handle, [string]$folder) {
    $state = Receive-Job $handle -Wait -AutoRemoveJob | Select-Object -Last 1
    if ($state.Kind -eq 'github') { return Receive-GitHubRun $state $folder }
    $state
}

# Runs the gh command line (or the script standing in for it); returns its output, sets $LASTEXITCODE.
function Invoke-Gh([string[]]$arguments) {
    $command = [Environment]::GetEnvironmentVariable($script:GhVariable)
    if ($command) { return & pwsh -NoProfile -File $command @arguments }
    & gh @arguments
}

# Waits for the commit's CI offload jobs ($group only, when given) as @{ Kind; Repository; Run; Jobs; Note }; Run is
# $null when they did not finish within $finishMinutes; Note names jobs that did not succeed.
function Wait-GitHubRun([string]$repository, [string]$commit, [int]$appearSeconds = $script:RunAppearSeconds, [int]$pollSeconds = $script:PollSeconds,
    [string]$group = '', [int]$finishMinutes = $script:RunFinishMinutes) {
    $state = @{ Kind = 'github'; Repository = $repository; Run = $null; Jobs = @(); Note = $null }
    $deadline = (Get-Date).AddSeconds($appearSeconds)
    $run = $null
    while ($true) {
        $found = Invoke-Gh @('run', 'list', '-R', $repository, '--commit', $commit, '--workflow', $script:Workflow, '--event', 'push', '--json', 'databaseId', '--limit', '1') 2>$null
        if ($LASTEXITCODE -eq 0 -and $found) { $run = (($found -join '') | ConvertFrom-Json | Select-Object -First 1).databaseId }
        if ($run) { break }
        if ((Get-Date) -gt $deadline) { $state.Note = "no CI run for the commit after $appearSeconds s"; return $state }
        Start-Sleep -Seconds $pollSeconds
    }
    $deadline = (Get-Date).AddMinutes($finishMinutes)
    $prefix = if ($group) { "$script:OffloadJob ($group *" } else { "$script:OffloadJob*" }
    while ($true) {
        $view = Invoke-Gh @('run', 'view', "$run", '-R', $repository, '--json', 'status,jobs') 2>$null
        if ($LASTEXITCODE -eq 0 -and $view) {
            $info = ($view -join '') | ConvertFrom-Json
            $jobs = @($info.jobs | Where-Object { $_.name -like $prefix })
            if ($jobs -and -not ($jobs | Where-Object status -ne 'completed')) {
                $state.Run = $run; $state.Jobs = $jobs
                $failed = @($jobs | Where-Object conclusion -ne 'success')
                if ($failed) { $state.Note = "$(($failed | ForEach-Object name) -join ', ') ended $(($failed | ForEach-Object conclusion | Sort-Object -Unique) -join ', ') in run $run" }
                return $state
            }
            if (-not $jobs -and $info.status -eq 'completed') { $state.Note = "run $run has no offload job"; return $state }
        }
        if ((Get-Date) -gt $deadline) { $state.Note = "run $run did not finish in $finishMinutes min"; return $state }
        Start-Sleep -Seconds $pollSeconds
    }
}

# Downloads a run's offload TRX artifacts into $folder as @{ Started; Trx; Failed; Note }. Trx joins the Windows
# shards ($null when none); Failed lists @{ Class; Platform } on any platform.
function Receive-GitHubRun($state, [string]$folder, [string]$group = '') {
    $result = [pscustomobject]@{ Started = $false; Trx = $null; Failed = @(); Note = $state.Note }
    if (-not $state.Run) { return $result }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $pattern = if ($group) { "$script:OffloadJob-$group-*" } else { "$script:OffloadJob-*" }
    $null = Invoke-Gh @('run', 'download', "$($state.Run)", '-R', $state.Repository, '-p', $pattern, '-D', $folder) 2>$null
    $files = @(Get-ChildItem $folder -Recurse -Filter *.trx -ErrorAction SilentlyContinue | Sort-Object FullName)
    $result.Failed = @(foreach ($file in $files) {
        $platform = if ($file.Directory.Name -match 'windows|ubuntu|macos') { $Matches[0] } else { $file.Directory.Name }
        Get-ClassOutcomes $file.FullName | Where-Object Failed | ForEach-Object { [pscustomobject]@{ Class = $_.Class; Platform = $platform } }
    })
    $windows = @($files | Where-Object { $_.Directory.Name -match 'windows' })
    if ($windows) {
        $result.Trx = Join-Path $folder 'offload.trx'
        Join-TrxFiles $result.Trx @($windows.FullName)
    }
    $result.Started = $true
    $result.Note = if ($state.Note) { $state.Note } else { "run $($state.Run)" }
    $result
}

# Runs gh (or its stand-in) for at most $seconds as @{ Code; Output; Error }.
# Code is $null when gh is not installed or did not answer in time; Error
# says which.
function Invoke-GhBounded([string[]]$arguments, [int]$seconds = $script:StatusCallSeconds) {
    $standIn = [Environment]::GetEnvironmentVariable($script:GhVariable)
    $gh = Get-Command gh -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($standIn) { $start = [Diagnostics.ProcessStartInfo]::new('pwsh'); foreach ($a in '-NoProfile', '-File', $standIn) { $start.ArgumentList.Add($a) } }
    elseif ($gh) { $start = [Diagnostics.ProcessStartInfo]::new($gh.Source) }
    else { return @{ Code = $null; Output = ''; Error = 'gh not installed' } }
    foreach ($a in $arguments) { $start.ArgumentList.Add($a) }
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    # A missing login fails at once instead of waiting on a prompt.
    $start.Environment['GH_PROMPT_DISABLED'] = '1'
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.ReadToEndAsync(); $errors = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($seconds * 1000)) {
        try { $process.Kill($true) } catch { }
        return @{ Code = $null; Output = ''; Error = "gh did not answer in $seconds s" }
    }
    $process.WaitForExit()
    @{ Code = $process.ExitCode; Output = $output.Result; Error = $errors.Result }
}

# Why a gh call gave no answer: the reason Invoke-GhBounded named, or the
# exit code and first error line.
function Get-GhFailure($call) {
    if ($null -eq $call.Code) { return $call.Error }
    $line = @("$($call.Error)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    "gh exit $($call.Code)$(if ($line) { ": $($line[0].Trim())" })"
}

# $workflow's newest run in $repository ($commit's push run, when given) as
# one line: its state, run id, branch, commit, time and the jobs that did not
# succeed; "unknown (<reason>)" when gh cannot tell, "no run" when it has none.
function Get-WorkflowRunStatus([string]$repository, [string]$workflow, [string]$commit = '') {
    $list = @('run', 'list', '-R', $repository, '--workflow', $workflow, '--json', 'databaseId,status,conclusion,headSha,headBranch,createdAt', '--limit', '1')
    # A manual run of the live job must not hide the push run's test jobs.
    if ($commit) { $list += '--commit', $commit, '--event', 'push' }
    $found = Invoke-GhBounded $list
    if ($found.Code -ne 0) { return "unknown ($(Get-GhFailure $found))" }
    $run = try { @($found.Output | ConvertFrom-Json) | Select-Object -First 1 } catch { return "unknown (gh output is not JSON)" }
    if (-not $run) { return 'no run' }
    $state = if ($run.status -eq 'completed') { $run.conclusion } else { $run.status }
    $sha = "$($run.headSha)"; $sha = $sha.Substring(0, [math]::Min(8, $sha.Length))
    # ConvertFrom-Json reads gh's ISO 8601 times as DateTime.
    $at = if ($run.createdAt -is [datetime]) { "$($run.createdAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)) UTC" } else { $run.createdAt }
    $line = "$state in run $($run.databaseId) on $($run.headBranch) ($sha) at $at"
    if ($run.status -ne 'completed' -or $run.conclusion -in 'success', 'skipped', 'neutral') { return $line }
    $view = Invoke-GhBounded @('run', 'view', "$($run.databaseId)", '-R', $repository, '--json', 'jobs')
    if ($view.Code -ne 0) { return "$line; failed jobs unknown ($(Get-GhFailure $view))" }
    $jobs = try { @(($view.Output | ConvertFrom-Json).jobs) } catch { return "$line; failed jobs unknown (gh output is not JSON)" }
    $failed = @($jobs | Where-Object { $_.conclusion -notin 'success', 'skipped', 'neutral' } | ForEach-Object name)
    if ($failed) { "$line; failed jobs: $($failed -join ', ')" } else { $line }
}

# Two lines for -Status: the newest CI workflow push run on origin's main
# (HEAD without it) and the newest release workflow run, each
# "unknown (<reason>)" when origin is not on github.com or gh cannot tell.
function Get-WorkflowStatus([string]$repo) {
    $commit = git -C $repo rev-parse --verify -q 'origin/main^{commit}' 2>$null
    $branch = 'main'
    if ($LASTEXITCODE -ne 0 -or -not $commit) { $commit = git -C $repo rev-parse --verify -q 'HEAD^{commit}' 2>$null; $branch = 'HEAD' }
    $commit = "$commit".Trim()
    $label = if ($commit) { "CI workflow on $branch $($commit.Substring(0, 8))" } else { 'CI workflow' }
    $url = (git -C $repo remote get-url origin 2>$null) -join ''
    if ($url -notmatch 'github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$') {
        "${label}: unknown (origin is not on github.com)"; 'Release workflow: unknown (origin is not on github.com)'; return
    }
    $repository = $Matches[1]
    "${label}: $(if ($commit) { Get-WorkflowRunStatus $repository $script:Workflow $commit } else { 'unknown (no commit)' })"
    "Release workflow: $(Get-WorkflowRunStatus $repository $script:ReleaseWorkflow)"
}

Export-ModuleMember -Function Get-WorkflowStatus, Get-WorkflowRunStatus, Invoke-Gh, Wait-GitHubRun, Receive-GitHubRun, Get-GitHubTarget, Get-RemoteClasses, Get-RemoteShard, Read-OffloadSeconds, Save-OffloadSeconds, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-TestOutcomes, Get-ProvedLessThere, Get-FastestClassSeconds, Get-SkippedOnBoth, Get-RerunClasses, Get-MixedClasses, Get-FailedThereNote, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-UndeferredFamilies, Save-DeferredClasses, Get-DeferredStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
