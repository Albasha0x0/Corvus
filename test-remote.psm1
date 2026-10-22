# Offloaded test classes (test.ps1 whole-suite runs): which classes run on another machine, the filter that leaves them
# out here, and how their results join the local ones. The transports below start the remote half and bring its TRX
# results back; a run with no usable target runs every class here.

# The classes a run sends: engine-free heavy classes (sweeps, matrices, round trips, reference comparisons).
$script:RemotePatterns = '*SweepTests', '*MatrixTests', 'PipelineRoundTripTests', '*OracleTests', '*ComparisonTests', '*CompareTests'
# Folders that stay here: engines and live sessions (their installs and permits are this machine's).
$script:LocalFolders = 'Engines', 'Live'
# Attributes that keep a class's file here: IDA and Ghidra facts, and real data that never leaves this machine.
$script:LocalAttributes = 'IdaFact', 'GhidraFact', 'RequiresRealDataFact'
# Where a run keeps each target's record and results, under the repository's .git.
$script:RecordFolder = 'corvus-remote'

# The classes of $testsDir a run sends: names matching the table, outside the local folders, in files that use none of
# the local attributes; with -CrossPlatform, also no Windows-only fact. Sorted; empty when none match.
function Get-RemoteClasses([string]$testsDir, [switch]$CrossPlatform) {
    $local = '\[(' + ($script:LocalAttributes -join '|') + $(if ($CrossPlatform) { '|WindowsFact' }) + ')\b'
    @(Get-ChildItem $testsDir -Directory | Where-Object { $_.Name -notin @('bin', 'obj') + $script:LocalFolders } | ForEach-Object {
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | ForEach-Object {
            $text = Get-Content $_.FullName -Raw
            if ($text -match $local) { return }
            [regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+)') | ForEach-Object { $_.Groups[1].Value } |
                Where-Object { $name = $_; $script:RemotePatterns | Where-Object { $name -like $_ } }
        }
    } | Sort-Object -Unique)
}

# Shard $index (0-based) of $count over $classes, dealt in name order so every machine computes the same shards.
function Get-RemoteShard([string[]]$classes, [int]$index, [int]$count) {
    @(for ($i = $index; $i -lt $classes.Count; $i += $count) { $classes[$i] })
}

# A dotnet test filter that runs $filter (everything when empty) without $classes.
function Get-LocalFilter([string]$filter, [string[]]$classes) {
    $without = ($classes | ForEach-Object { "FullyQualifiedName!~.$_" }) -join '&'
    if (-not $without) { return $filter }
    if ($filter) { return "($filter)&$without" }
    return $without
}

# A dotnet test filter for $classes, at routine strength (no Tier=Release tests) unless $releaseTier.
function Get-ClassFilter([string[]]$classes, [bool]$releaseTier) {
    $filter = ($classes | ForEach-Object { "FullyQualifiedName~.$_" }) -join '|'
    if ($releaseTier) { return $filter }
    "($filter)&Tier!=Release"
}

# Per class of a TRX file: whether any of its tests was skipped (NotExecuted).
function Get-ClassOutcomes([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) { $classOf[$test.Node.id] = ($test.Node.TestMethod.className -split '\.')[-1] -replace '\+.*$', '' }
    $skipped = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $class = $classOf[$result.Node.testId]
        $skipped[$class] = [bool]$skipped[$class] -or $result.Node.outcome -eq 'NotExecuted'
    }
    $skipped.Keys | ForEach-Object { [pscustomobject]@{ Class = $_; Skipped = $skipped[$_] } }
}

# Classes with a skipped test in $remoteTrx that ran every test in $localTrx (the last local whole run): the other
# machine lacks something they need, so their results there prove less and they run here.
function Get-SkippedOnHost([string]$remoteTrx, [string]$localTrx) {
    $skipped = Get-ClassOutcomes $remoteTrx | Where-Object Skipped | ForEach-Object Class
    if (-not $skipped) { return @() }
    $before = @{}; if (Test-Path $localTrx) { foreach ($c in Get-ClassOutcomes $localTrx) { $before[$c.Class] = $c } }
    @($skipped | Where-Object { -not $before[$_] -or -not $before[$_].Skipped } | Sort-Object -Unique)
}

# Writes to $target one TRX file holding the results of $sources (missing files are passed over), without the results
# of $dropClasses from every source after the first. Outcome counters are recounted, the others summed; an aborted
# source makes the run aborted.
function Join-TrxFiles([string]$target, [string[]]$sources, [string[]]$dropClasses = @()) {
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

# The file name a target's record and results take in the record folder.
function Get-TargetFileName([string]$name) { $name -replace '[^\w.-]', '_' }

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
        "$($r.target): $($r.state) on $($r.commit) at $($r.at) ($($r.classes) classes$(if ($null -ne $r.seconds) { ", $($r.seconds) s" }))$(if ($r.note) { "; $($r.note)" })"
    }
}

# The target a whole-suite run offloads to, as @{ Name; Kind; ... }, or $null when none is usable.
function Get-OffloadTarget([string]$repo) {
    return $null
}

# Starts the remote half of $classes on $target; returns a handle for Receive-Offload.
function Start-Offload($target, [string]$commit, [string[]]$classes, [bool]$releaseTier, [string]$module) {
    throw "Unknown offload target kind '$($target.Kind)'."
}

# Waits for the remote half: @{ Started; Copied; Code; Trx; Note }. Started false means no test ran there and its
# classes run here; Copied false after a start means its results never came back.
function Receive-Offload($handle, [string]$folder) {
    throw "Unknown offload handle."
}

Export-ModuleMember -Function Get-RemoteClasses, Get-RemoteShard, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-SkippedOnHost, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
