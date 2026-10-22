# Offloaded test classes (test.ps1 whole-suite runs): which classes run on another machine, the filter that leaves them
# out here, and how their results join the local ones. The transports below start the remote half and bring its TRX
# results back; a run with no usable target runs every class here.

# The classes a run sends: engine-free heavy classes (sweeps, matrices, round trips, reference comparisons).
$script:RemotePatterns = '*SweepTests', '*MatrixTests', 'PipelineRoundTripTests', '*OracleTests', '*ComparisonTests', '*CompareTests'
# Folders that stay here: engines and live sessions (their installs and permits are this machine's).
$script:LocalFolders = 'Engines', 'Live'
# Attributes that keep a class's file here: IDA and Ghidra facts, and real data that never leaves this machine.
$script:LocalAttributes = 'IdaFact', 'GhidraFact', 'RequiresRealDataFact'
# Classes whose inputs are this machine's own: every System32 import binding holds on a client edition only (a server
# image lacks some DLLs), the Program Files sweep grows with what is installed (past 30 min on a runner), the crash
# dump sweep reads this machine's dumps, and the comparisons over local data folders pass empty elsewhere.
$script:LocalClasses = 'NativeLinkSweepTests', 'NativeToolSweepTests', 'MinidumpSweepTests', 'FirmwareComparisonTests', 'InstallerComparisonTests',
    'DependencyListerComparisonTests'
# A class that took under this share of its last local time, when that was at least the given seconds, proved less
# there (a test that returns early without its inputs) and runs here.
$script:ShortShare = 0.2
$script:ShortFloorSeconds = 30
# Where a run keeps each target's record and results, under the repository's .git.
$script:RecordFolder = 'corvus-remote'
# Set to 0 to run every class here.
$script:OffloadVariable = 'CORVUS_TEST_OFFLOAD'
# Set by the background push run: its commit is on its way to origin, so its CI run is coming.
$script:PushRunVariable = 'CORVUS_TEST_PUSH_RUN'
# Stands in for the gh command line in the tests (a .ps1).
$script:GhVariable = 'CORVUS_TEST_GH'
# The workflow and the job name prefix of the CI offload job (.github/workflows/ci.yml); its TRX artifacts share it.
$script:Workflow = 'ci.yml'
$script:OffloadJob = 'offload'
# Seconds to wait for the commit's CI run to appear (a push run starts before its push lands), and minutes for its
# offload jobs to finish.
$script:RunAppearSeconds = 120
$script:RunFinishMinutes = 120
$script:PollSeconds = 15

# The classes of $testsDir a run sends: names matching the table but not the local classes, outside the local folders,
# in files that use none of the local attributes; with -CrossPlatform, also no Windows-only fact. Sorted; empty when none match.
function Get-RemoteClasses([string]$testsDir, [switch]$CrossPlatform) {
    $local = '\[(' + ($script:LocalAttributes -join '|') + $(if ($CrossPlatform) { '|WindowsFact' }) + ')\b'
    @(Get-ChildItem $testsDir -Directory | Where-Object { $_.Name -notin @('bin', 'obj') + $script:LocalFolders } | ForEach-Object {
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | ForEach-Object {
            $text = Get-Content $_.FullName -Raw
            if ($text -match $local) { return }
            [regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+)') | ForEach-Object { $_.Groups[1].Value } |
                Where-Object { $name = $_; $name -notin $script:LocalClasses -and ($script:RemotePatterns | Where-Object { $name -like $_ }) }
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

# Per class of a TRX file: whether any of its tests was skipped (NotExecuted), and its summed test seconds.
function Get-ClassOutcomes([string]$trxPath) {
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) { $classOf[$test.Node.id] = ($test.Node.TestMethod.className -split '\.')[-1] -replace '\+.*$', '' }
    $skipped = @{}; $seconds = @{}
    foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $class = $classOf[$result.Node.testId]
        $skipped[$class] = [bool]$skipped[$class] -or $result.Node.outcome -eq 'NotExecuted'
        $seconds[$class] = [double]$seconds[$class] + $(if ($result.Node.duration) { [TimeSpan]::Parse($result.Node.duration, [cultureinfo]::InvariantCulture).TotalSeconds } else { 0 })
    }
    $skipped.Keys | ForEach-Object { [pscustomobject]@{ Class = $_; Skipped = $skipped[$_]; Seconds = $seconds[$_] } }
}

# Classes whose results in $remoteTrx prove less than in $localTrx (the last local whole run): a test skipped there
# that ran here, or far less time than here (a test that returns early without its inputs). They run here.
function Get-SkippedOnHost([string]$remoteTrx, [string]$localTrx) {
    $before = @{}; if (Test-Path $localTrx) { foreach ($c in Get-ClassOutcomes $localTrx) { $before[$c.Class] = $c } }
    @(Get-ClassOutcomes $remoteTrx | Where-Object {
        $here = $before[$_.Class]
        ($_.Skipped -and -not ($here -and $here.Skipped)) -or ($here -and $here.Seconds -ge $script:ShortFloorSeconds -and $_.Seconds -lt $here.Seconds * $script:ShortShare)
    } | ForEach-Object Class | Sort-Object -Unique)
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

# The target a whole-suite run offloads to, as @{ Name; Kind; ... }, or $null when none is usable. GitHub: a routine
# run on a commit on origin's main (or the background push run's commit) whose ci.yml has the offload job, with the gh
# command line present; CORVUS_TEST_OFFLOAD=0 turns it off.
function Get-OffloadTarget([string]$repo, [bool]$releaseTier) {
    if ([Environment]::GetEnvironmentVariable($script:OffloadVariable) -in '0', 'false', 'off') { return $null }
    if ($releaseTier) { return $null }
    if (-not ([Environment]::GetEnvironmentVariable($script:GhVariable) -or (Get-Command gh -ErrorAction SilentlyContinue))) { return $null }
    $workflow = git -C $repo show "HEAD:.github/workflows/$script:Workflow" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not ($workflow -match "^  ${script:OffloadJob}:")) { return $null }
    if ([Environment]::GetEnvironmentVariable($script:PushRunVariable) -ne '1') {
        git -C $repo merge-base --is-ancestor HEAD origin/main 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
    }
    $url = (git -C $repo remote get-url origin 2>$null) -join ''
    if ($url -notmatch 'github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$') { return $null }
    @{ Name = 'github'; Kind = 'github'; Repository = $Matches[1] }
}

# Starts the remote half of $classes on $target; returns a handle for Receive-Offload. GitHub runs the offload job on
# push by itself, so its handle waits for that run.
function Start-Offload($target, [string]$commit, [string[]]$classes, [bool]$releaseTier, [string]$module) {
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

# Waits for the remote half: @{ Started; Copied; Code; Trx; Note }. Started false means no test ran there and its
# classes run here; Copied false after a start means its results never came back.
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

# Waits for the commit's CI run on push and its offload jobs: @{ Kind; Repository; Run; Jobs; Note }, with Run $null
# (and Note saying why) when the run never appeared, did not finish, or its offload jobs did not all succeed.
function Wait-GitHubRun([string]$repository, [string]$commit, [int]$appearSeconds = $script:RunAppearSeconds, [int]$pollSeconds = $script:PollSeconds) {
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
    $deadline = (Get-Date).AddMinutes($script:RunFinishMinutes)
    while ($true) {
        $view = Invoke-Gh @('run', 'view', "$run", '-R', $repository, '--json', 'status,jobs') 2>$null
        if ($LASTEXITCODE -eq 0 -and $view) {
            $info = ($view -join '') | ConvertFrom-Json
            $jobs = @($info.jobs | Where-Object { $_.name -like "$script:OffloadJob*" })
            if ($jobs -and -not ($jobs | Where-Object status -ne 'completed')) {
                $failed = @($jobs | Where-Object conclusion -ne 'success')
                if ($failed) { $state.Note = "its offload jobs ended $(($failed | ForEach-Object conclusion | Sort-Object -Unique) -join ', ') in run $run"; return $state }
                $state.Run = $run; $state.Jobs = $jobs
                return $state
            }
            if (-not $jobs -and $info.status -eq 'completed') { $state.Note = "run $run has no offload job"; return $state }
        }
        if ((Get-Date) -gt $deadline) { $state.Note = "run $run did not finish in $script:RunFinishMinutes min"; return $state }
        Start-Sleep -Seconds $pollSeconds
    }
}

# Downloads a finished run's TRX artifacts into $folder and joins the Windows shards into one file; the other
# platforms' shards gate the run (they had to succeed) and their expected skips stay out.
function Receive-GitHubRun($state, [string]$folder) {
    $result = [pscustomobject]@{ Started = $false; Copied = $false; Code = 0; Trx = $null; Note = $state.Note }
    if (-not $state.Run) { return $result }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $null = Invoke-Gh @('run', 'download', "$($state.Run)", '-R', $state.Repository, '-p', "$script:OffloadJob-*", '-D', $folder) 2>$null
    $files = @(Get-ChildItem $folder -Recurse -Filter *.trx -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "$script:OffloadJob-windows" } | Sort-Object FullName)
    $windows = @($state.Jobs | Where-Object { $_.name -match 'windows' })
    if (-not $files -or $files.Count -lt $windows.Count) { $result.Note = "the TRX artifacts of run $($state.Run) did not all download"; return $result }
    $joined = Join-Path $folder 'offload.trx'
    Join-TrxFiles $joined @($files.FullName)
    $result.Started = $true; $result.Copied = $true; $result.Trx = $joined; $result.Note = "run $($state.Run)"
    $result
}

Export-ModuleMember -Function Invoke-Gh, Wait-GitHubRun, Receive-GitHubRun, Get-RemoteClasses, Get-RemoteShard, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-SkippedOnHost, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
