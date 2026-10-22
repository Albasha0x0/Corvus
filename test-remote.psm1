# Offloaded test classes (test.ps1 whole-suite runs): which classes run on another machine, the filter that leaves them
# out here, and how their results join the local ones. The transports below start the remote half and bring its TRX
# results back; a run with no usable target runs every class here.

# The classes a run sends: engine-free heavy classes (sweeps, matrices, round trips, reference comparisons, the full
# contract matrix, discovery at every thread count).
$script:RemotePatterns = '*SweepTests', '*MatrixTests', 'PipelineRoundTripTests', '*OracleTests', '*ComparisonTests', '*CompareTests',
    'ContractSweepFullTests', 'ParallelDiscoveryTests'
# Groups of offloaded classes: sweeps and comparisons, Ghidra classes and the live family each a CI job of its own; the
# host group goes to a test host only and stays here when the run offloads to GitHub.
$script:Groups = 'sweep', 'ghidra', 'live', 'host'
$script:HostGroup = 'host'
# Classes for a test host only: the Program Files sweep reads the machine it runs on (past 30 min on a runner), and the
# timed and working-set classes need a machine no other run loads.
$script:HostClasses = 'NativeToolSweepTests', 'DevRelayRealServerTests', 'DeadlineTests', 'StreamedSummaryMemoryTests'
# Folders whose classes go only as the ghidra group (by their Ghidra facts).
$script:EngineFolders = 'Engines'
# Attributes that keep a class's file here: real data never leaves this machine.
$script:LocalAttributes = 'RequiresRealDataFact', 'LiveRealDataFact'
# Classes whose inputs are this machine's own: every System32 import binding holds on a client edition only (a server
# image lacks some DLLs), the crash dump sweep reads this machine's dumps, and the comparisons over local data folders
# pass empty elsewhere.
$script:LocalClasses = 'NativeLinkSweepTests', 'MinidumpSweepTests', 'FirmwareComparisonTests', 'InstallerComparisonTests',
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
# A test host prepared by test-remote-setup.ps1 ([user@]name); it takes the offloaded classes ahead of GitHub when it
# answers over ssh.
$script:HostVariable = 'CORVUS_TEST_REMOTE'
# The ssh and scp programs, a .ps1 script standing in for either in the tests; OpenSSH's own when unset.
$script:SshVariable = 'CORVUS_TEST_SSH'
$script:ScpVariable = 'CORVUS_TEST_SCP'
# OpenSSH's option strings: key auth only, no prompt (a new host's key is recorded), a connect that fails fast, and a
# dead connection noticed within 2 minutes.
$script:SshOptions = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=4')
# The host's folder under its user's home: the clone (repo), the run's worktree (run) and its results.
$script:HostFolder = 'corvus-test-host'
# Seconds the host waits for the commit to reach origin; a push run starts before its push lands.
$script:FetchWaitSeconds = 120

# The offloaded classes of $testsDir as @{ Class; Group; Mixed }: host, the host classes; live, the classes of the Live
# folder; ghidra, those in files with a Ghidra fact (Mixed when the file has IDA facts too); sweep, names matching the
# table outside the engine folder. Files with IDA facts alone or real data, and the local classes, stay here; with
# -CrossPlatform, files with a Windows-only fact too. Only classes named *Tests count (fixtures and test bases hold no
# test of their own; an abstract *Tests class holds nested ones).
function Get-RemoteEntries([string]$testsDir, [switch]$CrossPlatform) {
    $local = '\[(' + ($script:LocalAttributes -join '|') + $(if ($CrossPlatform) { '|WindowsFact' }) + ')\b'
    Get-ChildItem $testsDir -Directory | Where-Object { $_.Name -notin 'bin', 'obj' } | ForEach-Object {
        $folder = $_.Name
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | ForEach-Object {
            $text = Get-Content $_.FullName -Raw
            if ($text -match $local) { return }
            $ida = $text -match '\[IdaFact\b'; $ghidra = $text -match '\[GhidraFact\b'
            if ($ida -and -not $ghidra) { return }
            $of = if ($folder -eq 'Live') { 'live' } elseif ($ghidra) { 'ghidra' } elseif ($folder -notin $script:EngineFolders) { 'sweep' } else { return }
            [regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+Tests)\b') | ForEach-Object { $_.Groups[1].Value } |
                Where-Object { $name = $_; $name -in $script:HostClasses -or ($name -notin $script:LocalClasses -and ($of -ne 'sweep' -or ($script:RemotePatterns | Where-Object { $name -like $_ }))) } |
                ForEach-Object { [pscustomobject]@{ Class = $_; Group = $(if ($_ -in $script:HostClasses) { $script:HostGroup } else { $of }); Mixed = $ida } }
        }
    }
}

# The classes of $testsDir a run sends, of one group or (empty) of every group but the host group, which -TestHost adds
# (Get-RemoteEntries). Sorted; throws for an unknown group.
function Get-RemoteClasses([string]$testsDir, [string]$Group = '', [switch]$CrossPlatform, [switch]$TestHost) {
    if ($Group -and $Group -notin $script:Groups) { throw "Unknown offload group '$Group' (one of $($script:Groups -join ', '))." }
    @(Get-RemoteEntries $testsDir -CrossPlatform:$CrossPlatform |
        Where-Object { if ($Group) { $_.Group -eq $Group } else { $TestHost -or $_.Group -ne $script:HostGroup } } | ForEach-Object Class | Sort-Object -Unique)
}

# The sent classes that use both engines: their Ghidra tests run there and their IDA tests here, joined per test. Sorted.
function Get-MixedClasses([string]$testsDir) {
    @(Get-RemoteEntries $testsDir | Where-Object Mixed | ForEach-Object Class | Sort-Object -Unique)
}

# Shard $index (0-based) of $count over $classes, dealt in name order so every machine computes the same shards.
function Get-RemoteShard([string[]]$classes, [int]$index, [int]$count) {
    @(for ($i = $index; $i -lt $classes.Count; $i += $count) { $classes[$i] })
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

# Classes whose results in $remoteTrx prove less than in $localTrx (the last local whole run): a test skipped there
# that ran here, or far less time than here (a test that returns early without its inputs). They run here.
function Get-SkippedOnHost([string]$remoteTrx, [string]$localTrx) {
    $before = @{}; if (Test-Path $localTrx) { foreach ($c in Get-ClassOutcomes $localTrx) { $before[$c.Class] = $c } }
    @(Get-ClassOutcomes $remoteTrx | Where-Object {
        $here = $before[$_.Class]
        ($_.Skipped -and -not ($here -and $here.Skipped)) -or ($here -and $here.Seconds -ge $script:ShortFloorSeconds -and $_.Seconds -lt $here.Seconds * $script:ShortShare)
    } | ForEach-Object Class | Sort-Object -Unique)
}

# The sent classes that rerun here after the remote half: those with a failed test there on any platform, those that
# proved less there (Get-SkippedOnHost; for $mixed classes, whose IDA tests skip there, Get-SkippedOnBoth against this
# run's $hereTrx), and those with no results there that ran here in $localTrx (all of them when there is no
# $localTrx). Sorted; empty when the remote half covered every class.
function Get-RerunClasses($got, [string[]]$sent, [string]$localTrx, [string[]]$mixed = @(), [string]$hereTrx = '') {
    $there = @{}; if ($got.Trx) { foreach ($c in Get-ClassOutcomes $got.Trx) { $there[$c.Class] = $true } }
    $ranHere = if (Test-Path $localTrx) { @(Get-ClassOutcomes $localTrx | ForEach-Object Class) } else { $null }
    $missing = @($sent | Where-Object { -not $there[$_] -and ($null -eq $ranHere -or $_ -in $ranHere) })
    $short = if ($got.Trx) { @(Get-SkippedOnHost $got.Trx $localTrx | Where-Object { $_ -notin $mixed }) } else { @() }
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

# Writes to $target one TRX file holding the results of $sources (missing files are passed over), without the results
# of $dropClasses from every source after the first. A test of $mergeClasses keeps one result per class and test name:
# a failed one over a passed one over a skipped one. Outcome counters are recounted, the others summed; an aborted
# source makes the run aborted.
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

# The target a whole-suite run offloads to, as @{ Name; Kind; ... }, or $null when none is usable: a routine run on a
# commit on origin's main (or the background push run's commit) offloads to the test host CORVUS_TEST_REMOTE names when
# it answers over ssh, else to GitHub when ci.yml has the offload job and the gh command line is present.
# CORVUS_TEST_OFFLOAD=0 turns it off.
function Get-OffloadTarget([string]$repo, [bool]$releaseTier) {
    if ([Environment]::GetEnvironmentVariable($script:OffloadVariable) -in '0', 'false', 'off') { return $null }
    if ($releaseTier) { return $null }
    if ([Environment]::GetEnvironmentVariable($script:PushRunVariable) -ne '1') {
        git -C $repo merge-base --is-ancestor HEAD origin/main 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
    }
    $remote = "$([Environment]::GetEnvironmentVariable($script:HostVariable))".Trim()
    if ($remote -and (Test-RemoteHost $remote)) { return @{ Name = $remote; Kind = 'ssh'; Host = $remote } }
    if (-not ([Environment]::GetEnvironmentVariable($script:GhVariable) -or (Get-Command gh -ErrorAction SilentlyContinue))) { return $null }
    $workflow = git -C $repo show "HEAD:.github/workflows/$script:Workflow" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not ($workflow -match "^  ${script:OffloadJob}:")) { return $null }
    $url = (git -C $repo remote get-url origin 2>$null) -join ''
    if ($url -notmatch 'github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$') { return $null }
    @{ Name = 'github'; Kind = 'github'; Repository = $Matches[1] }
}

# Starts the remote half of $classes on $target; returns a handle for Receive-Offload. GitHub runs the offload job on
# push by itself, so its handle waits for that run; a test host runs the classes it is sent.
function Start-Offload($target, [string]$commit, [string[]]$classes, [bool]$releaseTier, [string]$module) {
    switch ($target.Kind) {
        'ssh' {
            $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
            $script = Get-RemoteRunScript $commit (Get-ClassFilter $classes $releaseTier) $id
            Start-ThreadJob -ArgumentList $module, $target.Host, $script, $id -ScriptBlock {
                param($module, $remoteHost, $script, $id)
                Import-Module $module
                Invoke-RemoteRun $remoteHost $script $id
            }
        }
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
    if ($state.Kind -eq 'ssh') { return Receive-RemoteRun $state $folder }
    $state
}

# Runs ssh or scp (or the script standing in for it) with $arguments; returns its output, sets $LASTEXITCODE.
function Invoke-Transport([string]$variable, [string]$program, [string[]]$arguments) {
    $command = [Environment]::GetEnvironmentVariable($variable)
    if (-not $command) { return & $program @arguments }
    & pwsh -NoProfile -File $command @arguments
}

# Whether the host answers over ssh with key auth within the connect timeout.
function Test-RemoteHost([string]$remoteHost) {
    $null = Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, 'exit 0')) 2>$null
    $LASTEXITCODE -eq 0
}

# The script a test host runs: wait for $commit on origin (or take it from the bundle sent beside the script), check it
# out in the host's worktree, build once and run $filter $repeat times there at below-normal priority, one script at a
# time. Its output names the start ("corvus-remote: started"), each run ("corvus-remote-run <n> <exit code>") and the
# end ("corvus-remote-exit <worst exit code>"); a script that never starts a run names why. Results go to
# results/<id>/run-<n>.trx under the host folder.
function Get-RemoteRunScript([string]$commit, [string]$filter, [string]$id, [int]$repeat = 1, [switch]$Bundle) {
    $quoted = $filter.Replace("'", "''")
    @"
`$ErrorActionPreference = 'Continue'
(Get-Process -Id `$PID).PriorityClass = 'BelowNormal'
`$base = Join-Path `$HOME '$script:HostFolder'
`$clone = Join-Path `$base 'repo'; `$tree = Join-Path `$base 'run'; `$out = Join-Path `$base 'results/$id'
`$bundle = Join-Path `$base '$id.bundle'
# One script at a time: push runs and lanes' loops share the worktree and the machine.
`$lock = [Threading.Mutex]::new(`$false, 'Global\corvus-test-host')
try { [void]`$lock.WaitOne() } catch [Threading.AbandonedMutexException] { }
try {
    Get-ChildItem (Join-Path `$base 'results') -Directory -ErrorAction SilentlyContinue | Where-Object LastWriteTime -lt (Get-Date).AddDays(-1) | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    `$deadline = (Get-Date).AddSeconds($(if ($Bundle) { 0 } else { $script:FetchWaitSeconds }))
    while (`$true) {
        git -C `$clone fetch --quiet origin 2>`$null
        if (Test-Path `$bundle) { git -C `$clone fetch --quiet `$bundle 'refs/corvus/remote-$($id):refs/corvus/remote-$id' 2>`$null }
        git -C `$clone cat-file -e '$commit^{commit}' 2>`$null
        if (`$LASTEXITCODE -eq 0) { break }
        if ((Get-Date) -gt `$deadline) { 'corvus-remote: the commit did not reach the host$(if (-not $Bundle) { " from origin in $script:FetchWaitSeconds s" })'; exit 0 }
        Start-Sleep -Seconds 10
    }
    if (Test-Path (Join-Path `$tree '.git')) { git -C `$tree checkout --quiet --detach --force '$commit'; git -C `$tree clean -fdq }
    else { git -C `$clone worktree prune; git -C `$clone worktree add --detach `$tree '$commit' | Out-Null }
    if ((git -C `$tree rev-parse HEAD) -ne '$commit') { 'corvus-remote: the checkout failed'; exit 0 }
    New-Item -ItemType Directory -Force `$out | Out-Null
    `$log = Join-Path `$out 'console.log'
    & dotnet build (Join-Path `$tree 'tests/Corvus.Tests') --nologo -c Release *> `$log
    if (`$LASTEXITCODE -ne 0) { 'corvus-remote: the build failed (see results/$id/console.log)'; exit 0 }
    'corvus-remote: started'
    `$env:CORVUS_ALL_TESTS = '1'
    `$worst = 0
    for (`$n = 1; `$n -le $repeat; `$n++) {
        & dotnet test (Join-Path `$tree 'tests/Corvus.Tests') --nologo --no-build -c Release --filter '$quoted' --logger "trx;LogFileName=run-`$n.trx" ``
            --results-directory `$out --blame-hang --blame-hang-timeout 30m --blame-hang-dump-type mini *>> `$log
        "corvus-remote-run `$n `$LASTEXITCODE"
        if (`$LASTEXITCODE -ne 0) { `$worst = `$LASTEXITCODE }
    }
    "corvus-remote-exit `$worst"
}
finally {
    `$lock.ReleaseMutex()
    Remove-Item `$bundle -Force -ErrorAction SilentlyContinue
    git -C `$clone update-ref -d 'refs/corvus/remote-$id' 2>`$null
}
"@
}

# Copies $script (and $bundle, when given) to the host and runs it there with its PowerShell 7 (the setup puts it on
# the user's PATH): @{ Kind; Host; Id; Output }. -Stream also prints each line as it arrives.
function Invoke-RemoteRun([string]$remoteHost, [string]$script, [string]$id, [string]$bundle = '', [switch]$Stream) {
    $file = Join-Path ([IO.Path]::GetTempPath()) "corvus-remote-$id.ps1"
    try {
        Set-Content $file $script -Encoding utf8
        $sources = @($file) + @(if ($bundle) { $bundle })
        $output = @(Invoke-Transport $script:ScpVariable 'scp' (@($script:SshOptions) + $sources + @("${remoteHost}:$script:HostFolder/")) 2>&1 | ForEach-Object { "$_" })
        if ($LASTEXITCODE -eq 0) {
            $output = @(Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, "pwsh -NoProfile -NonInteractive -File $script:HostFolder/$(Split-Path $file -Leaf)")) 2>&1 |
                ForEach-Object { if ($Stream) { Write-Host "  $_" }; "$_" })
            $null = Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, "pwsh -NoProfile -NonInteractive -Command Remove-Item $script:HostFolder/$(Split-Path $file -Leaf)")) 2>$null
        }
    }
    finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }
    @{ Kind = 'ssh'; Host = $remoteHost; Id = $id; Output = $output }
}

# A commit holding $repo's working tree as it is (tracked changes and untracked files outside .gitignore), made without
# touching its index or branches: HEAD itself when the tree is clean. Returns @{ Commit; Bundle }, Bundle being a
# bundle file of the commits origin/main lacks, or empty when origin has the commit already.
function New-RemoteSnapshot([string]$repo, [string]$id) {
    $index = Join-Path ([IO.Path]::GetTempPath()) "corvus-remote-$id.index"
    try {
        Copy-Item (git -C $repo rev-parse --path-format=absolute --git-path index) $index
        $env:GIT_INDEX_FILE = $index
        git -C $repo add -A 2>$null
        $tree = (git -C $repo write-tree).Trim()
    }
    finally { Remove-Item Env:GIT_INDEX_FILE -ErrorAction SilentlyContinue; Remove-Item $index -Force -ErrorAction SilentlyContinue }
    $head = (git -C $repo rev-parse HEAD).Trim()
    $commit = if ($tree -eq (git -C $repo rev-parse 'HEAD^{tree}').Trim()) { $head } else { (git -C $repo commit-tree $tree -p $head -m 'Working tree sent to a test host').Trim() }
    git -C $repo merge-base --is-ancestor $commit origin/main 2>$null
    if ($LASTEXITCODE -eq 0) { return @{ Commit = $commit; Bundle = '' } }
    $bundle = Join-Path ([IO.Path]::GetTempPath()) "$id.bundle"
    git -C $repo update-ref "refs/corvus/remote-$id" $commit
    try { git -C $repo bundle create --quiet $bundle "refs/corvus/remote-$id" '^origin/main' 2>$null }
    finally { git -C $repo update-ref -d "refs/corvus/remote-$id" }
    if ($LASTEXITCODE -ne 0) { throw "Bundling $commit failed." }
    @{ Commit = $commit; Bundle = $bundle }
}

# Runs $filter $repeat times on the test host from $repo's working tree as it is (test.ps1 -Remote), printing a line per
# run and copying the TRX files of failed runs into $folder. Returns 0 when every run passed, 1 when any failed, and 2
# when no run started there.
function Invoke-RemoteFilter([string]$repo, [string]$remoteHost, [string]$filter, [int]$repeat, [string]$folder) {
    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $snapshot = New-RemoteSnapshot $repo $id
    try {
        Write-Host "Sending $(if ($snapshot.Bundle) { "the working tree ($($snapshot.Commit.Substring(0, 8)))" } else { $snapshot.Commit.Substring(0, 8) }) to $remoteHost`: $filter, $repeat run$(if ($repeat -ne 1) { 's' })."
        $state = Invoke-RemoteRun $remoteHost (Get-RemoteRunScript $snapshot.Commit $filter $id $repeat -Bundle:([bool]$snapshot.Bundle)) $id $snapshot.Bundle -Stream
    }
    finally { if ($snapshot.Bundle) { Remove-Item $snapshot.Bundle -Force -ErrorAction SilentlyContinue } }
    $runs = @($state.Output | Where-Object { $_ -match '^corvus-remote-run (\d+) (-?\d+)$' } | ForEach-Object { [pscustomobject]@{ Run = [int]$Matches[1]; Code = [int]$Matches[2] } })
    if ($state.Output -notcontains 'corvus-remote: started') {
        $why = $state.Output | Where-Object { $_ -like 'corvus-remote: *' } | Select-Object -Last 1
        Write-Host "No run started on $remoteHost`: $(if ($why) { $why -replace '^corvus-remote: ', '' } else { "ssh failed$(if ($state.Output) { ": $($state.Output[-1])" })" })" -ForegroundColor Red
        return 2
    }
    $failed = @($runs | Where-Object Code -ne 0)
    if ($failed) {
        New-Item -ItemType Directory -Force $folder | Out-Null
        foreach ($run in $failed) {
            $null = Invoke-Transport $script:ScpVariable 'scp' (@($script:SshOptions) + @("${remoteHost}:$script:HostFolder/results/$id/run-$($run.Run).trx", (Join-Path $folder "run-$($run.Run).trx"))) 2>$null
        }
    }
    $missing = $repeat - $runs.Count
    Write-Host "$($runs.Count) of $repeat runs on $remoteHost`: $($runs.Count - $failed.Count) passed, $($failed.Count) failed$(if ($failed) { " (runs $(($failed.Run) -join ', '); TRX in $folder)" })$(if ($missing -gt 0) { "; $missing did not run (the connection ended)" })."
    if ($failed -or $missing -gt 0) { 1 } else { 0 }
}

# Brings a test host's results back into $folder: @{ Started; Trx; Failed; Note } as Receive-GitHubRun returns it.
# Started false means no test started there (ssh failed, or the commit never arrived), and Note says why.
function Receive-RemoteRun($state, [string]$folder) {
    $result = [pscustomobject]@{ Started = $false; Trx = $null; Failed = @(); Note = $null }
    $output = @($state.Output)
    if ($output -notcontains 'corvus-remote: started') {
        $why = $output | Where-Object { $_ -like 'corvus-remote: *' } | Select-Object -Last 1
        $result.Note = if ($why) { $why -replace '^corvus-remote: ', '' } else { "ssh $($state.Host) failed$(if ($output) { ": $($output[-1])" })" }
        return $result
    }
    $result.Started = $true
    $exit = $output | Where-Object { $_ -match '^corvus-remote-exit (-?\d+)$' } | Select-Object -Last 1
    $result.Note = if ($exit) { "exit $($exit -replace '^corvus-remote-exit ', '')" } else { 'the connection ended before the run did' }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $trx = Join-Path $folder 'offload.trx'
    $null = Invoke-Transport $script:ScpVariable 'scp' (@($script:SshOptions) + @("$($state.Host):$script:HostFolder/results/$($state.Id)/run-1.trx", $trx)) 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $trx)) {
        $result.Trx = $trx
        $result.Failed = @(Get-ClassOutcomes $trx | Where-Object Failed | ForEach-Object { [pscustomobject]@{ Class = $_.Class; Platform = 'host' } })
    }
    $result
}

# Runs the gh command line (or the script standing in for it); returns its output, sets $LASTEXITCODE.
function Invoke-Gh([string[]]$arguments) {
    $command = [Environment]::GetEnvironmentVariable($script:GhVariable)
    if ($command) { return & pwsh -NoProfile -File $command @arguments }
    & gh @arguments
}

# Waits for the commit's CI run on push and its offload jobs: @{ Kind; Repository; Run; Jobs; Note }, with Run $null
# (and Note saying why) when the run never appeared or did not finish; Note names the offload jobs that did not succeed.
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
                $state.Run = $run; $state.Jobs = $jobs
                $failed = @($jobs | Where-Object conclusion -ne 'success')
                if ($failed) { $state.Note = "$(($failed | ForEach-Object name) -join ', ') ended $(($failed | ForEach-Object conclusion | Sort-Object -Unique) -join ', ') in run $run" }
                return $state
            }
            if (-not $jobs -and $info.status -eq 'completed') { $state.Note = "run $run has no offload job"; return $state }
        }
        if ((Get-Date) -gt $deadline) { $state.Note = "run $run did not finish in $script:RunFinishMinutes min"; return $state }
        Start-Sleep -Seconds $pollSeconds
    }
}

# Downloads a finished run's TRX artifacts (offload-<group>-<os>-<shard>) into $folder: @{ Started; Trx; Failed; Note }.
# Trx joins the Windows shards ($null when none came back); the other platforms' expected skips stay out. Failed lists
# the classes with a failed test on any platform, as @{ Class; Platform }. Started false means no test ran there.
function Receive-GitHubRun($state, [string]$folder) {
    $result = [pscustomobject]@{ Started = $false; Trx = $null; Failed = @(); Note = $state.Note }
    if (-not $state.Run) { return $result }
    New-Item -ItemType Directory -Force $folder | Out-Null
    $null = Invoke-Gh @('run', 'download', "$($state.Run)", '-R', $state.Repository, '-p', "$script:OffloadJob-*", '-D', $folder) 2>$null
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

Export-ModuleMember -Function Invoke-Transport, Test-RemoteHost, Get-RemoteRunScript, Invoke-RemoteRun, Receive-RemoteRun, New-RemoteSnapshot, Invoke-RemoteFilter, Invoke-Gh, Wait-GitHubRun, Receive-GitHubRun, Get-RemoteClasses, Get-RemoteShard, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-TestOutcomes, Get-SkippedOnHost, Get-SkippedOnBoth, Get-RerunClasses, Get-MixedClasses, Get-FailedThereNote, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
