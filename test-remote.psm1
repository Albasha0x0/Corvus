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
# Classes with IDA facts: about half of them, by recorded time, go to a test host whose user variables name an IDA
# install (this variable), so the engine-ida permit chain runs on both machines at once; GitHub has no IDA.
$script:IdaGroup = 'ida'
$script:IdaVariable = 'CORVUS_IDA_DIR'
# Classes for a test host only: the Program Files sweep reads the machine it runs on (past 30 min on a runner), and the
# timed and working-set classes need a machine no other run loads.
$script:HostClasses = 'NativeToolSweepTests', 'DevRelayRealServerTests', 'DeadlineTests', 'StreamedSummaryMemoryTests'
# The host tier: stable families (test folders) that leave push runs here but for their smoke tests (trait
# Smoke=push) and run whole on the test host in whole runs.
$script:TierFamilies = 'Accuracy', 'Builds', 'Containers', 'DotnetEdits', 'Dumps', 'Il2Cpp', 'Mobile', 'NativeAot', 'NativeEdits',
    'NativeFormats', 'Support', 'Web'
$script:SmokeTrait = 'Smoke=push'
# The host tier's last nightly run on the test host, under the repository's .git: its record and its results.
$script:TierFile = 'corvus-host-tier.json'
# A Ghidra fact skips without its engine, as an IDA fact does without $script:IdaVariable.
$script:GhidraVariable = 'CORVUS_GHIDRA_DIR'
# Folders whose classes go only as the ghidra group (by their Ghidra facts).
$script:EngineFolders = 'Engines'
# Attributes that keep a class's file here: the live real-data facts.
$script:LocalAttributes = 'LiveRealDataFact'
# The real-data fact: its file's classes go to a test host whose user variables name an existing path for every
# variable the file's facts name (test-remote-setup.ps1 -Data copies them), and stay here otherwise. Real data never
# goes to GitHub.
$script:DataAttribute = 'RequiresRealDataFact'
# An IDA fact given real-data variables reads real data too.
$script:IdaDataFact = '\[IdaFact\(\s*[^)\s]'
# Real-data variables that name a program the tests run (reference decompilers, disassemblers, validators, a capture
# reader, the pipeline tool) rather than inputs: -Data leaves them out, and a class that needs one goes only to a host
# whose own install sets it.
$script:ToolVariables = 'CORVUS_TSHARK', 'CORVUS_WASM_TO_TEXT', 'CORVUS_WASM_VALIDATOR', 'CORVUS_JAVA_DECOMPILER', 'CORVUS_JAVA_DECOMPILER2',
    'CORVUS_DEX_DISASSEMBLER', 'CORVUS_HBC_DISASSEMBLER', 'CORVUS_PY_DECOMPILER', 'CORVUS_PIPELINE_TOOL'
# The file that names the real-data variables (RealData.Name constants).
$script:RealDataSource = 'Support/TestEnv.cs'
# Classes whose inputs are this machine's own: every System32 import binding holds on a client edition only (a server
# image lacks some DLLs), the crash dump sweep reads this machine's dumps, the comparisons over local data folders
# pass empty elsewhere, and the ISA sweep decompiles RISC-V, which the test host's IDA license lacks.
$script:LocalClasses = 'NativeLinkSweepTests', 'MinidumpSweepTests', 'FirmwareComparisonTests', 'InstallerComparisonTests',
    'DependencyListerComparisonTests', 'IsaEngineTests'
# A class that took under this share of its last local time, when that was at least the given seconds, proved less
# there (a test that returns early without its inputs) and runs here.
$script:ShortShare = 0.2
$script:ShortFloorSeconds = 30
# Where a run keeps each target's record and results, under the repository's .git.
$script:RecordFolder = 'corvus-remote'
# The host group's classes the last push run left to the nightly run, under the repository's .git.
$script:DeferredFile = 'corvus-host-deferred.txt'
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
# Minutes a push run waits for the GitHub live jobs in place of rerunning the live classes a test host left; they end
# 10 to 22 min after the push, well inside a push run.
$script:LiveFallbackMinutes = 10
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
# Seconds a short ssh or scp call (the probe, a query, a cleanup) may take in all: the ssh options bound the connect
# and a dead connection, not a session that hangs after login. A TRX copy gets four times as long.
$script:ShortCallSeconds = 30
# Seconds a timed-out call's process tree may take to exit once it is ended.
$script:KillWaitSeconds = 10
# Seconds the host waits for the commit to reach origin; a push run starts before its push lands.
$script:FetchWaitSeconds = 120

# The variables the real-data facts in $text name, '?' for one it cannot resolve (a fact without arguments, or an
# argument that is no string constant): RealData.Name through $constants, a "CORVUS_..." literal, or a constant of the
# file. Sorted, unique; empty when the file has no real-data fact.
function Get-DataVariables([string]$text, [hashtable]$constants) {
    $names = foreach ($fact in [regex]::Matches($text, '\[' + $script:DataAttribute + '\b(?:\(([^)]*)\))?')) {
        if (-not $fact.Groups[1].Success -or -not $fact.Groups[1].Value.Trim()) { '?'; continue }
        foreach ($argument in $fact.Groups[1].Value -split ',') {
            $argument = $argument.Trim()
            if ($argument -match '^RealData\.(\w+)$') { if ($constants.ContainsKey($Matches[1])) { $constants[$Matches[1]] } else { '?' } }
            elseif ($argument -match '^"(CORVUS_\w+)"$') { $Matches[1] }
            elseif ($argument -match '^\w+$' -and $text -match ('\bconst string ' + $argument + ' = "(CORVUS_\w+)"')) { $Matches[1] }
            else { '?' }
        }
    }
    @($names | Sort-Object -Unique)
}

# The RealData constants of $testsDir's real-data source, name to variable; empty when the file is absent.
function Get-RealDataConstants([string]$testsDir) {
    $constants = @{}
    $source = Join-Path $testsDir $script:RealDataSource
    if (Test-Path $source) { [regex]::Matches((Get-Content $source -Raw), 'public const string (\w+) = "(CORVUS_\w+)"') | ForEach-Object { $constants[$_.Groups[1].Value] = $_.Groups[2].Value } }
    $constants
}

# The top-level *Tests classes of C# source $text as @{ Class; Ida; Ghidra }: whether the class holds an IDA fact, and
# one a routine run includes (a Ghidra fact without the release tier on it or on its class). An offload never runs the
# release tier, so a class whose Ghidra facts are all release-tier counts as IDA alone.
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

# The offloaded classes of $testsDir as @{ Class; Group; Mixed; Variables }: host, the host classes and those in files
# with real-data facts (Variables, the variables those facts name); live, the classes of the Live folder; ghidra, the
# classes with a Ghidra fact a routine run includes (Mixed when the class has IDA facts too); ida, the classes with IDA
# facts alone; sweep, names matching the table outside the engine folder. Files with real data and IDA facts, live real
# data, and the local classes stay here; with -CrossPlatform, files with a Windows-only fact too. Only classes named *Tests count (fixtures and test bases
# hold no test of their own; an abstract *Tests class holds nested ones).
function Get-RemoteEntries([string]$testsDir, [switch]$CrossPlatform) {
    $local = '\[(' + ($script:LocalAttributes -join '|') + $(if ($CrossPlatform) { '|WindowsFact' }) + ')\b'
    $constants = Get-RealDataConstants $testsDir
    Get-ChildItem $testsDir -Directory | Where-Object { $_.Name -notin 'bin', 'obj' } | ForEach-Object {
        $folder = $_.Name
        Get-ChildItem $_.FullName -Recurse -Filter *.cs | ForEach-Object {
            $text = Get-Content $_.FullName -Raw
            if ($text -match $local) { return }
            $ida = $text -match '\[IdaFact\b'; $ghidra = $text -match '\[GhidraFact\b'
            if ($text -match ('\[' + $script:DataAttribute + '\b') -or $text -match $script:IdaDataFact) {
                if ($ida) { return }
                $variables = @(Get-DataVariables $text $constants)
                [regex]::Matches($text, '(?m)^public (?:sealed |abstract |partial |static )*class (\w+Tests)\b') | ForEach-Object { $_.Groups[1].Value } |
                    Where-Object { $_ -notin $script:LocalClasses } |
                    ForEach-Object { [pscustomobject]@{ Class = $_; Group = $script:HostGroup; Mixed = $false; Variables = $variables } }
                return
            }
            foreach ($class in Get-ClassEngines $text) {
                $name = $class.Class
                if ($class.Ida -and -not $class.Ghidra) {
                    if ($name -notin $script:LocalClasses) { [pscustomobject]@{ Class = $name; Group = $script:IdaGroup; Mixed = $false; Variables = @() } }
                    continue
                }
                $of = if ($folder -eq 'Live') { 'live' } elseif ($class.Ghidra) { 'ghidra' } elseif ($folder -notin $script:EngineFolders) { 'sweep' } else { continue }
                if (-not ($name -in $script:HostClasses -or ($name -notin $script:LocalClasses -and ($of -ne 'sweep' -or ($script:RemotePatterns | Where-Object { $name -like $_ }))))) { continue }
                [pscustomobject]@{ Class = $name; Group = $(if ($name -in $script:HostClasses) { $script:HostGroup } else { $of }); Mixed = $class.Ida; Variables = @() }
            }
        }
    }
}

# The host tier's families, without those in $returned (families a failure on the host sent back to push runs). Sorted.
function Get-TierFamilies([string[]]$returned = @()) {
    @($script:TierFamilies | Where-Object { $_ -notin $returned } | Sort-Object)
}

# The test classes (named *Tests) of the host tier's family folders under $testsDir, without the families in $returned.
# Sorted; a family folder that does not exist adds none.
function Get-TierClasses([string]$testsDir, [string[]]$returned = @()) {
    @($(foreach ($family in Get-TierFamilies $returned) {
        $folder = Join-Path $testsDir $family
        if (-not (Test-Path $folder)) { continue }
        Get-ChildItem $folder -Recurse -Filter *.cs | ForEach-Object {
            [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^public (?:sealed |abstract |partial |static )*class (\w+Tests)\b') | ForEach-Object { $_.Groups[1].Value }
        }
    }) | Sort-Object -Unique)
}

# The host tier's families (test folders under $testsDir) holding any of $classes. Sorted.
function Get-TierFamiliesOf([string]$testsDir, [string[]]$classes) {
    if (-not $classes) { return @() }
    @(Get-TierFamilies | Where-Object { $family = $_; @(Get-TierClasses $testsDir @(Get-TierFamilies | Where-Object { $_ -ne $family }) | Where-Object { $_ -in $classes }) })
}

# The host tier's families its last run on the test host returned to push runs (<gitDir>/corvus-host-tier.json): those
# with a class that failed there, until a later tier run passes them. Sorted; empty when the tier has not run.
function Get-TierReturned([string]$gitDir) {
    $file = Join-Path $gitDir $script:TierFile
    if (-not (Test-Path $file)) { return @() }
    @((Get-Content $file -Raw | ConvertFrom-Json).returned | Where-Object { $_ } | Sort-Object -Unique)
}

# A dotnet test filter that runs $filter (everything when empty) without $classes but with their smoke tests (trait
# Smoke=push); $filter itself when $classes is empty.
function Get-TierFilter([string]$filter, [string[]]$classes) {
    if (-not $classes) { return $filter }
    "($(Get-LocalFilter $filter $classes))|$script:SmokeTrait"
}

# Of the host tier's $classes, @{ Sent; Kept } for a test host whose user variables are $hostVariables: Kept names each
# class that stays unsent as "Class (reason)", a local class, a file with live real data, or a file whose real-data or
# engine facts need a variable not set there ('?' for one the facts do not name). Both sorted.
function Get-TierHostClasses([string]$testsDir, [string[]]$classes, [string[]]$hostVariables = @()) {
    $constants = Get-RealDataConstants $testsDir
    $local = '\[(' + ($script:LocalAttributes -join '|') + ')\b'
    $sent = [Collections.Generic.List[string]]::new(); $kept = [Collections.Generic.List[string]]::new()
    foreach ($family in $script:TierFamilies) {
        $folder = Join-Path $testsDir $family
        if (-not (Test-Path $folder)) { continue }
        foreach ($file in Get-ChildItem $folder -Recurse -Filter *.cs) {
            $text = Get-Content $file.FullName -Raw
            $data = if ($text -match ('\[' + $script:DataAttribute + '\b')) { @(Get-DataVariables $text $constants) } else { @() }
            foreach ($class in Get-ClassEngines $text | Where-Object Class -in $classes) {
                $name = $class.Class
                $needed = @($data) + @(if ($class.Ida) { $script:IdaVariable }) + @(if ($class.Ghidra) { $script:GhidraVariable })
                $absent = @($needed | Where-Object { $_ -notin $hostVariables } | Sort-Object -Unique)
                if ($name -in $script:LocalClasses) { $kept.Add("$name (this machine's inputs)") }
                elseif ($text -match $local) { $kept.Add("$name (live real data)") }
                elseif ($absent) { $kept.Add("$name ($($absent -join ', ') not set there)") }
                else { $sent.Add($name) }
            }
        }
    }
    @{ Sent = @($sent | Sort-Object -Unique); Kept = @($kept | Sort-Object -Unique) }
}

# What the host tier's run proved, from $got (Receive-Offload) for the $sent classes, as @{ Passed; Failed; Unproven }:
# the families of $classMap whose classes were all sent and all passed there with a full result (none proving less
# than in $localTrx, the last local whole run; Get-SkippedOnHost with $fastest), the families with a class that failed
# there, and the sent classes without a full result. Sorted; nothing passes without results.
function Get-TierPasses($got, [string[]]$sent, [hashtable]$classMap, [string]$localTrx, [hashtable]$fastest = @{}) {
    if (-not $got.Trx) { return @{ Passed = @(); Failed = @(); Unproven = @($sent | Sort-Object -Unique) } }
    $failedClasses = @($got.Failed | ForEach-Object Class)
    $unproven = @(Get-RerunClasses $got $sent $localTrx @() '' $fastest | Where-Object { $_ -notin $failedClasses })
    # A run that ended without its exit line and shows no failure passes nothing (Get-PassedFamilies).
    $exitCode = if ($got.Note -match '^exit (-?\d+)$') { [int]$Matches[1] } else { 1 }
    # The class map names every top-level class; fixtures and attributes hold no test to send.
    $unsent = @($classMap.Values | ForEach-Object { $_ } | Where-Object { $_ -like '*Tests' -and $_ -notin $sent })
    @{
        Passed = @(Get-UndeferredFamilies @(Get-PassedFamilies $got.Trx $classMap $exitCode) $classMap @($unsent + $unproven))
        Failed = @($classMap.Keys | Where-Object { $key = $_; @($classMap[$key] | Where-Object { $_ -in $failedClasses }) } | Sort-Object)
        Unproven = @($unproven | Sort-Object -Unique)
    }
}

# Saves the host tier's run record -Status shows: <gitDir>/corvus-host-tier.json.
function Save-TierRecord([string]$gitDir, [System.Collections.IDictionary]$record) {
    Set-Content -Path (Join-Path $gitDir $script:TierFile) -Value ($record | ConvertTo-Json -Depth 3) -NoNewline
}

# The host tier's last run as one line: "<state> on <commit> at <time> on <target> (<n> classes, <s> s); ...", naming
# the families it recorded, those that failed, those returned to push runs, the classes without a full result and those
# kept unsent; $null when it has not run.
function Get-TierStatus([string]$gitDir) {
    $file = Join-Path $gitDir $script:TierFile
    if (-not (Test-Path $file)) { return $null }
    $r = Get-Content $file -Raw | ConvertFrom-Json
    $parts = @("$($r.state) on $($r.commit) at $($r.at) on $($r.target) ($($r.classes) classes$(if ($null -ne $r.seconds) { ", $($r.seconds) s" }))")
    if ($r.transport -eq 'bundle') { $parts += 'the commit went as a bundle, origin lacked it' }
    if ($r.waited) { $parts += "waited $($r.waited) s for another run there" }
    if ($r.recorded) { $parts += "recorded: $($r.recorded -join ', ')" }
    if ($r.failed) { $parts += "failed there: $($r.failed -join ', ')" }
    if ($r.returned) { $parts += "returned to push runs: $($r.returned -join ', ')" }
    if ($r.unproven) { $parts += "no full result there: $($r.unproven -join ', ')" }
    if ($r.kept) { $parts += "kept here: $($r.kept -join '; ')" }
    if ($r.note) { $parts += $r.note }
    $parts -join '; '
}

# The classes of $testsDir a run sends, of one group or (empty) of every group but the host and IDA groups
# (Get-RemoteEntries). -TestHost adds the host group's classes whose real-data variables are all in $hostVariables.
# Sorted; throws for an unknown group.
function Get-RemoteClasses([string]$testsDir, [string]$Group = '', [switch]$CrossPlatform, [switch]$TestHost, [string[]]$hostVariables = @()) {
    if ($Group -and $Group -notin $script:Groups) { throw "Unknown offload group '$Group' (one of $($script:Groups -join ', '))." }
    @(Get-RemoteEntries $testsDir -CrossPlatform:$CrossPlatform |
        Where-Object {
            if ($Group) { $_.Group -eq $Group }
            elseif ($_.Group -eq $script:IdaGroup) { $false }
            else { $_.Group -ne $script:HostGroup -or ($TestHost -and -not @($_.Variables | Where-Object { $_ -notin $hostVariables })) }
        } |
        ForEach-Object Class | Sort-Object -Unique)
}

# The IDA classes of $testsDir a test host whose $hostVariables name an IDA install takes: of the classes with IDA
# facts it may run (alone or with Ghidra facts), those dealt to it when each, longest first by $seconds (class name to
# recorded seconds; an unrecorded class counts 1 s), goes to the machine with less so far. They run whole there.
# Sorted; empty when the host has no IDA. $hostPart is the host's fraction of the time, as Get-HostShare takes it.
function Get-IdaHostClasses([string]$testsDir, [hashtable]$seconds = @{}, [string[]]$hostVariables = @(), [double]$hostPart = 0.5) {
    if ($script:IdaVariable -notin $hostVariables) { return @() }
    Get-HostShare @(Get-RemoteEntries $testsDir | Where-Object { $_.Group -eq $script:IdaGroup -or $_.Mixed } | ForEach-Object Class | Sort-Object -Unique) $seconds $hostPart
}

# The Ghidra classes of $testsDir that stay here when a test host takes the rest: of the classes with Ghidra facts
# alone (a mixed class's Ghidra tests go there already), those not dealt to the host as Get-HostShare deals them, so
# the Ghidra chain runs on both machines. Sorted.
function Get-GhidraLocalClasses([string]$testsDir, [hashtable]$seconds = @{}, [double]$hostPart = 0.5) {
    $classes = @(Get-RemoteEntries $testsDir | Where-Object { $_.Group -eq 'ghidra' -and -not $_.Mixed } | ForEach-Object Class | Sort-Object -Unique)
    $there = @(Get-HostShare $classes $seconds $hostPart)
    @($classes | Where-Object { $_ -notin $there })
}

# The host's share of $classes: each, longest first by $seconds (class name to recorded seconds; an unrecorded class
# counts 1 s), goes to the machine with less so far for its part, the host first; $hostPart (0 to 1) is the host's
# part of the time. Sorted.
function Get-HostShare([string[]]$classes, [hashtable]$seconds, [double]$hostPart = 0.5) {
    $weight = @{}; foreach ($class in $classes) { $weight[$class] = if ($seconds.ContainsKey($class) -and $seconds[$class] -gt 0) { [double]$seconds[$class] } else { 1.0 } }
    $here = 0.0; $there = 0.0
    @(foreach ($class in $classes | Sort-Object @{ Expression = { $weight[$_] }; Descending = $true }, @{ Expression = { $_ } }) {
        if ($there * (1 - $hostPart) -le $here * $hostPart) { $there += $weight[$class]; $class } else { $here += $weight[$class] }
    }) | Sort-Object
}

# The real-data variables the host group's classes of $testsDir need that name inputs, or with -Tools those that name
# a program. Sorted, unresolved ones ('?') left out.
function Get-RealDataVariables([string]$testsDir, [switch]$Tools) {
    @(Get-RemoteEntries $testsDir | ForEach-Object { $_.Variables } | Where-Object { $_ -and $_ -ne '?' -and ($_ -in $script:ToolVariables) -eq [bool]$Tools } |
        Sort-Object -Unique)
}

# The host group's classes of $testsDir that stay here because a real-data variable they need is not in
# $hostVariables, each as "Class (VARIABLE, ...)" ('?' for a variable the facts do not name). Sorted.
function Get-HeldClasses([string]$testsDir, [string[]]$hostVariables = @()) {
    @(Get-RemoteEntries $testsDir | Where-Object Group -eq $script:HostGroup | ForEach-Object {
        $absent = @($_.Variables | Where-Object { $_ -notin $hostVariables })
        if ($absent) { "$($_.Class) ($($absent -join ', '))" }
    } | Sort-Object -Unique)
}

# The sent classes that use both engines: their Ghidra tests run there and their IDA tests here, joined per test. Sorted.
function Get-MixedClasses([string]$testsDir) {
    @(Get-RemoteEntries $testsDir | Where-Object Mixed | ForEach-Object Class | Sort-Object -Unique)
}

# Shard $index (0-based) of $count over $classes, in name order. With $seconds (class -> recorded seconds), each class,
# longest first, goes to the shard with the least recorded time so far (ties: by name, to the lower shard), a class with
# no record counting 1 s; without it, classes are dealt in name order. Every machine computes the same shards.
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

# The recorded seconds per offloaded class on $platform (class -> seconds) that Get-RemoteShard deals by: a class
# recorded only on other platforms takes the longest of their times. $null when the file at $path is missing or
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

# Records in $path, under $platform, per class, the median of its summed test seconds over the TRX files $trxPaths
# (offload job results from that platform), whole seconds, at least 1; classes recorded before and absent from these
# files keep their entry, and other platforms' entries are kept as they were.
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

# Classes whose results in $remoteTrx prove less than in $localTrx (the last local whole run): a test skipped there
# that ran here, or far less time than here (a test that returns early without its inputs). The time compared is the
# fewer of the last local run's and the fastest in $fastest: a loaded machine runs a class many times slower than an
# idle one, so the last local time alone would make a class on an idle host look short.
function Get-SkippedOnHost([string]$remoteTrx, [string]$localTrx, [hashtable]$fastest = @{}) {
    $before = @{}; if (Test-Path $localTrx) { foreach ($c in Get-ClassOutcomes $localTrx) { $before[$c.Class] = $c } }
    @(Get-ClassOutcomes $remoteTrx | Where-Object {
        $here = $before[$_.Class]
        $seconds = if (-not $here) { 0 } elseif ($fastest.ContainsKey($_.Class)) { [math]::Min($here.Seconds, $fastest[$_.Class]) } else { $here.Seconds }
        ($_.Skipped -and -not ($here -and $here.Skipped)) -or ($seconds -ge $script:ShortFloorSeconds -and $_.Seconds -lt $seconds * $script:ShortShare)
    } | ForEach-Object Class | Sort-Object -Unique)
}

# The sent classes that rerun here after the remote half: those with a failed test there on any platform, those that
# proved less there (Get-SkippedOnHost; for $mixed classes, whose IDA tests skip there, Get-SkippedOnBoth against this
# run's $hereTrx), and those with no results there that ran here in $localTrx (all of them when there is no
# $localTrx). $fastest is Get-FastestClassSeconds. Sorted; empty when the remote half covered every class.
function Get-RerunClasses($got, [string[]]$sent, [string]$localTrx, [string[]]$mixed = @(), [string]$hereTrx = '', [hashtable]$fastest = @{}) {
    $there = @{}; if ($got.Trx) { foreach ($c in Get-ClassOutcomes $got.Trx) { $there[$c.Class] = $true } }
    $ranHere = if (Test-Path $localTrx) { @(Get-ClassOutcomes $localTrx | ForEach-Object Class) } else { $null }
    $missing = @($sent | Where-Object { -not $there[$_] -and ($null -eq $ranHere -or $_ -in $ranHere) })
    $short = if ($got.Trx) { @(Get-SkippedOnHost $got.Trx $localTrx $fastest | Where-Object { $_ -notin $mixed }) } else { @() }
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

# Of $classes, the ones in the host group $hostGroup that a push run leaves to the nightly whole run, which runs every
# class: all but those in $failed, which run here so that a failure on the test host is checked on this machine too.
# Sorted.
function Get-DeferredClasses([string[]]$classes, [string[]]$hostGroup, [string[]]$failed = @()) {
    @($classes | Where-Object { $_ -in $hostGroup -and $_ -notin $failed } | Sort-Object -Unique)
}

# Of the families in $passed, those whose classes in $classMap include none of $deferred: a family whose class did not
# run records no pass. Sorted.
function Get-UndeferredFamilies([string[]]$passed, [hashtable]$classMap, [string[]]$deferred = @()) {
    @($passed | Where-Object { $family = $_; -not @($classMap[$family] | Where-Object { $_ -in $deferred }) } | Sort-Object)
}

# Saves the classes a push run left to the nightly run, as "<commit> at <time>: <classes>" in
# <gitDir>/corvus-host-deferred.txt for -Status; no class removes the file.
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
        "$($r.target): $state on $($r.commit) at $($r.at) ($($r.classes) classes$(if ($null -ne $r.seconds) { ", $($r.seconds) s" }))$(if ($r.transport -eq 'bundle') { '; the commit went as a bundle, origin lacked it' })$(if ($r.held) { "; $($r.held) kept here for real-data variables not set there" })$(if ($r.note) { "; $($r.note)" })"
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
    if ($remote -and (Test-RemoteHost $remote)) { return @{ Name = $remote; Kind = 'ssh'; Host = $remote; Variables = @(Get-HostVariables $remote); Processors = Get-HostProcessors $remote } }
    Get-GitHubTarget $repo
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

# Of $classes, live classes a test host left without a full result, those the live jobs of $commit's GitHub offload proved on
# Windows, as Get-RerunClasses judges against $localTrx and the $fastest class times. A failure on another platform does not count: a rerun here
# proves Windows only. @{ Proved; Trx; Drop; Note }, Drop naming the other classes of Trx; Proved is empty when GitHub
# is not usable or its live jobs did not finish within $finishMinutes.
function Receive-GitHubLive([string]$repo, [string]$commit, [string[]]$classes, [string]$localTrx, [string]$folder,
    [hashtable]$fastest = @{}, [int]$finishMinutes = $script:LiveFallbackMinutes, [int]$pollSeconds = $script:PollSeconds) {
    $result = [pscustomobject]@{ Proved = @(); Trx = $null; Drop = @(); Note = $null }
    $target = Get-GitHubTarget $repo
    if (-not $target) { $result.Note = 'no GitHub target'; return $result }
    $got = Receive-GitHubRun (Wait-GitHubRun $target.Repository $commit -pollSeconds $pollSeconds -group 'live' -finishMinutes $finishMinutes) $folder 'live'
    $result.Note = $got.Note
    if (-not ($got.Started -and $got.Trx)) { return $result }
    $windows = [pscustomobject]@{ Trx = $got.Trx; Failed = @($got.Failed | Where-Object Platform -eq 'windows') }
    $rerun = @(Get-RerunClasses $windows $classes $localTrx -fastest $fastest)
    # A runner lacks some targets this machine has, so a test that ran here last time but not there keeps its class.
    $ran = @{}; foreach ($t in Get-TestOutcomes $got.Trx) { if ($t.Outcome -ne 'NotExecuted') { $ran[$t.Key] = $true } }
    if (Test-Path $localTrx) { $rerun += @(Get-TestOutcomes $localTrx | Where-Object { $_.Class -in $classes -and $_.Outcome -ne 'NotExecuted' -and -not $ran[$_.Key] } | ForEach-Object Class) }
    $result.Proved = @($classes | Where-Object { $_ -notin $rerun } | Sort-Object -Unique)
    $result.Trx = $got.Trx
    $result.Drop = @(Get-ClassOutcomes $got.Trx | ForEach-Object Class | Where-Object { $_ -notin $result.Proved } | Sort-Object -Unique)
    $result
}

# Starts the remote half of $classes on $target; returns a handle for Receive-Offload. GitHub runs the offload job on
# push by itself, so its handle waits for that run; a test host runs the classes it is sent.
function Start-Offload($target, [string]$commit, [string[]]$classes, [bool]$releaseTier, [string]$module, [string[]]$mixed = @()) {
    switch ($target.Kind) {
        'ssh' {
            $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
            # A push run starts before its push lands: a commit origin lacks travels with the script as a bundle.
            # A bundle that fails leaves the wait for origin, and then the run here, as before.
            $bundle = try { New-CommitBundle (Split-Path $module -Parent) $commit $id } catch { '' }
            $script = Get-RemoteRunScript $commit (Get-ClassFilter $classes $releaseTier $mixed) $id -Bundle:([bool]$bundle)
            $job = Start-ThreadJob -ArgumentList $module, $target.Host, $script, $id, $bundle -ScriptBlock {
                param($module, $remoteHost, $script, $id, $bundle)
                Import-Module $module
                try { Invoke-RemoteRun $remoteHost $script $id $bundle }
                finally { if ($bundle) { Remove-Item $bundle -Force -ErrorAction SilentlyContinue } }
            }
            $job | Add-Member -NotePropertyName Transport -NotePropertyValue $(if ($bundle) { 'bundle' } else { 'origin' })
            $job
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
# Runs $program (or the .ps1 script $variable names) with $arguments and returns its output lines. With
# $timeoutSeconds, a call still running then is ended with its child processes, its output dropped, and
# $LASTEXITCODE set to -1.
function Invoke-Transport([string]$variable, [string]$program, [string[]]$arguments, [int]$timeoutSeconds = 0) {
    $command = [Environment]::GetEnvironmentVariable($variable)
    if ($timeoutSeconds -le 0) {
        if (-not $command) { return & $program @arguments }
        return & pwsh -NoProfile -File $command @arguments
    }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = if ($command) { (Get-Process -Id $PID).Path } else { (Get-Command $program -CommandType Application | Select-Object -First 1).Source }
    foreach ($argument in @(if ($command) { '-NoProfile', '-File', $command }) + $arguments) { $start.ArgumentList.Add($argument) }
    $start.UseShellExecute = $false; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $out = $process.StandardOutput.ReadToEndAsync()
        $null = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
            # Kill only starts the termination: wait for the exit, so no caller sees the call's process still alive.
            try { $process.Kill($true) } catch { }
            $null = $process.WaitForExit($script:KillWaitSeconds * 1000)
            $global:LASTEXITCODE = -1
            return
        }
        $process.WaitForExit()
        $global:LASTEXITCODE = $process.ExitCode
        @($out.Result -split '\r?\n' | Where-Object { $_ -ne '' })
    }
    finally { $process.Dispose() }
}

# Whether the host answers over ssh with key auth within $script:ShortCallSeconds; a host that does not is named and
# left unused.
function Test-RemoteHost([string]$remoteHost) {
    $null = Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, 'exit 0')) $script:ShortCallSeconds
    if ($LASTEXITCODE -eq -1) { Write-Host "Test host $remoteHost gave no answer within $script:ShortCallSeconds s; not used." }
    $LASTEXITCODE -eq 0
}

# The CORVUS_* user variables of the test host that name an existing path there; empty when ssh fails.
function Get-HostVariables([string]$remoteHost) {
    $script = "[Environment]::GetEnvironmentVariables('User').GetEnumerator() | Where-Object { `$_.Key -like 'CORVUS_*' -and `$(try { Test-Path -LiteralPath `$_.Value } catch { `$false }) } | ForEach-Object Key"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $names = @(Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, "powershell -NoProfile -NonInteractive -EncodedCommand $encoded")) $script:ShortCallSeconds)
    if ($LASTEXITCODE -ne 0) { return @() }
    @($names | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^CORVUS_\w+$' } | Sort-Object -Unique)
}

# The logical processor count of the test host $remoteHost; 0 when it cannot be read.
function Get-HostProcessors([string]$remoteHost) {
    $count = @(Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, 'powershell -NoProfile -NonInteractive -Command [Environment]::ProcessorCount')) $script:ShortCallSeconds)
    if ($LASTEXITCODE -ne 0) { return 0 }
    $n = 0; if ([int]::TryParse("$($count | Select-Object -Last 1)".Trim(), [ref]$n)) { $n } else { 0 }
}

# The script a test host runs: wait for $commit on origin (or take it from the bundle sent beside the script), check it
# out in the host's worktree, build once and run $filter $repeat times there at below-normal priority, one script at a
# time. Its output names a wait for another script ("corvus-remote: waiting for another run on the host", then
# "corvus-remote-waited <seconds>"), the start ("corvus-remote: started"), each run ("corvus-remote-run <n> <exit code>") and the
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
# One script at a time: push runs and lanes' loops share the worktree and the machine. A script that waits says so
# at once and names its wait once it runs, so a filter run queued behind a long run is not silent.
`$lock = [Threading.Mutex]::new(`$false, 'Global\corvus-test-host')
`$queued = [Diagnostics.Stopwatch]::StartNew()
try {
    if (-not `$lock.WaitOne(0)) {
        'corvus-remote: waiting for another run on the host'
        [void]`$lock.WaitOne()
        "corvus-remote-waited `$([math]::Round(`$queued.Elapsed.TotalSeconds))"
    }
}
catch [Threading.AbandonedMutexException] { }
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
    if (`$LASTEXITCODE -ne 0) {
        # Another program on the host can remove a tracked file after checkout; the line names such files, not only
        # the failed build.
        `$gone = @(git -C `$tree ls-files --deleted)
        if (`$gone) {
            `$names = (`$gone | Select-Object -First 3) -join ', '
            "corvus-remote: the build failed: `$(`$gone.Count) tracked file`$(if (`$gone.Count -ne 1) { 's' }) removed on the host after checkout (`$names`$(if (`$gone.Count -gt 3) { ', ...' })); see results/$id/console.log"
        }
        else { 'corvus-remote: the build failed (see results/$id/console.log)' }
        exit 0
    }
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
            $null = Invoke-Transport $script:SshVariable 'ssh' (@($script:SshOptions) + @($remoteHost, "pwsh -NoProfile -NonInteractive -Command Remove-Item $script:HostFolder/$(Split-Path $file -Leaf)")) $script:ShortCallSeconds
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
    @{ Commit = $commit; Bundle = (New-CommitBundle $repo $commit $id) }
}

# A bundle file of the commits $commit has that $repo's origin/main lacks, under ref refs/corvus/remote-$id as the
# host's run script fetches it; empty when origin/main contains $commit. Throws when bundling fails.
function New-CommitBundle([string]$repo, [string]$commit, [string]$id) {
    git -C $repo merge-base --is-ancestor $commit origin/main 2>$null
    if ($LASTEXITCODE -eq 0) { return '' }
    $bundle = Join-Path ([IO.Path]::GetTempPath()) "$id.bundle"
    git -C $repo update-ref "refs/corvus/remote-$id" $commit
    try { git -C $repo bundle create --quiet $bundle "refs/corvus/remote-$id" '^origin/main' 2>$null; $code = $LASTEXITCODE }
    finally { git -C $repo update-ref -d "refs/corvus/remote-$id" }
    if ($code -ne 0) { throw "Bundling $commit failed." }
    $bundle
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
            $null = Invoke-Transport $script:ScpVariable 'scp' (@($script:SshOptions) + @("${remoteHost}:$script:HostFolder/results/$id/run-$($run.Run).trx", (Join-Path $folder "run-$($run.Run).trx"))) (4 * $script:ShortCallSeconds)
        }
    }
    $missing = $repeat - $runs.Count
    Write-Host "$($runs.Count) of $repeat runs on $remoteHost`: $($runs.Count - $failed.Count) passed, $($failed.Count) failed$(if ($failed) { " (runs $(($failed.Run) -join ', '); TRX in $folder)" })$(if ($missing -gt 0) { "; $missing did not run (the connection ended)" })."
    if ($failed -or $missing -gt 0) { 1 } else { 0 }
}

# Brings a test host's results back into $folder: @{ Started; Trx; Failed; Note; Waited } as Receive-GitHubRun returns
# it, Waited being the seconds the script waited for another run there (0 when it did not). Started false means no
# test started there (ssh failed, or the commit never arrived), and Note says why.
function Receive-RemoteRun($state, [string]$folder) {
    $result = [pscustomobject]@{ Started = $false; Trx = $null; Failed = @(); Note = $null; Waited = 0 }
    $output = @($state.Output)
    $waited = $output | Where-Object { $_ -match '^corvus-remote-waited (\d+)$' } | Select-Object -Last 1
    if ($waited) { $result.Waited = [int]($waited -replace '^corvus-remote-waited ', '') }
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
    $null = Invoke-Transport $script:ScpVariable 'scp' (@($script:SshOptions) + @("$($state.Host):$script:HostFolder/results/$($state.Id)/run-1.trx", $trx)) (4 * $script:ShortCallSeconds)
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

# Waits for the commit's CI run on push and its offload jobs (those of $group only, when given): @{ Kind; Repository;
# Run; Jobs; Note }, with Run $null (and Note saying why) when the run never appeared or its jobs did not finish within
# $finishMinutes; Note names the offload jobs that did not succeed.
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

# Downloads a finished run's TRX artifacts (offload-<group>-<os>-<shard>, of $group only when given) into $folder:
# @{ Started; Trx; Failed; Note }.
# Trx joins the Windows shards ($null when none came back); the other platforms' expected skips stay out. Failed lists
# the classes with a failed test on any platform, as @{ Class; Platform }. Started false means no test ran there.
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

Export-ModuleMember -Function Invoke-Transport, Test-RemoteHost, Get-RemoteRunScript, Invoke-RemoteRun, Receive-RemoteRun, New-RemoteSnapshot, Invoke-RemoteFilter, Invoke-Gh, Wait-GitHubRun, Receive-GitHubRun, Get-GitHubTarget, Receive-GitHubLive, Get-RemoteClasses, Get-IdaHostClasses, Get-GhidraLocalClasses, Get-HeldClasses, Get-HostVariables, Get-RealDataVariables, Get-RemoteShard, Read-OffloadSeconds, Save-OffloadSeconds, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-TestOutcomes, Get-SkippedOnHost, Get-FastestClassSeconds, Get-SkippedOnBoth, Get-RerunClasses, Get-MixedClasses, Get-FailedThereNote, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-TierFamilies, Get-TierClasses, Get-TierFilter, Get-TierFamiliesOf, Get-TierReturned, Get-TierHostClasses, Get-TierPasses, Save-TierRecord, Get-TierStatus, Get-DeferredClasses, Get-UndeferredFamilies, Save-DeferredClasses, Get-DeferredStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
