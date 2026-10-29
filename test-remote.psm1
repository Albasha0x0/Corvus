# Offloaded test classes for whole-suite runs: which classes run elsewhere, the local filter, and joining the results.
# Without a usable target every class runs here.

# The classes a run sends: engine-free heavy classes (sweeps, matrices, round trips, reference comparisons, the full
# contract matrix, discovery at every thread count).
$script:RemotePatterns = '*SweepTests', '*MatrixTests', 'PipelineRoundTripTests', '*OracleTests', '*ComparisonTests', '*CompareTests',
    'ContractSweepFullTests', 'ParallelDiscoveryTests'
# Offload groups: sweep, ghidra and live are CI jobs; the host group goes to a test host only.
$script:Groups = 'sweep', 'ghidra', 'live', 'host'
$script:HostGroup = 'host'
# About half the IDA classes, by time, go to a test host whose user variables set this; GitHub has no IDA.
$script:IdaGroup = 'ida'
$script:IdaVariable = 'CORVUS_IDA_DIR'
# Test host only: the Program Files sweep (over 30 min on a runner) and classes that need an unloaded machine.
$script:HostClasses = 'NativeToolSweepTests', 'DevRelayRealServerTests', 'DeadlineTests', 'StreamedSummaryMemoryTests'
# Host tier: stable families that push runs cover only by Smoke=push tests; they run whole on the test host.
$script:TierFamilies = 'Accuracy', 'AotMetadata', 'Builds', 'Containers', 'DotnetEdits', 'Dumps', 'Mobile', 'NativeAot', 'NativeEdits',
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
# Real-data facts: their file's classes go to a test host that has every variable they name; never to GitHub.
$script:DataAttribute = 'RequiresRealDataFact'
# An IDA fact given real-data variables reads real data too.
$script:IdaDataFact = '\[IdaFact\(\s*[^)\s]'
# Real-data variables that name a program, not an input: -Data skips them; a class needing one goes only to a host
# that sets it.
$script:ToolVariables = 'CORVUS_TSHARK', 'CORVUS_WASM_TO_TEXT', 'CORVUS_WASM_VALIDATOR', 'CORVUS_JAVA_DECOMPILER', 'CORVUS_JAVA_DECOMPILER2',
    'CORVUS_DEX_DISASSEMBLER', 'CORVUS_HBC_DISASSEMBLER', 'CORVUS_PY_DECOMPILER', 'CORVUS_PIPELINE_TOOL'
# The file that names the real-data variables (RealData.Name constants).
$script:RealDataSource = 'Support/TestEnv.cs'
# Classes whose inputs are this machine's own: client-edition System32, local dumps and data folders, and RISC-V
# (not in the test host's IDA license).
$script:LocalClasses = 'NativeLinkSweepTests', 'MinidumpSweepTests', 'FirmwareComparisonTests', 'InstallerComparisonTests',
    'DependencyListerComparisonTests', 'IsaEngineTests'
# A class under this share of its last local time (when at least the given seconds) proved less there and reruns here.
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
$script:ReleaseWorkflow = 'release.yml'
# Seconds each gh call of -Status may take; past it the workflow's result is
# unknown.
$script:StatusCallSeconds = 10
# Seconds for the commit's CI run to appear (push runs start before the push lands), minutes for offload jobs.
$script:RunAppearSeconds = 120
$script:RunFinishMinutes = 120
# Minutes a push run waits for GitHub live jobs instead of rerunning live classes; they end 10 to 22 min after a push.
$script:LiveFallbackMinutes = 10
$script:PollSeconds = 15
# A test host prepared by test-remote-setup.ps1 ([user@]name); it takes the offloaded classes ahead of GitHub when it
# answers over ssh.
$script:HostVariable = 'CORVUS_TEST_REMOTE'
# The ssh and scp programs, a .ps1 script standing in for either in the tests; OpenSSH's own when unset.
$script:SshVariable = 'CORVUS_TEST_SSH'
$script:ScpVariable = 'CORVUS_TEST_SCP'
# OpenSSH options: key auth only, accept a new host key, fail fast on connect, detect a dead link within 2 min.
$script:SshOptions = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=4')
# The host's folder under its user's home: the clone (repo), the run's worktree (run) and its results.
$script:HostFolder = 'corvus-test-host'
# Seconds a short ssh or scp call may take, bounding a session that hangs after login; a TRX copy gets 4x.
$script:ShortCallSeconds = 30
# Seconds a timed-out call's process tree may take to exit once it is ended.
$script:KillWaitSeconds = 10
# Seconds the host waits for the commit to reach origin; a push run starts before its push lands.
$script:FetchWaitSeconds = 120

# Variables the real-data facts in $text name, sorted and unique; '?' for one that cannot be resolved; empty when the
# file has no real-data fact.
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

# Offloaded *Tests classes of $testsDir as @{ Class; Group; Mixed; Variables }, grouped host, live, ghidra, ida or
# sweep. Real data with IDA facts, live real data and local classes stay here; with -CrossPlatform, Windows-only too.
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

# *Tests classes of the host tier's family folders, without $returned families. Sorted; missing folders add none.
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

# Host tier families returned to push runs by a failure on the host, until a tier run passes them. Sorted; empty when
# the tier has not run.
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

# Host tier $classes as @{ Sent; Kept } for a host with $hostVariables; Kept entries read "Class (reason)". Sorted.
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

# What a host tier run proved as @{ Passed; Failed; Unproven }: families whose classes all passed with a full result,
# families with a failure, and sent classes without a full result. Sorted; nothing passes without results.
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

# The host tier's last run as one status line; $null when it has not run.
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

# Classes a run sends for one group, or (empty) all but host and ida; -TestHost adds host classes whose variables are
# all in $hostVariables. Sorted; throws for an unknown group.
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

# IDA classes a host with IDA takes, dealt by Get-HostShare with $hostPart; they run whole there. Sorted; empty
# without IDA on the host.
function Get-IdaHostClasses([string]$testsDir, [hashtable]$seconds = @{}, [string[]]$hostVariables = @(), [double]$hostPart = 0.5) {
    if ($script:IdaVariable -notin $hostVariables) { return @() }
    Get-HostShare @(Get-RemoteEntries $testsDir | Where-Object { $_.Group -eq $script:IdaGroup -or $_.Mixed } | ForEach-Object Class | Sort-Object -Unique) $seconds $hostPart
}

# Ghidra-only classes that stay here when a test host takes the rest, as Get-HostShare deals them. Sorted.
function Get-GhidraLocalClasses([string]$testsDir, [hashtable]$seconds = @{}, [double]$hostPart = 0.5) {
    $classes = @(Get-RemoteEntries $testsDir | Where-Object { $_.Group -eq 'ghidra' -and -not $_.Mixed } | ForEach-Object Class | Sort-Object -Unique)
    $there = @(Get-HostShare $classes $seconds $hostPart)
    @($classes | Where-Object { $_ -notin $there })
}

# Real-data classes that stay here when a test host takes the rest, dealt this machine first; timed host classes
# always go there. Sorted.
function Get-RealDataLocalClasses([string]$testsDir, [hashtable]$seconds = @{}, [string[]]$hostVariables = @(), [double]$hostPart = 0.5) {
    $classes = @(Get-RemoteEntries $testsDir | Where-Object { $_.Group -eq $script:HostGroup -and $_.Variables.Count -gt 0 -and -not @($_.Variables | Where-Object { $_ -notin $hostVariables }) } |
        ForEach-Object Class | Sort-Object -Unique)
    # This machine takes the longest first: it has more reference-tool permits, which the pipeline round trip waits on.
    @(Get-HostShare $classes $seconds (1 - $hostPart))
}

# The host's share of $classes: longest first by $seconds (unrecorded: 1 s), each to the machine with less time for
# its part; $hostPart (0 to 1) is the host's part. Sorted.
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
# the lower of the last run and $fastest, since a loaded machine would make an idle host look short.
function Get-SkippedOnHost([string]$remoteTrx, [string]$localTrx, [hashtable]$fastest = @{}) {
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

# Host group $classes a push run leaves to the nightly run, except $failed, which rerun here. Sorted.
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

# The offload target as @{ Name; Kind; ... }, or $null: the CORVUS_TEST_REMOTE host when it answers, else GitHub for a
# routine run on origin's main. Release strength offloads to the host only. CORVUS_TEST_OFFLOAD=0 turns it off.
function Get-OffloadTarget([string]$repo, [bool]$releaseTier) {
    if ([Environment]::GetEnvironmentVariable($script:OffloadVariable) -in '0', 'false', 'off') { return $null }
    if ([Environment]::GetEnvironmentVariable($script:PushRunVariable) -ne '1') {
        git -C $repo merge-base --is-ancestor HEAD origin/main 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
    }
    $remote = "$([Environment]::GetEnvironmentVariable($script:HostVariable))".Trim()
    if ($remote -and (Test-RemoteHost $remote)) { return @{ Name = $remote; Kind = 'ssh'; Host = $remote; Variables = @(Get-HostVariables $remote); Processors = Get-HostProcessors $remote } }
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

# Live $classes that $commit's GitHub live jobs proved on Windows, as @{ Proved; Trx; Drop; Note }. Proved is empty
# when GitHub is unusable or its jobs did not finish within $finishMinutes.
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
            $script = Get-RemoteRunScript $commit (Get-ClassFilter $classes $releaseTier $mixed) $id -Bundle:([bool]$bundle) -Exhaustive:$releaseTier
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

# Runs $program (or the .ps1 $variable names) and returns its output lines. Past $timeoutSeconds the call and its
# children are ended, output dropped, $LASTEXITCODE -1.
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

# The test host script: get $commit (origin or bundle), build once, run $filter $repeat times at below-normal
# priority, one script at a time. Output lines: "corvus-remote-waited <s>", "corvus-remote: started",
# "corvus-remote-run <n> <exit>", "corvus-remote-exit <worst exit>". Results: results/<id>/run-<n>.trx.
# -Exhaustive runs every sweep input.
function Get-RemoteRunScript([string]$commit, [string]$filter, [string]$id, [int]$repeat = 1, [switch]$Bundle, [switch]$Exhaustive) {
    $quoted = $filter.Replace("'", "''")
    @"
`$ErrorActionPreference = 'Continue'
(Get-Process -Id `$PID).PriorityClass = 'BelowNormal'
`$base = Join-Path `$HOME '$script:HostFolder'
`$clone = Join-Path `$base 'repo'; `$tree = Join-Path `$base 'run'; `$out = Join-Path `$base 'results/$id'
`$bundle = Join-Path `$base '$id.bundle'
# One script at a time, as runs share the worktree; a waiting script says so at once.
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
        # Another program can remove a tracked file after checkout; name such files, not only the failed build.
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
    `$env:CORVUS_SWEEP = $(if ($Exhaustive) { "'exhaustive'" } else { '$null' })
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

# A commit of $repo's working tree without touching index or branches (HEAD when clean), as @{ Commit; Bundle };
# Bundle holds what origin/main lacks, empty when origin has it.
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

# Runs $filter $repeat times on the test host from the working tree; failed runs' TRX go to $folder. Returns 0 all
# passed, 1 any failed, 2 none started.
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

# Brings a test host's results into $folder as @{ Started; Trx; Failed; Note; Waited }; Started false means no test
# started there and Note says why.
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

Export-ModuleMember -Function Get-WorkflowStatus, Get-WorkflowRunStatus, Invoke-Transport, Test-RemoteHost, Get-RemoteRunScript, Invoke-RemoteRun, Receive-RemoteRun, New-RemoteSnapshot, Invoke-RemoteFilter, Invoke-Gh, Wait-GitHubRun, Receive-GitHubRun, Get-GitHubTarget, Receive-GitHubLive, Get-RemoteClasses, Get-IdaHostClasses, Get-GhidraLocalClasses, Get-RealDataLocalClasses, Get-HeldClasses, Get-HostVariables, Get-RealDataVariables, Get-RemoteShard, Read-OffloadSeconds, Save-OffloadSeconds, Get-LocalFilter, Get-ClassFilter, Get-ClassOutcomes, Get-TestOutcomes, Get-SkippedOnHost, Get-FastestClassSeconds, Get-SkippedOnBoth, Get-RerunClasses, Get-MixedClasses, Get-FailedThereNote, Join-TrxFiles, Get-TargetFileName, Save-RemoteRecord, Get-RemoteStatus, Get-TierFamilies, Get-TierClasses, Get-TierFilter, Get-TierFamiliesOf, Get-TierReturned, Get-TierHostClasses, Get-TierPasses, Save-TierRecord, Get-TierStatus, Get-DeferredClasses, Get-UndeferredFamilies, Save-DeferredClasses, Get-DeferredStatus, Get-OffloadTarget, Start-Offload, Receive-Offload
