# Test run timing: TRX test times, a history of the last runs per mode, and the time report.

$script:Invariant = [cultureinfo]::InvariantCulture
# Run time targets in seconds: the commit gate with its build, the background run after a push, a whole-suite run.
$script:Targets = [ordered]@{ quick = 120; push = 900; full = 1800 }
# Report sections in this order; a mode's section is replaced by its next run and kept meanwhile.
$script:Modes = 'full', 'push', 'quick', 'perf', 'filter'
# A test that passed in less than this many seconds is kept only in its class's line, which bounds the history's size.
$script:KeepSeconds = 1.0
$script:TestLine = [regex]::new('^\{"kind":"test","run":"[^"]*","mode":"([^"]*)","name":("(?:[^"\\]|\\.)*"),"class":"[^"]*","start":([0-9.]+),"end":([0-9.]+)', 'Compiled')
$script:ClassLine = [regex]::new('^\{"kind":"class","run":"[^"]*","mode":"([^"]*)","name":("(?:[^"\\]|\\.)*"),"start":[0-9.]+,"end":[0-9.]+,"seconds":([0-9.]+)', 'Compiled')
$script:RunId = [regex]::new('^\{"kind":"[a-z]+","run":"([^"]*)"', 'Compiled')

function Format-Seconds([double]$seconds) {
    if ($seconds -ge 90) { [string]::Format($script:Invariant, '{0:0.0} min', $seconds / 60) } else { [string]::Format($script:Invariant, '{0:0.0} s', $seconds) }
}

function Format-Number([double]$value) { $value.ToString('0.###', $script:Invariant) }

function ConvertTo-JsonString([string]$text) {
    '"' + [System.Text.Json.JsonEncodedText]::Encode($text, [System.Text.Encodings.Web.JavaScriptEncoder]::UnsafeRelaxedJsonEscaping).ToString() + '"'
}

# The seconds of a test or class in a history's runs, oldest first; $null when the history has none.
function Get-Past($table, [string]$name) {
    if ($name.Length -gt 300) { $name = $name.Substring(0, 300) }
    $list = $null
    if ($table.TryGetValue((ConvertTo-JsonString $name), [ref]$list)) { return , $list }
    return $null
}

# Median and 90th percentile cells of a table row: "| median | p90 | runs |", dashes without a history.
function Format-Spread($past) {
    $spread = Get-Spread $past
    if (-not $spread) { return '| - | - | 0 |' }
    "| $(Format-Seconds $spread[0]) | $(Format-Seconds $spread[1]) | $($past.Count) |"
}

# The median and 90th percentile (nearest rank) of a list of numbers, as a two-element array; $null for an empty list.
function Get-Spread($values) {
    $sorted = @($values | Sort-Object)
    if (-not $sorted) { return $null }
    $median = if ($sorted.Count % 2) { $sorted[($sorted.Count - 1) / 2] } else { ($sorted[$sorted.Count / 2 - 1] + $sorted[$sorted.Count / 2]) / 2 }
    @($median, $sorted[[math]::Ceiling(0.9 * $sorted.Count) - 1])
}

# A TRX file's tests timed from the first start: At, Wall, Summed and Tests (Name, Class as Outer+Inner, Start, End,
# Seconds, Outcome); $null when the file is missing or no result has times.
function Read-TestTimes([string]$trxPath) {
    if (-not (Test-Path $trxPath)) { return $null }
    [xml]$trx = Get-Content $trxPath -Raw
    $ns = @{ t = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010' }
    $classOf = @{}
    foreach ($test in Select-Xml -Xml $trx -XPath '//t:UnitTest' -Namespace $ns) {
        $classOf[$test.Node.id] = ($test.Node.TestMethod.className -split '\.')[-1]
    }
    $raw = foreach ($result in Select-Xml -Xml $trx -XPath '//t:UnitTestResult' -Namespace $ns) {
        $node = $result.Node
        if (-not ($node.startTime -and $node.endTime)) { continue }
        [pscustomobject]@{ Name = $node.testName; Class = $classOf[$node.testId]; From = [datetimeoffset]::Parse($node.startTime, $script:Invariant); To = [datetimeoffset]::Parse($node.endTime, $script:Invariant); Outcome = $node.outcome }
    }
    if (-not $raw) { return $null }
    $at = ($raw | Measure-Object -Property From -Minimum).Minimum
    $tests = [System.Collections.Generic.List[object]]::new()
    $summed = 0.0; $wall = 0.0
    foreach ($r in $raw) {
        $start = ($r.From - $at).TotalSeconds; $end = ($r.To - $at).TotalSeconds
        $tests.Add([pscustomobject]@{ Name = $r.Name; Class = $r.Class; Start = $start; End = $end; Seconds = $end - $start; Outcome = $r.Outcome })
        $summed += $end - $start
        if ($end -gt $wall) { $wall = $end }
    }
    [pscustomobject]@{ At = $at; Wall = $wall; Summed = $summed; Tests = $tests }
}

# The machine's CPU load in percent, sampled over about a second; $null where it cannot be read.
function Get-MachineLoad {
    try {
        if ($IsWindows) { return [int](Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average }
        if (Test-Path /proc/loadavg) { return [int](100 * [double]::Parse((Get-Content /proc/loadavg -Raw).Split(' ')[0], [cultureinfo]::InvariantCulture) / [Environment]::ProcessorCount) }
    }
    catch { }
    return $null
}

# Samples machine load on its own thread so it costs the run no time; Receive-Job returns it.
function Start-MachineLoad { Start-ThreadJob -ScriptBlock ${function:Get-MachineLoad} }

# Processes with ProcessId, ParentProcessId, KernelModeTime and UserModeTime (100 ns); $null off Windows.
function Read-ProcessTimes {
    if (-not $IsWindows) { return $null }
    try { @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, KernelModeTime, UserModeTime -ErrorAction Stop) } catch { $null }
}

# CPU percent used outside $rootPid's tree since the previous call with $state; $null on the first call or without
# $processes. A process stays in the tree once seen; one that ended between calls is not counted.
function Get-OtherLoad([int]$rootPid, [hashtable]$state, [object[]]$processes, [double]$seconds, [int]$cores = [Environment]::ProcessorCount) {
    if ($null -eq $processes) { return $null }
    if (-not $state.Ours) { $state.Ours = [Collections.Generic.HashSet[int]]::new([int[]]@($rootPid)) }
    do {
        $added = $false
        foreach ($p in $processes) { if ($state.Ours.Contains([int]$p.ParentProcessId) -and $state.Ours.Add([int]$p.ProcessId)) { $added = $true } }
    } while ($added)
    $first = $null -eq $state.Times
    $before = if ($first) { @{} } else { $state.Times }
    $times = @{}
    $used = 0.0
    # Process 0 is the idle process: its time is the machine's idle time.
    foreach ($p in $processes | Where-Object { $_.ProcessId -ne 0 }) {
        $times[[int]$p.ProcessId] = $cpu = [double]$p.KernelModeTime + [double]$p.UserModeTime
        if (-not $state.Ours.Contains([int]$p.ProcessId)) { $used += [math]::Max(0.0, $cpu - [double]$before[[int]$p.ProcessId]) }
    }
    $elapsed = $seconds - $state.Seconds
    $state.Times = $times; $state.Seconds = $seconds
    if ($first -or $elapsed -le 0) { return $null }
    [int][math]::Min(100, 100 * $used / ($elapsed * 1e7 * $cores))
}

# Writes "<time><tab>others=<percent>" (Get-OtherLoad) to $log every $seconds; unreadable samples write nothing.
function Invoke-LoadSampler([string]$log, [int]$rootPid, [int]$seconds = 10) {
    $state = @{}
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $load = Get-OtherLoad $rootPid $state (Read-ProcessTimes) $clock.Elapsed.TotalSeconds
        if ($null -ne $load) { Add-Content -Path $log -Value "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture))`tothers=$load" }
        Start-Sleep -Seconds $seconds
    }
}

# Starts Invoke-LoadSampler on its own thread; it ends with the process or Stop-Job.
function Start-LoadSampler([string]$log) {
    Set-Content -Path $log -Value $null
    $functions = 'Read-ProcessTimes', 'Get-OtherLoad', 'Invoke-LoadSampler' | ForEach-Object { "function $_ {$((Get-Item "function:$_").Definition)}" }
    Start-ThreadJob -InitializationScript ([scriptblock]::Create($functions -join "`n")) -ScriptBlock { Invoke-LoadSampler @args } -ArgumentList $log, $PID
}

# Other load a perf run met: Text says how often others used over $busy percent; Partial when over $share of samples.
# $null when the log has no sample (load unknown).
function Get-PerfContention([string]$log, [int]$busy = 25, [double]$share = 0.1) {
    $samples = @(Get-Content $log -ErrorAction SilentlyContinue | Where-Object { $_ -match "`tothers=(\d+)$" } | ForEach-Object { [int]($_ -replace '.*=', '') })
    if (-not $samples) { return $null }
    $over = @($samples | Where-Object { $_ -gt $busy })
    [pscustomobject]@{
        Partial = $over.Count -gt $share * $samples.Count
        Text = "other processes used over $busy% of the machine in $($over.Count) of $($samples.Count) samples (up to $(($samples | Measure-Object -Maximum).Maximum)%)"
    }
}

# Writes a line to $log every $seconds: wake lag in ms (shows CPU starvation), file create-write-delete ms per folder,
# disk queue length and idle percent, free memory MB and pages per second; -1 where a value cannot be read.
function Invoke-IoSampler([string]$log, [string[]]$folders, [int]$seconds = 10) {
    $volume = if ($IsWindows) { Split-Path -Qualifier $folders[-1] } else { $null }
    $counters = if ($volume) { "\LogicalDisk($volume)\Avg. Disk Queue Length", "\LogicalDisk($volume)\% Idle Time", '\Memory\Available MBytes', '\Memory\Pages/sec' } else { @() }
    $invariant = [cultureinfo]::InvariantCulture
    # The helper times files at normal priority, so a starved run does not read as a slow file system.
    $time = '$file = Join-Path $folder "corvus-io-probe-$PID.tmp"; $watch = [Diagnostics.Stopwatch]::StartNew(); ' +
        'try { [IO.File]::WriteAllBytes($file, [byte[]]::new(64)); [IO.File]::Delete($file); [int]$watch.ElapsedMilliseconds } catch { -1 }'
    $probe = 'while ($null -ne ($folder = [Console]::In.ReadLine())) { [Console]::Out.WriteLine($(' + $time + ')); [Console]::Out.Flush() }'
    $start = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($arg in '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))) { $start.ArgumentList.Add($arg) }
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    # Without a helper the thread times the file itself, at the run's priority.
    $helper = try { [Diagnostics.Process]::Start($start) } catch { $null }
    if ($helper) { try { $helper.PriorityClass = 'Normal' } catch { } }
    $local = [scriptblock]::Create($time)
    $due = [Diagnostics.Stopwatch]::StartNew()
    $next = 0
    try {
        while ($true) {
            $lag = [math]::Max(0, [int]($due.ElapsedMilliseconds - $next))
            $fields = @((Get-Date).ToString('yyyy-MM-dd HH:mm:ss', $invariant), "lag=$lag")
            foreach ($folder in $folders) {
                $ms = if (-not $helper) { & $local } else { try { $helper.StandardInput.WriteLine($folder); [int]$helper.StandardOutput.ReadLine() } catch { -1 } }
                $fields += "open=$ms"
            }
            $values = @(-1, -1, -1, -1)
            if ($counters) {
                try { $values = @((Get-Counter -Counter $counters -MaxSamples 1 -ErrorAction Stop).CounterSamples | ForEach-Object CookedValue) } catch { }
            }
            $fields += ('queue=' + ([double]$values[0]).ToString('0.##', $invariant)), "idle=$([int]$values[1])", "freeMB=$([int]$values[2])", "pages=$([int]$values[3])"
            Add-Content -Path $log -Value ($fields -join "`t")
            $next = [math]::Max($next + $seconds * 1000, $due.ElapsedMilliseconds)
            $left = $next - $due.ElapsedMilliseconds
            if ($left -gt 0) { Start-Sleep -Milliseconds $left }
        }
    }
    finally {
        if ($helper) {
            $helper.StandardInput.Close()
            if (-not $helper.WaitForExit(2000)) { $helper.Kill() }
        }
    }
}

# Starts Invoke-IoSampler on its own thread; it ends with the process or Stop-Job.
function Start-IoSampler([string]$log, [string[]]$folders) {
    Set-Content -Path $log -Value $null
    Start-ThreadJob -ScriptBlock ${function:Invoke-IoSampler} -ArgumentList $log, $folders
}

# Windows of samples where a file or the wake lag took over $limitMs, one line each with the worst values ("unknown"
# where unreadable); empty when none or no log.
function Get-IoStalls([string]$log, [int]$limitMs = 1000) {
    if (-not (Test-Path $log)) { return @() }
    # The worse of a window's value and a sample's; a sample's -1 is unreadable and leaves the window's value.
    function Worse($known, [double]$sample, [bool]$higher) {
        if ($sample -lt 0) { return $known }
        if ($null -eq $known) { return $sample }
        if ($higher) { [math]::Max($known, $sample) } else { [math]::Min($known, $sample) }
    }
    function Shown($value, [string]$text) { if ($null -eq $value) { 'unknown' } else { $text } }
    $window = $null
    foreach ($line in @(Get-Content $log) + @('')) {
        $parts = $line -split "`t"
        $values = @{ opens = @() }
        foreach ($part in $parts | Select-Object -Skip 1) {
            $name, $value = $part -split '=', 2
            if ($name -eq 'open') { $values.opens += [int]$value } else { $values[$name] = [double]::Parse($value, $script:Invariant) }
        }
        $worst = ($values.opens | Measure-Object -Maximum).Maximum
        $late = if ($values.ContainsKey('lag')) { $values.lag } else { -1 }
        if ($worst -gt $limitMs -or $late -gt $limitMs) {
            if (-not $window) { $window = @{ From = $parts[0]; Samples = 0; Open = 0; Lag = $null; Queue = $null; Idle = $null; Free = $null; Pages = $null } }
            $window.To = $parts[0]; $window.Samples++
            $window.Open = [math]::Max($window.Open, $worst)
            $window.Lag = Worse $window.Lag $late $true
            $window.Queue = Worse $window.Queue $values.queue $true
            $window.Idle = Worse $window.Idle $values.idle $false
            $window.Free = Worse $window.Free $values.freeMB $false
            $window.Pages = Worse $window.Pages $values.pages $true
            continue
        }
        if ($window) {
            $w = $window
            "$($w.From) to $($w.To) ($($w.Samples) samples): a file took up to $(Format-Seconds ($w.Open / 1000)); " +
                "run lag $(Shown $w.Lag "up to $(Format-Seconds ($w.Lag / 1000))"); " +
                "disk queue $(Shown $w.Queue "up to $(Format-Number $w.Queue)"), idle $(Shown $w.Idle "down to $($w.Idle)%"); " +
                "free memory $(Shown $w.Free "down to $($w.Free) MB"), pages/s $(Shown $w.Pages "up to $($w.Pages)")"
            $window = $null
        }
    }
}

# Runs a block while holding the history's named mutex: lanes' runs share the repository's .git.
function Invoke-HistoryLocked([scriptblock]$action) {
    $mutex = [System.Threading.Mutex]::new($false, 'Global\corvus-test-history')
    $held = $false
    try {
        try { $held = $mutex.WaitOne([TimeSpan]::FromMinutes(1)) } catch [System.Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'the test history is locked by another run for over a minute' }
        & $action
    }
    finally {
        if ($held) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# Appends a run to the history and returns its id: a run line, class lines, and lines for tests of $KeepSeconds or
# more or not passed. Keeps the last $keep runs per mode.
function Add-TestHistory([string]$path, $times, [System.Collections.IDictionary]$context, [int]$keep = 30) {
    $id = (Get-Date -Format 'yyyyMMdd-HHmmss-') + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $mode = $context.mode
    $head = { param($kind) "{`"kind`":`"$kind`",`"run`":`"$id`",`"mode`":`"$mode`"" }
    $run = [ordered]@{ kind = 'run'; run = $id }
    foreach ($name in $context.Keys) { $run[$name] = $context[$name] }
    $run.tests = $times.Tests.Count
    $run.failed = @($times.Tests | Where-Object Outcome -notin 'Passed', 'NotExecuted').Count
    $run.testWall = [math]::Round($times.Wall, 1)
    $run.summed = [math]::Round($times.Summed, 1)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add(($run | ConvertTo-Json -Compress -Depth 3))
    foreach ($group in $times.Tests | Group-Object Class) {
        $start = ($group.Group | Measure-Object Start -Minimum).Minimum; $end = ($group.Group | Measure-Object End -Maximum).Maximum
        $seconds = ($group.Group | Measure-Object Seconds -Sum).Sum
        $lines.Add((& $head 'class') + ",`"name`":$(ConvertTo-JsonString $group.Name),`"start`":$(Format-Number $start),`"end`":$(Format-Number $end),`"seconds`":$(Format-Number $seconds),`"tests`":$($group.Count)}")
    }
    foreach ($test in $times.Tests | Where-Object { $_.Seconds -ge $script:KeepSeconds -or $_.Outcome -notin 'Passed', 'NotExecuted' }) {
        $name = if ($test.Name.Length -gt 300) { $test.Name.Substring(0, 300) } else { $test.Name }
        $lines.Add((& $head 'test') + ",`"name`":$(ConvertTo-JsonString $name),`"class`":$(ConvertTo-JsonString $test.Class),`"start`":$(Format-Number $test.Start),`"end`":$(Format-Number $test.End),`"outcome`":`"$($test.Outcome)`",`"wait`":0}")
    }
    Invoke-HistoryLocked {
        $old = if (Test-Path $path) { [IO.File]::ReadAllLines($path) } else { @() }
        $runs = @($old | Where-Object { $_.StartsWith('{"kind":"run"') } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object mode -eq $mode)
        if ($runs.Count -ge $keep) {
            $drop = [System.Collections.Generic.HashSet[string]]::new([string[]]@($runs | Select-Object -First ($runs.Count - $keep + 1) | ForEach-Object run))
            $kept = @($old | Where-Object { -not $drop.Contains($script:RunId.Match($_).Groups[1].Value) })
            [IO.File]::WriteAllLines("$path.tmp", [string[]]($kept + $lines))
            Move-Item -Force "$path.tmp" $path
        }
        else { [IO.File]::AppendAllLines($path, [string[]]$lines) }
    }
    return $id
}

# One mode's history: Runs (all modes, oldest first), Tests and Classes (seconds per JSON-encoded name). Empty without
# a history file.
function Read-TestHistory([string]$path, [string]$mode) {
    $runs = [System.Collections.Generic.List[object]]::new()
    $tests = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[double]]]::new()
    $classes = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[double]]]::new()
    if (Test-Path $path) {
        $tag = "`"mode`":`"$mode`""
        foreach ($line in Invoke-HistoryLocked { [IO.File]::ReadAllLines($path) }) {
            if ($line.StartsWith('{"kind":"run"')) { $runs.Add(($line | ConvertFrom-Json)); continue }
            if (-not $line.Contains($tag)) { continue }
            $m = $script:TestLine.Match($line)
            if ($m.Success -and $m.Groups[1].Value -eq $mode) {
                $seconds = [double]::Parse($m.Groups[4].Value, $script:Invariant) - [double]::Parse($m.Groups[3].Value, $script:Invariant)
                $list = $null; if (-not $tests.TryGetValue($m.Groups[2].Value, [ref]$list)) { $list = [System.Collections.Generic.List[double]]::new(); $tests[$m.Groups[2].Value] = $list }
                $list.Add($seconds)
                continue
            }
            $m = $script:ClassLine.Match($line)
            if ($m.Success -and $m.Groups[1].Value -eq $mode) {
                $list = $null; if (-not $classes.TryGetValue($m.Groups[2].Value, [ref]$list)) { $list = [System.Collections.Generic.List[double]]::new(); $classes[$m.Groups[2].Value] = $list }
                $list.Add([double]::Parse($m.Groups[3].Value, $script:Invariant))
            }
        }
    }
    [pscustomobject]@{ Runs = $runs; Tests = $tests; Classes = $classes }
}

# Critical path: the last test to end, then the last to end before it started, back to the start.
function Get-CriticalPath($times) {
    $byEnd = @($times.Tests | Sort-Object End)
    $ends = [double[]]@($byEnd | ForEach-Object End)
    $chain = [System.Collections.Generic.List[object]]::new()
    $i = $byEnd.Count - 1
    while ($i -ge 0) {
        $test = $byEnd[$i]
        $chain.Add($test)
        # The last test that ended by this one's start (1 ms of clock slack), always an earlier one.
        $j = [Array]::BinarySearch($ends, $test.Start + 0.001)
        $i = [math]::Min($i - 1, $(if ($j -ge 0) { $j } else { (-bnot $j) - 1 }))
    }
    $chain
}

# The average number of tests running in each bucket of a run, as objects with From (seconds) and Running.
function Get-Concurrency($times, [double]$bucket) {
    $count = [math]::Max(1, [math]::Ceiling($times.Wall / $bucket))
    $busy = [double[]]::new($count)
    foreach ($test in $times.Tests) {
        $first = [math]::Min($count - 1, [math]::Floor($test.Start / $bucket)); $last = [math]::Min($count - 1, [math]::Floor($test.End / $bucket))
        for ($b = $first; $b -le $last; $b++) {
            $busy[$b] += [math]::Min($test.End, ($b + 1) * $bucket) - [math]::Max($test.Start, $b * $bucket)
        }
    }
    for ($b = 0; $b -lt $count; $b++) {
        $length = [math]::Min($bucket, $times.Wall - $b * $bucket)
        [pscustomobject]@{ From = $b * $bucket; Running = if ($length -gt 0) { $busy[$b] / $length } else { 0 } }
    }
}

# A run's time outside its tests: build and setup separately when built first, otherwise one figure.
function Format-Setup($times, $run) {
    $outside = [math]::Max(0, $run.wall - $times.Wall)
    if ($null -eq $run.build) { return "build and setup $(Format-Seconds $outside)" }
    "build $(Format-Seconds $run.build), test start and setup $(Format-Seconds ([math]::Max(0, $outside - $run.build)))"
}

# The report section of one run, as markdown lines.
function Get-RunSection($times, $run, $history) {
    $mode = $run.mode
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("## Latest $mode run")
    $lines.Add('')
    $lines.Add("$($run.commit) at $($run.at), exit code $($run.code): $($run.tests) tests, $($run.failed) failed.")
    $lines.Add('')
    $parallel = if ($times.Wall -gt 0) { $times.Summed / $times.Wall } else { 0 }
    $lines.Add("- Wall time $(Format-Seconds $run.wall) (tests $(Format-Seconds $times.Wall), $(Format-Setup $times $run)); summed test time $(Format-Seconds $times.Summed), $([string]::Format($script:Invariant, '{0:0.0}', $parallel)) tests at a time on average.")
    $before = @($history.Runs | Where-Object { $_.mode -eq $mode -and $_.run -ne $run.run } | Select-Object -Last 5)
    if ($before) {
        $median = (Get-Spread @($before | ForEach-Object wall))[0]
        $change = if ($median -gt 0) { [string]::Format($script:Invariant, '{0:+0;-0}%', 100 * ($run.wall - $median) / $median) } else { 'n/a' }
        $lines.Add("- Median wall time of the previous $($before.Count) $mode runs: $(Format-Seconds $median) ($change).")
    }
    $load = { param($v) if ($null -eq $v) { 'unknown' } else { "$v%" } }
    $lines.Add("- CPU load at start $(& $load $run.loadStart), at end $(& $load $run.loadEnd); heavy lock $(if ($null -eq $run.heavyWait) { 'not taken' } else { "waited for $(Format-Seconds $run.heavyWait)" }).")
    $lines.Add("- Permit waits: $(if ($run.permits) { ($run.permits.PSObject.Properties | ForEach-Object { "$($_.Name) $(Format-Seconds $_.Value)" }) -join ', ' } else { 'not recorded (the run took no permits)' }).")
    if ($null -ne $run.reused) { $lines.Add("- Selection: $($run.reused) of $($run.families) families reused from earlier passes.") }
    if ($run.offload) { $lines.Add("- Offload: $($run.offload).") }
    $lines.Add('')

    $bucket = if ($times.Wall -ge 900) { 300 } else { 60 }
    $lines.Add("### Tests running, average per $($bucket / 60)-minute bucket")
    $lines.Add('')
    $lines.Add('| Minute | Running | |')
    $lines.Add('|---:|---:|---|')
    foreach ($b in Get-Concurrency $times $bucket) {
        $lines.Add([string]::Format($script:Invariant, '| {0:0} | {1:0.0} | {2} |', $b.From / 60, $b.Running, '#' * [math]::Min(40, [math]::Round($b.Running * 2))))
    }
    $lines.Add('')

    $chain = @(Get-CriticalPath $times)
    $chainSeconds = ($chain | Measure-Object Seconds -Sum).Sum
    $lines.Add('### Critical path')
    $lines.Add('')
    $lines.Add("$($chain.Count) tests in sequence set the end time: $(Format-Seconds $chainSeconds) of the $(Format-Seconds $times.Wall) test wall time. By class:")
    $lines.Add('')
    $lines.Add('| Class | Tests | Time |')
    $lines.Add('|---|---:|---:|')
    foreach ($group in $chain | Group-Object Class | Sort-Object { ($_.Group | Measure-Object Seconds -Sum).Sum } -Descending | Select-Object -First 10) {
        $lines.Add("| $($group.Name) | $($group.Count) | $(Format-Seconds ($group.Group | Measure-Object Seconds -Sum).Sum) |")
    }
    $lines.Add('')

    $lines.Add('### Slowest classes')
    $lines.Add('')
    $lines.Add('| Class | Tests | Summed | Wall | Median | p90 | Runs |')
    $lines.Add('|---|---:|---:|---:|---:|---:|---:|')
    $classes = $times.Tests | Group-Object Class | ForEach-Object {
        [pscustomobject]@{ Name = $_.Name; Count = $_.Count; Summed = ($_.Group | Measure-Object Seconds -Sum).Sum
            Wall = ($_.Group | Measure-Object End -Maximum).Maximum - ($_.Group | Measure-Object Start -Minimum).Minimum }
    } | Sort-Object Summed -Descending | Select-Object -First 20
    foreach ($class in $classes) {
        $lines.Add("| $($class.Name) | $($class.Count) | $(Format-Seconds $class.Summed) | $(Format-Seconds $class.Wall) $(Format-Spread (Get-Past $history.Classes $class.Name))")
    }
    $lines.Add('')

    $lines.Add('### Slowest tests')
    $lines.Add('')
    $lines.Add('| Test | Time | Median | p90 | Runs |')
    $lines.Add('|---|---:|---:|---:|---:|')
    foreach ($test in $times.Tests | Sort-Object Seconds -Descending | Select-Object -First 20) {
        $lines.Add("| $($test.Name -replace '\|', '\|') | $(Format-Seconds $test.Seconds) $(Format-Spread (Get-Past $history.Tests $test.Name))")
    }
    $lines.Add('')

    # A regression holds in this run and the one before it, against the median of the runs before both.
    $regressions = foreach ($key in $history.Tests.Keys) {
        $past = $history.Tests[$key]
        if ($past.Count -lt 5) { continue }
        $recent = $past[$past.Count - 2], $past[$past.Count - 1]
        $median = (Get-Spread $past.GetRange(0, $past.Count - 2))[0]
        if (($recent | Where-Object { $_ -gt 5 -and $_ -gt 1.5 * $median }).Count -eq 2) {
            [pscustomobject]@{ Name = ($key | ConvertFrom-Json); Median = $median; Last = $recent[1] }
        }
    }
    $lines.Add('### Regressions')
    $lines.Add('')
    if ($regressions) {
        $lines.Add('Over 5 s and 1.5 times their median in the last two runs:')
        $lines.Add('')
        foreach ($r in $regressions | Sort-Object { $_.Last / [math]::Max($_.Median, 0.001) } -Descending) { $lines.Add("- $($r.Name): $(Format-Seconds $r.Last), median $(Format-Seconds $r.Median)") }
    }
    else { $lines.Add('None: no test over 5 s took 1.5 times its median in the last two runs.') }
    $lines.Add('')

    $failed = @($times.Tests | Where-Object Outcome -notin 'Passed', 'NotExecuted')
    $lines.Add('### Failed tests')
    $lines.Add('')
    if ($failed) { foreach ($test in $failed | Select-Object -First 20) { $lines.Add("- $($test.Name) ($($test.Outcome), $(Format-Seconds $test.Seconds))") } }
    else { $lines.Add('None.') }
    if ($failed.Count -gt 20) { $lines.Add("- and $($failed.Count - 20) more") }
    $lines.Add('')
    $lines
}

# Targets table as markdown lines: each mode's latest run against its target, and what keeps it over.
function Get-TargetSection($history, [hashtable]$reasons) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('## Targets')
    $lines.Add('')
    $lines.Add('| Run | Target | Latest | When | Met | Out of reach because |')
    $lines.Add('|---|---:|---:|---|---|---|')
    foreach ($mode in 'quick', 'push', 'full', 'perf') {
        $latest = $history.Runs | Where-Object mode -eq $mode | Select-Object -Last 1
        $target = $script:Targets[$mode]
        $goal = if ($target) { "under $(Format-Seconds $target)" } else { 'measured apart' }
        if (-not $latest) { $lines.Add("| $mode | $goal | no run yet | | | |"); continue }
        $met = if (-not $target) { '' } elseif ($latest.wall -le $target) { 'yes' } else { 'no' }
        $lines.Add("| $mode | $goal | $(Format-Seconds $latest.wall) | $($latest.at) on $($latest.commit) | $met | $(if ($met -eq 'no') { $reasons[$mode] }) |")
    }
    $lines.Add('')
    $lines
}

# What keeps a run over target: commit gate build and tests of 1 s or more, else the critical path's longest tests.
function Get-TargetReason($times, $run) {
    $slow = if ($run.mode -eq 'quick') {
        @(Format-Setup $times $run) + @($times.Tests | Where-Object Seconds -ge 1 | Sort-Object Seconds -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $(Format-Seconds $_.Seconds)" })
    }
    else { @(Get-CriticalPath $times | Sort-Object Seconds -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $(Format-Seconds $_.Seconds)" }) }
    ($slow -join '; ') -replace '\|', '\|'
}

# Records a run and rewrites the time report; returns the one-line summary the run prints.
function Save-TestTimes([string]$trxPath, [System.Collections.IDictionary]$context, [string]$historyPath, [string]$reportPath) {
    $times = Read-TestTimes $trxPath
    if (-not $times) { return 'Time report not updated: the run wrote no timed results.' }
    $id = Add-TestHistory $historyPath $times $context
    $history = Read-TestHistory $historyPath $context.mode
    $run = $history.Runs | Where-Object run -eq $id | Select-Object -Last 1
    $section = Get-RunSection $times $run $history
    Invoke-HistoryLocked {
        $old = if (Test-Path $reportPath) { Get-Content $reportPath -Raw } else { '' }
        $reasons = @{}
        foreach ($m in [regex]::Matches($old, '<!-- reason (\w+): (.*) -->')) { $reasons[$m.Groups[1].Value] = $m.Groups[2].Value }
        $reasons[$context.mode] = Get-TargetReason $times $run
        $text = [System.Text.StringBuilder]::new()
        [void]$text.AppendLine('# Test time report').AppendLine()
        [void]$text.AppendLine("Written by test.ps1 after every run; the history is $historyPath.").AppendLine()
        foreach ($line in Get-TargetSection $history $reasons) { [void]$text.AppendLine($line) }
        foreach ($mode in $reasons.Keys | Sort-Object) { [void]$text.AppendLine("<!-- reason ${mode}: $($reasons[$mode]) -->") }
        [void]$text.AppendLine()
        foreach ($mode in $script:Modes) {
            $body = if ($mode -eq $context.mode) { $section -join "`n" } elseif ($old -match "(?s)<!-- mode: $mode -->\n(.*?)<!-- end: $mode -->") { $Matches[1].TrimEnd() } else { $null }
            if ($body) { [void]$text.AppendLine("<!-- mode: $mode -->").AppendLine($body.TrimEnd()).AppendLine("<!-- end: $mode -->").AppendLine() }
        }
        [IO.File]::WriteAllText("$reportPath.tmp", ($text.ToString() -replace "`r`n", "`n"))
        Move-Item -Force "$reportPath.tmp" $reportPath
    }
    $slowest = $times.Tests | Group-Object Class | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Seconds = ($_.Group | Measure-Object Seconds -Sum).Sum } } | Sort-Object Seconds -Descending | Select-Object -First 1
    "Time: $($times.Tests.Count) tests, $(Format-Seconds $run.wall) wall, $(Format-Seconds $times.Summed) summed; slowest class $($slowest.Name) ($(Format-Seconds $slowest.Seconds)); report $reportPath"
}

# The latest run of each mode against its target, as lines for test.ps1 -Status; empty without a history.
function Get-TimeSummary([string]$historyPath) {
    if (-not (Test-Path $historyPath)) { return @() }
    $runs = @(Invoke-HistoryLocked { [IO.File]::ReadAllLines($historyPath) } | Where-Object { $_.StartsWith('{"kind":"run"') } | ForEach-Object { $_ | ConvertFrom-Json })
    foreach ($mode in 'quick', 'push', 'full', 'perf', 'filter') {
        $latest = $runs | Where-Object mode -eq $mode | Select-Object -Last 1
        if (-not $latest) { continue }
        $target = $script:Targets[$mode]
        $verdict = if (-not $target) { '' } elseif ($latest.wall -le $target) { " (target $(Format-Seconds $target): met)" } else { " (target $(Format-Seconds $target): not met)" }
        "${mode}: $(Format-Seconds $latest.wall)$verdict, $($latest.tests) tests, at $($latest.at) on $($latest.commit)"
    }
}

# Maximum permit counts from MachinePermits.cs (Counts plus LargeMachineExtra), as @{ resource = count }.
function Get-PermitCounts([string]$sourcePath) {
    $source = Get-Content $sourcePath -Raw
    $counts = @{}
    foreach ($name in 'Counts', 'LargeMachineExtra') {
        $table = [regex]::Match($source, "(?s)\b$name = new Dictionary<string, int>\s*\{(.*?)\};").Groups[1].Value
        foreach ($m in [regex]::Matches($table, '\["([a-z-]+)"\]\s*=\s*(\d+)')) { $counts[$m.Groups[1].Value] = [int]$counts[$m.Groups[1].Value] + [int]$m.Groups[2].Value }
    }
    if (-not $counts.Count) { throw "no permit counts in $sourcePath" }
    return $counts
}

# Engine permits per engine on a machine with $memoryBytes, as MachinePermits.cs counts them (IDA and Ghidra match).
function Get-EnginePermits([string]$sourcePath, [long]$memoryBytes) {
    $source = Get-Content $sourcePath -Raw
    $base = [int][regex]::Match($source, '(?s)\bCounts = new Dictionary.*?\["engine-ida"\]\s*=\s*(\d+)').Groups[1].Value
    $extra = [int][regex]::Match($source, '(?s)\bLargeMachineExtra = new Dictionary.*?\["engine-ida"\]\s*=\s*(\d+)').Groups[1].Value
    $large = [regex]::Match($source, 'LargeMemory = (\d+)L << 30;')
    if (-not $base -or -not $large.Success) { throw "no engine permit counts in $sourcePath" }
    $base + $(if ($memoryBytes -ge ([long]$large.Groups[1].Value -shl 30)) { $extra } else { 0 })
}

# Takes every permit slot in $folder, waiting for holders, and returns the slots for Exit-AllPermits.
function Enter-AllPermits([hashtable]$counts, [string]$folder = (Join-Path ([IO.Path]::GetTempPath()) 'corvus-test-data/permits')) {
    $slots = [System.Collections.Generic.List[IO.FileStream]]::new()
    foreach ($resource in $counts.Keys | Sort-Object) {
        $dir = Join-Path $folder $resource
        New-Item -ItemType Directory -Force $dir | Out-Null
        for ($i = 0; $i -lt $counts[$resource]; $i++) {
            while ($true) {
                try { $slots.Add([IO.FileStream]::new((Join-Path $dir "slot-$i"), 'OpenOrCreate', 'ReadWrite', 'None')); break }
                catch [IO.IOException] { Start-Sleep -Milliseconds 500 }
            }
            # A waiting test counts a script holder as making progress while its process lives (MachinePermits).
            Set-Content -Path (Join-Path $dir "slot-$i.owner") -Value "$PID script" -NoNewline
        }
    }
    return , $slots
}

# Releases the permits Enter-AllPermits took, with their owner records.
function Exit-AllPermits($slots) {
    foreach ($slot in $slots) {
        $slot.Dispose()
        Remove-Item ($slot.Name + '.owner') -Force -ErrorAction SilentlyContinue
    }
}

# Tests over budget in most of $samples samples; $rerun reruns undecided tests and returns those that failed again.
function Get-PerfOverBudget([string[]]$over, [scriptblock]$rerun, [int]$samples = 5) {
    $over = @($over | Where-Object { $_ })
    if (-not $over) { return @() }
    $majority = [math]::Floor($samples / 2) + 1
    $failed = @{}; $taken = 1
    foreach ($test in $over) { $failed[$test] = 1 }
    while ($taken -lt $samples) {
        $pending = @($over | Where-Object { $failed[$_] -lt $majority -and $taken - $failed[$_] -lt $majority })
        if (-not $pending) { break }
        $again = @(& $rerun $pending)
        foreach ($test in $pending) { if ($test -in $again) { $failed[$test]++ } }
        $taken++
    }
    @($over | Where-Object { $failed[$_] -ge $majority })
}

# Records a perf run's flagged tests in $path and returns those flagged in the previous run too.
function Update-PerfVerdicts([string]$path, [string[]]$over, [string]$commit) {
    $over = @($over | Where-Object { $_ })
    $before = if (Test-Path $path) { @((Get-Content $path -Raw | ConvertFrom-Json).over | Where-Object { $_ }) } else { @() }
    $record = [ordered]@{ commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); over = $over }
    Set-Content -Path "$path.tmp" -Value ($record | ConvertTo-Json -Depth 3) -NoNewline
    Move-Item -Force "$path.tmp" $path
    @($over | Where-Object { $_ -in $before })
}

Export-ModuleMember -Function Get-PermitCounts, Get-EnginePermits, Enter-AllPermits, Exit-AllPermits, Get-PerfOverBudget, Update-PerfVerdicts, Read-TestTimes, Get-MachineLoad, Start-MachineLoad, Read-ProcessTimes, Get-OtherLoad, Invoke-LoadSampler, Start-LoadSampler, Get-PerfContention, Invoke-IoSampler, Start-IoSampler, Get-IoStalls, Add-TestHistory, Read-TestHistory, Get-CriticalPath, Get-Concurrency, Save-TestTimes, Get-TimeSummary
