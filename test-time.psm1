# Test run timing (test.ps1 records every run): the test times of a run's TRX results, a history of the last runs of
# each mode, and the time report built from both.

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

# The tests of a TRX file, timed from the first test's start: an object with At (that start), Wall (seconds to the last
# test's end), Summed (seconds of all tests) and Tests (Name, Class, Start, End, Seconds, Outcome; Class is the test
# class, a nested one as Outer+Inner); $null when the file is missing or no result has times.
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

# Starts sampling the machine's load on a thread of its own, so the sample costs a run no time; Receive-Job returns it.
function Start-MachineLoad { Start-ThreadJob -ScriptBlock ${function:Get-MachineLoad} }

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

# Appends a run to the history file and returns its id: one line for the run ($context with its counts and times), one
# per class (tests, summed seconds, first start, last end) and one per test that took $KeepSeconds or more or did not
# pass. Keeps the last $keep runs of each mode.
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

# The history of one mode: Runs (every run line of every mode, oldest first), and Tests and Classes (the seconds of each
# test and class in that mode's runs, oldest first, keyed by their JSON-encoded names). Empty without a history file.
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

# The chain of tests that sets a run's end: the test that ended last, then the test that ended last before it started,
# and so on back to the start. In a serial tail it is every test of the tail.
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

# The report section of one run, as markdown lines.
function Get-RunSection($times, $run, $history) {
    $mode = $run.mode
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("## Latest $mode run")
    $lines.Add('')
    $lines.Add("$($run.commit) at $($run.at), exit code $($run.code): $($run.tests) tests, $($run.failed) failed.")
    $lines.Add('')
    $parallel = if ($times.Wall -gt 0) { $times.Summed / $times.Wall } else { 0 }
    $lines.Add("- Wall time $(Format-Seconds $run.wall) (tests $(Format-Seconds $times.Wall), build and setup $(Format-Seconds ([math]::Max(0, $run.wall - $times.Wall)))); summed test time $(Format-Seconds $times.Summed), $([string]::Format($script:Invariant, '{0:0.0}', $parallel)) tests at a time on average.")
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

# The targets table, as markdown lines: each mode's latest run against its target, and what keeps an unmet target out
# of reach (the longest tests of the critical path; for the commit gate, its build or its slowest tests).
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

# What keeps a run over its target: for the commit gate its build and its tests of a second or more, otherwise the
# longest tests of the critical path.
function Get-TargetReason($times, $run) {
    $slow = if ($run.mode -eq 'quick') {
        $build = [math]::Max(0, $run.wall - $times.Wall)
        @("build and setup $(Format-Seconds $build)") + @($times.Tests | Where-Object Seconds -ge 1 | Sort-Object Seconds -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $(Format-Seconds $_.Seconds)" })
    }
    else { @(Get-CriticalPath $times | Sort-Object Seconds -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $(Format-Seconds $_.Seconds)" }) }
    ($slow -join '; ') -replace '\|', '\|'
}

# Records a run in the history and rewrites the time report: the targets table, this run's section, and the other
# modes' sections as their last runs left them. Returns the one-line summary a run prints.
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

# The permit counts of Support/MachinePermits.cs, as @{ resource = count }: the table the tests take permits by.
function Get-PermitCounts([string]$sourcePath) {
    $table = [regex]::Match((Get-Content $sourcePath -Raw), '(?s)Counts = new Dictionary<string, int>\s*\{(.*?)\};').Groups[1].Value
    $counts = @{}
    foreach ($m in [regex]::Matches($table, '\["([a-z-]+)"\]\s*=\s*(\d+)')) { $counts[$m.Groups[1].Value] = [int]$m.Groups[2].Value }
    if (-not $counts.Count) { throw "no permit counts in $sourcePath" }
    return $counts
}

# Takes every permit of every resource in $folder (the slot files MachinePermits opens), waiting until their holders
# end, and returns the open slots for Exit-AllPermits.
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
        }
    }
    return , $slots
}

# Releases the permits Enter-AllPermits took.
function Exit-AllPermits($slots) { foreach ($slot in $slots) { $slot.Dispose() } }

# The tests over budget in most of $samples samples: $over failed the first sample, and $rerun (a block taking test
# names and returning the ones that failed again) takes the rest, only for tests not yet decided either way.
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

# Records a perf run's tests over budget in $path and returns those also over budget in the perf run before: a
# regression is confirmed by two runs in a row, not one slow run.
function Update-PerfVerdicts([string]$path, [string[]]$over, [string]$commit) {
    $over = @($over | Where-Object { $_ })
    $before = if (Test-Path $path) { @((Get-Content $path -Raw | ConvertFrom-Json).over | Where-Object { $_ }) } else { @() }
    $record = [ordered]@{ commit = $commit; at = (Get-Date -Format 'yyyy-MM-dd HH:mm'); over = $over }
    Set-Content -Path "$path.tmp" -Value ($record | ConvertTo-Json -Depth 3) -NoNewline
    Move-Item -Force "$path.tmp" $path
    @($over | Where-Object { $_ -in $before })
}

Export-ModuleMember -Function Get-PermitCounts, Enter-AllPermits, Exit-AllPermits, Get-PerfOverBudget, Update-PerfVerdicts, Read-TestTimes, Get-MachineLoad, Start-MachineLoad, Add-TestHistory, Read-TestHistory, Get-CriticalPath, Get-Concurrency, Save-TestTimes, Get-TimeSummary
