using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Corvus.Tests;

/// <summary>test-time.psm1: a run's test times, the history of the last runs per mode, and the time report.</summary>
public class TestTimeTests
{
    private static readonly DateTimeOffset Origin = new(2026, 10, 1, 8, 0, 0, TimeSpan.FromHours(3));

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_history_keeps_the_last_runs_of_each_mode_and_slow_or_failed_tests_by_name()
    {
        var dir = NewFolder();
        var trx = Path.Combine(dir, "run.trx");
        File.WriteAllText(trx, Trx(("A", "Slow", 0, 2, "Passed"), ("A", "Next", 2, 3, "Passed"), ("B", "Fast", 0, 0.5, "Passed"), ("B", "Broken", 0.5, 0.75, "Failed")));
        var history = Path.Combine(dir, "history.jsonl");
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                $times = Read-TestTimes '{{trx}}'
                'wall=' + $times.Wall
                foreach ($mode in 'quick', 'quick', 'quick', 'push') { $null = Add-TestHistory '{{history}}' $times ([ordered]@{ mode = $mode; wall = 4.0 }) 2 }
                $h = Read-TestHistory '{{history}}' 'quick'
                'runs=' + (($h.Runs | ForEach-Object mode) -join ',')
                'tests=' + (($h.Tests.Keys | Sort-Object | ForEach-Object { $_ + ':' + $h.Tests[$_].Count }) -join ',')
                'classes=' + (($h.Classes.Keys | Sort-Object | ForEach-Object { $_ + ':' + $h.Classes[$_][0] }) -join ',')
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Equal("3", Line(lines, "wall"));
            Assert.Equal("quick,quick,push", Line(lines, "runs"));
            // The fast test that passed is kept only in its class's line.
            Assert.Equal("\"Corvus.Tests.A.Next\":2,\"Corvus.Tests.A.Slow\":2,\"Corvus.Tests.B.Broken\":2", Line(lines, "tests"));
            Assert.Equal("\"A\":3,\"B\":0.75", Line(lines, "classes"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_critical_path_is_the_chain_of_tests_that_sets_the_end_time()
    {
        var dir = NewFolder();
        var trx = Path.Combine(dir, "run.trx");
        File.WriteAllText(trx, Trx(("A", "Long", 0, 10, "Passed"), ("A", "Short", 0, 3, "Passed"), ("B", "Tail", 10, 12, "Passed"), ("B", "Last", 12, 15, "Passed")));
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                $times = Read-TestTimes '{{trx}}'
                'path=' + ((Get-CriticalPath $times | ForEach-Object Name) -join ',')
                'running=' + ((Get-Concurrency $times 5 | ForEach-Object { $_.Running.ToString('0.0', [cultureinfo]::InvariantCulture) }) -join ',')
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Equal("Corvus.Tests.B.Last,Corvus.Tests.B.Tail,Corvus.Tests.A.Long", Line(lines, "path"));
            Assert.Equal("1.6,1.0,1.0", Line(lines, "running"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_report_names_a_missed_target_and_a_regression_and_keeps_other_modes_sections()
    {
        var dir = NewFolder();
        var usual = Path.Combine(dir, "usual.trx");
        var slower = Path.Combine(dir, "slower.trx");
        File.WriteAllText(usual, Trx(("Engine", "Open", 0, 6, "Passed"), ("Engine", "Read", 0, 0.5, "Passed")));
        File.WriteAllText(slower, Trx(("Engine", "Open", 0, 20, "Passed"), ("Engine", "Read", 0, 0.5, "Passed")));
        var history = Path.Combine(dir, "history.jsonl");
        var report = Path.Combine(dir, "report.md");
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                foreach ($trx in '{{usual}}', '{{usual}}', '{{usual}}', '{{slower}}', '{{slower}}') {
                    $last = Save-TestTimes $trx ([ordered]@{ mode = 'full'; commit = 'abc'; at = '2026-10-01 08:00'; code = 0; wall = 2000.0 }) '{{history}}' '{{report}}'
                }
                'line=' + $last
                $null = Save-TestTimes '{{usual}}' ([ordered]@{ mode = 'quick'; commit = 'abc'; at = '2026-10-01 09:00'; code = 0; wall = 30.0 }) '{{history}}' '{{report}}'
                foreach ($line in Get-TimeSummary '{{history}}') { 'summary=' + $line }
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.StartsWith("Time: 2 tests, 33.3 min wall", Line(lines, "line"));
            Assert.Equal(
                ["quick: 30.0 s (target 2.0 min: met), 2 tests, at 2026-10-01 09:00 on abc", "full: 33.3 min (target 30.0 min: not met), 2 tests, at 2026-10-01 08:00 on abc"],
                lines.Where(l => l.StartsWith("summary=")).Select(l => l["summary=".Length..]));
            var text = File.ReadAllText(report);
            Assert.Contains("| full | under 30.0 min | 33.3 min | 2026-10-01 08:00 on abc | no | Corvus.Tests.Engine.Open 20.0 s |", text);
            Assert.Contains("- Corvus.Tests.Engine.Open: 20.0 s, median 6.0 s", text);
            Assert.Contains("<!-- mode: full -->", text);
            Assert.Contains("<!-- mode: quick -->", text);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_timed_build_is_reported_apart_from_test_start_and_an_untimed_one_is_not()
    {
        var dir = NewFolder();
        var trx = Path.Combine(dir, "run.trx");
        File.WriteAllText(trx, Trx(("Engine", "Open", 0, 6, "Passed")));
        var history = Path.Combine(dir, "history.jsonl");
        var report = Path.Combine(dir, "report.md");
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                $null = Save-TestTimes '{{trx}}' ([ordered]@{ mode = 'quick'; commit = 'abc'; at = '2026-10-01 09:00'; code = 0; wall = 150.0; build = 20.0 }) '{{history}}' '{{report}}'
                'timed=' + ((Get-Content '{{report}}' | Where-Object { $_ -like '- Wall time*' }) -join '')
                'reason=' + ((Get-Content '{{report}}' | Where-Object { $_ -like '<!-- reason quick:*' }) -join '')
                $null = Save-TestTimes '{{trx}}' ([ordered]@{ mode = 'quick'; commit = 'abc'; at = '2026-10-01 09:10'; code = 0; wall = 150.0; build = $null }) '{{history}}' '{{report}}'
                'untimed=' + ((Get-Content '{{report}}' | Where-Object { $_ -like '- Wall time*' }) -join '')
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.StartsWith("- Wall time 2.5 min (tests 6.0 s, build 20.0 s, test start and setup 2.1 min);", Line(lines, "timed"));
            Assert.Equal("<!-- reason quick: build 20.0 s, test start and setup 2.1 min; Corvus.Tests.Engine.Open 6.0 s -->", Line(lines, "reason"));
            Assert.StartsWith("- Wall time 2.5 min (tests 6.0 s, build and setup 2.4 min);", Line(lines, "untimed"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_perf_regression_needs_most_of_five_samples_and_two_runs_in_a_row()
    {
        var dir = NewFolder();
        var verdicts = Path.Combine(dir, "verdicts.json");
        var source = Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "Support", "MachinePermits.cs").Replace("'", "''");
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                # Slow fails every sample, Noisy the first three, Once only the first.
                $script:calls = 0
                $over = Get-PerfOverBudget @('Slow', 'Noisy', 'Once') {
                    param($pending)
                    $script:calls++
                    @($pending | Where-Object { $_ -eq 'Slow' -or ($_ -eq 'Noisy' -and $script:calls -le 2) })
                }
                'over=' + ($over -join ',')
                'calls=' + $script:calls
                'first=' + ((Update-PerfVerdicts '{{verdicts}}' $over 'abc') -join ',')
                'second=' + ((Update-PerfVerdicts '{{verdicts}}' @('Slow') 'def') -join ',')
                'engines=' + (Get-EnginePermits '{{source}}' (16GB)) + ',' + (Get-EnginePermits '{{source}}' (80GB))
                $counts = Get-PermitCounts '{{source}}'
                'counts=' + (($counts.Keys | Sort-Object | ForEach-Object { "$_=$($counts[$_])" }) -join ',')
                $held = Enter-AllPermits @{ x = 2 } '{{dir}}'
                try { [IO.File]::Open('{{dir}}/x/slot-1', 'Open', 'ReadWrite', 'None').Dispose(); 'open=yes' } catch { 'open=no' }
                Exit-AllPermits $held
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Equal("Slow,Noisy", Line(lines, "over"));
            // Three samples decide each: Slow and Noisy over budget, Once within it.
            Assert.Equal("3", Line(lines, "calls"));
            Assert.Equal("", Line(lines, "first"));
            Assert.Equal("Slow", Line(lines, "second"));
            Assert.Equal(string.Join(',', MachinePermits.Counts.OrderBy(c => c.Key, StringComparer.Ordinal)
                .Select(c => $"{c.Key}={c.Value + MachinePermits.LargeMachineExtra.GetValueOrDefault(c.Key)}")), Line(lines, "counts"));
            Assert.Equal("no", Line(lines, "open"));
            var ida = MachinePermits.Counts["engine-ida"];
            Assert.Equal($"{ida},{ida + MachinePermits.LargeMachineExtra["engine-ida"]}", Line(lines, "engines"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void The_status_names_each_window_of_slow_file_opens_or_late_samples_with_its_worst_values()
    {
        var dir = NewFolder();
        var log = Path.Combine(dir, "background.log.io");
        File.WriteAllLines(log, [
            "2026-10-22 22:24:00\tlag=3\topen=12\topen=9\tqueue=0.5\tidle=95\tfreeMB=20000\tpages=10",
            "2026-10-22 22:24:10\tlag=40\topen=4200\topen=30\tqueue=12.25\tidle=3\tfreeMB=900\tpages=5000",
            "2026-10-22 22:24:20\tlag=600\topen=15\topen=1800\tqueue=8\tidle=10\tfreeMB=1200\tpages=7000",
            "2026-10-22 22:24:30\tlag=2\topen=11\topen=8\tqueue=0.4\tidle=97\tfreeMB=19000\tpages=12",
            "2026-10-22 22:26:00\tlag=6400\topen=10\topen=7\tqueue=0.1\tidle=99\tfreeMB=21000\tpages=8",
            "2026-10-22 22:26:10\tlag=1\topen=10\topen=7\tqueue=0.1\tidle=99\tfreeMB=21000\tpages=8",
            // A line written before the lag was recorded.
            "2026-10-22 22:30:00\topen=-1\topen=2500\tqueue=-1\tidle=-1\tfreeMB=-1\tpages=-1",
        ]);
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                Get-IoStalls '{{log}}' | ForEach-Object { 'stall=' + $_ }
                'none=' + @(Get-IoStalls '{{Path.Combine(dir, "missing.io")}}').Count
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Equal([
                "stall=2026-10-22 22:24:10 to 2026-10-22 22:24:20 (2 samples): a file took up to 4.2 s; run lag up to 0.6 s; disk queue up to 12.25, idle down to 3%; free memory down to 900 MB, pages/s up to 7000",
                "stall=2026-10-22 22:26:00 to 2026-10-22 22:26:00 (1 samples): a file took up to 0.0 s; run lag up to 6.4 s; disk queue up to 0.1, idle down to 99%; free memory down to 21000 MB, pages/s up to 8",
                "stall=2026-10-22 22:30:00 to 2026-10-22 22:30:00 (1 samples): a file took up to 2.5 s; run lag unknown; disk queue unknown, idle unknown; free memory unknown, pages/s unknown",
            ], lines.Where(l => l.StartsWith("stall=")));
            Assert.Equal("0", Line(lines, "none"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void A_perf_run_is_partial_when_processes_outside_its_tree_load_the_machine()
    {
        var dir = NewFolder();
        string Log(string name, params int[] loads)
        {
            var path = Path.Combine(dir, name);
            File.WriteAllLines(path, loads.Select((l, i) => $"2026-10-23 13:{43 + i / 6:00}:{i % 6 * 10:00}\tothers={l}"));
            return path.Replace("'", "''");
        }
        try
        {
            var lines = Run($$"""
                Import-Module '{{Module}}'
                function P($id, $parent, $cpu) { [pscustomobject]@{ ProcessId = $id; ParentProcessId = $parent; KernelModeTime = 0; UserModeTime = $cpu } }
                # The run is 10 with child 11 and grandchild 12; 20 is other work; 0 is the idle process. 2 cores, 10 s apart.
                $state = @{}
                'first=' + (Get-OtherLoad 10 $state @((P 0 0 0), (P 10 1 0), (P 11 10 0), (P 12 11 0), (P 20 1 0)) 0 2)
                'second=' + (Get-OtherLoad 10 $state @((P 0 0 9e7), (P 10 1 1e7), (P 11 10 5e7), (P 12 11 5e7), (P 20 1 5e7)) 10 2)
                # 11 ended: 12 stays the run's, and 21 starts as other work.
                'orphan=' + (Get-OtherLoad 10 $state @((P 10 1 1e7), (P 12 11 2e8), (P 20 1 5e7), (P 21 1 1e8)) 20 2)
                'unread=' + ($null -eq (Get-OtherLoad 10 $state $null 30 2))
                $busy = Get-PerfContention '{{Log("busy.log", 5, 90, 100, 5, 8, 6, 7, 5, 4, 3)}}'
                'busy=' + $busy.Partial + ' ' + $busy.Text
                $quiet = Get-PerfContention '{{Log("quiet.log", 5, 90, 5, 8, 6, 7, 5, 4, 3, 2)}}'
                'quiet=' + $quiet.Partial + ' ' + $quiet.Text
                'unknown=' + ($null -eq (Get-PerfContention '{{Path.Combine(dir, "missing.log")}}'))
                """);
            if (lines is ["skip"]) return; // no pwsh on this machine
            Assert.Equal("", Line(lines, "first"));
            Assert.Equal("25", Line(lines, "second"));
            Assert.Equal("50", Line(lines, "orphan"));
            Assert.Equal("True", Line(lines, "unread"));
            Assert.Equal("True other processes used over 25% of the machine in 2 of 10 samples (up to 100%)", Line(lines, "busy"));
            Assert.Equal("False other processes used over 25% of the machine in 1 of 10 samples (up to 90%)", Line(lines, "quiet"));
            Assert.Equal("True", Line(lines, "unknown"));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static string Module => Path.Combine(DocsTests.RepoRoot(), "test-time.psm1").Replace("'", "''");

    private static string NewFolder()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"corvus-time-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    // Results with start and end times in seconds from Origin.
    private static string Trx(params (string Class, string Name, double Start, double End, string Outcome)[] tests)
    {
        StringBuilder results = new(), definitions = new();
        for (var i = 0; i < tests.Length; i++)
        {
            var (cls, name, start, end, outcome) = tests[i];
            var from = Origin.AddSeconds(start).ToString("o", CultureInfo.InvariantCulture);
            var to = Origin.AddSeconds(end).ToString("o", CultureInfo.InvariantCulture);
            results.Append($"""<UnitTestResult testId="{i}" testName="Corvus.Tests.{cls}.{name}" startTime="{from}" endTime="{to}" outcome="{outcome}" />""");
            definitions.Append($"""<UnitTest id="{i}"><TestMethod className="Corvus.Tests.{cls}" name="{name}" /></UnitTest>""");
        }
        return $"""<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results>{results}</Results><TestDefinitions>{definitions}</TestDefinitions></TestRun>""";
    }

    private static string Line(string[] lines, string name) => lines.Single(l => l.StartsWith(name + "=")).Substring(name.Length + 1);

    private static string[] Run(string script)
    {
        ProcessStartInfo start = new("pwsh") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in new[] { "-NoProfile", "-NonInteractive", "-Command", script })
            start.ArgumentList.Add(arg);
        Process? process;
        try { process = Process.Start(start); }
        catch (System.ComponentModel.Win32Exception) { return ["skip"]; }
        using (process)
        {
            var output = process!.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.True(process.ExitCode == 0, error);
            return output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
