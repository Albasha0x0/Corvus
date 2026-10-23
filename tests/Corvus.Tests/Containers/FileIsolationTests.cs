using System.IO.Compression;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Corvus.Setup;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A test folder, worker pools and sessions for the file tools in the "files" worker.</summary>
public abstract class FileIsolationTestBase : IDisposable
{
    private protected readonly TempDir _dir = new();

    // The machine load when the pool was made; 1 on a quiet machine.
    private protected double _load = 1;

    public void Dispose() => _dir.Dispose();

    /// <summary>
    /// A pool whose workers also answer the fixture files. The worker start limit scales with the machine load, so a
    /// loaded run waits as long for the same start as a quiet one does.
    /// </summary>
    private protected WorkerPool Pool(ChildProcessStart? start = null, long memoryLimitBytes = 0)
    {
        _load = MachineLoad.Factor();
        var options = new WorkerPoolOptions();
        return new(options with
        {
            Enabled = true,
            MemoryLimitBytes = memoryLimitBytes,
            Start = start ?? WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [WorkerHost.FixtureOpsVariable] = "1" } },
            StartTimeout = options.StartTimeout * _load,
        });
    }

    /// <summary>The text with the machine load and the worker start limit it gave, for a failure message.</summary>
    private protected string Noted(string text) =>
        _load == 1 ? text : $"{text}\n(machine load x{_load:0.00}, worker start limit {new WorkerPoolOptions().StartTimeout * _load})";

    private protected static Task<ToolSession> Session(bool inProcess, params string[] args) => Session(inProcess, null, args);

    private protected static async Task<ToolSession> Session(bool inProcess, TimeProvider? time, params string[] args)
    {
        var options = ServerOptions.Parse(["--no-index", "--no-watch", .. args]);
        options.InProcessParsing = inProcess;
        return await ToolSession.StartAsync(options, CancellationToken.None, time);
    }

    private protected static async Task<CallToolResult> Call(ToolSession session, string tool, Dictionary<string, object?> args) =>
        await session.Client.CallToolAsync(tool, args);

    /// <summary>The whole result as the client sees it: every text block, then the structured content.</summary>
    /// <summary>Asserts that summarize_file over <paramref name="path"/> succeeds, naming the error when it does not.</summary>
    private protected async Task ReadsAsync(ToolSession session, string path)
    {
        var r = await Call(session, "summarize_file", new() { ["path"] = path });
        Assert.True(r.IsError != true, Noted(Whole(r)));
    }

    private protected static string Whole(CallToolResult r) =>
        string.Join("\n---\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text)) + "\n===\n" + (r.StructuredContent is { } s ? s.GetRawText() : "");

    private protected string Fixture(string name, string text)
    {
        var path = Path.Combine(_dir.Path, name);
        File.WriteAllText(path, text);
        return path;
    }

    private protected (string Zip, string Package, string Library, string Bytes) Inputs()
    {
        var library = Path.Combine(_dir.Path, "Lib.dll");
        var dll = Roslyn.Release("Lib", """namespace Lib { public static class C { public static string U() => "https://example.com/api/items"; } }""");
        File.WriteAllBytes(library, dll);
        var zip = Path.Combine(_dir.Path, "three.zip");
        using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            for (int i = 0; i < 3; i++)
                using (var writer = new StreamWriter(archive.CreateEntry($"docs/f{i}.txt").Open())) writer.Write($"text {i}");
        var package = Path.Combine(_dir.Path, "Lib.1.0.0.nupkg");
        using (var archive = ZipFile.Open(package, ZipArchiveMode.Create))
        {
            using (var stream = archive.CreateEntry("lib/net8.0/Lib.dll").Open()) stream.Write(dll);
            using (var writer = new StreamWriter(archive.CreateEntry("Lib.nuspec").Open()))
                writer.Write("<package><metadata><id>Lib</id><version>1.0.0</version></metadata></package>");
        }
        var bytes = Path.Combine(_dir.Path, "bytes.bin");
        File.WriteAllBytes(bytes, [.. Enumerable.Range(0, 4096).Select(i => (byte)(i * 31 % 251))]);
        return (zip, package, library, bytes);
    }
}

/// <summary>The file tools in the "files" worker: the same results as in process, and named errors when the worker fails.</summary>
public sealed class FileIsolationTests(ITestOutputHelper output) : FileIsolationTestBase
{
    [Theory]
    [InlineData("exit")]
    [InlineData("stack")]
    public async Task A_reader_that_ends_the_worker_is_named_and_the_next_read_succeeds(string fault)
    {
        var (zip, _, _, _) = Inputs();
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);
        var failed = await Call(session, "summarize_file", new() { ["path"] = Fixture("fault.txt", Corvus.Tools.FileOps.FixtureMarker + fault) });
        Assert.True(failed.IsError == true);
        var text = Whole(failed);
        Assert.Contains("Error (provider_unavailable)", text);
        Assert.Contains("fault.txt", text);
        Assert.Contains("nothing from that read is kept", text);
        await ReadsAsync(session, zip);
    }

    [Fact]
    public async Task A_reader_past_the_memory_limit_is_named_and_the_next_read_succeeds()
    {
        var (zip, _, _, _) = Inputs();
        using var pool = Pool(memoryLimitBytes: WorkerPool.MinimumMemoryBytes);
        using var shared = WorkerPool.UseShared(pool);
        await using var session = await Session(false);
        var text = Whole(await Call(session, "summarize_file", new() { ["path"] = Fixture("big.txt", Corvus.Tools.FileOps.FixtureMarker + "allocate") }));
        // Assert.Contains cuts the text short; a worker that did not start is named only past that cut.
        Assert.True(text.Contains("Error (limit_exceeded)"), Noted(text));
        Assert.Contains(WorkerPool.MemoryVariable, text);
        Assert.Contains("big.txt", text);
        await ReadsAsync(session, zip);
    }

    [Fact]
    public async Task A_worker_that_cannot_start_is_refused_with_the_in_process_setting_named()
    {
        var (zip, _, _, _) = Inputs();
        using var pool = Pool(new ChildProcessStart(Path.Combine(_dir.Path, "no-such-program"), []));
        using var shared = WorkerPool.UseShared(pool);
        await using (var session = await Session(false))
        {
            var text = Whole(await Call(session, "summarize_file", new() { ["path"] = zip }));
            Assert.Contains("Error (provider_unavailable", text);
            Assert.Contains(ServerOptions.InProcessParsingVariable + "=1", text);
        }
        // With in-process parsing the same call needs no worker.
        await using (var session = await Session(true))
            await ReadsAsync(session, zip);
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_warm_worker_adds_little_to_a_small_read()
    {
        var (zip, _, _, _) = Inputs();
        const int Calls = 20;
        async Task<(TimeSpan First, double Median)> Measure(bool inProcess)
        {
            await using var session = await Session(inProcess);
            var clock = System.Diagnostics.Stopwatch.StartNew();
            await ReadsAsync(session, zip);
            var first = clock.Elapsed;
            var times = new List<double>();
            for (int i = 0; i < Calls; i++)
            {
                clock.Restart();
                await ReadsAsync(session, zip);
                times.Add(clock.Elapsed.TotalMilliseconds);
            }
            times.Sort();
            return (first, times[Calls / 2]);
        }
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        var (_, inProcess) = await Measure(true);
        var (start, worker) = await Measure(false);
        PerfBudget.AtMost("files/worker-call-overhead", worker - inProcess, 20, "ms", output, $"worker {worker:0.0} ms, in process {inProcess:0.0} ms, median of {Calls}");
        PerfBudget.Time("files/worker-start-and-first-read", start, TimeSpan.FromSeconds(2), output);
    }

    /// <summary>Every file tool in both modes: a class of its own, so its long run overlaps the other worker tests.</summary>
    public sealed class BothModes : FileIsolationTestBase
    {
        [Fact]
        public async Task Each_file_tool_answers_the_same_bytes_in_the_worker_as_in_process()
        {
            var (zip, package, library, bytes) = Inputs();
            var dump = SyntheticCrash.Write(_dir);
            var calls = new List<(string Tool, Func<string, Dictionary<string, object?>> Args)>
            {
                ("open_minidump", _ => new() { ["path"] = dump }),
                ("open_minidump", _ => new() { ["path"] = "synth.dmp", ["view"] = "modules" }),
                ("open_minidump", _ => new() { ["path"] = dump, ["view"] = "threads", ["limit"] = 2 }),
                ("open_minidump", _ => new() { ["path"] = dump, ["view"] = "memory" }),
                ("open_minidump", _ => new() { ["path"] = dump, ["view"] = "unloaded" }),
                ("open_minidump", _ => new() { ["path"] = dump, ["view"] = "no_such_view" }),
                ("open_minidump", _ => new() { ["path"] = Path.Combine(_dir.Path, "absent.dmp") }),
                ("read_dump_memory", _ => new() { ["dump"] = "synth.dmp", ["address"] = $"0x{SyntheticCrash.Base:X}", ["length"] = 96 }),
                ("read_dump_memory", _ => new() { ["dump"] = dump, ["address"] = $"0x{SyntheticCrash.Stack:X}", ["length"] = 64, ["dumpOnly"] = true }),
                ("dump_heap", _ => new() { ["dump"] = dump }),
                ("dump_object", _ => new() { ["dump"] = dump, ["address"] = "0x1000" }),
                ("summarize_file", _ => new() { ["path"] = zip }),
                ("summarize_file", _ => new() { ["path"] = package }),
                ("summarize_file", _ => new() { ["path"] = library }),
                ("summarize_file", _ => new() { ["path"] = library, ["view"] = "managed" }),
                ("summarize_file", _ => new() { ["path"] = bytes }),
                ("summarize_file", _ => new() { ["path"] = Path.Combine(_dir.Path, "absent.bin") }),
                ("list_assemblies", _ => new() { ["path"] = package }),
                ("list_assemblies", _ => new() { ["path"] = zip }),
                ("search_container", _ => new() { ["path"] = package, ["query"] = "C" }),
                ("search_container", _ => new() { ["path"] = zip, ["query"] = "*", ["kind"] = "file", ["limit"] = 2 }),
                ("search_container", _ => new() { ["path"] = zip, ["query"] = "x", ["kind"] = "no_such_kind" }),
                ("unpack_container", mode => new() { ["path"] = package, ["outputDirectory"] = Path.Combine(_dir.Path, mode) }),
                ("unpack_container", mode => new() { ["path"] = zip, ["outputDirectory"] = Path.Combine(_dir.Path, mode + "-zip"), ["extractOnly"] = true }),
            };
            async Task<List<string>> Run(bool inProcess)
            {
                var mode = inProcess ? "in-process" : "worker";
                await using var session = await Session(inProcess);
                var exit = Fixture("exit.txt", Corvus.Tools.FileOps.FixtureMarker + "exit");
                // Both modes make these calls, so both register the same dump ids; only the worker reads the fixture as a crash.
                var crashes = new[] { await Call(session, "summarize_file", new() { ["path"] = exit }), await Call(session, "open_minidump", new() { ["path"] = exit }) };
                if (!inProcess)
                    foreach (var crash in crashes) Assert.Contains("provider_unavailable", Whole(crash));
                var results = new List<string>();
                foreach (var (tool, args) in calls)
                    results.Add(Whole(await Call(session, tool, args(mode))).Replace(Path.Combine(_dir.Path, mode), "<out>").Replace(JsonEncodedText.Encode(Path.Combine(_dir.Path, mode)).ToString(), "<out>"));
                // The package unpack loaded an assembly: dump reads now name frames from it, so they stay in this process.
                Assert.DoesNotContain("provider_unavailable", Whole(await Call(session, "open_minidump", new() { ["path"] = exit })));
                return results;
            }
            using var pool = Pool();
            using var shared = WorkerPool.UseShared(pool);
            var inProcess = await Run(true);
            var worker = await Run(false);
            for (int i = 0; i < calls.Count; i++)
                Assert.True(inProcess[i] == worker[i], $"{calls[i].Tool} #{i}:\nin process:\n{inProcess[i]}\n\nworker:\n{worker[i]}");
        }
    }

    /// <summary>A read that waits out the call deadline: a class of its own, so the wait overlaps the other worker tests.</summary>
    public sealed class CallDeadline : FileIsolationTestBase
    {
        [Fact]
        public async Task A_reader_past_the_call_deadline_ends_as_a_timeout_and_the_next_read_succeeds()
        {
            var (zip, _, _, _) = Inputs();
            using var pool = Pool();
            using var shared = WorkerPool.UseShared(pool);
            var clock = new ArmedClock();
            await using var session = await Session(false, clock);
            var reading = Call(session, "summarize_file", new() { ["path"] = Fixture("loop.txt", Corvus.Tools.FileOps.FixtureMarker + "loop") });
            // The deadline must find the read looping in the worker, not still starting it.
            await Task.Run(async () => { while (pool.RunningRequests == 0 && !reading.IsCompleted) await Task.Delay(5); }).WaitAsync(TimeSpan.FromMinutes(1));
            await clock.RunUntilAsync(reading);
            var text = Whole(await reading);
            Assert.True(text.Contains("Error (timeout"), Noted(text));
            // The clock stands still from here, so the next read's deadline cannot end it while a new worker starts.
            await ReadsAsync(session, zip);
        }
    }

    /// <summary>Sets CORVUS_IN_PROCESS_PARSING, which every server's options read: runs with nothing in parallel.</summary>
    [Collection(ProcessEnvironmentCollection.Name)]
    public sealed class InProcessParsingVariable
    {
        [Fact]
        public void The_in_process_setting_reads_its_option_and_variable()
        {
            Assert.True(ServerOptions.Parse([ServerOptions.InProcessParsingOption]).InProcessParsing);
            Assert.True(ServerOptions.Switches.ContainsKey(ServerOptions.InProcessParsingOption));
            var before = Environment.GetEnvironmentVariable(ServerOptions.InProcessParsingVariable);
            try
            {
                Environment.SetEnvironmentVariable(ServerOptions.InProcessParsingVariable, "0");
                Assert.False(ServerOptions.Parse([]).InProcessParsing);
                Assert.True(ServerOptions.Parse([ServerOptions.InProcessParsingOption]).InProcessParsing);
                Environment.SetEnvironmentVariable(ServerOptions.InProcessParsingVariable, "1");
                Assert.True(ServerOptions.Parse([]).InProcessParsing);
            }
            finally { Environment.SetEnvironmentVariable(ServerOptions.InProcessParsingVariable, before); }
        }
    }
}
