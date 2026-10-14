using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>An analysis cache shared by the IDA tests that only read, so each image is analyzed once per run.</summary>
public sealed class IdaCacheFixture : IDisposable
{
    public TempDir Cache { get; } = new();
    private IdaProvider? _provider;

    public IdaProvider Provider => _provider ??= NewProvider();

    public IdaProvider NewProvider() => new(new IdaProviderOptions { CacheRoot = Cache.Path });

    public void Dispose()
    {
        _provider?.Dispose();
        Cache.Dispose();
    }
}

/// <summary>
/// The IDA provider against real system DLLs. Needs IDA Pro 9+ with idalib and a 64-bit Python; skipped otherwise.
/// One class so that tests sharing a cache entry never run in parallel. Tests that rename, or need a cold cache,
/// use an isolated provider.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeIdaProviderTests(ITestOutputHelper output, IdaCacheFixture shared) : IClassFixture<IdaCacheFixture>, IDisposable
{
    private const string Dll = "imagehlp.dll";
    private const string Export = "CheckSumMappedFile";
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };

    private readonly List<IDisposable> _owned = [];

    private IdaProvider Provider => shared.Provider;

    /// <summary>A provider with its own empty cache (under a path with spaces and parentheses), disposed with the test.</summary>
    private IdaProvider Isolated()
    {
        var dir = new TempDir();
        var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = Path.Combine(dir.Path, "cache (with spaces)") });
        _owned.Add(provider);
        _owned.Add(dir);
        return provider;
    }

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
    }

    public static string System64 => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", Dll);
    public static string System32OnWow => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", Dll);

    [IdaFact]
    public async Task Probe_reports_version()
    {
        var a = await Provider.ProbeAsync();
        Assert.True(a.IsAvailable, a.Reason);
        Assert.StartsWith("9.", a.Details["version"]);
        output.WriteLine(string.Join("\n", a.Details.Select(d => $"{d.Key}: {d.Value}")));
    }

    [IdaFact]
    public Task X64_open_list_decompile_disassemble_xrefs() => Walk(System64, NativeArch.X64);

    [IdaFact]
    public async Task The_function_list_is_kept_until_an_edit()
    {
        await using var s = (IdaSession)await Isolated().OpenAsync(System64, null, Offline);
        var exportRva = ExportRva(System64, Export);
        var first = await s.ListFunctionsAsync(withReferences: true);
        Assert.Same(first, await s.ListFunctionsAsync(withReferences: true));
        Assert.Same(first, await s.ListFunctionsAsync(withReferences: false)); // a list with references serves one without
        await s.SetNameAsync(exportRva, "kept_list_renamed");
        var after = await s.ListFunctionsAsync(withReferences: false);
        Assert.NotSame(first, after);
        Assert.Equal("kept_list_renamed", after.Single(f => f.StartRva == exportRva).Name);
        await s.RunScriptAsync("1"); // scripts may change anything
        Assert.NotSame(after, await s.ListFunctionsAsync(withReferences: false));

        var strings = await s.ListStringsAsync(1000);
        Assert.NotEmpty(strings);
        Assert.Same(strings, await s.ListStringsAsync(1000));
        await s.SetCommentAsync(exportRva, "edit");
        Assert.NotSame(strings, await s.ListStringsAsync(1000));
    }

    [IdaFact]
    public async Task References_to_several_addresses_come_in_one_request_as_one_at_a_time()
    {
        await using var s = await Provider.OpenAsync(System64, null, Offline);
        var starts = (await s.ListFunctionsAsync()).Select(f => f.StartRva).Take(40).ToList();
        var many = await s.GetXrefsToManyAsync(starts);
        Assert.Equal(starts.Count, many.Count);
        for (int i = 0; i < starts.Count; i++)
            Assert.Equal(await s.GetXrefsToAsync(starts[i]), many[i]);
        Assert.Contains(many, x => x.Count > 0);
    }

    [IdaFact]
    public async Task A_rename_shows_in_the_callers_pseudocode_decompiled_before()
    {
        await using var s = await Isolated().OpenAsync(System64, null, Offline);
        var functions = await s.ListFunctionsAsync();
        var starts = functions.Select(f => f.StartRva).ToHashSet();
        // a function with a caller that is itself a function
        var (callee, caller) = functions.Select(f => (f.StartRva, Caller: s.GetXrefsToAsync(f.StartRva).GetAwaiter().GetResult()
                .FirstOrDefault(x => x.Kind == NativeXrefKind.Call && x.FromFunctionRva is { } c && starts.Contains(c))?.FromFunctionRva))
            .First(p => p.Caller != null);
        Assert.DoesNotContain("renamed_for_callers", (await s.DecompileAsync(caller!.Value)).Text);
        await s.ApplyNamesAsync([new NativeNameItem(callee, "renamed_for_callers", null)]);
        Assert.Contains("renamed_for_callers", (await s.DecompileAsync(caller.Value)).Text);
        Assert.Contains("renamed_for_callers", (await s.DecompileAsync(callee)).Text);
    }

    [IdaFact]
    public async Task A_deep_cache_folder_opens_and_a_too_deep_one_names_the_path_length()
    {
        var dir = new TempDir();
        _owned.Add(dir);
        var input = Path.Combine(dir.Path, "Vendor.Product.Component.Library.Native.amd64.dll");
        File.Copy(System64, input);
        string Root(int length)
        {
            var r = Path.Combine(dir.Path, "c");
            while (r.Length < length) r = Path.Combine(r, new string('d', Math.Max(1, Math.Min(40, length - r.Length - 1))));
            return r;
        }
        var deep = new IdaProvider(new IdaProviderOptions { CacheRoot = Root(150) });
        _owned.Add(deep);
        await using (var s = await deep.OpenAsync(input, null, Offline))
            Assert.NotEmpty(await s.ListFunctionsAsync());

        var tooDeep = new IdaProvider(new IdaProviderOptions { CacheRoot = Root(230) });
        _owned.Add(tooDeep);
        var e = await Assert.ThrowsAsync<ToolError>(() => tooDeep.OpenAsync(input, null, Offline));
        output.WriteLine(e.Message + "\n" + e.Remediation);
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("characters", e.Message);
        Assert.Contains("CORVUS_DATA_DIR", e.Remediation);
    }

    [IdaFact]
    public Task X86_open_list_decompile_disassemble_xrefs()
    {
        if (!File.Exists(System32OnWow)) return Task.CompletedTask;
        return Walk(System32OnWow, NativeArch.X86);
    }

    private async Task Walk(string path, NativeArch arch)
    {
        var exportRva = ExportRva(path, Export);
        var clock = Stopwatch.StartNew();
        await using var s = await Provider.OpenAsync(path, null, Offline);
        output.WriteLine($"{arch} open: {s.OpenTime.TotalMilliseconds:0} ms (reused {s.ReusedDatabase})");
        Assert.Equal(arch, s.Arch);
        Assert.Equal(HeaderImageBase(path), s.ImageBase);
        Assert.Equal(AnalysisCache.HashFile(path), s.Sha256);
        Assert.True(s.DecompilerAvailable);
        Assert.False(File.Exists(path + ".i64"));
        Assert.False(File.Exists(Path.ChangeExtension(path, ".i64")));

        var functions = await s.ListFunctionsAsync();
        output.WriteLine($"{functions.Count} functions");
        Assert.True(functions.Count > 50);
        var fn = Assert.Single(functions, f => f.StartRva == exportRva);
        Assert.Contains(Export, fn.Name);
        Assert.All(functions, f => Assert.True(f.EndRva > f.StartRva));

        clock.Restart();
        var d = await s.DecompileAsync(exportRva);
        output.WriteLine($"decompile {Export}: {clock.ElapsedMilliseconds} ms, {d.Text.Split('\n').Length} lines\n{d.Text}");
        Assert.Equal(exportRva, d.StartRva);
        Assert.Contains(Export, d.Text);
        Assert.Contains("{", d.Text);
        Assert.NotEmpty(d.LineAddresses);
        var lineCount = d.Text.Split('\n').Length;
        Assert.All(d.LineAddresses, l => Assert.InRange(l.Line, 0, lineCount - 1));
        Assert.Contains(d.LineAddresses, l => l.Rva >= fn.StartRva && l.Rva < fn.EndRva);

        // An address inside the function decompiles the same function.
        var inner = await s.DecompileAsync(exportRva + 1);
        Assert.Equal(exportRva, inner.StartRva);

        var asm = await s.DisassembleAsync(exportRva);
        Assert.Equal(exportRva, asm.StartRva);
        Assert.NotEmpty(asm.Instructions);
        var first = asm.Instructions[0];
        Assert.Equal(exportRva, first.Rva);
        Assert.Equal(FileBytes(path, first.Rva, first.Bytes.Length), first.Bytes);
        Assert.True(asm.Instructions.Zip(asm.Instructions.Skip(1)).All(p => p.First.Rva < p.Second.Rva));

        // Call edges agree in both directions.
        var calls = (await s.GetXrefsFromAsync(exportRva, wholeFunction: true)).Where(x => x.Kind == NativeXrefKind.Call).ToList();
        Assert.All(calls, c => Assert.Equal(exportRva, c.FromFunctionRva));
        var starts = functions.Select(f => f.StartRva).ToHashSet();
        var call = calls.FirstOrDefault(c => starts.Contains(c.ToRva))
            ?? throw new Xunit.Sdk.XunitException($"{Export} has no direct call to a function in the image");
        var to = await s.GetXrefsToAsync(call.ToRva);
        Assert.Contains(to, x => x.FromRva == call.FromRva && x.Kind == NativeXrefKind.Call && x.FromFunctionRva == exportRva);

        var single = await s.GetXrefsFromAsync(call.FromRva);
        Assert.Contains(single, x => x.ToRva == call.ToRva);

        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => s.DecompileAsync(0x10))).Code);
    }

    [IdaFact]
    public async Task Names_and_comments_round_trip_and_persist()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        var provider = Isolated();
        await using (var s = await provider.OpenAsync(path, null, Offline))
        {
            Assert.Equal("sample_checksum", await s.SetNameAsync(rva, "sample_checksum"));
            Assert.Equal("first line\nsecond", await s.SetCommentAsync(rva, "first line\nsecond"));
            Assert.Contains("sample_checksum", (await s.DecompileAsync(rva)).Text);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);

            var other = (await s.ListFunctionsAsync()).First(f => f.StartRva != rva && !f.Flags.HasFlag(NativeFunctionFlags.Thunk));
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "sample_checksum"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "bad name;{}"))).Code);
        }
        await using (var s = await provider.OpenAsync(path, null, Offline))
        {
            Assert.True(s.ReusedDatabase);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);
            Assert.Equal("", await s.SetCommentAsync(rva, ""));
        }
    }

    [IdaFact]
    public async Task Reopen_uses_the_saved_database_and_is_faster()
    {
        var timings = new List<string>();
        var provider = Isolated();
        foreach (var path in new[] { System64, System32OnWow }.Where(File.Exists))
        {
            TimeSpan cold, warm;
            var stages = new StageLog();
            await using (var s = await provider.OpenAsync(path, null, Offline with { Progress = stages }))
            {
                Assert.False(s.ReusedDatabase);
                cold = s.OpenTime;
                var clock = Stopwatch.StartNew();
                await s.DecompileAsync(ExportRva(path, Export));
                timings.Add($"{path}: first decompile {clock.ElapsedMilliseconds} ms; cold stages {stages}");
                clock.Restart();
                await s.DecompileAsync(ExportRva(path, Export));
                timings.Add($"{path}: repeated decompile {clock.ElapsedMilliseconds} ms");
            }
            stages = new StageLog();
            await using (var s = await provider.OpenAsync(path, null, Offline with { Progress = stages }))
            {
                Assert.True(s.ReusedDatabase);
                warm = s.OpenTime;
            }
            timings.Add($"{path}: cold open {cold.TotalMilliseconds:0} ms, cached open {warm.TotalMilliseconds:0} ms; cached stages {stages}");
            Assert.True(warm < cold, $"cached open {warm} not faster than cold {cold}");
        }
        output.WriteLine(string.Join("\n", timings));
    }

    [IdaFact]
    public async Task Disposing_the_provider_kills_the_worker()
    {
        var provider = shared.NewProvider();
        var s = (IdaSession)await provider.OpenAsync(System64, null, Offline);
        var pid = s.WorkerProcessId ?? throw new Xunit.Sdk.XunitException("no worker");
        var tree = s.Worker!.TreeProcessIds();
        Assert.Contains(pid, tree);
        using var process = Process.GetProcessById(pid);
        provider.Dispose();
        Assert.True(process.WaitForExit(10_000), "worker still running after dispose");
        Assert.False(s.IsOpen);
        Assert.Equal(ErrorCode.NotLoaded, (await Assert.ThrowsAsync<ToolError>(() => s.ListFunctionsAsync())).Code);
    }

    [IdaFact]
    public async Task Timeout_returns_a_partial_result_and_keeps_the_worker()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        await using var s = (IdaSession)await Isolated().OpenAsync(path, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(3) });
        await s.SetNameAsync(rva, "sample_before_timeout");
        var pid = s.WorkerProcessId!.Value;

        var clock = Stopwatch.StartNew();
        var r = await s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, default);
        Assert.Contains(r.GetProperty("partial").GetString(), (string[])["deadline", "cancelled"]);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"the partial answer took {clock.Elapsed}");
        Assert.Equal(pid, s.WorkerProcessId);

        // a script stops at the deadline as well
        var e = await Assert.ThrowsAsync<ToolError>(() => s.RunScriptAsync("import time\nwhile True: time.sleep(0.01)"));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Equal(pid, s.WorkerProcessId);
        Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_before_timeout");
    }

    [IdaFact]
    public async Task A_users_database_beside_the_input_is_copied_when_it_was_made_from_that_input()
    {
        var dir = new TempDir();
        _owned.Add(dir);
        var input = Path.Combine(dir.Path, "imagehlp.dll");
        File.Copy(System64, input);
        var rva = ExportRva(input, Export);
        // the user's database, as the IDA GUI leaves it next to the file
        await using (var made = (IdaSession)await Isolated().OpenAsync(input, null, Offline))
        {
            await made.SetNameAsync(rva, "named_in_the_users_database");
            await made.RunScriptAsync("ida_netnode.netnode('$ corvus stamps', 0, False).kill()"); // IDA's own record of the input remains
            await made.CallAsync("save_as", IdaProvider.Args(("path", Path.Combine(dir.Path, "imagehlp.i64"))), default);
        }
        var user = Path.Combine(dir.Path, "imagehlp.i64");
        var before = AnalysisCache.HashFile(user);

        await using (var s = (IdaSession)await Isolated().OpenAsync(input, null, Offline))
        {
            output.WriteLine(s.DatabaseNote);
            Assert.True(s.ReusedDatabase);
            Assert.Contains("copy of " + user, s.DatabaseNote);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "named_in_the_users_database");
            await s.SetNameAsync(rva, "changed_in_the_copy");
            await s.SaveAsync();
        }
        Assert.Equal(before, AnalysisCache.HashFile(user)); // never written

        // beside other bytes it is not used: the image is analyzed from scratch
        var other = Path.Combine(dir.Path, "other", "imagehlp.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(other)!);
        var bytes = File.ReadAllBytes(System64);
        bytes[^1] ^= 0xFF;
        File.WriteAllBytes(other, bytes);
        File.Copy(user, Path.ChangeExtension(other, ".i64"));
        await using (var s = (IdaSession)await Isolated().OpenAsync(other, null, Offline))
        {
            output.WriteLine(s.DatabaseNote);
            Assert.False(s.ReusedDatabase);
            Assert.Contains("was not used", s.DatabaseNote);
            Assert.DoesNotContain(await s.ListFunctionsAsync(), f => f.Name == "named_in_the_users_database");
        }
    }

    [IdaFact]
    public async Task A_tight_script_loop_stops_in_place_at_its_limit()
    {
        var dir = new TempDir();
        _owned.Add(dir);
        // a long grace: an answer before it means the worker stopped the work itself rather than being killed
        var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path, CancelGrace = TimeSpan.FromSeconds(60) });
        _owned.Add(provider);
        await using (var s = (IdaSession)await provider.OpenAsync(System64, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(3) }))
        {
            var pid = s.WorkerProcessId!.Value;
            var clock = Stopwatch.StartNew();
            var e = await Assert.ThrowsAsync<ToolError>(() => s.RunScriptAsync("x = 0\nwhile True:\n    try:\n        x += 1\n    except Exception:\n        pass"));
            output.WriteLine($"tight loop: {e.Code} after {clock.Elapsed.TotalSeconds:0.0} s: {e.Message}");
            Assert.Equal(ErrorCode.Timeout, e.Code);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(15), $"took {clock.Elapsed}");
            Assert.Equal(pid, s.WorkerProcessId);
            Assert.Equal("2", (await s.RunScriptAsync("1 + 1")).Result);
        }
    }

    [IdaFact]
    public async Task Request_that_ignores_cancel_is_killed_and_the_next_request_restarts()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        var dir = new TempDir();
        _owned.Add(dir);
        var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path, CancelGrace = TimeSpan.FromSeconds(1) });
        _owned.Add(provider);
        await using var s = (IdaSession)await provider.OpenAsync(path, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(2) });
        await s.SetNameAsync(rva, "sample_before_kill"); // unsaved: replayed after the restart
        var pid = s.WorkerProcessId!.Value;
        using var process = Process.GetProcessById(pid);

        var clock = Stopwatch.StartNew();
        var e = await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60, ["ignore_cancel"] = true }, default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("stopped", e.Message);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(15), $"timeout took {clock.Elapsed}");
        Assert.True(process.WaitForExit(5000), "the worker that ignored the cancel is still running");

        Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_before_kill");
        Assert.NotEqual(pid, s.WorkerProcessId);
    }

    [IdaFact]
    public async Task Worker_crash_is_reported_with_stderr_and_recovered()
    {
        await using var s = (IdaSession)await Provider.OpenAsync(System64, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(60) });
        var pid = s.WorkerProcessId!.Value;
        var running = s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, default);
        await Task.Delay(500);
        Process.GetProcessById(pid).Kill();
        var e = await Assert.ThrowsAsync<ToolError>(() => running);
        output.WriteLine(e.Render("test"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("exited", e.Message);
        Assert.NotEmpty(await s.ListFunctionsAsync());
    }

    [IdaFact]
    public async Task Cancellation_stops_the_running_request()
    {
        await using var s = (IdaSession)await Provider.OpenAsync(System64, null, Offline);
        var pid = s.WorkerProcessId!.Value;
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        var clock = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, cts.Token));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"cancel took {clock.Elapsed}");
        // the worker stopped the request itself and keeps the database open
        Assert.Equal(pid, s.WorkerProcessId);
        Assert.NotEmpty(await s.ListFunctionsAsync());
        Assert.Equal(pid, s.WorkerProcessId);
    }

    [IdaFact]
    public async Task Session_state_answers_while_the_worker_is_busy()
    {
        await using var s = (IdaSession)await Provider.OpenAsync(System64, null, Offline);
        var running = s.CallAsync("sleep", new JsonObject { ["seconds"] = 3 }, default);
        await Task.Delay(500);
        var clock = Stopwatch.StartNew();
        var state = Assert.Single(Provider.SessionStates(), x => x.ImagePath == System64);
        Assert.True(clock.ElapsedMilliseconds < 100, $"state took {clock.ElapsedMilliseconds} ms");
        Assert.Equal(("ida", "busy", "sleep", s.WorkerProcessId), (state.Engine, state.State, state.BusyOp, state.WorkerPid));
        Assert.Equal(s.DatabasePath, state.Database);
        await running;
        Assert.Equal("idle", Provider.SessionStates().Single(x => x.ImagePath == System64).State);
    }

    [IdaFact]
    public async Task Open_without_auto_analysis_keeps_its_own_database_and_decompiles_on_demand()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        var provider = Isolated();
        await using (var s = (IdaSession)await provider.OpenAsync(path, null, Offline with { Analysis = EngineAnalysis.None }))
        {
            Assert.False(s.AnalysisComplete);
            Assert.Contains("noauto", Path.GetFileName(s.DatabasePath));
            Assert.Contains("no auto-analysis", ((INativeDecompilerSession)s).DatabaseNote);
            var decompiled = await s.DecompileAsync(rva);
            Assert.Equal(rva, decompiled.StartRva);
            Assert.True(s.OpenTime < TimeSpan.FromSeconds(60));
        }
        // the full-analysis database of the same bytes is untouched (never made here)
        var sha = AnalysisCache.HashFile(path);
        Assert.False(File.Exists(provider.SavedDatabasePath(sha, "nopdb")));
        Assert.True(File.Exists(provider.SavedDatabasePath(sha, "nopdb-noauto")));
    }

    [IdaFact]
    public async Task A_database_held_by_another_process_opens_as_a_read_only_snapshot()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        var dir = new TempDir();
        _owned.Add(dir);
        using var owner = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path });
        await using var held = (IdaSession)await owner.OpenAsync(path, null, Offline);
        await held.SetNameAsync(rva, "sample_owner_name");
        await held.SaveAsync();
        // as if another server process held the entry
        var entryDir = Path.GetDirectoryName(held.DatabasePath)!;
        File.WriteAllText(Path.Combine(entryDir, ".owner"), "4242");

        using var second = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path });
        string snapshotDb;
        await using (var s = (IdaSession)await second.OpenAsync(path, null, Offline))
        {
            snapshotDb = s.DatabasePath;
            Assert.NotEqual(held.DatabasePath, snapshotDb);
            Assert.True(s.ReusedDatabase);
            Assert.Contains("read-only snapshot", ((INativeDecompilerSession)s).DatabaseNote);
            Assert.Contains("4242", ((INativeDecompilerSession)s).DatabaseNote);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_owner_name");
            await s.SetNameAsync(rva, "sample_snapshot_name");
            Assert.Equal(0, s.UnsavedCount);
            Assert.Contains("read-only snapshot", Assert.Single(second.SessionStates()).Note);
        }
        Assert.False(Directory.Exists(Path.GetDirectoryName(snapshotDb)));
        Assert.Contains(await held.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_owner_name");

        // no saved database of the asked profile: the conflict names the owner
        File.WriteAllText(Path.Combine(entryDir, ".owner"), "4242");
        var e = await Assert.ThrowsAsync<ToolError>(() => second.OpenAsync(path, null, new NativeOpenOptions()));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Contains("process 4242", e.Message);
    }

    [IdaFact]
    public async Task A_session_reports_the_IDA_version_in_the_availability()
    {
        var provider = Isolated();
        Assert.StartsWith("not probed", provider.CheckAvailability().Details["version"]);
        await using var s = await provider.OpenAsync(System64, null, Offline);
        Assert.StartsWith("9.", provider.CheckAvailability().Details["version"]);
    }

    [IdaFact]
    public async Task The_worker_runs_in_batch_mode()
    {
        await using var s = await Provider.OpenAsync(System64, null, Offline);
        // idc.batch returns the mode before the call: already on
        Assert.Contains((await s.RunScriptAsync("import idc\nidc.batch(1)")).Result, (string[])["1", "True"]);
    }

    [IdaFact]
    public async Task Concurrent_requests_are_serialized()
    {
        await using var s = await Provider.OpenAsync(System64, null, Offline);
        var functions = (await s.ListFunctionsAsync()).Where(f => !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Take(12).ToList();
        var results = await Task.WhenAll(functions.Select(f => Task.Run(() => s.DisassembleAsync(f.StartRva))));
        Assert.Equal(functions.Select(f => f.StartRva), results.Select(r => r.StartRva));
    }

    [IdaFact]
    public async Task Bad_inputs_fail_with_typed_errors()
    {
        using var tmp = new TempDir();
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(tmp.File("missing.dll")))).Code);

        var garbage = tmp.File("garbage.dll");
        File.WriteAllBytes(garbage, [.. "MZ"u8, .. Enumerable.Range(0, 4096).Select(i => (byte)(i * 7))]);
        Assert.Equal(ErrorCode.MalformedInput, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(garbage))).Code);

        var text = tmp.File("text.dll");
        File.WriteAllText(text, "not a PE file");
        Assert.Equal(ErrorCode.MalformedInput, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(text))).Code);

        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(System64, new string('0', 64), Offline))).Code);

        // Headers intact, sections cut off: IDA loads what is there or fails with a typed error, never hangs.
        var truncated = tmp.File("truncated.dll");
        File.WriteAllBytes(truncated, File.ReadAllBytes(System64)[..4096]);
        try
        {
            await using var s = await Provider.OpenAsync(truncated, null, Offline with { OpenTimeout = TimeSpan.FromMinutes(2) });
            output.WriteLine($"truncated image opened: {(await s.ListFunctionsAsync()).Count} functions");
        }
        catch (ToolError e)
        {
            output.WriteLine(e.Render("test"));
            Assert.Contains(e.Code, new[] { ErrorCode.MalformedInput, ErrorCode.ProviderUnavailable, ErrorCode.Failed });
        }
    }

    [IdaFact]
    public async Task Rebase_keeps_rvas_stable()
    {
        await using var s = (IdaSession)await Provider.OpenAsync(System64, null, Offline);
        var before = await s.ListFunctionsAsync();
        var moved = s.ImageBase + 0x1000_0000;
        var r = await s.CallAsync("rebase", new JsonObject { ["imagebase"] = moved }, default);
        Assert.Equal(moved, r.GetProperty("imagebase").GetUInt64());
        Assert.Equal(before.Select(f => (f.StartRva, f.EndRva)), (await s.ListFunctionsAsync()).Select(f => (f.StartRva, f.EndRva)));
        r = await s.CallAsync("rebase", new JsonObject { ["imagebase"] = s.ImageBase }, default);
        Assert.Equal(s.ImageBase, r.GetProperty("imagebase").GetUInt64());
    }

    [IdaFact]
    public async Task Managed_assembly_is_unsupported()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(Env.FixturePath, null, Offline));
        output.WriteLine(e.Render("test"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.NotNull(e.Remediation);
        // The failed open released its cache entry: a second attempt fails the same way, not with Conflict.
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(Env.FixturePath, null, Offline))).Code);
    }

    [IdaFact]
    public async Task Same_image_cannot_be_open_twice()
    {
        await using var s = await Provider.OpenAsync(System64, null, Offline);
        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(System64, null, Offline))).Code);
    }

    [IdaFact]
    public async Task Leftovers_of_a_killed_worker_do_not_break_the_next_open()
    {
        var provider = Isolated();
        var s = (IdaSession)await provider.OpenAsync(System64, null, Offline);
        var db = s.DatabasePath;
        Process.GetProcessById(s.WorkerProcessId!.Value).Kill();
        await Task.Delay(500);
        output.WriteLine(string.Join(", ", Directory.GetFiles(Path.GetDirectoryName(db)!).Select(Path.GetFileName)));
        Assert.True(File.Exists(db), "the first analysis is saved as soon as it finishes");
        s.Dispose();

        // Unpacked components of the killed worker are discarded; the saved .i64 is reused.
        await using (var again = await provider.OpenAsync(System64, null, Offline))
        {
            Assert.True(again.ReusedDatabase);
            Assert.NotEmpty(await again.ListFunctionsAsync());
        }

        // A damaged .i64 is rebuilt from the input copy.
        File.WriteAllBytes(db, Encoding.ASCII.GetBytes("not a database"));
        await using var rebuilt = await provider.OpenAsync(System64, null, Offline);
        Assert.False(rebuilt.ReusedDatabase);
        Assert.NotEmpty(await rebuilt.ListFunctionsAsync());
    }

    [IdaFact]
    public async Task A_long_journal_is_saved_instead_of_growing()
    {
        var dir = new TempDir();
        _owned.Add(dir);
        var provider = new IdaProvider(new IdaProviderOptions { CacheRoot = dir.Path, JournalSaveThreshold = 2 });
        _owned.Add(provider);
        var rva = ExportRva(System64, Export);
        await using var s = (IdaSession)await provider.OpenAsync(System64, null, Offline);
        await s.SetNameAsync(rva, "sample_first");
        Assert.Equal(1, s.UnsavedCount);
        await s.SetCommentAsync(rva, "saved with the second edit");
        Assert.Equal(0, s.UnsavedCount);
        // nothing to replay: the restarted worker reads both from the saved database
        await WorkerKill.KillAsync(s);
        Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_first");
        Assert.Equal("saved with the second edit", (await s.DisassembleAsync(rva)).Instructions[0].Comment);
    }

    [IdaFact]
    public async Task Database_is_keyed_by_the_IDA_build_and_rebuilt_when_made_from_other_input()
    {
        var provider = Isolated();
        string dbA;
        await using (var a = (IdaSession)await provider.OpenAsync(System64, null, Offline))
        {
            dbA = a.DatabasePath;
            Assert.Matches(@"^ida-nopdb-\d+(\.\d+)+-[0-9a-f]{12}\.i64$", Path.GetFileName(dbA));
            Assert.Equal(dbA, provider.SavedDatabasePath(a.Sha256, "nopdb"));
        }
        await using (var a = await provider.OpenAsync(System64, null, Offline)) Assert.True(a.ReusedDatabase);

        var other = Path.Combine(Environment.SystemDirectory, "version.dll");
        string dbB;
        await using (var b = (IdaSession)await provider.OpenAsync(other, null, Offline)) dbB = b.DatabasePath;
        File.Copy(dbA, dbB, overwrite: true); // a database of other input under this input's key
        await using var again = await provider.OpenAsync(other, null, Offline);
        Assert.False(again.ReusedDatabase);
        var export = ExportRva(other, "GetFileVersionInfoSizeW");
        Assert.Contains(await again.ListFunctionsAsync(), f => f.StartRva == export);
    }

    /// <summary>RVA of a named export, read from the export directory.</summary>
    internal static uint ExportRva(string path, string name)
    {
        using var pe = new PEReader(File.OpenRead(path));
        var dir = pe.PEHeaders.PEHeader!.ExportTableDirectory;
        var r = pe.GetSectionData(dir.RelativeVirtualAddress).GetReader();
        r.Offset = 20; // NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
        var functionCount = r.ReadInt32();
        var nameCount = r.ReadInt32();
        var functions = r.ReadInt32();
        var names = r.ReadInt32();
        var ordinals = r.ReadInt32();
        for (int i = 0; i < nameCount; i++)
        {
            var nameRva = pe.GetSectionData(names + i * 4).GetReader().ReadInt32();
            var nr = pe.GetSectionData(nameRva).GetReader();
            var sb = new StringBuilder();
            for (byte b; (b = nr.ReadByte()) != 0;) sb.Append((char)b);
            if (sb.ToString() != name) continue;
            var ordinal = pe.GetSectionData(ordinals + i * 2).GetReader().ReadUInt16();
            Assert.InRange(ordinal, 0, functionCount - 1);
            return pe.GetSectionData(functions + ordinal * 4).GetReader().ReadUInt32();
        }
        throw new Xunit.Sdk.XunitException($"{name} is not exported by {path}");
    }

    private static ulong HeaderImageBase(string path)
    {
        using var pe = new PEReader(File.OpenRead(path));
        return pe.PEHeaders.PEHeader!.ImageBase;
    }

    private static byte[] FileBytes(string path, uint rva, int count)
    {
        using var pe = new PEReader(File.OpenRead(path));
        return pe.GetSectionData((int)rva).GetReader().ReadBytes(count);
    }
}

/// <summary>Records open stages synchronously (Progress&lt;T&gt; would post them later).</summary>
internal sealed class StageLog : IProgress<NativeProviderProgress>
{
    private readonly List<string> _stages = [];

    public void Report(NativeProviderProgress value)
    {
        lock (_stages) _stages.Add($"{value.Stage}@{value.Elapsed.TotalMilliseconds:0}");
    }

    public override string ToString()
    {
        lock (_stages) return string.Join(" ", _stages);
    }
}

internal static class WorkerKill
{
    /// <summary>
    /// Kills a session's worker process and waits until its connection has seen it go, so the next call restarts it
    /// (a call sent before that goes to the dying worker and fails).
    /// </summary>
    public static async Task KillAsync(object session)
    {
        var connection = ((WorkerSessionBase)session).Worker ?? throw new Xunit.Sdk.XunitException("the session has no worker");
        using (var process = Process.GetProcessById(connection.ProcessId)) process.Kill();
        await connection.Closed.WaitAsync(TimeSpan.FromMinutes(1));
    }
}

/// <summary>Runs only when an IDA install with idalib and a usable 64-bit Python are present (checked once per run).</summary>
public sealed class IdaFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> SkipReason = new(() =>
    {
        if (!OperatingSystem.IsWindows()) return "IDA provider tests use Windows system DLLs.";
        using var probe = new IdaProvider(new IdaProviderOptions { CacheRoot = Path.GetTempPath() });
        var a = probe.CheckAvailability();
        return a.IsAvailable ? null : $"IDA provider unavailable: {a.Reason}";
    });

    public IdaFactAttribute()
    {
        if (IdaInstallation.Locate(null, out var reason, out _) == null) Skip = reason;
        else if (SkipReason.Value is { } r) Skip = r;
    }
}
