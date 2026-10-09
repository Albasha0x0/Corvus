using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

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
            Assert.Equal("ndm_checksum", await s.SetNameAsync(rva, "ndm_checksum"));
            Assert.Equal("first line\nsecond", await s.SetCommentAsync(rva, "first line\nsecond"));
            Assert.Contains("ndm_checksum", (await s.DecompileAsync(rva)).Text);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "ndm_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);

            var other = (await s.ListFunctionsAsync()).First(f => f.StartRva != rva && !f.Flags.HasFlag(NativeFunctionFlags.Thunk));
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "ndm_checksum"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "bad name;{}"))).Code);
        }
        await using (var s = await provider.OpenAsync(path, null, Offline))
        {
            Assert.True(s.ReusedDatabase);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "ndm_checksum");
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
    public async Task Timeout_stops_the_worker_and_the_next_request_restarts_it()
    {
        var path = System64;
        var rva = ExportRva(path, Export);
        await using var s = (IdaSession)await Isolated().OpenAsync(path, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(2) });
        await s.SetNameAsync(rva, "ndm_before_timeout"); // unsaved: replayed after the restart
        var pid = s.WorkerProcessId!.Value;
        using var process = Process.GetProcessById(pid);

        var clock = Stopwatch.StartNew();
        var e = await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.True(e.Retryable);
        Assert.NotNull(e.Remediation);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(15), $"timeout took {clock.Elapsed}");
        Assert.True(process.WaitForExit(5000), "timed-out worker still running");

        clock.Restart();
        Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "ndm_before_timeout");
        output.WriteLine($"restart after timeout: {clock.ElapsedMilliseconds} ms");
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
        using var process = Process.GetProcessById(s.WorkerProcessId!.Value);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, cts.Token));
        Assert.True(process.WaitForExit(5000));
        Assert.NotEmpty(await s.ListFunctionsAsync());
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
