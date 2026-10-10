using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ghidra;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>A cache and a copy of the sample DLL shared by the Ghidra tests that only read, so the image is analyzed once per run.</summary>
public sealed class GhidraCacheFixture : IDisposable
{
    public TempDir Cache { get; } = new();
    private GhidraProvider? _provider;

    public GhidraProvider Provider => _provider ??= NewProvider();

    public GhidraProvider NewProvider() => new(new GhidraProviderOptions { CacheRoot = Cache.File("cache") });

    /// <summary>A private copy of a system DLL: the engine must never write next to its input.</summary>
    public string Sample => _sample ??= Copy(NativeIdaProviderTests.System64);
    private string? _sample;

    public string Copy(string path)
    {
        var dir = Cache.File("input-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        var copy = Path.Combine(dir, Path.GetFileName(path));
        File.Copy(path, copy);
        return copy;
    }

    public void Dispose()
    {
        _provider?.Dispose();
        Cache.Dispose();
    }
}

/// <summary>
/// The Ghidra provider against a real Ghidra (NDM_GHIDRA_DIR) and JDK, on copies of system DLLs; skipped otherwise.
/// One class so tests sharing a cache entry never run in parallel; tests that write or need a cold cache use an
/// isolated provider.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeGhidraProviderTests(ITestOutputHelper output, GhidraCacheFixture shared) : IClassFixture<GhidraCacheFixture>, IDisposable
{
    private const string Export = "CheckSumMappedFile";
    private static readonly NativeOpenOptions Offline = new() { Symbols = SymbolMode.Off };
    private readonly List<IDisposable> _owned = [];

    private GhidraProvider Provider => shared.Provider;

    private GhidraProvider Isolated()
    {
        var dir = new TempDir();
        var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = Path.Combine(dir.Path, "cache (with spaces)") });
        _owned.Add(provider);
        _owned.Add(dir);
        return provider;
    }

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
    }

    [GhidraFact]
    public async Task Probe_builds_the_worker_and_reports_the_version()
    {
        var a = await Provider.ProbeAsync();
        Assert.True(a.IsAvailable, a.Reason);
        Assert.StartsWith("12.", a.Details["version"]);
        output.WriteLine(string.Join("\n", a.Details.Select(d => $"{d.Key}: {d.Value}")));
        var workers = Directory.GetDirectories(Provider.Directories.Workers);
        Assert.Contains(Directory.GetFiles(Assert.Single(workers)), f => f.EndsWith("ndm-ghidra-worker.jar", StringComparison.Ordinal));
    }

    [GhidraFact]
    public async Task Open_list_decompile_disassemble_blocks_xrefs()
    {
        var path = shared.Sample;
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = (GhidraSession)await Provider.OpenAsync(path, null, Offline);
        output.WriteLine($"open: {s.OpenTime.TotalMilliseconds:0} ms (reused {s.ReusedDatabase}, complete {s.AnalysisComplete}, {s.FunctionCount} functions, {s.Language})");
        foreach (var w in s.Warnings) output.WriteLine("warning: " + w);
        Assert.Empty(s.Warnings);
        Assert.Equal(NativeArch.X64, s.Arch);
        Assert.Equal(HeaderImageBase(path), s.ImageBase);
        Assert.Equal(AnalysisCache.HashFile(path), s.Sha256);
        Assert.True(s.DecompilerAvailable);
        Assert.True(s.AnalysisComplete);
        Assert.Equal([Path.GetFileName(path)], Directory.GetFileSystemEntries(Path.GetDirectoryName(path)!).Select(Path.GetFileName));

        var clock = Stopwatch.StartNew();
        var functions = await s.ListFunctionsAsync(withReferences: true);
        output.WriteLine($"{functions.Count} functions in {clock.ElapsedMilliseconds} ms");
        Assert.True(functions.Count > 150, $"only {functions.Count} functions: analysis did not run"); // GhidraProject.analyze finds far fewer
        var fn = Assert.Single(functions, f => f.StartRva == exportRva);
        Assert.Contains(Export, fn.Name);
        Assert.All(functions, f => Assert.True(f.EndRva > f.StartRva));
        Assert.Contains(functions, f => f.References > 0);

        clock.Restart();
        var d = await s.DecompileAsync(exportRva);
        output.WriteLine($"decompile {Export}: {clock.ElapsedMilliseconds} ms, {d.Text.Split('\n').Length} lines\n{d.Text}");
        Assert.Equal(exportRva, d.StartRva);
        Assert.Contains(Export, d.Text);
        Assert.Contains("{", d.Text);
        var lineCount = d.Text.Split('\n').Length;
        Assert.NotEmpty(d.LineAddresses);
        Assert.All(d.LineAddresses, l => Assert.InRange(l.Line, 0, lineCount - 1));
        Assert.Contains(d.LineAddresses, l => l.Rva >= fn.StartRva && l.Rva < fn.EndRva);
        clock.Restart();
        Assert.Equal(exportRva, (await s.DecompileAsync(exportRva + 1)).StartRva);
        output.WriteLine($"repeated decompile: {clock.ElapsedMilliseconds} ms");

        var asm = await s.DisassembleAsync(exportRva);
        Assert.Equal(exportRva, asm.StartRva);
        var first = asm.Instructions[0];
        Assert.Equal(exportRva, first.Rva);
        Assert.Equal(FileBytes(path, first.Rva, first.Bytes.Length), first.Bytes);
        Assert.True(asm.Instructions.Zip(asm.Instructions.Skip(1)).All(p => p.First.Rva < p.Second.Rva));

        var range = await s.DisassembleRangeAsync(exportRva, 5);
        Assert.Equal(5, range.Instructions.Count);
        Assert.Equal(asm.Instructions.Take(5).Select(i => i.Rva), range.Instructions.Select(i => i.Rva));

        var graph = await s.GetBlocksAsync(exportRva);
        Assert.Contains(graph.Blocks, b => b.StartRva == exportRva);
        Assert.Contains(graph.Blocks, b => b.Kind == "ret");
        Assert.All(graph.Blocks, b => Assert.True(b.EndRva > b.StartRva && b.Instructions > 0));

        var calls = (await s.GetXrefsFromAsync(exportRva, wholeFunction: true)).Where(x => x.Kind == NativeXrefKind.Call).ToList();
        Assert.All(calls, c => Assert.Equal(exportRva, c.FromFunctionRva));
        var starts = functions.Select(f => f.StartRva).ToHashSet();
        var call = calls.FirstOrDefault(c => starts.Contains(c.ToRva)) ?? throw new Xunit.Sdk.XunitException($"{Export} has no direct call to a function in the image");
        Assert.Contains(await s.GetXrefsToAsync(call.ToRva), x => x.FromRva == call.FromRva && x.Kind == NativeXrefKind.Call && x.FromFunctionRva == exportRva);
        Assert.Contains(await s.GetXrefsFromAsync(call.FromRva), x => x.ToRva == call.ToRva);

        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => s.DecompileAsync(0x10))).Code);
    }

    [GhidraFact]
    public async Task Reads_run_concurrently_and_agree_with_serial_results()
    {
        await using var s = await Provider.OpenAsync(shared.Sample, null, Offline);
        var functions = (await s.ListFunctionsAsync()).Where(f => !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Take(16).ToList();
        await Task.WhenAll(functions.Take(4).Select(f => s.DecompileAsync(f.StartRva))); // starts the pooled decompiler processes
        var clock = Stopwatch.StartNew();
        var serial = new List<DecompiledFunction>();
        foreach (var f in functions) serial.Add(await s.DecompileAsync(f.StartRva));
        var serialMs = clock.ElapsedMilliseconds;
        clock.Restart();
        var parallel = await Task.WhenAll(functions.Select(f => Task.Run(() => s.DecompileAsync(f.StartRva))));
        output.WriteLine($"{functions.Count} decompiles: serial {serialMs} ms, parallel {clock.ElapsedMilliseconds} ms");
        Assert.Equal(serial.Select(d => d.Text), parallel.Select(d => d.Text));
    }

    [GhidraFact]
    public async Task Names_and_comments_round_trip_survive_a_crash_and_persist()
    {
        var path = shared.Sample;
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        var provider = Isolated();
        await using (var s = (GhidraSession)await provider.OpenAsync(path, null, Offline))
        {
            Assert.Equal("ndm_checksum", await s.SetNameAsync(rva, "ndm_checksum"));
            Assert.Equal("first line\nsecond", await s.SetCommentAsync(rva, "first line\nsecond"));
            Assert.Contains("ndm_checksum", (await s.DecompileAsync(rva)).Text);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "ndm_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);

            var other = (await s.ListFunctionsAsync()).First(f => f.StartRva != rva && !f.Flags.HasFlag(NativeFunctionFlags.Thunk));
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "ndm_checksum"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "bad name;{}"))).Code);

            var batch = await s.ApplyNamesAsync([new NativeNameItem(other.StartRva, "ndm_batch", "batch comment")], "names", "v1");
            Assert.Equal(1, batch.Named);
            Assert.Equal("v1", await s.GetStampAsync("names"));

            // Unsaved changes are journaled: a killed worker is restarted from the saved project and they are applied again.
            var pid = s.WorkerProcessId!.Value;
            Process.GetProcessById(pid).Kill();
            await Task.Delay(500);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == other.StartRva && f.Name == "ndm_batch");
            Assert.NotEqual(pid, s.WorkerProcessId);
        }
        await using (var s = await provider.OpenAsync(path, null, Offline))
        {
            Assert.True(s.ReusedDatabase);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "ndm_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);
            Assert.Equal("v1", await s.GetStampAsync("names"));
            Assert.Equal("", await s.SetCommentAsync(rva, ""));
            Assert.StartsWith("FUN_", await s.SetNameAsync(rva, ""), StringComparison.Ordinal);
        }
    }

    [GhidraFact]
    public async Task Cold_open_then_warm_reopen_of_the_saved_project()
    {
        var provider = Isolated();
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        TimeSpan cold, warm, firstDecompile;
        var userFiles = UserGhidraFiles();
        var stages = new StageLog();
        await using (var s = await provider.OpenAsync(path, null, Offline with { Progress = stages }))
        {
            Assert.False(s.ReusedDatabase);
            cold = s.OpenTime;
            var clock = Stopwatch.StartNew();
            await s.DecompileAsync(rva);
            firstDecompile = clock.Elapsed;
        }
        output.WriteLine($"cold stages: {stages}");
        stages = new StageLog();
        await using (var s = await provider.OpenAsync(path, null, Offline with { Progress = stages }))
        {
            Assert.True(s.ReusedDatabase);
            warm = s.OpenTime;
            var clock = Stopwatch.StartNew();
            await s.DecompileAsync(rva);
            output.WriteLine($"cold open {cold.TotalSeconds:0.0} s, first decompile {firstDecompile.TotalMilliseconds:0} ms; warm open {warm.TotalSeconds:0.0} s, " +
                $"first decompile {clock.ElapsedMilliseconds} ms; warm stages: {stages}");
        }
        Assert.True(warm < cold, $"warm open {warm} not faster than cold {cold}");
        var changed = UserGhidraFiles().Where(f => !userFiles.TryGetValue(f.Key, out var t) || t != f.Value).Select(f => f.Key).ToList();
        Assert.True(changed.Count == 0, "written under the user's Ghidra directories:\n" + string.Join("\n", changed.Take(10)));
        Assert.True(Directory.Exists(provider.Directories.Settings));
    }

    [GhidraFact]
    public async Task Cancel_and_timeout_stop_the_request_and_keep_the_worker()
    {
        await using var s = (GhidraSession)await Provider.OpenAsync(shared.Sample, null, Offline with { RequestTimeout = TimeSpan.FromSeconds(2) });
        var pid = s.WorkerProcessId!.Value;
        using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500)))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, cts.Token));
        var clock = Stopwatch.StartNew();
        var e = await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"timeout took {clock.Elapsed}");
        Assert.Equal(pid, s.WorkerProcessId);
        Assert.NotEmpty(await s.ListFunctionsAsync());
        Assert.Equal(pid, s.WorkerProcessId);
    }

    [GhidraFact]
    public async Task Disposing_the_provider_kills_the_worker_and_the_decompilers()
    {
        var provider = shared.NewProvider();
        var s = (GhidraSession)await provider.OpenAsync(shared.Sample, null, Offline);
        var functions = (await s.ListFunctionsAsync()).Where(f => !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Take(4).ToList();
        await Task.WhenAll(functions.Select(f => s.DecompileAsync(f.StartRva)));
        var tree = s.Worker!.TreeProcessIds();
        output.WriteLine($"worker tree: {string.Join(", ", tree)}");
        Assert.True(tree.Count >= 2, "the decompiler processes run inside the worker's job");
        var processes = tree.Select(TryOpen).Where(p => p != null).ToList();
        provider.Dispose();
        foreach (var p in processes) Assert.True(p!.WaitForExit(15_000), $"process {p.Id} survived the provider");
        Assert.False(s.IsOpen);
        Assert.Equal(ErrorCode.NotLoaded, (await Assert.ThrowsAsync<ToolError>(() => s.ListFunctionsAsync())).Code);
    }

    [GhidraFact]
    public async Task A_damaged_project_is_rebuilt()
    {
        var provider = Isolated();
        var path = shared.Copy(NativeIdaProviderTests.System64);
        string project;
        await using (var s = (GhidraSession)await provider.OpenAsync(path, null, Offline with { OpenTimeout = TimeSpan.FromMinutes(10) }))
            project = s.ProjectDirectory;
        foreach (var f in Directory.GetFiles(Path.Combine(project, GhidraSession.ProjectName + ".rep"), "*", SearchOption.AllDirectories))
            File.WriteAllBytes(f, [0x42]);
        await using var rebuilt = await provider.OpenAsync(path, null, Offline);
        Assert.False(rebuilt.ReusedDatabase);
        Assert.NotEmpty(await rebuilt.ListFunctionsAsync());
    }

    [GhidraFact]
    public async Task Base_zero_shared_object_loads_at_its_file_base()
    {
        // A small x86-64 shared object from Ghidra's class exercises; Ghidra's default for base 0 would be 0x100000.
        var ghidra = GhidraInstallation.Locate(null, out _, out _)!;
        var elf = Path.Combine(ghidra.Directory, "docs", "GhidraClass", "ExerciseFiles", "Advanced", "override.so");
        if (!File.Exists(elf)) return;
        var header = GhidraSession.ReadHeader(elf, elf);
        Assert.True(header.IsElf);
        Assert.Equal(0UL, header.ImageBase);
        await using var s = (GhidraSession)await Isolated().OpenAsync(shared.Copy(elf), null, Offline);
        output.WriteLine($"{s.Language} base 0x{s.ImageBase:X}, {s.FunctionCount} functions, open {s.OpenTime.TotalSeconds:0.0} s");
        Assert.Equal(header.Arch, s.Arch);
        Assert.Equal(0UL, s.ImageBase);
        var functions = await s.ListFunctionsAsync();
        // Code functions sit inside the file's segments (imports get a synthetic block after the image).
        Assert.True(functions.Count(f => f.StartRva < new FileInfo(elf).Length) >= 5, string.Join(", ", functions.Select(f => $"{f.Name}@0x{f.StartRva:X}")));
    }

    [GhidraFact]
    public async Task Managed_assembly_is_unsupported()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(Env.FixturePath, null, Offline));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => Provider.OpenAsync(Env.FixturePath, null, Offline))).Code);
    }

    /// <summary>Files under the user's own Ghidra directories (%APPDATA%\ghidra and %LOCALAPPDATA%\ghidra on Windows) with their write times.</summary>
    private static Dictionary<string, DateTime> UserGhidraFiles()
    {
        var files = new Dictionary<string, DateTime>();
        foreach (var root in new[] { Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.LocalApplicationData })
        {
            var dir = Path.Combine(Environment.GetFolderPath(root), "ghidra");
            if (Directory.Exists(dir))
                foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories)) files[f] = File.GetLastWriteTimeUtc(f);
        }
        return files;
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

    private static Process? TryOpen(int pid)
    {
        try { return Process.GetProcessById(pid); }
        catch (ArgumentException) { return null; }
    }
}

/// <summary>Runs when Ghidra (NDM_GHIDRA_DIR or GHIDRA_INSTALL_DIR) and a JDK for it are present, on Windows (system DLL samples).</summary>
public sealed class GhidraFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> SkipReason = new(() =>
    {
        if (!OperatingSystem.IsWindows()) return "Ghidra provider tests use Windows system DLLs.";
        using var probe = new GhidraProvider(new GhidraProviderOptions { CacheRoot = Path.GetTempPath() });
        var a = probe.CheckAvailability();
        return a.IsAvailable ? null : $"Ghidra provider unavailable: {a.Reason}";
    });

    public GhidraFactAttribute()
    {
        if (SkipReason.Value is { } r) Skip = r;
    }
}
