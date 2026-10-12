using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Xunit.Abstractions;

namespace Corvus.Tests;

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
/// The Ghidra provider against a real Ghidra (CORVUS_GHIDRA_DIR) and JDK, on copies of system DLLs; skipped otherwise.
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
        Assert.Contains(Directory.GetFiles(Assert.Single(workers)), f => f.EndsWith("ghidra-worker.jar", StringComparison.Ordinal));
    }

    [GhidraFact]
    public async Task Open_without_auto_analysis_keeps_its_own_project_and_decompiles_on_demand()
    {
        var path = shared.Sample;
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        var dir = new TempDir();
        _owned.Add(dir);
        var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.Path });
        _owned.Add(provider);
        await using var s = (GhidraSession)await provider.OpenAsync(path, null, Offline with { Analysis = EngineAnalysis.None });
        Assert.False(s.AnalysisComplete);
        Assert.Contains("no auto-analysis", ((INativeDecompilerSession)s).DatabaseNote);
        Assert.True(s.OpenTime < TimeSpan.FromSeconds(120), $"open {s.OpenTime}");
        var decompiled = await s.DecompileAsync(rva);
        Assert.Equal(rva, decompiled.StartRva);
        var project = Directory.GetFiles(dir.Path, "*.gpr", SearchOption.AllDirectories).Single();
        Assert.EndsWith("-noauto", Path.GetFileName(Path.GetDirectoryName(project)));
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

        // one batch request runs its items across the decompiler pool and keeps their order and per-item outcomes
        clock.Restart();
        var batch = await s.DecompileManyAsync([.. functions.Select(f => f.StartRva), 0x10u], 60, 600);
        output.WriteLine($"batch of {batch.Count}: {clock.ElapsedMilliseconds} ms");
        Assert.Equal([.. functions.Select(f => f.StartRva), 0x10u], batch.Select(b => b.Rva));
        Assert.Equal(serial.Select(d => d.Text), batch.Take(functions.Count).Select(b => b.Function!.Text));
        Assert.Equal((DecompileStatus.Error, "not_found"), (batch[^1].Status, batch[^1].ErrorCode));
    }

    [GhidraFact]
    public async Task Names_and_comments_round_trip_survive_a_crash_and_persist()
    {
        var path = shared.Sample;
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        var provider = Isolated();
        await using (var s = (GhidraSession)await provider.OpenAsync(path, null, Offline))
        {
            Assert.Equal("sample_checksum", await s.SetNameAsync(rva, "sample_checksum"));
            Assert.Equal("first line\nsecond", await s.SetCommentAsync(rva, "first line\nsecond"));
            Assert.Contains("sample_checksum", (await s.DecompileAsync(rva)).Text);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);

            var other = (await s.ListFunctionsAsync()).First(f => f.StartRva != rva && !f.Flags.HasFlag(NativeFunctionFlags.Thunk));
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "sample_checksum"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => s.SetNameAsync(other.StartRva, "bad name;{}"))).Code);

            var batch = await s.ApplyNamesAsync([new NativeNameItem(other.StartRva, "sample_batch", "batch comment")], "names", "v1");
            Assert.Equal(1, batch.Named);
            Assert.Equal("v1", await s.GetStampAsync("names"));

            // Unsaved changes are journaled: a killed worker is restarted from the saved project and they are applied again.
            var pid = s.WorkerProcessId!.Value;
            await WorkerKill.KillAsync(s);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == other.StartRva && f.Name == "sample_batch");
            Assert.NotEqual(pid, s.WorkerProcessId);
        }
        await using (var s = await provider.OpenAsync(path, null, Offline))
        {
            Assert.True(s.ReusedDatabase);
            Assert.Contains(await s.ListFunctionsAsync(), f => f.StartRva == rva && f.Name == "sample_checksum");
            Assert.Equal("first line\nsecond", (await s.DisassembleAsync(rva)).Instructions[0].Comment);
            Assert.Equal("v1", await s.GetStampAsync("names"));
            Assert.Equal("", await s.SetCommentAsync(rva, ""));
            Assert.StartsWith("FUN_", await s.SetNameAsync(rva, ""), StringComparison.Ordinal);
        }
        // The journal is bounded: reaching the threshold saves the project.
        Assert.Equal(50, new GhidraProviderOptions().JournalSaveThreshold);
        using (var bounded = new GhidraProvider(provider.Options with { JournalSaveThreshold = 2 }))
        await using (var s = (GhidraSession)await bounded.OpenAsync(path, null, Offline))
        {
            await s.SetNameAsync(rva, "sample_bounded");
            Assert.Equal(1, s.UnsavedCount);
            await s.SetCommentAsync(rva, "bounded");
            Assert.Equal(0, s.UnsavedCount);
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
        // the worker stops the request before the time limit and answers with what it has
        var r = await s.CallAsync("sleep", new JsonObject { ["seconds"] = 60 }, default);
        Assert.Contains(r.GetProperty("partial").GetString(), (string[])["deadline", "cancelled"]);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(10), $"the partial answer took {clock.Elapsed}");
        Assert.Equal(pid, s.WorkerProcessId);
        Assert.NotEmpty(await s.ListFunctionsAsync());
        Assert.Equal(pid, s.WorkerProcessId);
    }

    [GhidraFact]
    public async Task A_decompile_that_times_out_or_overflows_is_retried_with_more_time_and_payload()
    {
        var path = shared.Sample;
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = (GhidraSession)await Provider.OpenAsync(path, null, Offline);
        var d = await s.DecompileCoreAsync(exportRva, TimeSpan.FromSeconds(5), failFirst: true, default);
        Assert.Contains(Export, d.Text);
        Assert.Equal(1, s.DecompileRetries);
        Assert.Equal(d.Text, (await s.DecompileWithinAsync(exportRva, TimeSpan.FromSeconds(5))).Text);
        Assert.Equal(1, s.DecompileRetries);
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
    public async Task Patches_sync_into_the_project_and_revert_exactly()
    {
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var rva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = await Isolated().OpenAsync(path, null, Offline);
        var original = (await s.DisassembleRangeAsync(rva, 1)).Instructions[0];
        var bodyEnd = (await s.ListFunctionsAsync()).Single(f => f.StartRva == rva).EndRva;
        Assert.True(bodyEnd > rva + 1);

        var clock = Stopwatch.StartNew();
        var r = await s.SyncPatchesAsync([new NativeByteRange(rva, [0xC3])]);
        output.WriteLine($"patch: {r} in {clock.ElapsedMilliseconds} ms");
        Assert.True(r.Complete);
        Assert.Equal((1, 0, 1), (r.Patched, r.Reverted, r.Ranges));
        Assert.True(r.Functions >= 1);
        var patched = (await s.DisassembleRangeAsync(rva, 1)).Instructions[0];
        Assert.Equal([0xC3], patched.Bytes);
        Assert.Contains("RET", patched.Text, StringComparison.OrdinalIgnoreCase);
        // the body was recomputed: the function ends at the ret
        Assert.Equal(rva + 1, (await s.ListFunctionsAsync()).Single(f => f.StartRva == rva).EndRva);
        var same = await s.SyncPatchesAsync([new NativeByteRange(rva, [0xC3])]);
        Assert.Equal((0, 0), (same.Patched, same.Reverted));

        // a byte outside the image is missing; the others still take
        var outside = await s.SyncPatchesAsync([new NativeByteRange(rva, [0xC3]), new NativeByteRange(0x7FFF_FF00, [0x90])]);
        Assert.Equal((1, false), (outside.Missing, outside.Complete));
        Assert.Contains(0x7FFF_FF00u, outside.Problems);

        // the empty set restores the file's bytes and the function's body
        var reverted = await s.SyncPatchesAsync([]);
        Assert.Equal((0, 1), (reverted.Patched, reverted.Reverted));
        Assert.Equal(original.Bytes, (await s.DisassembleRangeAsync(rva, 1)).Instructions[0].Bytes);
        Assert.Equal(bodyEnd, (await s.ListFunctionsAsync()).Single(f => f.StartRva == rva).EndRva);
    }

    [GhidraFact]
    public async Task Recovered_types_classes_and_prototypes_reach_the_pseudocode()
    {
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = await Isolated().OpenAsync(path, null, Offline);
        var functions = await s.ListFunctionsAsync();
        // functions Ghidra named itself carry no prototype from a type library
        var plain = functions.Where(f => f.Name.StartsWith("FUN_", StringComparison.Ordinal) && !f.Flags.HasFlag(NativeFunctionFlags.Thunk)).Take(2).ToList();
        Assert.Equal(2, plain.Count);
        var vftable = RdataRva(path) + 0x40;
        var batch = new NativeTypeBatch(
            "struct SamplePoint { int x; int y; };\ntypedef struct SamplePoint *PSamplePoint;\nstruct SampleBroken { int };\n",
            [new NativePrototype(exportRva, "int __fastcall SampleProto(PSamplePoint point, int count);")],
            [new NativeClassType("SampleBase", [new NativeVftableType(0, vftable, [plain[0].StartRva, plain[1].StartRva])], []),
             new NativeClassType("SampleDerived", [], [new NativeBaseType("SampleBase", 0)])],
            [new NativeMethodOwner(plain[0].StartRva, "SampleBase"), new NativeMethodOwner(exportRva, "SampleMissing")], 8);
        var r = await s.ApplyTypesAsync(batch, "types", "t1");
        output.WriteLine($"{r.DeclarationErrors} declaration errors, {r.Typed} typed, {r.Structs} structs, {r.VftablesTyped} vftables, {r.MethodsTyped} methods, " +
                         $"skips {string.Join(", ", r.MethodSkips.Select(k => $"{k.Key} {k.Value}"))}, failures {string.Join("; ", r.Failures)}");
        Assert.Equal(1, r.DeclarationErrors);
        Assert.Equal((1, 0), (r.Typed, r.TypeFailures));
        Assert.Equal(3, r.Structs); // SampleBase_vftable, SampleBase, SampleDerived
        Assert.Equal(1, r.VftablesTyped);
        Assert.Equal(1, r.MethodsTyped);
        Assert.Equal(1, r.MethodSkips["no_class_type"]);
        Assert.Equal("t1", await s.GetStampAsync("types"));

        var proto = await s.DecompileAsync(exportRva);
        output.WriteLine(proto.Text.Split('\n').FirstOrDefault(l => l.Contains('(')));
        Assert.Contains("PSamplePoint point", proto.Text);
        Assert.Contains(Export, proto.Text); // the prototype does not rename
        Assert.Contains("SampleBase *this", (await s.DecompileAsync(plain[0].StartRva)).Text);
        // a failed prototype is counted, not thrown
        var bad = await s.ApplyTypesAsync(new NativeTypeBatch(null, [new NativePrototype(exportRva, "int f(NoSuchType x);")], [], [], 8));
        Assert.Equal(1, bad.TypeFailures);
    }

    /// <summary>An x86 Il2Cpp prototype carries __cdecl, which replaces the convention Ghidra gave the function (here an export's __stdcall).</summary>
    [GhidraFact]
    public async Task X86_prototypes_keep_their_cdecl_convention()
    {
        var path = shared.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "version.dll"));
        var rva = NativeIdaProviderTests.ExportRva(path, "GetFileVersionInfoSizeW");
        await using var s = await Isolated().OpenAsync(path, null, Offline);
        var r = await s.ApplyTypesAsync(new NativeTypeBatch(null, [new NativePrototype(rva, "int __cdecl SampleMethod(void *__this, int count, void *method);")], [], [], 4));
        Assert.Equal((1, 0), (r.Typed, r.TypeFailures));
        var f = await s.GetFunctionRecordAsync(rva);
        output.WriteLine($"{f.CallingConvention}: {f.Prototype}");
        Assert.Equal("__cdecl", f.CallingConvention);
    }

    [GhidraFact]
    public async Task Call_targets_name_the_references_and_the_decompiler_view()
    {
        var path = shared.Sample;
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = await Provider.OpenAsync(path, null, Offline);
        var starts = (await s.ListFunctionsAsync()).Select(f => f.StartRva).ToHashSet();
        var calls = (await s.GetXrefsFromAsync(exportRva, wholeFunction: true)).Where(x => x.Kind == NativeXrefKind.Call && starts.Contains(x.ToRva)).ToList();
        Assert.NotEmpty(calls);
        var t = await s.GetCallTargetsAsync([exportRva], calls.Select(c => c.FromRva).ToList(), 60);
        output.WriteLine(string.Join("\n", t.Targets));
        Assert.True(t.DecompilerAvailable);
        Assert.Equal(1, t.Decompiled);
        Assert.Contains(t.Targets, x => x.Kind == "xref" && x.Target == calls[0].ToRva && x.Site == calls[0].FromRva);
        Assert.Contains(t.Targets, x => x.Kind == "direct" && x.Target == calls[0].ToRva);
        Assert.Single((await s.GetCallTargetsAsync([0x10], [], 60)).Failed);
    }

    [GhidraFact]
    public async Task User_types_frames_locals_and_the_type_list()
    {
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        await using var s = await Isolated().OpenAsync(path, null, Offline);
        var frame = await s.GetFrameAsync(exportRva + 1);
        output.WriteLine($"frame of {frame.Name}: {frame.LocalSize} bytes, return address +0x{frame.ReturnAddressOffset:X}\n" +
                         string.Join("\n", frame.Members.Select(m => $"  +0x{m.Offset:X} {m.Name} {m.Type} {m.Size} {m.Kind}")) + "\n" +
                         string.Join("\n", frame.Locals.Select(l => $"  {l.Name} {l.Type} {l.Location} {l.Stack} arg={l.IsArgument}")));
        Assert.Equal(exportRva, frame.StartRva);
        Assert.Null(frame.DecompilerError);
        Assert.Contains(frame.Members, m => m.Kind == "special" && m.Offset == frame.ReturnAddressOffset);
        Assert.Contains(frame.Locals, l => l.IsArgument);

        // declarations: errors with the parser's message, the names made, the types listed and shown
        var declared = await s.ApplyUserTypesAsync(new NativeUserTypeBatch(["struct SamplePacket { int length; char data[16]; };", "struct SampleBad { int };"], [], [], []),
            "user_types", "u1");
        Assert.Equal(1, declared.DeclarationErrors);
        Assert.Contains("SamplePacket", declared.DeclaredTypes);
        Assert.Contains(declared.DeclarationMessages, m => m.StartsWith("struct SampleBad", StringComparison.Ordinal));
        Assert.Equal("u1", await s.GetStampAsync("user_types"));
        var list = await s.ListTypesAsync("samplepacket", "struct", 0, 10);
        Assert.Equal(1, list.Total);
        Assert.Equal(new NativeTypeEntry("SamplePacket", "struct", 20, 2), list.Types[0]);
        Assert.True((await s.ListTypesAsync(null, null, 0, 5)).Total > 5);
        var type = await s.GetTypeAsync("SamplePacket");
        output.WriteLine(type.Declaration);
        Assert.Contains("char data[16];", type.Declaration);
        Assert.Equal(new NativeTypeMember(4, "data", "char[16]", 16), type.Members[1]);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => s.GetTypeAsync("SampleNoSuchType"))).Code);

        // a decompiler local by its name, then the prototype, a global, a stack member
        var arg = frame.Locals.First(l => l.IsArgument);
        var local = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([], [], [], [new NativeLocalEdit(exportRva, arg.Name, arg.Stack, "sample_image", "SamplePacket *")]));
        var edit = Assert.Single(local.Items);
        Assert.True(edit.Applied, edit.Error);
        Assert.Equal(arg.Name, edit.Resolved);
        Assert.Equal("SamplePacket * sample_image", edit.Text);
        Assert.Contains("SamplePacket *sample_image", (await s.DecompileAsync(exportRva)).Text);

        var global = RdataRva(path) + 0x80;
        var typed = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([],
            [new NativePrototype(exportRva, "int __fastcall SampleUserProto(SamplePacket *packet, ulonglong size, uint *header, int *sum)"),
             new NativePrototype(global, "SamplePacket"), new NativePrototype(exportRva + 2, "int")], [], []));
        foreach (var i in typed.Items) output.WriteLine($"{i.Kind} 0x{i.Rva:X} {i.Target}: {i.Applied} {i.Error} {i.Text}");
        Assert.True(typed.Items[0].Applied, typed.Items[0].Error);
        Assert.Contains("SamplePacket * packet", typed.Items[0].Text);
        Assert.Equal((true, "SamplePacket"), (typed.Items[1].Applied, typed.Items[1].Text));
        Assert.Contains("inside the function", typed.Items[2].Error);
        Assert.Contains("SamplePacket *packet", (await s.DecompileAsync(exportRva)).Text);
        // recovered prototypes leave the user's alone
        var recovered = await s.ApplyTypesAsync(new NativeTypeBatch(null, [new NativePrototype(exportRva, "int __fastcall Other(int a);")], [], [], 8));
        Assert.Equal((0, 0), (recovered.Typed, recovered.TypeFailures));
        Assert.Contains("SamplePacket *packet", (await s.DecompileAsync(exportRva)).Text);

        var slot = frame.Members.First(m => m.Kind == "local");
        var stack = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([], [], [new NativeStackVarEdit(exportRva, slot.Offset, "sample_slot", null),
            new NativeStackVarEdit(exportRva, frame.ReturnAddressOffset, "sample_ret", "int")], []));
        Assert.True(stack.Items[0].Applied, stack.Items[0].Error);
        Assert.EndsWith(" sample_slot", stack.Items[0].Text);
        Assert.Contains("return address", stack.Items[1].Error);
        Assert.Contains((await s.GetFrameAsync(exportRva)).Members, m => m.Offset == slot.Offset && m.Name == "sample_slot");

        var cleared = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([], [new NativePrototype(global, "")], [], []));
        Assert.True(cleared.Items[0].Applied);
    }

    [GhidraFact]
    public async Task Parameters_only_the_decompiler_knows_are_committed_before_an_edit()
    {
        // the minimal profile runs no parameter analysis, so the database holds no parameters the decompiler shows
        var path = shared.Copy(NativeIdaProviderTests.System64);
        var exportRva = NativeIdaProviderTests.ExportRva(path, Export);
        var dir = new TempDir();
        _owned.Add(dir);
        using var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.File("cache"), Profile = GhidraAnalysisProfile.Minimal });
        await using var s = await provider.OpenAsync(path, null, Offline);
        var args = (await s.GetFrameAsync(exportRva)).Locals.Where(l => l.IsArgument).ToList();
        output.WriteLine(string.Join(", ", args.Select(a => $"{a.Type} {a.Name} {a.Location}")));
        Assert.True(args.Count >= 2);
        var second = args[1];
        var edit = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([], [], [], [new NativeLocalEdit(exportRva, second.Name, second.Stack, "sample_second", "uint")]));
        var item = Assert.Single(edit.Items);
        Assert.True(item.Applied, item.Error);
        Assert.Equal("uint sample_second", item.Text);
        var text = (await s.DecompileAsync(exportRva)).Text;
        output.WriteLine(text);
        Assert.Contains("uint sample_second", text);
        var after = (await s.GetFrameAsync(exportRva)).Locals.Where(l => l.IsArgument).ToList();
        Assert.Equal(args.Count, after.Count);
        Assert.Equal([args[0].Name, "sample_second", .. args.Skip(2).Select(a => a.Name)], after.Select(a => a.Name));
    }

    [GhidraFact]
    public async Task Type_names_resolve_through_C_and_Windows_spellings()
    {
        // Windows typedefs the PE loader defines are taken as they are; the others resolve through aliases, prefixes and case
        var path = shared.Copy(NativeIdaProviderTests.System64);
        await using var s = await Isolated().OpenAsync(path, null, Offline);
        (string Type, string? Shown)[] table =
        [
            ("DWORD", null), ("dword", "dword"), ("unsigned int", "uint"), ("PVOID", "PVOID"), ("uchar *", "uchar *"), ("char *", "char *"),
            ("size_t", null), ("unsigned __int64", "ulonglong"), ("LPCSTR", "LPCSTR"), ("struct _IMAGE_DOS_HEADER *", "IMAGE_DOS_HEADER *"),
            ("BYTE[16]", null), ("__int64", "longlong"), ("ULONG_PTR", "ULONG_PTR"), ("LPCWSTR", "LPCWSTR"), ("PIMAGE_DOS_HEADER", "IMAGE_DOS_HEADER *"),
            ("image_dos_header", "IMAGE_DOS_HEADER"), ("const char *", "char *"), ("unsigned __int64 *[2]", "ulonglong *[2]"), ("SampleNoSuchType", null),
        ];
        var global = RdataRva(path) + 0x100;
        var result = await s.ApplyUserTypesAsync(new NativeUserTypeBatch([], [.. table.Select((t, i) => new NativePrototype(global + (uint)i * 0x80, t.Type))], [], []));
        for (int i = 0; i < table.Length; i++)
            output.WriteLine($"{table[i].Type,-30} {result.Items[i].Applied} {result.Items[i].Text ?? result.Items[i].Error}");
        for (int i = 0; i < table.Length; i++)
        {
            var item = result.Items[i];
            if (table[i].Type == "SampleNoSuchType") { Assert.False(item.Applied); continue; }
            Assert.True(item.Applied, $"{table[i].Type}: {item.Error}");
            if (table[i].Shown is { } shown) Assert.True(shown == item.Text, $"{table[i].Type}: {item.Text}");
        }
    }

    /// <summary>The RVA of the image's .rdata section.</summary>
    private static uint RdataRva(string path)
    {
        using var pe = new PEReader(File.OpenRead(path));
        return (uint)pe.PEHeaders.SectionHeaders.First(h => h.Name == ".rdata").VirtualAddress;
    }

    [GhidraFact]
    public async Task An_extension_from_the_extension_directory_loads_from_the_private_settings()
    {
        var ghidra = GhidraInstallation.Locate(null, out _, out _)!;
        var dir = new TempDir();
        _owned.Add(dir);
        GhidraExtensionTests.ExtensionZip(dir.File("ext"), "SampleProbe", ghidra.Version);
        var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.File("cache"), ExtensionsDirectory = dir.File("ext") });
        _owned.Add(provider);
        Assert.Equal("SampleProbe", provider.CheckAvailability().Details["extensions"]);
        var userFiles = UserGhidraFiles();
        var a = await provider.ProbeAsync();
        Assert.True(a.IsAvailable, a.Reason);
        Assert.Equal("SampleProbe", a.Details["extensions_loaded"]);
        Assert.True(File.Exists(Path.Combine(GhidraExtensions.InstallDirectory(provider.Directories, ghidra), "SampleProbe", "lib", "SampleProbe.jar")));
        Assert.Equal(userFiles.Keys.Order(), UserGhidraFiles().Keys.Order());
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

/// <summary>Runs when Ghidra (CORVUS_GHIDRA_DIR or GHIDRA_INSTALL_DIR) and a JDK for it are present, on Windows (system DLL samples).</summary>
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
