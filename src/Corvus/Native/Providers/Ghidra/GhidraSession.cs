using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers.Ghidra;

/// <summary>One image open in a Ghidra worker: concurrent reads, serialized journaled changes, a project keyed by profile.</summary>
internal sealed class GhidraSession(GhidraProvider provider, GhidraInstallation ghidra, JavaRuntime java, NativeOpenOptions options)
    : WorkerSessionBase(options), INativeDecompilerSession
{
    internal const string ProjectName = "corvus";

    // Migration only: the project name before the rename; such a project is renamed (its .gpr file and .rep folder) when opened.
    private const string LegacyProjectName = "ndm";

    /// <summary>Whether <paramref name="directory"/> holds a saved project, under the current name or the one before the rename.</summary>
    internal static bool HasProject(string directory) =>
        File.Exists(Path.Combine(directory, ProjectName + ".gpr")) || File.Exists(Path.Combine(directory, LegacyProjectName + ".gpr"));

    /// <summary>Renames a project saved under the name before the rename, unless it is open (locked) or ours exists.</summary>
    internal static void RenameLegacyProject(string directory)
    {
        string Of(string name, string extension) => Path.Combine(directory, name + extension);
        if (!File.Exists(Of(LegacyProjectName, ".gpr")) || File.Exists(Of(ProjectName, ".gpr")) || File.Exists(Of(LegacyProjectName, ".lock"))) return;
        try
        {
            if (Directory.Exists(Of(LegacyProjectName, ".rep"))) Directory.Move(Of(LegacyProjectName, ".rep"), Of(ProjectName, ".rep"));
            File.Move(Of(LegacyProjectName, ".gpr"), Of(ProjectName, ".gpr"));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private ulong? _headerImageBase;
    private string _projectDirectory = "";
    private List<KeyValuePair<string, string>> _loaderArguments = [];
    private IReadOnlyList<KeyValuePair<string, string>> _analyzerOptions = [];

    public override string ProviderId => GhidraProvider.ProviderId;
    protected override string EngineName => "Ghidra";
    protected override TimeSpan ShutdownGrace => provider.Options.ShutdownGrace;
    protected override int MaxRestarts => provider.Options.MaxRestarts;
    protected override bool ConcurrentRequests => true;

    /// <summary>The worker's read requests (Worker.java runs them under read()), and save.</summary>
    private static readonly HashSet<string> ReadOps =
    [
        "hello", "functions", "decompile", "disasm", "disasm_range", "blocks", "xrefs_to", "xrefs_from", "names", "type_guess", "virtual_targets", "frame",
        "types", "type", "get_stamp", "decompile_many", "insn", "value_slice", "image_info", "defined_data", "defined_strings", "function_info", "namespaces",
        "field_xrefs", "export_types", "analyzers", "function_candidates", "emulate", "function_table", "memory", "fixups", "save",
    ];

    protected override bool ReadsOnly(string op) => ReadOps.Contains(op);
    protected override int JournalSaveThreshold => provider.Options.JournalSaveThreshold;
    internal string ProjectDirectory => _projectDirectory;
    protected override string? DatabaseLocation => _projectDirectory.Length > 0 ? _projectDirectory : null;
    /// <summary>False when the first analysis ran out of time; the saved project then holds what was analyzed.</summary>
    public bool AnalysisComplete { get; private set; }

    public string? DatabaseNote => Note;

    protected override string? Note => string.Join("; ", new[]
    {
        Options.Analysis == EngineAnalysis.None && !AnalysisComplete ? "no auto-analysis: functions made where asked" : null,
        Options.Overrides is { } ov ? "import overrides: " + ov.Text : null,
        Entry?.SnapshotOf is { } pid ? $"read-only snapshot of the project process {pid} has open: edits are not saved" : null,
    }.Where(n => n != null)) is { Length: > 0 } note ? note : null;
    internal string Language { get; private set; } = "";
    internal int FunctionCount { get; private set; }
    internal IReadOnlyList<string> Warnings { get; private set; } = [];

    /// <summary>The image's cache entry; when another server process holds it, a read-only snapshot of its saved project, else Conflict.</summary>
    protected override CacheEntry AcquireEntry(string imagePath, string? sha256) =>
        provider.Cache.Acquire(ProviderId, imagePath, sha256, (locked, sha) =>
        {
            if (locked.OwnerPid is not { } pid || pid == Environment.ProcessId) throw locked.Conflict;
            var header = Options.Raw is { } raw ? new Header(raw.Arch, raw.Base, false) : ReadHeader(imagePath, imagePath);
            var project = Project(provider, ghidra, locked.Directory, header, Options.Symbols, Options.Analysis, Options.Raw, Options.GhidraDatabase, Options.Overrides).Directory;
            if (!File.Exists(Path.Combine(project, ProjectName + ".gpr")))
                throw new ToolError(ErrorCode.Conflict, $"{locked.Conflict.Message} It has no saved project of this image to take a read-only snapshot of yet.",
                    locked.Conflict.Remediation) { RetryAfter = locked.Conflict.RetryAfter, Retryable = true };
            return provider.Cache.Snapshot(ProviderId, locked, sha, Path.GetFullPath(imagePath), [project]);
        });

    protected override void PrepareOpen()
    {
        var header = Options.Raw is { } raw ? new Header(raw.Arch, raw.Base, false) : ReadHeader(Entry!.InputCopy, ImagePath);
        Arch = header.Arch;
        _headerImageBase = header.ImageBase;
        if (Options.Overrides is { } overrides)
        {
            if (Options.GhidraDatabase != null)
                throw new ToolError(ErrorCode.InvalidArgument, "A Ghidra archive is opened as its database: import overrides do not apply.", "load the source file with the overrides instead");
            EngineOverrideChecks.CheckGhidra(ghidra.Directory, overrides, Options.Raw?.Isa.GhidraLanguage);
        }
        (_projectDirectory, _loaderArguments, _analyzerOptions) = Project(provider, ghidra, Entry!.Directory, header, Options.Symbols, Options.Analysis, Options.Raw,
            Options.GhidraDatabase, Options.Overrides);
        RenameLegacyProject(_projectDirectory);
    }

    /// <summary>The project directory an open uses in a cache entry, with its loader and analyzer options (also found without an open).</summary>
    internal static (string Directory, List<KeyValuePair<string, string>> Loader, IReadOnlyList<KeyValuePair<string, string>> Analyzers) Project(
        GhidraProvider provider, GhidraInstallation ghidra, string entryDirectory, Header header, SymbolMode symbols, EngineAnalysis analysis,
        RawLayout? raw = null, PackedDatabase? packed = null, EngineOverrides? overrides = null)
    {
        var profile = provider.Profile;
        List<KeyValuePair<string, string>> loader = [.. GhidraOptions.LoaderArguments(profile)];
        if (header.IsElf && header.ImageBase is { } elfBase)
            loader.Add(new(GhidraOptions.ElfImageBaseArgument, elfBase.ToString("x", CultureInfo.InvariantCulture)));
        var analyzers = GhidraOptions.AnalyzerOptions(profile, symbols, provider.ExtraOptions,
            completion: provider.CompletionPass && analysis != EngineAnalysis.None && packed == null);
        var key = GhidraOptions.ProfileKey(ghidra, profile, loader, analyzers, provider.Extensions);
        // Analyzers turned off at import enter the project name through the overrides key.
        if (overrides is { DisabledAnalyzers.Count: > 0 })
            analyzers = [.. analyzers.Where(a => !overrides.DisabledAnalyzers.Contains(a.Key)), .. overrides.DisabledAnalyzers.Select(a => KeyValuePair.Create(a, "false"))];
        // Load-only, raw layout and import overrides each name their own project.
        return (Path.Combine(entryDirectory, "p-" + key + (analysis == EngineAnalysis.None ? "-noauto" : "") +
                (raw != null ? "-raw-" + raw.Key.Replace('@', '-') : "") + (packed != null ? "-gzf-" + packed.Sha256[..16] : "") +
                (overrides != null ? "-" + overrides.Key : "")), loader, analyzers);
    }

    /// <summary>The project's name for the input file: characters Ghidra rejects in a name (LocalFileSystem) become '_'.</summary>
    internal static string ProgramName(string file) => string.Concat(file.Select(c => c < ' ' || c > 'ÿ' || @"/\'`""*:<>?|".Contains(c) ? '_' : c));

    /// <summary>Whether a project directory is that of <paramref name="overrides"/> (an overrides key), or of no overrides when null.</summary>
    internal static bool OfOverrides(string directory, string? overrides) =>
        overrides != null ? directory.EndsWith("-" + overrides, StringComparison.Ordinal) : !Path.GetFileName(directory).Contains("-ov-", StringComparison.Ordinal);

    internal readonly record struct Header(NativeArch Arch, ulong? ImageBase, bool IsElf);

    /// <summary>Architecture and image base from a PE, ELF or thin Mach-O header; other formats take Ghidra's loaded base.</summary>
    internal static Header ReadHeader(string copy, string original)
    {
        try
        {
            var head = new byte[64];
            int n;
            using (var s = File.OpenRead(copy)) n = s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            if (n >= 2 && head[0] == 'M' && head[1] == 'Z') return ReadPe(copy, original);
            if (n >= 20 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') return ReadElf(copy, original);
            // Mach-O: Ghidra's loader maps it at __TEXT, our image base too.
            if (NativeImageLoader.Detect(head.AsSpan(0, n)) == NativeFileKind.MachO) return new Header(NativeImageLoader.Open(copy).Arch, null, false);
            return new Header(NativeArch.Unknown, null, false);
        }
        catch (IOException ex)
        {
            throw new ToolError(ErrorCode.IoError, $"Reading {original} failed: {ex.Message}");
        }
    }

    private static Header ReadPe(string copy, string original)
    {
        try
        {
            using var s = File.OpenRead(copy);
            using var pe = new PEReader(s);
            if (pe.PEHeaders.PEHeader is not { } opt) return new Header(NativeArch.Unknown, null, false); // DOS or NE/LE: Ghidra decides
            if (pe.PEHeaders.CorHeader is { } cor && (cor.Flags & CorFlags.ILOnly) != 0)
                throw new ToolError(ErrorCode.Unsupported, $"{original} is an IL-only .NET assembly; it has no native code to decompile.",
                    "Load it as a .NET assembly and use the .NET decompiler.");
            var arch = pe.PEHeaders.CoffHeader.Machine switch
            {
                Machine.I386 => NativeArch.X86,
                Machine.Amd64 => NativeArch.X64,
                Machine.Arm64 => NativeArch.Arm64,
                Machine.Arm or Machine.ArmThumb2 or Machine.Thumb => NativeArch.Arm,
                _ => NativeArch.Unknown,
            };
            return new Header(arch, opt.ImageBase, false);
        }
        catch (BadImageFormatException ex)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{original} is not a valid PE image: {ex.Message}");
        }
    }

    private static Header ReadElf(string copy, string original)
    {
        var bytes = File.ReadAllBytes(copy);
        bool is64 = bytes[4] == 2, little = bytes[5] != 2;
        ulong U(int at, int size)
        {
            if (at < 0 || at + size > bytes.Length) throw new ToolError(ErrorCode.MalformedInput, $"{original} has a truncated ELF header.");
            var span = bytes.AsSpan(at, size);
            return size switch
            {
                2 => little ? BinaryPrimitives.ReadUInt16LittleEndian(span) : BinaryPrimitives.ReadUInt16BigEndian(span),
                4 => little ? BinaryPrimitives.ReadUInt32LittleEndian(span) : BinaryPrimitives.ReadUInt32BigEndian(span),
                _ => little ? BinaryPrimitives.ReadUInt64LittleEndian(span) : BinaryPrimitives.ReadUInt64BigEndian(span),
            };
        }
        var arch = U(18, 2) switch
        {
            3 => NativeArch.X86,
            62 => NativeArch.X64,
            40 => NativeArch.Arm,
            183 => NativeArch.Arm64,
            _ => NativeArch.Unknown,
        };
        var phoff = (long)U(is64 ? 32 : 28, is64 ? 8 : 4);
        var phentsize = (int)U(is64 ? 54 : 42, 2);
        var phnum = (int)U(is64 ? 56 : 44, 2);
        ulong? lowest = null;
        for (int i = 0; i < phnum && phoff + (long)(i + 1) * phentsize <= bytes.Length; i++)
        {
            var at = (int)(phoff + (long)i * phentsize);
            if (U(at, 4) != 1) continue; // PT_LOAD
            var vaddr = is64 ? U(at + 16, 8) : U(at + 8, 4);
            if (lowest is not { } l || vaddr < l) lowest = vaddr;
        }
        return new Header(arch, lowest ?? 0, true);
    }

    protected override bool DatabaseExists => File.Exists(Path.Combine(_projectDirectory, ProjectName + ".gpr"));

    protected override void DeleteDatabase()
    {
        try
        {
            if (Directory.Exists(_projectDirectory)) Directory.Delete(_projectDirectory, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"Removing the damaged Ghidra project {_projectDirectory} failed: {ex.Message}", "Close other programs using it and retry.");
        }
    }

    protected override async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        Options.Progress?.Report(new NativeProviderProgress("start", clock.Elapsed));
        var worker = await provider.StartWorkerAsync(ghidra, java, new FileInfo(Entry!.InputCopy).Length, cancellationToken, refill: true).ConfigureAwait(false);
        SetWorker(worker);
        worker.EventReceived += e =>
        {
            if (e.Name == "progress" && e.Body.TryGetProperty("stage", out var stage) && stage.GetString() is { Length: > 0 } s)
                Options.Progress?.Report(new NativeProviderProgress(s, clock.Elapsed));
        };
        await provider.WaitStartedAsync(worker, Options.OpenTimeout, cancellationToken).ConfigureAwait(false);

        // An archive given for the image imports as an analyzed database.
        var reuse = DatabaseExists || Options.GhidraDatabase != null;
        ReusedDatabase = reuse;
        StartStage(reuse ? "load" : "analysis");
        Options.Progress?.Report(new NativeProviderProgress(reuse ? "load" : "analysis", clock.Elapsed));
        if (!reuse) await provider.ColdAnalysis.WaitAsync(cancellationToken).ConfigureAwait(false);
        System.Text.Json.JsonElement info;
        try
        {
            var remaining = Options.OpenTimeout - clock.Elapsed;
            if (remaining <= TimeSpan.Zero) remaining = TimeSpan.FromSeconds(1);
            // The analysis stops early enough to save what it has inside the open's limit.
            var budget = Options.AnalysisBudget ?? remaining - TimeSpan.FromSeconds(Math.Min(120, remaining.TotalSeconds * 0.2));
            var args = WorkerRows.Args(
                ("input", Entry.InputCopy),
                ("project_dir", _projectDirectory),
                ("project_name", ProjectName),
                ("program_name", ProgramName(Path.GetFileName(Entry.InputCopy))),
                ("loader_args", Pairs(_loaderArguments)),
                ("options", Pairs(_analyzerOptions)),
                ("budget_seconds", Math.Max(1, budget.TotalSeconds)),
                ("analysis", Options.Analysis == EngineAnalysis.None ? "none" : "full"),
                ("pdb", Options.Symbols == SymbolMode.Off ? null : Options.PdbPath),
                ("decompilers", provider.Options.Decompilers),
                ("decompile_timeout", (int)provider.DecompileTimeout.TotalSeconds),
                ("decompile_payload_mb", provider.DecompilePayloadMb));
            if (Options.GhidraDatabase is { } packed) args["gzf"] = packed.Path;
            // Analyzers the standard profile caps run again uncapped while the worker is idle.
            else if (provider.Profile == GhidraAnalysisProfile.Standard && Options.Analysis != EngineAnalysis.None && provider.CompletionPass) args["completion"] = true;
            if (Options.Raw is { } layout)
            {
                args["loader"] = layout.Isa.GhidraLoader ?? "BinaryLoader";
                args["language"] = layout.Isa.GhidraLanguage;
                // A format loader places the image and its entry itself.
                if (layout.Isa.GhidraLoader == null)
                {
                    args["entry"] = layout.EntryOffset;
                    args["raw_base"] = layout.Base;
                }
            }
            var seeds = new JsonArray();
            if (Options.Overrides is { } ov)
            {
                if (ov.Language != null) args["language"] = ov.Language;
                if (ov.CompilerSpec != null) args["compiler"] = ov.CompilerSpec;
                foreach (var s in ov.Seeds) seeds.Add(new JsonArray(s.Kind.ToString().ToLowerInvariant(), s.Rva, s.Name));
            }
            // Real mode: Ghidra resolves no call through a near-pointer table, so the scanned handlers are seeds.
            if (Options.Raw is { } real && Options.Analysis != EngineAnalysis.None
                && Code.RealModeDispatch.Of(await File.ReadAllBytesAsync(Entry.InputCopy, cancellationToken).ConfigureAwait(false), real) is { } image)
                foreach (var offset in Code.RealModeDispatch.Handlers(image))
                    seeds.Add(new JsonArray("function", real.Isa.GhidraLoader != null ? GhidraOptions.MzLoadModule + offset : offset, null));
            if (seeds.Count > 0) args["seeds"] = seeds;
            info = await worker.RequestAsync("open", args, remaining, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (!reuse) provider.ColdAnalysis.Release();
        }

        var loadedBase = ulong.Parse(info.GetProperty("imagebase").GetRawText(), CultureInfo.InvariantCulture);
        if (_headerImageBase is { } want && loadedBase != want)
        {
            var rebased = await worker.RequestAsync("rebase", WorkerRows.Args(("imagebase", want)), Options.RequestTimeout, cancellationToken).ConfigureAwait(false);
            loadedBase = ulong.Parse(rebased.GetProperty("imagebase").GetRawText(), CultureInfo.InvariantCulture);
            if (loadedBase != want)
                throw new ToolError(ErrorCode.Failed, $"Ghidra loaded {ImagePath} at 0x{loadedBase:X} and could not rebase it to the header image base 0x{want:X}.");
        }
        ImageBase = loadedBase;
        DecompilerAvailable = info.GetProperty("decompiler").GetBoolean();
        AnalysisComplete = info.GetProperty("analysis_complete").GetBoolean();
        RecordAnalysis(AnalysisComplete);
        Language = info.GetProperty("language").GetString() ?? "";
        FunctionCount = info.GetProperty("functions").GetInt32();
        var warnings = info.GetProperty("warnings").EnumerateArray().Select(w => w.GetString() ?? "").ToList();
        // An extension Ghidra did not load is a warning, not a failure.
        var loaded = info.TryGetProperty("extensions", out var e) ? e.EnumerateArray().Select(x => x.GetString() ?? "").ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
        foreach (var x in provider.Extensions.Where(x => !loaded.Contains(x.Name)))
            warnings.Add($"the extension {x.Name} ({x.Source}) was not loaded by Ghidra {ghidra.Version}");
        Warnings = warnings;
        if (info.TryGetProperty("analyzer_seconds", out var times) && times.GetArrayLength() > 0)
            Options.Progress?.Report(new NativeProviderProgress("analyzers", clock.Elapsed)
            {
                Analyzers = [.. times.EnumerateArray().Select(t => KeyValuePair.Create(t[0].GetString() ?? "", t[1].GetDouble()))],
            });
        if (Arch == NativeArch.Unknown) Arch = ArchOf(Language);
        if (Options.Analysis == EngineAnalysis.None && Arch == NativeArch.Arm && Options.ThumbCode is { } thumb)
        {
            var ranges = await thumb(cancellationToken).ConfigureAwait(false);
            if (ranges.Count > 0)
                await worker.RequestAsync("set_thumb", WorkerRows.Args(("ranges", new JsonArray(ranges.Select(r => (JsonNode)new JsonArray(r.Start, r.End)).ToArray()))),
                    Options.RequestTimeout, cancellationToken).ConfigureAwait(false);
        }
        Options.Progress?.Report(new NativeProviderProgress("ready", clock.Elapsed));
    }

    private static JsonArray Pairs(IEnumerable<KeyValuePair<string, string>> pairs) =>
        new(pairs.Select(p => (JsonNode)new JsonArray(p.Key, p.Value)).ToArray());

    /// <summary>Architecture from a Ghidra language id such as "x86:LE:64:default" or "AARCH64:LE:64:v8A".</summary>
    internal static NativeArch ArchOf(string language)
    {
        var parts = language.Split(':');
        if (parts.Length < 3) return NativeArch.Unknown;
        return (parts[0].ToUpperInvariant(), parts[2]) switch
        {
            ("X86", "64") => NativeArch.X64,
            ("X86", "32") => NativeArch.X86,
            ("AARCH64", _) => NativeArch.Arm64,
            ("ARM", _) => NativeArch.Arm,
            _ => NativeArch.Unknown,
        };
    }

    protected override JsonObject CloseArgs(bool save) => WorkerRows.Args(("save", save));

    protected override void Forget() => provider.Forget(this);

    public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
        ListFunctionsAsync(false, cancellationToken);

    // Function table per worker instance and change counter: one stamp request instead of every row per call.
    private readonly Dictionary<bool, (string Stamp, List<NativeFunctionInfo> Functions)> _functionTables = [];

    public async Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default)
    {
        var s = await CallAsync("stamp", WorkerRows.Args(), cancellationToken).ConfigureAwait(false);
        var stamp = $"{s.GetProperty("instance").GetString()}:{s.GetProperty("modification").GetInt64()}";
        lock (_functionTables)
            if (_functionTables.TryGetValue(withReferences, out var cached) && cached.Stamp == stamp) return cached.Functions;
        var functions = NameThunks(await WorkerRows.FunctionsPaged(start => CallAsync("functions", WorkerRows.Args(("refs", withReferences), ("start", start)), cancellationToken)).ConfigureAwait(false));
        lock (_functionTables) _functionTables[withReferences] = (stamp, functions);
        return functions;
    }

    /// <summary>Renames thunks that share their target's name to thunk_name, so their call sites do not read as the target's.</summary>
    internal static List<NativeFunctionInfo> NameThunks(List<NativeFunctionInfo> functions)
    {
        var bodies = functions.Where(f => (f.Flags & NativeFunctionFlags.Thunk) == 0).Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
        for (int i = 0; i < functions.Count; i++)
            if ((functions[i].Flags & NativeFunctionFlags.Thunk) != 0 && bodies.Contains(functions[i].Name))
                functions[i] = functions[i] with { Name = "thunk_" + functions[i].Name };
        return functions;
    }

    /// <summary>The decompiler's high p-code of the function at <paramref name="rva"/>, per basic block (decompile_native view=pcode).</summary>
    internal async Task<DecompiledFunction> PcodeAsync(uint rva, CancellationToken cancellationToken)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"Ghidra's native decompiler is not built for {GhidraInstallation.PlatformName} in {ghidra.Directory}.",
                ghidra.DecompilerRemediation);
        return WorkerRows.Decompiled(await FunctionCallAsync("pcode", WorkerRows.Args(("rva", rva)), rva, cancellationToken,
            GhidraOptions.DecompileRequestTimeout(provider.DecompileTimeout, Options.RequestTimeout)).ConfigureAwait(false));
    }

    public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) =>
        DecompileWithinAsync(rva, null, cancellationToken);

    /// <summary>Decompiles within <paramref name="timeout"/> (null: the provider's limit); one retry with 4x time and 2x payload.</summary>
    public Task<DecompiledFunction> DecompileWithinAsync(uint rva, TimeSpan? timeout, CancellationToken cancellationToken = default) =>
        DecompileCoreAsync(rva, timeout, failFirst: false, cancellationToken);

    /// <summary>failFirst: the worker treats the first attempt as timed out (test hook for the retry).</summary>
    internal async Task<DecompiledFunction> DecompileCoreAsync(uint rva, TimeSpan? timeout, bool failFirst, CancellationToken cancellationToken)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"Ghidra's native decompiler is not built for {GhidraInstallation.PlatformName} in {ghidra.Directory}.",
                ghidra.DecompilerRemediation);
        var first = timeout ?? provider.DecompileTimeout;
        async Task<DecompiledFunction> Ask()
        {
            var args = WorkerRows.Args(("rva", rva), ("timeout", (int)Math.Ceiling(first.TotalSeconds)),
                ("retry_timeout", (int)GhidraOptions.RetryTimeout(first).TotalSeconds), ("fail_first", failFirst));
            var r = await FunctionCallAsync("decompile", args, rva, cancellationToken, GhidraOptions.DecompileRequestTimeout(first, Options.RequestTimeout)).ConfigureAwait(false);
            if (r.TryGetProperty("retried", out var retried) && retried.GetBoolean()) Interlocked.Increment(ref _retries);
            return WorkerRows.Decompiled(r);
        }
        // Pseudocode does not depend on the time it took; the retry hook always asks the worker.
        return failFirst ? await Ask().ConfigureAwait(false) : await CachedAsync(OutputCacheKinds.Decompile, OutputCacheKinds.At(rva), Ask).ConfigureAwait(false);
    }

    /// <summary>A request about the function at <paramref name="rva"/>; a function the server's index knows is made first and the request rerun.</summary>
    private async Task<System.Text.Json.JsonElement> FunctionCallAsync(string op, JsonObject args, uint rva, CancellationToken cancellationToken, TimeSpan? timeout = null)
    {
        try
        {
            return await CallAsync(op, args, cancellationToken, timeout: timeout).ConfigureAwait(false);
        }
        catch (ToolError e) when (e.Code == ErrorCode.NotFound && Options.KnownStart != null)
        {
            if (!await Options.KnownStart(rva, cancellationToken).ConfigureAwait(false)) throw;
        }
        await CallAsync("make_function", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false);
        return await CallAsync(op, args, cancellationToken, timeout: timeout).ConfigureAwait(false);
    }

    private int _retries;
    /// <summary>Decompilations that succeeded only on the retry.</summary>
    internal int DecompileRetries => Volatile.Read(ref _retries);

    public async Task<IReadOnlyList<DecompileOutcome>> DecompileManyAsync(IReadOnlyList<uint> rvas, double secondsPerItem, double budgetSeconds,
        CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"Ghidra's native decompiler is not built for {GhidraInstallation.PlatformName} in {ghidra.Directory}.",
                ghidra.DecompilerRemediation);
        return await CachedManyAsync(rvas, async asked =>
        {
            var args = WorkerRows.Args(("rvas", new JsonArray(asked.Select(r => (JsonNode)r).ToArray())), ("seconds_per_item", secondsPerItem), ("budget_seconds", budgetSeconds));
            return WorkerRows.DecompiledMany(await CallAsync("decompile_many", args, cancellationToken, timeout: TimeSpan.FromSeconds(budgetSeconds + 60)).ConfigureAwait(false));
        }).ConfigureAwait(false);
    }

    public async Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Disassembly(await FunctionCallAsync("disasm", WorkerRows.Args(("rva", rva)), rva, cancellationToken).ConfigureAwait(false));

    public async Task<FunctionDisassembly> DisassembleRangeAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        WorkerRows.Range(rva, await CallAsync("disasm_range", WorkerRows.Args(("rva", rva), ("count", Math.Clamp(count, 1, 200_000))), cancellationToken).ConfigureAwait(false));

    public async Task<EngineSlice> ValueSliceAsync(EngineSliceRequest request, CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"Ghidra's native decompiler is not built for {GhidraInstallation.PlatformName} in {ghidra.Directory}.",
                ghidra.DecompilerRemediation);
        return WorkerRows.Slice(await CallAsync("value_slice", WorkerRows.SliceArgs(request), cancellationToken,
            timeout: TimeSpan.FromSeconds(request.Seconds + 30)).ConfigureAwait(false));
    }

    public async Task<IReadOnlyList<EngineInstructionItem>> InspectAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        EngineInstructions.Parse(await CallAsync("insn", WorkerRows.Args(("rva", rva), ("count", Math.Clamp(count, 1, 64))), cancellationToken).ConfigureAwait(false));

    public async Task<NativeBlockGraph> GetBlocksAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Blocks(await FunctionCallAsync("blocks", WorkerRows.Args(("rva", rva)), rva, cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await CallAsync("xrefs_to", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await (wholeFunction ? FunctionCallAsync("xrefs_from", WorkerRows.Args(("rva", rva), ("function", true)), rva, cancellationToken)
            : CallAsync("xrefs_from", WorkerRows.Args(("rva", rva), ("function", false)), cancellationToken)).ConfigureAwait(false));

    public async Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        var r = await CallAsync("set_name", WorkerRows.Args(("rva", rva), ("name", name)), cancellationToken, journal: true).ConfigureAwait(false);
        return r.GetProperty("name").GetString() ?? "";
    }

    public async Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        var r = await CallAsync("set_comment", WorkerRows.Args(("rva", rva), ("text", text), ("repeatable", repeatable)), cancellationToken, journal: true).ConfigureAwait(false);
        return r.GetProperty("comment").GetString() ?? "";
    }

    public async Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        var args = WorkerRows.Args(("items", WorkerRows.NameItems(items)), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
        return WorkerRows.NameBatch(await CallAsync("apply_names", args, cancellationToken, journal: !save, saves: save).ConfigureAwait(false));
    }

    public async Task<NativeTypeGuess> GuessTypeAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeGuess(await CallAsync("type_guess", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<PseudoCommentOutcome>> SetPseudoCommentsAsync(IReadOnlyList<(uint Rva, string Text)> items, CancellationToken cancellationToken = default) =>
        WorkerRows.PseudoComments(await CallAsync("pseudo_comments", WorkerRows.PseudoCommentArgs(items), cancellationToken, journal: true).ConfigureAwait(false));

    public async Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) =>
        WorkerRows.Stamp(await CallAsync("get_stamp", WorkerRows.Args(("key", key)), cancellationToken).ConfigureAwait(false));

    // Journaled: a worker restarted from the saved project gets the same patch set again (the operation is idempotent).
    public async Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
        WorkerRows.PatchSync(await CallAsync("sync_patches", WorkerRows.Args(("items", WorkerRows.ByteRanges(wanted))), cancellationToken, journal: true)
            .ConfigureAwait(false));

    public async Task<TypeBatchResult> ApplyTypesAsync(NativeTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        return WorkerRows.TypeBatch(await CallAsync("apply_types", WorkerRows.TypeBatchArgs(batch, stampKey, stamp, save), cancellationToken,
            journal: !save, saves: save).ConfigureAwait(false));
    }

    public async Task<NativeCallTargets> GetCallTargetsAsync(IReadOnlyList<uint> functions, IReadOnlyList<uint> sites, double seconds,
        CancellationToken cancellationToken = default)
    {
        // A decompilation a loaded machine slows past the budget ends the batch instead of the request.
        double budget = Math.Clamp(seconds, 1, Math.Max(1, RequestTimeout.TotalSeconds * 0.6));
        var args = WorkerRows.Args(("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())),
            ("sites", new JsonArray(sites.Select(s => (JsonNode)s).ToArray())), ("seconds", budget));
        return WorkerRows.CallTargets(await CallBatchAsync("virtual_targets", args, budget, cancellationToken).ConfigureAwait(false));
    }

    public async Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        return WorkerRows.UserTypes(await CallAsync("apply_user_types", WorkerRows.UserTypeArgs(batch, stampKey, stamp, save), cancellationToken,
            journal: !save, saves: save).ConfigureAwait(false));
    }

    public Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default) => GetFrameAsync(rva, true, cancellationToken);

    public Task<IReadOnlyList<NativeFrameOutcome>> GetFramesAsync(IReadOnlyList<uint> rvas, bool locals, CancellationToken cancellationToken = default) =>
        FramesAsync(rvas, locals, cancellationToken);

    public Task<NativeFrame> GetFrameAsync(uint rva, bool locals, CancellationToken cancellationToken = default) => locals
        ? CachedAsync(OutputCacheKinds.Frame, OutputCacheKinds.At(rva), () => FrameAsync(rva, true, cancellationToken))
        : FrameAsync(rva, false, cancellationToken);

    private async Task<NativeFrame> FrameAsync(uint rva, bool locals, CancellationToken cancellationToken) =>
        WorkerRows.Frame(await FunctionCallAsync("frame", WorkerRows.Args(("rva", rva), ("locals", locals)), rva, cancellationToken).ConfigureAwait(false));

    public async Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeList(await CallAsync("types", WorkerRows.Args(("filter", filter), ("kind", kind), ("offset", offset), ("limit", limit)), cancellationToken)
            .ConfigureAwait(false));

    public async Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeDetail(await CallAsync("type", WorkerRows.Args(("name", name)), cancellationToken).ConfigureAwait(false), name);

    public async Task<PdbLoadResult> LoadPdbAsync(string pdbPath, string stampKey, string stamp, bool trustAnalysisLoad, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdbPath);
        // A large PDB takes minutes: the open's limit, not a single request's.
        return WorkerRows.PdbLoad(await CallAsync("load_pdb", WorkerRows.Args(("path", pdbPath), ("stamp_key", stampKey), ("stamp", stamp),
            ("trust_analysis", trustAnalysisLoad)), cancellationToken, saves: true, timeout: Options.OpenTimeout).ConfigureAwait(false));
    }

    /// <summary>A name Ghidra has from its loader or analysis (Function ID library names included); never one this server pushed.</summary>
    internal sealed record GhidraName(uint Rva, string Name, bool Imported, bool Function);

    /// <summary>Every name Ghidra's loader and analysis gave, except its generated defaults, in pages of 50,000.</summary>
    internal async Task<IReadOnlyList<GhidraName>> ListNamesAsync(CancellationToken cancellationToken = default)
    {
        var list = new List<GhidraName>();
        for (int total = int.MaxValue; list.Count < total;)
        {
            var r = await CallAsync("names", WorkerRows.Args(("offset", list.Count), ("limit", 50_000)), cancellationToken).ConfigureAwait(false);
            total = r.GetProperty("total").GetInt32();
            int before = list.Count;
            foreach (var x in r.GetProperty("rows").EnumerateArray())
                list.Add(new GhidraName(x[0].GetUInt32(), x[1].GetString() ?? "", x[2].GetString() == "imported", x[3].GetBoolean()));
            if (list.Count == before) break;
        }
        return list;
    }

    public async Task<EngineImageInfo> GetEngineInfoAsync(CancellationToken cancellationToken = default) =>
        WorkerRows.ImageInfo(await CallAsync("image_info", new JsonObject(), cancellationToken).ConfigureAwait(false));

    public async Task<EngineDataList> ListDataAsync(int max, CancellationToken cancellationToken = default) =>
        WorkerRows.DataList(await CallAsync("defined_data", WorkerRows.Args(("max", Math.Clamp(max, 1, 500_000))), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<EngineString>> ListStringsAsync(int max, CancellationToken cancellationToken = default) =>
        WorkerRows.Strings(await CallAsync("defined_strings", WorkerRows.Args(("max", Math.Clamp(max, 1, 500_000))), cancellationToken).ConfigureAwait(false));

    public async Task<EngineFunctionRecord> GetFunctionRecordAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.FunctionRecord(await FunctionCallAsync("function_info", WorkerRows.Args(("rva", rva)), rva, cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<EngineNamespace>> ListNamespacesAsync(CancellationToken cancellationToken = default) =>
        WorkerRows.Namespaces(await CallAsync("namespaces", new JsonObject(), cancellationToken).ConfigureAwait(false));

    public async Task<NativeFieldXrefs> GetFieldXrefsAsync(IReadOnlyList<string> types, string? member, int? offset, IReadOnlyList<uint> functions, double seconds,
        uint? allFrom = null, CancellationToken cancellationToken = default)
    {
        // The budget stays under the request timeout so slow decompilation ends the scan, not the request.
        double budget = Math.Clamp(seconds, 1, Math.Max(1, Options.RequestTimeout.TotalSeconds * 0.6));
        var args = WorkerRows.Args(("types", new JsonArray(types.Select(t => (JsonNode)t).ToArray())), ("member", member), ("offset", offset),
            ("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())), ("seconds", budget), ("all_from", allFrom));
        return WorkerRows.FieldXrefs(await CallAsync("field_xrefs", args, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Java (a GhidraScript class or a run() body) within the request limit; see <see cref="RunJavaAsync"/>.</summary>
    public Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default) =>
        RunJavaAsync(code, Options.RequestTimeout.TotalSeconds, cancellationToken);

    /// <summary>Runs a script in one transaction within <paramref name="seconds"/>, committed on normal return, then saves; not journaled, as a restart could not replay it, so its committed changes are on disk.</summary>
    internal async Task<NativeScriptResult> RunJavaAsync(string code, double seconds, CancellationToken cancellationToken = default,
        string? name = null, IReadOnlyList<string>? args = null, string? userDirectory = null, string? language = null)
    {
        ArgumentNullException.ThrowIfNull(code);
        var request = WorkerRows.Args(("code", code), ("timeout", seconds), ("name", name), ("user_dir", userDirectory), ("language", language));
        if (args is { Count: > 0 }) request["args"] = new System.Text.Json.Nodes.JsonArray([.. args.Select(a => (System.Text.Json.Nodes.JsonNode?)a)]);
        var r = await CallAsync("script", request, cancellationToken, saves: true,
            timeout: TimeSpan.FromSeconds(seconds + 30)).ConfigureAwait(false);
        return new NativeScriptResult(null, WorkerRows.Text(r.GetProperty("stdout")) ?? "", WorkerRows.Text(r.GetProperty("stderr")) ?? "",
            WorkerRows.Text(r.GetProperty("error")));
    }

    /// <summary>The analysis's Error and Warning bookmarks: the counts and up to <paramref name="max"/> rows "type 0xVA category: comment".</summary>
    internal async Task<(int Errors, int Warnings, IReadOnlyList<string> Rows)> BookmarksAsync(int max, Func<uint, string> va, CancellationToken cancellationToken)
    {
        var r = await CallAsync("bookmarks", WorkerRows.Args(("max", max)), cancellationToken).ConfigureAwait(false);
        var rows = r.GetProperty("rows").EnumerateArray()
            .Select(x => $"{x[0].GetString()!.ToLowerInvariant()} {va(x[1].GetUInt32())} {x[2].GetString()}: {x[3].GetString()}").ToList();
        return (r.GetProperty("error").GetInt32(), r.GetProperty("warning").GetInt32(), rows);
    }

    /// <summary>The completion pass as status shows it after the profile: "→full" when done, its progress while it runs, else null.</summary>
    internal async Task<string?> CompletionAsync(CancellationToken cancellationToken)
    {
        var r = await CallAsync("completion", WorkerRows.Args(), cancellationToken).ConfigureAwait(false);
        return r.GetProperty("state").GetString() switch
        {
            "done" => "→full",
            "off" or null => null,
            "running" or "pending" => $" (completion pass: {r.GetProperty("done").GetInt32():N0} of {r.GetProperty("total").GetInt32():N0} functions{Shared(r)})",
            var other => $" (completion pass {other})",
        };
    }

    // The requests that ran beside a slice and the slices that gave way to a writer; empty when there were none.
    private static string Shared(System.Text.Json.JsonElement r)
    {
        int beside = r.TryGetProperty("beside", out var b) ? b.GetInt32() : 0, yielded = r.TryGetProperty("yielded", out var y) ? y.GetInt32() : 0;
        return (beside > 0 ? $"; {beside:N0} requests ran beside a slice" : "") + (yielded > 0 ? $"; {yielded:N0} slices gave way to a writer" : "");
    }

    /// <summary>Saves the program and writes it to <paramref name="path"/> as a packed Ghidra archive (.gzf); returns the path and size.</summary>
    internal async Task<(string Path, long Bytes)> ExportPackedAsync(string path, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("export_gzf", WorkerRows.Args(("path", path)), cancellationToken, saves: true, timeout: Options.OpenTimeout).ConfigureAwait(false);
        return (r.GetProperty("path").GetString() ?? path, r.GetProperty("size").GetInt64());
    }

    /// <summary>Whether the worker's background function pass has its table ready for the current program, and its size.</summary>
    internal async Task<(bool Ready, int Functions)> FunctionTableAsync(CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("function_table", new JsonObject(), cancellationToken).ConfigureAwait(false);
        return (r.GetProperty("ready").GetBoolean(), r.GetProperty("functions").GetInt32());
    }

    /// <summary>The program's own data types as a C header ("h") or a data type archive ("gdt") at <paramref name="path"/>.</summary>
    internal async Task<(string Path, long Bytes, int Types)> ExportTypesAsync(string path, string format, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("export_types", WorkerRows.Args(("path", path), ("format", format)), cancellationToken).ConfigureAwait(false);
        return (r.GetProperty("path").GetString() ?? path, r.GetProperty("size").GetInt64(), r.GetProperty("types").GetInt32());
    }

    // --- analysis control (EngineControl) ---

    /// <summary>Size of the worker's decompiler pool: decompile requests that run at once.</summary>
    internal int DecompilerPool => provider.Options.Decompilers;

    /// <summary>A lookup that failed on a project whose analysis was cut short may succeed once the analysis is complete: the Next line says so.</summary>
    protected override ToolError Explain(ToolError error)
    {
        if (AnalysisComplete || error.Code is not (ErrorCode.NotFound or ErrorCode.Failed or ErrorCode.Unsupported)) return error;
        var why = Options.Analysis == EngineAnalysis.None ? $"{Path.GetFileName(ImagePath)} was loaded without Ghidra's analysis ({Core.ServerOptions.EngineAnalysisVariable}=none)"
            : $"the Ghidra analysis of {Path.GetFileName(ImagePath)} is partial (the open's budget ran out)";
        var next = $"{why}: reanalyze_native image={Path.GetFileName(ImagePath)} engine=ghidra completes it";
        return new ToolError(error.Code, error.Message, error.Remediation is { Length: > 0 } r ? $"{r}; or {next}" : next) { Details = error.Details, Partial = error.Partial };
    }

    /// <summary>After a reanalysis: whether the saved project now holds a complete analysis, and its function count.</summary>
    internal void Reanalyzed(bool complete, int functions)
    {
        AnalysisComplete = complete;
        FunctionCount = functions;
        RecordAnalysis(complete);
    }
}
