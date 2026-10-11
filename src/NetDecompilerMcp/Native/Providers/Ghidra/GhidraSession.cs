using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Reflection.PortableExecutable;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ghidra;

/// <summary>
/// One image open in a Ghidra worker. Reads run concurrently on the worker's decompiler pool; changes are serialized
/// and journaled (see <see cref="WorkerSessionBase"/>). The project lives in the cache entry under a directory named
/// by the profile key, so a later open of the same bytes under the same configuration reopens it without analysis.
/// </summary>
internal sealed class GhidraSession(GhidraProvider provider, GhidraInstallation ghidra, JavaRuntime java, NativeOpenOptions options)
    : WorkerSessionBase(options), INativeDecompilerSession
{
    internal const string ProjectName = "ndm";

    private ulong? _headerImageBase;
    private string _projectDirectory = "";
    private List<KeyValuePair<string, string>> _loaderArguments = [];
    private IReadOnlyList<KeyValuePair<string, string>> _analyzerOptions = [];

    public override string ProviderId => GhidraProvider.ProviderId;
    protected override string EngineName => "Ghidra";
    protected override TimeSpan ShutdownGrace => provider.Options.ShutdownGrace;
    protected override int MaxRestarts => provider.Options.MaxRestarts;
    protected override bool ConcurrentRequests => true;
    protected override int JournalSaveThreshold => provider.Options.JournalSaveThreshold;
    internal string ProjectDirectory => _projectDirectory;
    protected override string? DatabaseLocation => _projectDirectory.Length > 0 ? _projectDirectory : null;
    /// <summary>False when the first analysis ran out of time; the saved project then holds what was analyzed.</summary>
    public bool AnalysisComplete { get; private set; }
    internal string Language { get; private set; } = "";
    internal int FunctionCount { get; private set; }
    internal IReadOnlyList<string> Warnings { get; private set; } = [];

    protected override CacheEntry AcquireEntry(string imagePath, string? sha256) => provider.Cache.Acquire(ProviderId, imagePath, sha256);

    protected override void PrepareOpen()
    {
        var header = ReadHeader(Entry!.InputCopy, ImagePath);
        Arch = header.Arch;
        _headerImageBase = header.ImageBase;
        var profile = provider.Profile;
        _loaderArguments = [.. GhidraOptions.LoaderArguments(profile)];
        if (header.IsElf && header.ImageBase is { } elfBase)
            _loaderArguments.Add(new(GhidraOptions.ElfImageBaseArgument, elfBase.ToString("x", CultureInfo.InvariantCulture)));
        _analyzerOptions = GhidraOptions.AnalyzerOptions(profile, Options.Symbols, provider.ExtraOptions);
        var key = GhidraOptions.ProfileKey(ghidra, profile, _loaderArguments, _analyzerOptions, provider.Extensions);
        _projectDirectory = Path.Combine(Entry.Directory, "p-" + key);
    }

    internal readonly record struct Header(NativeArch Arch, ulong? ImageBase, bool IsElf);

    /// <summary>
    /// Architecture and image base from a PE or ELF header (ELF: the lowest PT_LOAD address); the architecture of a thin
    /// Mach-O. Other formats are left to Ghidra's loaders, whose base is then taken as loaded.
    /// </summary>
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
        var worker = await provider.StartWorkerAsync(ghidra, java, new FileInfo(Entry!.InputCopy).Length, cancellationToken).ConfigureAwait(false);
        SetWorker(worker);
        worker.EventReceived += e =>
        {
            if (e.Name == "progress" && e.Body.TryGetProperty("stage", out var stage) && stage.GetString() is { Length: > 0 } s)
                Options.Progress?.Report(new NativeProviderProgress(s, clock.Elapsed));
        };
        await worker.WaitReadyAsync(provider.Options.StartTimeout, cancellationToken).ConfigureAwait(false);

        var reuse = DatabaseExists;
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
            var budget = remaining - TimeSpan.FromSeconds(Math.Min(120, remaining.TotalSeconds * 0.2));
            var args = WorkerRows.Args(
                ("input", Entry.InputCopy),
                ("project_dir", _projectDirectory),
                ("project_name", ProjectName),
                ("program_name", Path.GetFileName(Entry.InputCopy)),
                ("loader_args", Pairs(_loaderArguments)),
                ("options", Pairs(_analyzerOptions)),
                ("budget_seconds", Math.Max(1, budget.TotalSeconds)),
                ("pdb", Options.Symbols == SymbolMode.Off ? null : Options.PdbPath),
                ("decompilers", provider.Options.Decompilers),
                ("decompile_timeout", (int)provider.DecompileTimeout.TotalSeconds),
                ("decompile_payload_mb", provider.DecompilePayloadMb));
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
        Language = info.GetProperty("language").GetString() ?? "";
        FunctionCount = info.GetProperty("functions").GetInt32();
        var warnings = info.GetProperty("warnings").EnumerateArray().Select(w => w.GetString() ?? "").ToList();
        // an extension Ghidra did not load is a warning, not a failure: the analysis runs without it
        var loaded = info.TryGetProperty("extensions", out var e) ? e.EnumerateArray().Select(x => x.GetString() ?? "").ToHashSet(StringComparer.OrdinalIgnoreCase) : [];
        foreach (var x in provider.Extensions.Where(x => !loaded.Contains(x.Name)))
            warnings.Add($"the extension {x.Name} ({x.Source}) was not loaded by Ghidra {ghidra.Version}");
        Warnings = warnings;
        if (Arch == NativeArch.Unknown) Arch = ArchOf(Language);
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

    public async Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default) =>
        await WorkerRows.FunctionsPaged(start => CallAsync("functions", WorkerRows.Args(("refs", withReferences), ("start", start)), cancellationToken)).ConfigureAwait(false);

    public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) =>
        DecompileWithinAsync(rva, null, cancellationToken);

    /// <summary>
    /// The decompiler gets <paramref name="timeout"/> (null: the provider's limit); a timeout or a full response buffer is tried once
    /// more with four times the time and twice the payload, inside the same request.
    /// </summary>
    public Task<DecompiledFunction> DecompileWithinAsync(uint rva, TimeSpan? timeout, CancellationToken cancellationToken = default) =>
        DecompileCoreAsync(rva, timeout, failFirst: false, cancellationToken);

    /// <summary>failFirst: the worker treats the first attempt as timed out (test hook for the retry).</summary>
    internal async Task<DecompiledFunction> DecompileCoreAsync(uint rva, TimeSpan? timeout, bool failFirst, CancellationToken cancellationToken)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"Ghidra's native decompiler is not built for {GhidraInstallation.PlatformName} in {ghidra.Directory}.",
                ghidra.DecompilerRemediation);
        var first = timeout ?? provider.DecompileTimeout;
        var args = WorkerRows.Args(("rva", rva), ("timeout", (int)Math.Ceiling(first.TotalSeconds)),
            ("retry_timeout", (int)GhidraOptions.RetryTimeout(first).TotalSeconds), ("fail_first", failFirst));
        var r = await CallAsync("decompile", args, cancellationToken, timeout: GhidraOptions.DecompileRequestTimeout(first, Options.RequestTimeout)).ConfigureAwait(false);
        if (r.TryGetProperty("retried", out var retried) && retried.GetBoolean()) Interlocked.Increment(ref _retries);
        return WorkerRows.Decompiled(r);
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
        var args = WorkerRows.Args(("rvas", new JsonArray(rvas.Select(r => (JsonNode)r).ToArray())), ("seconds_per_item", secondsPerItem), ("budget_seconds", budgetSeconds));
        return WorkerRows.DecompiledMany(await CallAsync("decompile_many", args, cancellationToken, timeout: TimeSpan.FromSeconds(budgetSeconds + 60)).ConfigureAwait(false));
    }

    public async Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Disassembly(await CallAsync("disasm", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

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
        WorkerRows.Blocks(await CallAsync("blocks", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await CallAsync("xrefs_to", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await CallAsync("xrefs_from", WorkerRows.Args(("rva", rva), ("function", wholeFunction)), cancellationToken).ConfigureAwait(false));

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
        // the budget stays under the request timeout so a slow decompilation ends the batch instead of the request
        double budget = Math.Clamp(seconds, 1, Math.Max(1, RequestTimeout.TotalSeconds * 0.6));
        var args = WorkerRows.Args(("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())),
            ("sites", new JsonArray(sites.Select(s => (JsonNode)s).ToArray())), ("seconds", budget));
        return WorkerRows.CallTargets(await CallAsync("virtual_targets", args, cancellationToken).ConfigureAwait(false));
    }

    public async Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        return WorkerRows.UserTypes(await CallAsync("apply_user_types", WorkerRows.UserTypeArgs(batch, stampKey, stamp, save), cancellationToken,
            journal: !save, saves: save).ConfigureAwait(false));
    }

    public async Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Frame(await CallAsync("frame", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeList(await CallAsync("types", WorkerRows.Args(("filter", filter), ("kind", kind), ("offset", offset), ("limit", limit)), cancellationToken)
            .ConfigureAwait(false));

    public async Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeDetail(await CallAsync("type", WorkerRows.Args(("name", name)), cancellationToken).ConfigureAwait(false), name);

    public async Task<PdbLoadResult> LoadPdbAsync(string pdbPath, string stampKey, string stamp, bool trustAnalysisLoad, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdbPath);
        // a large PDB takes minutes: the open's limit, not a single request's
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
        WorkerRows.FunctionRecord(await CallAsync("function_info", WorkerRows.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<EngineNamespace>> ListNamespacesAsync(CancellationToken cancellationToken = default) =>
        WorkerRows.Namespaces(await CallAsync("namespaces", new JsonObject(), cancellationToken).ConfigureAwait(false));

    public async Task<NativeFieldXrefs> GetFieldXrefsAsync(IReadOnlyList<string> types, string? member, int? offset, IReadOnlyList<uint> functions, double seconds,
        CancellationToken cancellationToken = default)
    {
        // the budget stays under the request timeout so slow decompilation ends the scan instead of the request
        double budget = Math.Clamp(seconds, 1, Math.Max(1, Options.RequestTimeout.TotalSeconds * 0.6));
        var args = WorkerRows.Args(("types", new JsonArray(types.Select(t => (JsonNode)t).ToArray())), ("member", member), ("offset", offset),
            ("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())), ("seconds", budget));
        return WorkerRows.FieldXrefs(await CallAsync("field_xrefs", args, cancellationToken).ConfigureAwait(false));
    }

    /// <summary>Java (a GhidraScript class or a run() body) within the request limit; see <see cref="RunJavaAsync"/>.</summary>
    public Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default) =>
        RunJavaAsync(code, Options.RequestTimeout.TotalSeconds, cancellationToken);

    /// <summary>
    /// Runs a script in one transaction within <paramref name="seconds"/>, committed only when it returns normally, and saves
    /// the program after it: the script is not journaled (a restart could not replay it), its committed changes are on disk.
    /// </summary>
    internal async Task<NativeScriptResult> RunJavaAsync(string code, double seconds, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        var r = await CallAsync("script", WorkerRows.Args(("code", code), ("timeout", seconds)), cancellationToken, saves: true,
            timeout: TimeSpan.FromSeconds(seconds + 30)).ConfigureAwait(false);
        return new NativeScriptResult(null, WorkerRows.Text(r.GetProperty("stdout")) ?? "", WorkerRows.Text(r.GetProperty("stderr")) ?? "",
            WorkerRows.Text(r.GetProperty("error")));
    }

    /// <summary>Saves the program and writes it to <paramref name="path"/> as a packed Ghidra archive (.gzf); returns the path and size.</summary>
    internal async Task<(string Path, long Bytes)> ExportPackedAsync(string path, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("export_gzf", WorkerRows.Args(("path", path)), cancellationToken, saves: true, timeout: Options.OpenTimeout).ConfigureAwait(false);
        return (r.GetProperty("path").GetString() ?? path, r.GetProperty("size").GetInt64());
    }
}
