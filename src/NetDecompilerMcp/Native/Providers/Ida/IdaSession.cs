using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ida;

/// <summary>One image open in an idalib worker; requests run one at a time (see <see cref="WorkerSessionBase"/>).</summary>
internal sealed class IdaSession(IdaProvider provider, IdaInstallation ida, PythonInterpreter python, NativeOpenOptions options)
    : WorkerSessionBase(options), INativeDecompilerSession
{
    private static readonly string[] UnpackedExtensions = [".id0", ".id1", ".id2", ".nam", ".til"];

    private string _databasePath = "";
    private ulong _headerImageBase;

    public override string ProviderId => IdaProvider.ProviderId;
    protected override string EngineName => "IDA";
    protected override TimeSpan ShutdownGrace => provider.Options.ShutdownGrace;
    protected override int MaxRestarts => provider.Options.MaxRestarts;
    protected override int JournalSaveThreshold => provider.Options.JournalSaveThreshold;
    internal string DatabasePath => _databasePath;
    /// <summary>False when opened without auto-analysis: the engine's function list is not complete.</summary>
    public bool AnalysisComplete => Options.Analysis != EngineAnalysis.None;
    public string? DatabaseNote => Note;

    protected override string? Note => string.Join("; ", new[]
    {
        AnalysisComplete ? null : "no auto-analysis: functions made where asked",
        Entry?.SnapshotOf is { } pid ? $"read-only snapshot of the database process {pid} has open: edits are not saved" : null,
    }.Where(n => n != null)) is { Length: > 0 } note ? note : null;
    protected override string? DatabaseLocation => _databasePath.Length > 0 ? _databasePath : null;

    private string Profile => (Options.Symbols == SymbolMode.Off ? "nopdb" : "default") + (Options.Analysis == EngineAnalysis.None ? "-noauto" : "");

    /// <summary>
    /// The image's cache entry; when another server process holds it, a read-only snapshot of its last saved database,
    /// else Conflict naming that process.
    /// </summary>
    protected override CacheEntry AcquireEntry(string imagePath, string? sha256) =>
        provider.Cache.Acquire(ProviderId, imagePath, sha256, (locked, sha) =>
        {
            if (locked.OwnerPid is not { } pid || pid == Environment.ProcessId) throw locked.Conflict;
            var saved = Path.Combine(locked.Directory, IdaProvider.DatabaseFileName(ida, Profile));
            if (!File.Exists(saved))
                throw new ToolError(ErrorCode.Conflict, $"{locked.Conflict.Message} It has no saved database of this image to take a read-only snapshot of yet.",
                    locked.Conflict.Remediation);
            return provider.Cache.Snapshot(ProviderId, locked, sha, Path.GetFullPath(imagePath), [saved]);
        });

    protected override void PrepareOpen()
    {
        (Arch, _headerImageBase) = ReadHeader(Entry!.InputCopy, ImagePath);
        _databasePath = Path.Combine(Entry.Directory, IdaProvider.DatabaseFileName(ida, Profile));
    }

    /// <summary>
    /// Machine and image base from the PE header, or from our ELF / Mach-O reader (ELF: the lowest PT_LOAD page; Mach-O:
    /// __TEXT, a thin image); rejects what IDA would load as something else.
    /// </summary>
    internal static (NativeArch, ulong) ReadHeader(string copy, string original)
    {
        switch (NativeImageLoader.DetectFile(copy))
        {
            case NativeFileKind.Elf or NativeFileKind.MachO:
                var image = NativeImageLoader.Open(copy);
                if (image.Arch is NativeArch.Unknown)
                    throw new ToolError(ErrorCode.Unsupported, $"{original} is for machine {image.MachineName}, which the server cannot identify for IDA.");
                return (image.Arch, image.ImageBase);
            case NativeFileKind.MachOFat:
                throw new ToolError(ErrorCode.InvalidArgument, $"{original} is a universal Mach-O; IDA is given one slice.", "load the image with slice= and open that");
        }
        try
        {
            using var s = File.OpenRead(copy);
            using var pe = new PEReader(s);
            if (pe.PEHeaders.PEHeader is not { } opt)
                throw new ToolError(ErrorCode.MalformedInput, $"{original} is not a PE image (no optional header).");
            var arch = pe.PEHeaders.CoffHeader.Machine switch
            {
                Machine.I386 => NativeArch.X86,
                Machine.Amd64 => NativeArch.X64,
                Machine.Arm64 => NativeArch.Arm64,
                Machine.Arm or Machine.ArmThumb2 or Machine.Thumb => NativeArch.Arm,
                var m => throw new ToolError(ErrorCode.Unsupported, $"{original} is for machine {m} (0x{(ushort)m:X4}); x86, x64, ARM and ARM64 PE images are supported."),
            };
            if (pe.PEHeaders.CorHeader is { } cor && (cor.Flags & CorFlags.ILOnly) != 0)
                throw new ToolError(ErrorCode.Unsupported, $"{original} is an IL-only .NET assembly; it has no native code to decompile.",
                    "Load it as a .NET assembly and use the .NET decompiler.");
            return (arch, opt.ImageBase);
        }
        catch (BadImageFormatException ex)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{original} is not a valid PE image: {ex.Message}");
        }
        catch (IOException ex)
        {
            throw new ToolError(ErrorCode.IoError, $"Reading {original} failed: {ex.Message}");
        }
    }

    protected override bool DatabaseExists => File.Exists(_databasePath);

    protected override async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        Options.Progress?.Report(new NativeProviderProgress("start", clock.Elapsed));
        var worker = provider.StartWorker(ida, python, Options.Symbols == SymbolMode.Off ? null : Options.PdbPath);
        SetWorker(worker);
        worker.EventReceived += e =>
        {
            if (e.Name == "progress") Options.Progress?.Report(new NativeProviderProgress(ReusedDatabase ? "load" : "analysis", clock.Elapsed));
        };
        await worker.WaitReadyAsync(provider.Options.StartTimeout, cancellationToken).ConfigureAwait(false);

        provider.CheckVersion(await worker.RequestAsync("hello", null, provider.Options.StartTimeout, cancellationToken).ConfigureAwait(false));
        var reuse = File.Exists(_databasePath);
        ReusedDatabase = reuse;
        StartStage(reuse ? "load" : "analysis");
        Options.Progress?.Report(new NativeProviderProgress(reuse ? "load" : "analysis", clock.Elapsed));
        var idaArgs = new JsonArray();
        if (Options.Symbols == SymbolMode.Off) idaArgs.Add("-Opdb:off");
        var remaining = Options.OpenTimeout - clock.Elapsed;
        if (remaining <= TimeSpan.Zero) remaining = TimeSpan.FromSeconds(1);
        var info = await worker.RequestAsync("open", IdaProvider.Args(("input", Entry!.InputCopy), ("idb", _databasePath), ("ida_args", idaArgs), ("auto", Options.Analysis != EngineAnalysis.None),
            ("sha256", Entry.Sha256)), remaining, cancellationToken).ConfigureAwait(false);

        var loadedBase = info.GetProperty("imagebase").GetUInt64();
        if (loadedBase != _headerImageBase)
        {
            var rebased = await worker.RequestAsync("rebase", IdaProvider.Args(("imagebase", _headerImageBase)), Options.RequestTimeout, cancellationToken).ConfigureAwait(false);
            loadedBase = rebased.GetProperty("imagebase").GetUInt64();
            if (loadedBase != _headerImageBase)
                throw new ToolError(ErrorCode.Failed, $"IDA loaded {ImagePath} at 0x{loadedBase:X} and could not rebase it to the header image base 0x{_headerImageBase:X}.");
        }
        ImageBase = loadedBase;
        DecompilerAvailable = info.GetProperty("decompiler").GetBoolean();
        if (info.TryGetProperty("idb", out var idb) && idb.GetString() is { Length: > 0 } actual && !PathsEqual(actual, _databasePath))
            _databasePath = actual;
        Options.Progress?.Report(new NativeProviderProgress("ready", clock.Elapsed));
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    /// <summary>Unpacked database components left by a worker that was killed; the packed .i64 holds the last save.</summary>
    protected override void DiscardLeftovers()
    {
        var stem = Path.Combine(Path.GetDirectoryName(_databasePath)!, Path.GetFileNameWithoutExtension(_databasePath));
        foreach (var ext in UnpackedExtensions) TryDelete(stem + ext);
        if (File.Exists(_databasePath) && new FileInfo(_databasePath).Length == 0) TryDelete(_databasePath);
    }

    protected override void DeleteDatabase()
    {
        DiscardLeftovers();
        TryDelete(_databasePath);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    protected override JsonObject CloseArgs(bool save) => IdaProvider.Args(("save", save));

    protected override void Forget() => provider.Forget(this);

    public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
        ListFunctionsAsync(false, cancellationToken);

    public async Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default)
    {
        return await WorkerRows.FunctionsPaged(start =>
            CallAsync("functions", IdaProvider.Args(("refs", withReferences), ("start", start)), cancellationToken)).ConfigureAwait(false);
    }

    public async Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The Hex-Rays decompiler is not available for {Arch} in this IDA install (not installed or not licensed).",
                IdaProvider.Remediation(ErrorCode.Unsupported, ""));
        return WorkerRows.Decompiled(await CallAsync("decompile", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));
    }

    public async Task<IReadOnlyList<DecompileOutcome>> DecompileManyAsync(IReadOnlyList<uint> rvas, double secondsPerItem, double budgetSeconds,
        CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The Hex-Rays decompiler is not available for {Arch} in this IDA install (not installed or not licensed).",
                IdaProvider.Remediation(ErrorCode.Unsupported, ""));
        var args = IdaProvider.Args(("rvas", new JsonArray(rvas.Select(r => (JsonNode)r).ToArray())), ("seconds_per_item", secondsPerItem), ("budget_seconds", budgetSeconds));
        // the worker keeps the budget; the request limit only catches a stuck worker
        return WorkerRows.DecompiledMany(await CallAsync("decompile_many", args, cancellationToken, timeout: TimeSpan.FromSeconds(budgetSeconds + 60)).ConfigureAwait(false));
    }

    public async Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Disassembly(await CallAsync("disasm", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<FunctionDisassembly> DisassembleRangeAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        WorkerRows.Range(rva, await CallAsync("disasm_range", IdaProvider.Args(("rva", rva), ("count", Math.Clamp(count, 1, 200_000))), cancellationToken).ConfigureAwait(false));

    public async Task<EngineSlice> ValueSliceAsync(EngineSliceRequest request, CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The Hex-Rays decompiler is not available for {Arch} in this IDA install (not installed or not licensed).",
                IdaProvider.Remediation(ErrorCode.Unsupported, ""));
        return WorkerRows.Slice(await CallAsync("value_slice", WorkerRows.SliceArgs(request), cancellationToken,
            timeout: TimeSpan.FromSeconds(request.Seconds + 30)).ConfigureAwait(false));
    }

    public async Task<IReadOnlyList<EngineInstructionItem>> InspectAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        EngineInstructions.Parse(await CallAsync("insn", IdaProvider.Args(("rva", rva), ("count", Math.Clamp(count, 1, 64))), cancellationToken).ConfigureAwait(false));

    public async Task<NativeBlockGraph> GetBlocksAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Blocks(await CallAsync("blocks", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<NativeCallTargets> GetCallTargetsAsync(IReadOnlyList<uint> functions, IReadOnlyList<uint> sites, double seconds,
        CancellationToken cancellationToken = default)
    {
        // the budget stays under the request timeout so a slow decompilation ends the batch instead of the worker
        double budget = Math.Clamp(seconds, 1, Math.Max(1, RequestTimeout.TotalSeconds * 0.6));
        var args = IdaProvider.Args(("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())),
            ("sites", new JsonArray(sites.Select(s => (JsonNode)s).ToArray())), ("seconds", budget));
        var r = await CallAsync("virtual_targets", args, cancellationToken).ConfigureAwait(false);
        var targets = new List<NativeCallTarget>();
        foreach (var row in r.GetProperty("rows").EnumerateArray())
        {
            uint site = row[0].GetUInt32();
            var kind = row[1].GetString() ?? "other";
            targets.Add(kind switch
            {
                "xref" or "direct" => new NativeCallTarget(site, kind, row[2].GetUInt32(), null, null),
                "vftable" => new NativeCallTarget(site, kind, null, row[2].GetString(), row[3].GetInt32()),
                _ => new NativeCallTarget(site, "other", null, row.GetArrayLength() > 2 ? row[2].GetString() : null, null),
            });
        }
        var failed = r.GetProperty("failed").EnumerateArray().Select(f => (f[0].GetUInt32(), f[1].GetString() ?? "")).ToList();
        var (partial, next) = WorkerRows.Partial(r);
        return new NativeCallTargets(targets, r.GetProperty("decompiled").GetInt32(), failed, r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean())
            { Partial = partial, Next = next };
    }

    public async Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await CallAsync("xrefs_to", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
        WorkerRows.Xrefs(await CallAsync("xrefs_from", IdaProvider.Args(("rva", rva), ("function", wholeFunction)), cancellationToken).ConfigureAwait(false));

    public async Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        var r = await CallAsync("set_name", IdaProvider.Args(("rva", rva), ("name", name)), cancellationToken, journal: true).ConfigureAwait(false);
        return r.GetProperty("name").GetString() ?? "";
    }

    public async Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        var r = await CallAsync("set_comment", IdaProvider.Args(("rva", rva), ("text", text), ("repeatable", repeatable)), cancellationToken, journal: true).ConfigureAwait(false);
        return r.GetProperty("comment").GetString() ?? "";
    }

    public async Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        var args = IdaProvider.Args(("items", WorkerRows.NameItems(items)), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
        // A saved batch is in the database; an unsaved one is journaled so a restart re-applies it.
        return WorkerRows.NameBatch(await CallAsync("apply_names", args, cancellationToken, journal: !save, saves: save).ConfigureAwait(false));
    }

    public async Task<NativeTypeGuess> GuessTypeAsync(uint rva, CancellationToken cancellationToken = default) =>
        WorkerRows.TypeGuess(await CallAsync("type_guess", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<PseudoCommentOutcome>> SetPseudoCommentsAsync(IReadOnlyList<(uint Rva, string Text)> items, CancellationToken cancellationToken = default) =>
        WorkerRows.PseudoComments(await CallAsync("pseudo_comments", WorkerRows.PseudoCommentArgs(items), cancellationToken, journal: true).ConfigureAwait(false));

    public async Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(wanted);
        var rows = new JsonArray();
        foreach (var w in wanted) rows.Add(new JsonArray(w.Rva, Convert.ToHexString(w.Bytes)));
        // Journaled: a worker restarted from the saved database gets the same patch set again (the operation is idempotent).
        var r = await CallAsync("sync_patches", IdaProvider.Args(("items", rows)), cancellationToken, journal: true).ConfigureAwait(false);
        var problems = r.GetProperty("missing").EnumerateArray().Concat(r.GetProperty("mismatches").EnumerateArray()).Select(e => e.GetUInt32()).ToList();
        return new PatchSyncResult(r.GetProperty("patched").GetInt32(), r.GetProperty("reverted").GetInt32(), r.GetProperty("ranges").GetInt32(),
            r.GetProperty("functions").GetInt32(), r.GetProperty("missing_count").GetInt32(), r.GetProperty("mismatch_count").GetInt32(), problems,
            TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()));
    }

    public async Task<TypeBatchResult> ApplyTypesAsync(NativeTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        var prototypes = new JsonArray();
        foreach (var p in batch.Prototypes) prototypes.Add(new JsonArray(p.Rva, p.Declaration));
        JsonObject? classes = null;
        if (batch.Classes.Count > 0 || batch.Methods.Count > 0)
        {
            var list = new JsonArray();
            foreach (var c in batch.Classes)
            {
                var vftables = new JsonArray();
                foreach (var v in c.Vftables) vftables.Add(new JsonArray(v.Offset, v.Rva, new JsonArray(v.Slots.Select(s => (JsonNode)s).ToArray())));
                var bases = new JsonArray();
                foreach (var b in c.Bases) bases.Add(new JsonArray(b.Name, b.Offset));
                list.Add(new JsonObject { ["name"] = c.Name, ["vftables"] = vftables, ["bases"] = bases });
            }
            var methods = new JsonArray();
            foreach (var m in batch.Methods) methods.Add(new JsonArray(m.Rva, m.Class));
            classes = new JsonObject { ["ptr"] = batch.PointerSize, ["classes"] = list, ["methods"] = methods };
        }
        var args = IdaProvider.Args(("decls", batch.Declarations), ("prototypes", prototypes), ("classes", classes), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
        // The request is large and mostly in the type library: a saved batch is in the database, an unsaved one journaled.
        var r = await CallAsync("apply_types", args, cancellationToken, journal: !save, saves: save).ConfigureAwait(false);
        return new TypeBatchResult(r.GetProperty("decl_errors").GetInt32(), r.GetProperty("typed").GetInt32(), r.GetProperty("type_failures").GetInt32(),
            r.GetProperty("structs").GetInt32(), r.GetProperty("vftables_typed").GetInt32(), r.GetProperty("methods_typed").GetInt32(),
            TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()), r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList(),
            r.TryGetProperty("method_skips", out var skips) ? skips.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetInt32()) : new Dictionary<string, int>());
    }

    public async Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(batch);
        return WorkerRows.UserTypes(await CallAsync("apply_user_types", WorkerRows.UserTypeArgs(batch, stampKey, stamp, save), cancellationToken,
            journal: !save, saves: save).ConfigureAwait(false));
    }

    public async Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("types", IdaProvider.Args(("filter", filter), ("kind", kind), ("offset", offset), ("limit", limit)), cancellationToken).ConfigureAwait(false);
        return new NativeTypeList(r.GetProperty("total").GetInt32(), r.GetProperty("rows").EnumerateArray()
            .Select(x => new NativeTypeEntry(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetInt64(), x[3].GetInt32())).ToList());
    }

    public async Task<NativeFieldXrefs> GetFieldXrefsAsync(IReadOnlyList<string> types, string? member, int? offset, IReadOnlyList<uint> functions, double seconds,
        CancellationToken cancellationToken = default)
    {
        // the budget stays under the request timeout so slow decompilation ends the scan instead of the worker
        double budget = Math.Clamp(seconds, 1, Math.Max(1, RequestTimeout.TotalSeconds * 0.6));
        var args = IdaProvider.Args(("types", new JsonArray(types.Select(t => (JsonNode)t).ToArray())), ("member", member), ("offset", offset),
            ("functions", new JsonArray(functions.Select(f => (JsonNode)f).ToArray())), ("seconds", budget));
        var r = await CallAsync("field_xrefs", args, cancellationToken).ConfigureAwait(false);
        var rows = r.GetProperty("rows").EnumerateArray()
            .Select(x => new NativeFieldAccess(x[0].GetUInt32(), x[1].GetString() ?? "", x[2].ValueKind == JsonValueKind.Number ? x[2].GetUInt32() : null)).ToList();
        return new NativeFieldXrefs(r.GetProperty("type").GetString() ?? "", r.GetProperty("member").GetString() ?? "", r.GetProperty("offset").GetInt32(),
            r.GetProperty("size").GetInt32(), r.GetProperty("member_type").GetString() ?? "", rows, r.GetProperty("candidates").GetInt32(),
            r.GetProperty("scanned").GetInt32(), r.GetProperty("failed").GetInt32(), r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean())
            { Partial = WorkerRows.Partial(r).Partial, Next = WorkerRows.Partial(r).Next };
    }

    public async Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        var r = await CallAsync("python", IdaProvider.Args(("code", code), ("reset", reset)), cancellationToken).ConfigureAwait(false);
        return new NativeScriptResult(Text(r.GetProperty("result")), Text(r.GetProperty("stdout")) ?? "", Text(r.GetProperty("stderr")) ?? "", Text(r.GetProperty("error")));
    }

    public async Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("type", IdaProvider.Args(("name", name)), cancellationToken).ConfigureAwait(false);
        return new NativeTypeDetail(r.GetProperty("name").GetString() ?? name, r.GetProperty("kind").GetString() ?? "", r.GetProperty("size").GetInt64(),
            r.GetProperty("decl").GetString() ?? "", r.GetProperty("members").EnumerateArray()
                .Select(x => new NativeTypeMember(x[0].GetInt64(), x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].GetInt64())).ToList());
    }

    private static string? Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() : null;

    public async Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("frame", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false);
        var members = r.GetProperty("members").EnumerateArray()
            .Select(x => new NativeFrameMember(x[0].GetInt32(), x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].GetInt32(), x[4].GetString() ?? "local")).ToList();
        var locals = r.GetProperty("locals").EnumerateArray()
            .Select(x => new NativeLocal(x[0].GetString() ?? "", x[1].GetString() ?? "", x[2].GetString() ?? "", x[3].ValueKind == JsonValueKind.Number ? x[3].GetInt32() : null,
                x[4].GetBoolean(), x[5].GetBoolean(), x[6].GetBoolean())).ToList();
        return new NativeFrame(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", r.GetProperty("frame_size").GetInt32(),
            r.GetProperty("saved_regs").GetInt32(), r.GetProperty("retaddr").GetInt32(), members, locals, Text(r.GetProperty("decompile_error")));
    }

    public async Task<PdbLoadResult> LoadPdbAsync(string pdbPath, string stampKey, string stamp, bool trustAnalysisLoad, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pdbPath);
        // A large PDB takes IDA a while: the open's limit, not a single request's.
        var r = await CallAsync("load_pdb", IdaProvider.Args(("path", pdbPath), ("stamp_key", stampKey), ("stamp", stamp), ("trust_analysis", trustAnalysisLoad)),
            cancellationToken, saves: true, timeout: Options.OpenTimeout).ConfigureAwait(false);
        return new PdbLoadResult(r.GetProperty("loaded").GetBoolean(), r.GetProperty("from_analysis").GetBoolean(), r.GetProperty("plugin").GetBoolean(),
            r.GetProperty("types_before").GetInt32(), r.GetProperty("types_after").GetInt32(), TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()));
    }

    public async Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default)
    {
        return WorkerRows.Stamp(await CallAsync("get_stamp", IdaProvider.Args(("key", key)), cancellationToken).ConfigureAwait(false));
    }

}
