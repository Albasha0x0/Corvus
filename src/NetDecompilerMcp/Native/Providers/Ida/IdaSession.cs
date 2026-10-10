using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers.Ida;

/// <summary>
/// One image open in an idalib worker. Requests are serialized by <see cref="_gate"/>. When the worker dies (crash,
/// timeout, cancellation) the next request starts a new worker on the saved .i64 and re-applies the names and
/// comments set since the last save; more than <see cref="IdaProviderOptions.MaxRestarts"/> consecutive failures
/// close the session.
/// </summary>
internal sealed class IdaSession : INativeDecompilerSession
{
    private static readonly string[] UnpackedExtensions = [".id0", ".id1", ".id2", ".nam", ".til"];

    private readonly IdaProvider _provider;
    private readonly IdaInstallation _ida;
    private readonly PythonInterpreter _python;
    private readonly NativeOpenOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<(string Op, JsonObject Args)> _unsaved = [];
    private CacheEntry? _entry;
    private string _databasePath = "";
    private ulong _headerImageBase;
    private WorkerConnection? _worker;
    private int _failures;
    private bool _closed;

    public IdaSession(IdaProvider provider, IdaInstallation ida, PythonInterpreter python, NativeOpenOptions options)
    {
        _provider = provider;
        _ida = ida;
        _python = python;
        _options = options;
    }

    public string ProviderId => IdaProvider.ProviderId;
    public string ImagePath { get; private set; } = "";
    public string Sha256 => _entry?.Sha256 ?? "";
    public NativeArch Arch { get; private set; }
    public ulong ImageBase { get; private set; }
    public bool ReusedDatabase { get; private set; }
    public TimeSpan OpenTime { get; private set; }
    public bool DecompilerAvailable { get; private set; }
    public bool IsOpen => !_closed;
    /// <summary>Process id of the current worker, or null when none is running.</summary>
    internal int? WorkerProcessId => _worker is { IsAlive: true } w ? w.ProcessId : null;
    internal WorkerConnection? Worker => _worker;
    internal string DatabasePath => _databasePath;

    public async Task OpenAsync(string imagePath, string? sha256, CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        ImagePath = imagePath;
        _entry = await Task.Run(() => _provider.Cache.Acquire(ProviderId, imagePath, sha256), cancellationToken).ConfigureAwait(false);
        (Arch, _headerImageBase) = ReadHeader(_entry.InputCopy, imagePath);
        var profile = _options.Symbols == SymbolMode.Off ? "nopdb" : "default";
        _databasePath = Path.Combine(_entry.Directory, $"ida-{profile}.i64");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StartAsync(firstOpen: true, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        OpenTime = clock.Elapsed;
    }

    /// <summary>Machine and image base from the PE header; rejects what IDA would load as something else.</summary>
    private static (NativeArch, ulong) ReadHeader(string copy, string original)
    {
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
                var m => throw new ToolError(ErrorCode.Unsupported, $"{original} is for machine {m} (0x{(ushort)m:X4}); x86, x64, ARM and ARM64 images are supported."),
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

    /// <summary>Starts a worker and opens the database (reused when saved), falling back to a fresh analysis once when the saved database fails.</summary>
    private async Task StartAsync(bool firstOpen, CancellationToken cancellationToken)
    {
        DiscardUnpacked();
        var reuse = File.Exists(_databasePath);
        try
        {
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (reuse && e.Code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.MalformedInput)
        {
            // A damaged .i64 (killed during save, older IDA format) is rebuilt from the input copy.
            KillWorker("reopen");
            DeleteDatabase();
            if (!firstOpen) _unsaved.Clear();
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        if (!firstOpen)
        {
            foreach (var (op, args) in _unsaved)
            {
                try { await _worker!.RequestAsync(op, (JsonObject)args.DeepClone(), _options.RequestTimeout, cancellationToken).ConfigureAwait(false); }
                catch (ToolError e) when (e.Code is not (ErrorCode.Timeout or ErrorCode.ProviderUnavailable)) { /* rejected now: skip */ }
            }
        }
    }

    private async Task StartWorkerAndOpenAsync(CancellationToken cancellationToken)
    {
        try
        {
            await StartWorkerAndOpenCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            KillWorker("open failed");
            throw;
        }
    }

    private async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        _options.Progress?.Report(new NativeProviderProgress("start", clock.Elapsed));
        var worker = _provider.StartWorker(_ida, _python, _options.Symbols == SymbolMode.Off ? null : _options.PdbPath);
        _worker = worker;
        worker.EventReceived += e =>
        {
            if (e.Name == "progress") _options.Progress?.Report(new NativeProviderProgress(ReusedDatabase ? "load" : "analysis", clock.Elapsed));
        };
        await worker.WaitReadyAsync(_provider.Options.StartTimeout, cancellationToken).ConfigureAwait(false);

        var reuse = File.Exists(_databasePath);
        ReusedDatabase = reuse;
        _options.Progress?.Report(new NativeProviderProgress(reuse ? "load" : "analysis", clock.Elapsed));
        var idaArgs = new JsonArray();
        if (_options.Symbols == SymbolMode.Off) idaArgs.Add("-Opdb:off");
        var remaining = _options.OpenTimeout - clock.Elapsed;
        if (remaining <= TimeSpan.Zero) remaining = TimeSpan.FromSeconds(1);
        var info = await worker.RequestAsync("open", IdaProvider.Args(("input", _entry!.InputCopy), ("idb", _databasePath), ("ida_args", idaArgs)),
            remaining, cancellationToken).ConfigureAwait(false);

        var loadedBase = info.GetProperty("imagebase").GetUInt64();
        if (loadedBase != _headerImageBase)
        {
            var rebased = await worker.RequestAsync("rebase", IdaProvider.Args(("imagebase", _headerImageBase)), _options.RequestTimeout, cancellationToken).ConfigureAwait(false);
            loadedBase = rebased.GetProperty("imagebase").GetUInt64();
            if (loadedBase != _headerImageBase)
                throw new ToolError(ErrorCode.Failed, $"IDA loaded {ImagePath} at 0x{loadedBase:X} and could not rebase it to the header image base 0x{_headerImageBase:X}.");
        }
        ImageBase = loadedBase;
        DecompilerAvailable = info.GetProperty("decompiler").GetBoolean();
        if (info.TryGetProperty("idb", out var idb) && idb.GetString() is { Length: > 0 } actual && !PathsEqual(actual, _databasePath))
            _databasePath = actual;
        _options.Progress?.Report(new NativeProviderProgress("ready", clock.Elapsed));
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    /// <summary>Unpacked database components left by a worker that was killed; the packed .i64 holds the last save.</summary>
    private void DiscardUnpacked()
    {
        var stem = Path.Combine(Path.GetDirectoryName(_databasePath)!, Path.GetFileNameWithoutExtension(_databasePath));
        foreach (var ext in UnpackedExtensions) TryDelete(stem + ext);
        if (File.Exists(_databasePath) && new FileInfo(_databasePath).Length == 0) TryDelete(_databasePath);
    }

    private void DeleteDatabase()
    {
        DiscardUnpacked();
        TryDelete(_databasePath);
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private void KillWorker(string reason)
    {
        var w = _worker;
        _worker = null;
        if (w == null) return;
        w.Kill(reason);
        w.Dispose();
    }

    /// <summary>Runs one request, restarting the worker first when it is gone.</summary>
    internal async Task<JsonElement> CallAsync(string op, JsonObject args, CancellationToken cancellationToken, bool journal = false, bool saves = false)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_closed) throw new ToolError(ErrorCode.NotLoaded, $"The IDA session for {ImagePath} is closed.", "Open the image again.");
            if (_worker is not { IsAlive: true })
            {
                KillWorker("restart");
                try
                {
                    await StartAsync(firstOpen: false, cancellationToken).ConfigureAwait(false);
                }
                catch (ToolError)
                {
                    Failed();
                    throw;
                }
            }
            try
            {
                var result = await _worker!.RequestAsync(op, (JsonObject)args.DeepClone(), _options.RequestTimeout, cancellationToken).ConfigureAwait(false);
                _failures = 0;
                if (journal) _unsaved.Add((op, args));
                if (saves) _unsaved.Clear();
                return result;
            }
            catch (ToolError e) when (e.Code is ErrorCode.ProviderUnavailable or ErrorCode.Timeout)
            {
                KillWorker(e.Code == ErrorCode.Timeout ? "timeout" : "failure");
                Failed();
                throw;
            }
            catch (OperationCanceledException)
            {
                KillWorker("cancelled");
                throw;
            }
        }
        finally { _gate.Release(); }
    }

    private void Failed()
    {
        if (++_failures <= _provider.Options.MaxRestarts) return;
        _closed = true;
        KillWorker("restart budget exhausted");
        _entry?.Dispose();
        _provider.Forget(this);
    }

    public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
        ListFunctionsAsync(false, cancellationToken);

    public async Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("functions", IdaProvider.Args(("refs", withReferences)), cancellationToken).ConfigureAwait(false);
        var list = new List<NativeFunctionInfo>(r.GetArrayLength());
        foreach (var f in r.EnumerateArray())
            list.Add(new NativeFunctionInfo(f[0].GetUInt32(), f[1].GetUInt32(), f[2].GetString() ?? "", (NativeFunctionFlags)f[3].GetInt32(),
                f.GetArrayLength() > 4 ? f[4].GetInt32() : null));
        return list;
    }

    public async Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
    {
        if (!DecompilerAvailable)
            throw new ToolError(ErrorCode.Unsupported, $"The Hex-Rays decompiler is not available for {Arch} in this IDA install (not installed or not licensed).",
                IdaProvider.Remediation(ErrorCode.Unsupported, ""));
        var r = await CallAsync("decompile", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false);
        var lines = r.GetProperty("lines").EnumerateArray().Select(l => new PseudocodeLineAddress(l[0].GetInt32(), l[1].GetUInt32())).ToList();
        return new DecompiledFunction(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", r.GetProperty("text").GetString() ?? "", lines);
    }

    public async Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("disasm", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false);
        var insns = r.GetProperty("insns").EnumerateArray()
            .Select(i => new DisassembledInstruction(i[0].GetUInt32(), Convert.FromHexString(i[1].GetString() ?? ""), i[2].GetString() ?? "",
                i[3].ValueKind == JsonValueKind.String ? i[3].GetString() : null))
            .ToList();
        return new FunctionDisassembly(r.GetProperty("start").GetUInt32(), r.GetProperty("end").GetUInt32(), r.GetProperty("name").GetString() ?? "",
            insns, r.GetProperty("truncated").GetBoolean());
    }

    public async Task<FunctionDisassembly> DisassembleRangeAsync(uint rva, int count, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("disasm_range", IdaProvider.Args(("rva", rva), ("count", Math.Clamp(count, 1, 200_000))), cancellationToken).ConfigureAwait(false);
        var insns = Instructions(r);
        return new FunctionDisassembly(rva, insns.Count > 0 ? insns[^1].Rva + (uint)insns[^1].Bytes.Length : rva, "", insns, r.GetProperty("truncated").GetBoolean());
    }

    private static List<DisassembledInstruction> Instructions(JsonElement r) =>
        r.GetProperty("insns").EnumerateArray()
            .Select(i => new DisassembledInstruction(i[0].GetUInt32(), Convert.FromHexString(i[1].GetString() ?? ""), i[2].GetString() ?? "",
                i[3].ValueKind == JsonValueKind.String ? i[3].GetString() : null))
            .ToList();

    public async Task<NativeBlockGraph> GetBlocksAsync(uint rva, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("blocks", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false);
        var blocks = r.GetProperty("blocks").EnumerateArray()
            .Select(b => new NativeBlockInfo(b[0].GetUInt32(), b[1].GetUInt32(), b[2].GetInt32(), b[3].GetString() ?? "normal",
                b[4].EnumerateArray().Select(s => s.GetUInt32()).ToList(), b[5].GetBoolean()))
            .ToList();
        return new NativeBlockGraph(r.GetProperty("start").GetUInt32(), r.GetProperty("name").GetString() ?? "", blocks,
            r.GetProperty("tail_calls").EnumerateArray().Select(t => t.GetUInt32()).ToList());
    }

    public async Task<NativeCallTargets> GetCallTargetsAsync(IReadOnlyList<uint> functions, IReadOnlyList<uint> sites, double seconds,
        CancellationToken cancellationToken = default)
    {
        // the budget stays under the request timeout so a slow decompilation ends the batch instead of the worker
        double budget = Math.Clamp(seconds, 1, Math.Max(1, _options.RequestTimeout.TotalSeconds * 0.6));
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
        return new NativeCallTargets(targets, r.GetProperty("decompiled").GetInt32(), failed, r.GetProperty("skipped").GetInt32(), r.GetProperty("decompiler").GetBoolean());
    }

    public async Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
        Xrefs(await CallAsync("xrefs_to", IdaProvider.Args(("rva", rva)), cancellationToken).ConfigureAwait(false));

    public async Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
        Xrefs(await CallAsync("xrefs_from", IdaProvider.Args(("rva", rva), ("function", wholeFunction)), cancellationToken).ConfigureAwait(false));

    private static List<NativeXref> Xrefs(JsonElement r) =>
        r.EnumerateArray().Select(x => new NativeXref(x[0].GetUInt32(), x[1].GetUInt32(), Kind(x[2].GetString()),
            x[3].ValueKind == JsonValueKind.Number ? x[3].GetUInt32() : null)).ToList();

    private static NativeXrefKind Kind(string? kind) => kind switch
    {
        "call" => NativeXrefKind.Call,
        "jump" => NativeXrefKind.Jump,
        "code" => NativeXrefKind.Code,
        "read" => NativeXrefKind.Read,
        "write" => NativeXrefKind.Write,
        "offset" => NativeXrefKind.Offset,
        "text" => NativeXrefKind.Text,
        "info" => NativeXrefKind.Info,
        _ => NativeXrefKind.Data,
    };

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
        var rows = new JsonArray();
        foreach (var i in items)
            rows.Add(new JsonArray(i.Rva, i.Name, i.Comment, i.MakeFunction ? 1 : 0));
        var args = IdaProvider.Args(("items", rows), ("stamp_key", stampKey), ("stamp", stamp), ("save", save));
        // A saved batch is in the database; an unsaved one is journaled so a restart re-applies it.
        var r = await CallAsync("apply_names", args, cancellationToken, journal: !save, saves: save).ConfigureAwait(false);
        return new NameBatchResult(r.GetProperty("named").GetInt32(), r.GetProperty("name_failures").GetInt32(), r.GetProperty("commented").GetInt32(),
            r.GetProperty("functions_created").GetInt32(), TimeSpan.FromSeconds(r.GetProperty("seconds").GetDouble()),
            r.GetProperty("failures").EnumerateArray().Select(f => f.GetString() ?? "").ToList());
    }

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

    public async Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default)
    {
        var r = await CallAsync("get_stamp", IdaProvider.Args(("key", key)), cancellationToken).ConfigureAwait(false);
        return r.GetProperty("stamp").ValueKind == JsonValueKind.String ? r.GetProperty("stamp").GetString() : null;
    }

    public Task SaveAsync(CancellationToken cancellationToken = default) =>
        CallAsync("save", new JsonObject(), cancellationToken, saves: true);

    public async Task CloseAsync(bool save = true, CancellationToken cancellationToken = default)
    {
        if (!await _gate.WaitAsync(_provider.Options.ShutdownGrace, cancellationToken).ConfigureAwait(false))
            KillWorker("close while busy"); // the running request fails; its release is still awaited below
        else
        {
            try { await CloseCoreAsync(save).ConfigureAwait(false); }
            finally { _gate.Release(); }
            return;
        }
        await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try { await CloseCoreAsync(save).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task CloseCoreAsync(bool save)
    {
        if (_closed && _worker == null) return;
        _closed = true;
        var w = _worker;
        _worker = null;
        if (w != null)
        {
            try { await w.ShutdownAsync("close", IdaProvider.Args(("save", save)), _provider.Options.ShutdownGrace).ConfigureAwait(false); }
            finally { w.Dispose(); }
        }
        _entry?.Dispose();
        _provider.Forget(this);
    }

    public async ValueTask DisposeAsync() => await CloseAsync(save: true).ConfigureAwait(false);

    public void Dispose()
    {
        try
        {
            var close = Task.Run(() => CloseAsync(save: true));
            if (!close.Wait(_provider.Options.ShutdownGrace * 2 + TimeSpan.FromSeconds(5)))
                KillWorker("dispose timeout");
        }
        catch (AggregateException) { KillWorker("dispose failed"); }
        finally
        {
            _closed = true;
            _entry?.Dispose();
            _provider.Forget(this);
        }
    }
}
