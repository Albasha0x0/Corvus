namespace Corvus.Native.Providers;

/// <summary>An external engine (IDA, Ghidra) that analyzes and decompiles a native image; addresses are RVAs from the base the engine loaded, which the session checks against the header; failures are <see cref="Core.ToolError"/>.</summary>
public interface INativeDecompilerProvider : IDisposable
{
    /// <summary>Stable identifier ("ida", "ghidra").</summary>
    string Id { get; }

    string DisplayName { get; }

    /// <summary>Static checks only (install found, files present, interpreter found); cached after the first call.</summary>
    ProviderAvailability CheckAvailability();

    /// <summary>Static checks plus starting the engine once; reports load and version problems the static checks miss.</summary>
    Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default);

    /// <summary>Opens a private copy matching <paramref name="sha256"/> (file hash when null); the database is kept per hash for reuse.</summary>
    Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>State of the sessions this provider has open or opening; answered without asking a worker.</summary>
    IReadOnlyList<EngineSessionState> SessionStates() => [];
}

/// <summary>One engine session's state: worker, running request and stage, queue, edits a restart would replay, restarts, database.</summary>
public sealed record EngineSessionState(string Engine, string ImagePath, int? WorkerPid, string State, string? BusyOp, double BusySeconds,
    string? Stage, int Queued, int Unsaved, int Restarts, string? Database, bool ReusedDatabase, string? Note = null)
{
    /// <summary>running (the open's analysis), complete, or partial (the analysis budget ran out).</summary>
    public string? Analysis { get; init; }
}

/// <summary>One analyzed image; writes run in order, a timed-out request stops the engine, and the next request restarts it replaying unsaved edits.</summary>
/// <remarks>An engine may run reads in parallel (Ghidra). A timeout stops the engine only when it cannot stop that request
/// alone. Disposing waits no longer than the shutdown grace period.</remarks>
public interface INativeDecompilerSession : IAsyncDisposable, IDisposable
{
    string ProviderId { get; }
    /// <summary>The file the caller opened (not the private copy).</summary>
    string ImagePath { get; }
    string Sha256 { get; }
    NativeArch Arch { get; }
    /// <summary>Image base of the loaded image; equals the PE header's ImageBase.</summary>
    ulong ImageBase { get; }
    /// <summary>Whether the open reused a saved analysis database instead of analyzing from scratch.</summary>
    bool ReusedDatabase { get; }
    /// <summary>Wall time of the open (copy, engine start, load or analysis).</summary>
    TimeSpan OpenTime { get; }
    /// <summary>Whether <see cref="DecompileAsync"/> can work for this image's architecture.</summary>
    bool DecompilerAvailable { get; }
    /// <summary>False once the session is closed or the engine failed more often than the restart budget allows.</summary>
    bool IsOpen { get; }
    /// <summary>False when the first analysis ran out of time and the database holds only part of it.</summary>
    bool AnalysisComplete => true;
    /// <summary>What sets this database apart, for output headers ("no auto-analysis"), or null.</summary>
    string? DatabaseNote => null;

    Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default);

    /// <summary>The functions, with the number of code references to each start when <paramref name="withReferences"/> is set.</summary>
    Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default) =>
        ListFunctionsAsync(cancellationToken);

    /// <summary>Pseudocode of the function containing <paramref name="rva"/>.</summary>
    Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>As <see cref="DecompileAsync"/> with the engine's per-function limit set to <paramref name="timeout"/> (null: its default); engines without one ignore it.</summary>
    Task<DecompiledFunction> DecompileWithinAsync(uint rva, TimeSpan? timeout, CancellationToken cancellationToken = default) =>
        DecompileAsync(rva, cancellationToken);

    /// <summary>Pseudocode per RVA in order, bounded per item and overall; failures stay per item, items past the budget are skipped.</summary>
    async Task<IReadOnlyList<DecompileOutcome>> DecompileManyAsync(IReadOnlyList<uint> rvas, double secondsPerItem, double budgetSeconds,
        CancellationToken cancellationToken = default)
    {
        var results = new List<DecompileOutcome>(rvas.Count);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        foreach (var rva in rvas)
        {
            if (clock.Elapsed.TotalSeconds >= budgetSeconds)
            {
                results.Add(new DecompileOutcome(rva, DecompileStatus.Skipped, null, null, null));
                continue;
            }
            using var item = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            item.CancelAfter(TimeSpan.FromSeconds(Math.Min(secondsPerItem, Math.Max(1, budgetSeconds - clock.Elapsed.TotalSeconds))));
            try
            {
                results.Add(new DecompileOutcome(rva, DecompileStatus.Ok, await DecompileAsync(rva, item.Token).ConfigureAwait(false), null, null));
            }
            catch (Core.ToolError e)
            {
                results.Add(new DecompileOutcome(rva, DecompileStatus.Error, null, Core.ToolError.CodeName(e.Code), e.Message));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                results.Add(new DecompileOutcome(rva, DecompileStatus.Error, null, "timeout", $"not decompiled within {secondsPerItem:0.#} s"));
            }
        }
        return results;
    }

    /// <summary>Instructions of the function containing <paramref name="rva"/>, in address order including chunks.</summary>
    Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>Up to <paramref name="count"/> items (instructions, or data the engine did not decode) from <paramref name="rva"/> in address order.</summary>
    Task<FunctionDisassembly> DisassembleRangeAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not disassemble address ranges.");

    /// <summary>What is at <paramref name="rva"/> and at most <paramref name="count"/> items after it, as the engine has them.</summary>
    Task<IReadOnlyList<EngineInstructionItem>> InspectAsync(uint rva, int count, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not inspect instructions.");

    /// <summary>The per-function value slice the engine's decompiler IR gives for <paramref name="request"/> (see <see cref="EngineSliceRequest"/>).</summary>
    Task<EngineSlice> ValueSliceAsync(EngineSliceRequest request, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not slice values.");

    /// <summary>Basic blocks of the function containing <paramref name="rva"/>, as the engine splits them.</summary>
    Task<NativeBlockGraph> GetBlocksAsync(uint rva, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report basic blocks.");

    /// <summary>Makes the database's patched bytes exactly <paramref name="wanted"/> restoring unwanted ones, and redecodes touched code; missing or mismatched bytes mean it could not, and the caller analyzes the patched file instead.</summary>
    Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not apply byte patches.");

    /// <summary>Imports declarations, prototypes and C++ class types in one request; failures are counted, not thrown; stamp and save as in <see cref="ApplyNamesAsync"/>.</summary>
    Task<TypeBatchResult> ApplyTypesAsync(NativeTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not take types.");

    /// <summary>Code references from the call <paramref name="sites"/> and how the decompiler shows them in <paramref name="functions"/>, within <paramref name="seconds"/>.</summary>
    Task<NativeCallTargets> GetCallTargetsAsync(IReadOnlyList<uint> functions, IReadOnlyList<uint> sites, double seconds,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report call targets.");

    /// <summary>Loads a PDB with the engine's loader, then records the stamp, drops the names stamp (the PDB's names replace pushed ones, which are pushed again) and saves.</summary>
    /// <param name="trustAnalysisLoad">A PDB the engine loaded during auto-analysis counts as this one.</param>
    Task<PdbLoadResult> LoadPdbAsync(string pdbPath, string stampKey, string stamp, bool trustAnalysisLoad, CancellationToken cancellationToken = default) =>
        Task.FromResult(new PdbLoadResult(false, false, false, 0, 0, TimeSpan.Zero));

    /// <summary>Applies user types, reported per item and kept over later recovered types; an empty batch only records the stamp.</summary>
    Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not take user types.");

    /// <summary>The stack frame and decompiler locals of the function containing <paramref name="rva"/>.</summary>
    Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report stack frames.");

    /// <summary>The frame, with the decompiler's locals only when <paramref name="locals"/> (without them nothing is decompiled).</summary>
    Task<NativeFrame> GetFrameAsync(uint rva, bool locals, CancellationToken cancellationToken = default) => GetFrameAsync(rva, cancellationToken);

    /// <summary>Frames of several functions, in order; a function that fails carries its error. The engines answer in one request.</summary>
    async Task<IReadOnlyList<NativeFrameOutcome>> GetFramesAsync(IReadOnlyList<uint> rvas, bool locals, CancellationToken cancellationToken = default)
    {
        var frames = new List<NativeFrameOutcome>();
        foreach (var rva in rvas)
        {
            try { frames.Add(new(rva, await GetFrameAsync(rva, locals, cancellationToken).ConfigureAwait(false), null)); }
            catch (Corvus.Core.ToolError e) { frames.Add(new(rva, null, e.Message)); }
        }
        return frames;
    }

    /// <summary>Named types whose name contains <paramref name="filter"/> (case-insensitive), of <paramref name="kind"/> when given, paged.</summary>
    Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list types.");

    /// <summary>One named type (NotFound when there is none).</summary>
    Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list types.");

    /// <summary>Typed operands and pseudocode accesses of a struct member (first existing of <paramref name="types"/>); NotFound when absent.</summary>
    Task<NativeFieldXrefs> GetFieldXrefsAsync(IReadOnlyList<string> types, string? member, int? offset, IReadOnlyList<uint> functions, double seconds,
        uint? allFrom = null, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report struct member references.");

    /// <summary>Runs an engine script; globals persist unless <paramref name="reset"/>. Not journaled: a restart loses its unsaved changes.</summary>
    Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not run scripts.");

    /// <summary>The engine's own view of the open image: language, compiler, format, entry points, input hashes, memory blocks.</summary>
    Task<EngineImageInfo> GetEngineInfoAsync(CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not describe the image.");

    /// <summary>The engine's defined data items in address order, at most <paramref name="max"/>; <see cref="EngineDataList.Total"/> counts them all.</summary>
    Task<EngineDataList> ListDataAsync(int max, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list defined data.");

    /// <summary>The engine's defined strings in address order, at most <paramref name="max"/>, whether code references them or not.</summary>
    Task<IReadOnlyList<EngineString>> ListStringsAsync(int max, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list strings.");

    /// <summary>The engine's record of the function containing <paramref name="rva"/> (NotFound when none does).</summary>
    Task<EngineFunctionRecord> GetFunctionRecordAsync(uint rva, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not describe functions.");

    /// <summary>The engine's non-global namespaces (classes, plain namespaces, external libraries), sorted by qualified name.</summary>
    Task<IReadOnlyList<EngineNamespace>> ListNamespacesAsync(CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list namespaces.");

    /// <summary>References to <paramref name="rva"/> (ordinary flow excluded).</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>References to each of <paramref name="rvas"/>, in order (one request where the engine takes several).</summary>
    async Task<IReadOnlyList<IReadOnlyList<NativeXref>>> GetXrefsToManyAsync(IReadOnlyList<uint> rvas, CancellationToken cancellationToken = default)
    {
        var all = new List<IReadOnlyList<NativeXref>>(rvas.Count);
        foreach (var rva in rvas) all.Add(await GetXrefsToAsync(rva, cancellationToken).ConfigureAwait(false));
        return all;
    }

    /// <summary>References from the instruction at <paramref name="rva"/>, or from every instruction of its function.</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default);

    /// <summary>Names <paramref name="rva"/>; an empty name removes a user name. Returns the name now in effect.</summary>
    Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default);

    /// <summary>Sets (or with empty text clears) the comment at <paramref name="rva"/>. Returns the comment now stored.</summary>
    Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default);

    /// <summary>Applies names (forced, suffixed on clash) and comments in one request; failures are counted; records the stamp, optionally saves.</summary>
    Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default);

    /// <summary>The engine's guess of the type at <paramref name="rva"/> (nothing is applied).</summary>
    Task<NativeTypeGuess> GuessTypeAsync(uint rva, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not guess types.");

    /// <summary>Sets (empty: removes) decompiler comments on the statement from each address or the nearest before it.</summary>
    Task<IReadOnlyList<PseudoCommentOutcome>> SetPseudoCommentsAsync(IReadOnlyList<(uint Rva, string Text)> items, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not take pseudocode comments.");

    /// <summary>The stamp recorded in the database under <paramref name="key"/> by <see cref="ApplyNamesAsync"/>, or null.</summary>
    Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>Writes the analysis database so names and comments survive a crash.</summary>
    Task SaveAsync(CancellationToken cancellationToken = default);

    /// <summary>Closes the engine, saving the database when <paramref name="save"/> is set.</summary>
    Task CloseAsync(bool save = true, CancellationToken cancellationToken = default);
}

/// <summary>Result of an availability check: what is missing and how to fix it.</summary>
public sealed record ProviderAvailability(string ProviderId, bool IsAvailable, string? Reason, string? Remediation, IReadOnlyDictionary<string, string> Details)
{
    public static ProviderAvailability Ok(string id, IReadOnlyDictionary<string, string> details) => new(id, true, null, null, details);

    public static ProviderAvailability Missing(string id, string reason, string remediation, IReadOnlyDictionary<string, string>? details = null) =>
        new(id, false, reason, remediation, details ?? new Dictionary<string, string>());
}

/// <summary>Debug symbol use during the first analysis of an image.</summary>
public enum SymbolMode
{
    /// <summary>The engine's own configuration (IDA: PDBs from the symbol path, downloading when configured).</summary>
    Default,
    /// <summary>No PDB loading: deterministic, offline.</summary>
    Off,
}

/// <summary>A Ghidra archive (.gzf) made from an image: Ghidra imports it as the image's database instead of analyzing.</summary>
public sealed record PackedDatabase(string Path, string Sha256);

public sealed record NativeOpenOptions
{
    public PackedDatabase? GhidraDatabase { get; init; }
    public SymbolMode Symbols { get; init; } = SymbolMode.Default;
    /// <summary>A headerless image's mapping: the engine loads the file as raw bytes at its base with its processor.</summary>
    public RawLayout? Raw { get; init; }
    /// <summary>The image's import overrides, applied before the first analysis; part of the database name.</summary>
    public EngineOverrides? Overrides { get; init; }
    /// <summary>The image's PDB as located by the server (verified by GUID and age); the engine looks there first. Ignored with <see cref="SymbolMode.Off"/>.</summary>
    public string? PdbPath { get; init; }
    /// <summary>Limit for engine start plus loading or auto-analysis.</summary>
    public TimeSpan OpenTimeout { get; init; } = TimeSpan.FromMinutes(20);
    /// <summary>Ghidra's auto-analysis limit on a first open; by default what <see cref="OpenTimeout"/> leaves after start and import, less time to save.</summary>
    internal TimeSpan? AnalysisBudget { get; init; }
    /// <summary>Limit for each request after the open.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromMinutes(2);
    /// <summary>Receives start and analysis progress (elapsed time and stage).</summary>
    public IProgress<NativeProviderProgress>? Progress { get; init; }
    /// <summary>Whether the engine runs its auto-analysis on the first open (IDA); without it the database is kept under its own profile.</summary>
    public EngineAnalysis Analysis { get; init; } = EngineAnalysis.Full;
    /// <summary>32-bit ARM Thumb ranges (exclusive ends) for code made on request without auto-analysis, which Ghidra would otherwise decode as ARM; null when unknown.</summary>
    public Func<CancellationToken, Task<IReadOnlyList<(uint Start, uint End)>>>? ThumbCode { get; init; }
    /// <summary>Whether the server's index has a function at an RVA, so the engine can make one on request; null when unknown.</summary>
    public Func<uint, CancellationToken, Task<bool>>? KnownStart { get; init; }
    /// <summary>Where answers to read requests are kept across processes; null keeps none.</summary>
    public EngineOutputCache? OutputCache { get; init; }
    /// <summary>The engine's build and analysis settings, part of every output key.</summary>
    public string? OutputIdentity { get; init; }
}

/// <summary>Full: the engine's auto-analysis. None: load only, functions made where they are asked for (huge or hostile inputs).</summary>
public enum EngineAnalysis { Full, None }

/// <summary>An open's stage; <see cref="Analyzers"/>: the engine's exact seconds per analyzer, once its analysis ended.</summary>
public sealed record NativeProviderProgress(string Stage, TimeSpan Elapsed)
{
    public IReadOnlyList<KeyValuePair<string, double>>? Analyzers { get; init; }
}

[Flags]
public enum NativeFunctionFlags
{
    None = 0,
    /// <summary>A jump or call stub to another function or import.</summary>
    Thunk = 1,
    /// <summary>Recognized library code (signatures).</summary>
    Library = 2,
    /// <summary>32-bit ARM code in Thumb state (IDA's T segment register).</summary>
    Thumb = 4,
    /// <summary>The engine has a type (prototype) for the function: IDA type info, a Ghidra signature not of default source.</summary>
    Typed = 8,
}

/// <summary>A function as the engine sees it; <see cref="EndRva"/> is exclusive, main chunk only; <see cref="References"/> when asked.</summary>
public sealed record NativeFunctionInfo(uint StartRva, uint EndRva, string Name, NativeFunctionFlags Flags, int? References = null);

/// <summary>Pseudocode line (0-based) and the lowest instruction RVA it was generated from.</summary>
public sealed record PseudocodeLineAddress(int Line, uint Rva);

public sealed record DecompiledFunction(uint StartRva, string Name, string Text, IReadOnlyList<PseudocodeLineAddress> LineAddresses);

/// <summary>A per-function slice request; Seed: location, argument, parameter, result, returns, stored or loaded; engine register names.</summary>
public sealed record EngineSliceRequest(uint Function, string Seed, uint Rva, bool Forward, string? Register = null, int Index = -1, int MaxNodes = 256,
    double Seconds = 30);

/// <summary>One slice node; Kind is a source (constant, global, parameter, call_result...) or, forward, a use (store, return, compare...).</summary>
public sealed record EngineSliceNode(string Kind, uint Rva, string Text, string Why)
{
    public ulong? Value { get; init; }
    public uint? Target { get; init; }
    public uint? Site { get; init; }
    public int Index { get; init; } = -1;
    public string? Callee { get; init; }
    public bool Derived { get; init; }
}

/// <summary>An engine's slice: nodes (the root first), edges (from the value's source to its use: copy, merge, loop, field, use), the variable it followed.</summary>
public sealed record EngineSlice(IReadOnlyList<EngineSliceNode> Nodes, IReadOnlyList<(int From, int To, string Kind)> Edges, bool Truncated, string? Note, string? Variable);

public enum DecompileStatus : byte { Ok, Error, Skipped }

/// <summary>One item of <see cref="INativeDecompilerSession.DecompileManyAsync"/>: the function, or the error's code and message, or skipped.</summary>
public sealed record DecompileOutcome(uint Rva, DecompileStatus Status, DecompiledFunction? Function, string? ErrorCode, string? Error);

public sealed record DisassembledInstruction(uint Rva, byte[] Bytes, string Text, string? Comment);

/// <summary>An engine basic block [start, end): instruction count, end kind (normal, indjump, ret, cndret, noret, enoret, error), successors, resolved switch.</summary>
public sealed record NativeBlockInfo(uint StartRva, uint EndRva, int Instructions, string Kind, IReadOnlyList<uint> Successors, bool Switch)
{
    /// <summary>The engine's switch details, when it reports them.</summary>
    public NativeSwitchInfo? SwitchInfo { get; init; }
}

/// <summary>A recovered switch: jump, values per target, default, jump table, optional byte index table; value = table index + bias.</summary>
public sealed record NativeSwitchInfo(uint? Jump, IReadOnlyList<(uint Target, IReadOnlyList<long> Values)> Cases, uint? Default, uint? Table, int EntrySize, int Entries,
    uint? IndexTable, int? IndexEntries, long Bias);

/// <summary>The blocks of one function and the targets its jumps reach outside it (tail calls).</summary>
public sealed record NativeBlockGraph(uint StartRva, string Name, IReadOnlyList<NativeBlockInfo> Blocks, IReadOnlyList<uint> TailCalls);

/// <summary>A C declaration for the function at <see cref="Rva"/> ("ret name(params);").</summary>
public sealed record NativePrototype(uint Rva, string Declaration);

/// <summary>A vftable of a class: the subobject offset it serves, its RVA and its slot targets.</summary>
public sealed record NativeVftableType(uint Offset, uint Rva, IReadOnlyList<uint> Slots);

/// <summary>A base class subobject (by its type name in the batch) at an offset in the class.</summary>
public sealed record NativeBaseType(string Name, int Offset);

/// <summary>A polymorphic class as far as RTTI tells: C identifier name, vftables, base subobjects (bases listed earlier in the batch).</summary>
public sealed record NativeClassType(string Name, IReadOnlyList<NativeVftableType> Vftables, IReadOnlyList<NativeBaseType> Bases);

/// <summary>A function whose first argument is a pointer to <see cref="Class"/> (a virtual method found only in that class's vftable).</summary>
public sealed record NativeMethodOwner(uint Rva, string Class);

/// <summary>Types for <see cref="INativeDecompilerSession.ApplyTypesAsync"/>.</summary>
public sealed record NativeTypeBatch(string? Declarations, IReadOnlyList<NativePrototype> Prototypes, IReadOnlyList<NativeClassType> Classes,
    IReadOnlyList<NativeMethodOwner> Methods, int PointerSize);

/// <summary><see cref="MethodSkips"/>: methods not typed, by reason (no_class_type, not_own_function, typed, no_type, no_arguments, rejected).</summary>
public sealed record TypeBatchResult(int DeclarationErrors, int Typed, int TypeFailures, int Structs, int VftablesTyped, int MethodsTyped, TimeSpan Elapsed,
    IReadOnlyList<string> Failures, IReadOnlyDictionary<string, int> MethodSkips)
{
    /// <summary>The first declarations the engine refused, each with its parser's message (Ghidra).</summary>
    public IReadOnlyList<string> DeclarationMessages { get; init; } = [];
}

/// <summary>A PDB load result: loaded, loaded by auto-analysis, loader available, and type counts before and after.</summary>
public sealed record PdbLoadResult(bool Loaded, bool FromAnalysis, bool LoaderAvailable, int TypesBefore, int TypesAfter, TimeSpan Elapsed);

/// <summary>Bytes wanted at an RVA (a patch's replacement).</summary>
public sealed record NativeByteRange(uint Rva, byte[] Bytes);

/// <summary>A patch sync result: counts patched, reverted, redecoded; <see cref="Problems"/> holds up to 20 RVAs each of missing and mismatched bytes.</summary>
public sealed record PatchSyncResult(int Patched, int Reverted, int Ranges, int Functions, int Missing, int Mismatches, IReadOnlyList<uint> Problems,
    TimeSpan Elapsed)
{
    public bool Complete => Missing == 0 && Mismatches == 0;
}

public sealed record FunctionDisassembly(uint StartRva, uint EndRva, string Name, IReadOnlyList<DisassembledInstruction> Instructions, bool Truncated);

public enum NativeXrefKind
{
    Call,
    Jump,
    /// <summary>Other code reference.</summary>
    Code,
    Read,
    Write,
    /// <summary>The address is taken (pointer, offset operand, table entry).</summary>
    Offset,
    Text,
    Info,
    Data,
}

/// <summary>A name or comment to apply: null keeps, empty removes; <see cref="MakeFunction"/> creates a function when none contains the RVA.</summary>
public sealed record NativeNameItem(uint Rva, string? Name, string? Comment, bool MakeFunction = false)
{
    /// <summary>The comment's engine kind: eol, pre or plate; null: repeatable (the function comment at a function start).</summary>
    public string? CommentKind { get; init; }
}

/// <summary>A guessed type: <see cref="Method"/> decompiler, ida, existing or size (null: none), <see cref="Confidence"/> high, low or none.</summary>
public sealed record NativeTypeGuess(string? Type, string? Method, string Confidence);

/// <summary>One pseudocode comment: whether it attached, the address of the statement it is on, or why not.</summary>
public sealed record PseudoCommentOutcome(uint Rva, bool Applied, uint? Anchor, string? Error);

public sealed record NameBatchResult(int Named, int NameFailures, int Commented, int FunctionsCreated, TimeSpan Elapsed, IReadOnlyList<string> Failures);

/// <summary>One call site's target; Kind: xref, vftable (struct member offset), direct, or other (untyped; TypeName is the expression kind).</summary>
public sealed record NativeCallTarget(uint Site, string Kind, uint? Target, string? TypeName, int? MemberOffset);

/// <summary>Result of <see cref="INativeDecompilerSession.GetCallTargetsAsync"/>: functions decompiled, failed (with the reason) and not reached in time.</summary>
public sealed record NativeCallTargets(IReadOnlyList<NativeCallTarget> Targets, int Decompiled, IReadOnlyList<(uint Function, string Reason)> Failed, int Skipped,
    bool DecompilerAvailable)
{
    /// <summary>Why functions were skipped (budget, deadline or cancelled), or null; <see cref="Next"/>: the first one skipped.</summary>
    public string? Partial { get; init; }
    public uint? Next { get; init; }
}

/// <summary>A decompiler local edit, matched by stack offset, else first-edit name, else name; <see cref="Clear"/> drops user settings.</summary>
public sealed record NativeLocalEdit(uint Function, string Local, int? Stack, string? Name, string? Type)
{
    public const string AutoStorage = "auto";

    public bool Clear { get; init; }

    /// <summary>Moves an argument to a register, or back to its calling-convention place with <see cref="AutoStorage"/>.</summary>
    public string? Storage { get; init; }
}

/// <summary>A frame member edit at <see cref="Offset"/> from the frame's lowest address; <see cref="Delete"/> removes, <see cref="Clear"/> restores the engine's.</summary>
public sealed record NativeStackVarEdit(uint Function, int Offset, string? Name, string? Type)
{
    public bool Delete { get; init; }
    public bool Clear { get; init; }

    /// <summary>The member's offset from the return address, when known: engines place it by this (their lowest addresses differ).</summary>
    public int? FromReturn { get; init; }
}

/// <summary>Member <see cref="Member"/> of enum <see cref="Enum"/> (created when missing) gets <see cref="Value"/>; a null value removes the member.</summary>
public sealed record NativeEnumMemberEdit(string Enum, string Member, long? Value);

/// <summary>Named type <see cref="Name"/> is renamed to <see cref="NewName"/>, or deleted when that is null.</summary>
public sealed record NativeTypeEdit(string Name, string? NewName);

/// <summary>A struct member edit by name or offset (null FieldType removes), or with <see cref="Op"/> a layout edit.</summary>
public sealed record NativeFieldEdit(string Type, string? Name, int? Offset, string? FieldType)
{
    /// <summary>Insert the member at Offset and move the later members down; a null FieldType cuts it and moves them back.</summary>
    public const string Insert = "insert";
    /// <summary>Set the struct's size to Offset bytes.</summary>
    public const string Resize = "resize";
    /// <summary>Name the unnamed gaps gap_&lt;offset&gt; (char arrays); a null FieldType removes those names.</summary>
    public const string Gaps = "gaps";

    /// <summary>Null for a member edit, else the layout edit.</summary>
    public string? Op { get; init; }

    /// <summary>The edit as kept, one per type and key: the member's name (else @0x and its offset); +member for an insert; !resize, !gaps.</summary>
    public string Key
    {
        get
        {
            var member = Name ?? FormattableString.Invariant($"@0x{Offset:X}");
            return Op switch { null => member, Insert => "+" + member, _ => "!" + Op };
        }
    }
}

/// <summary>An analysis edit at <see cref="Rva"/>: code, function, undefine, flow, or data of <see cref="Type"/> (a scalar, string or C type, optional [count]; a string without a count ends at End or its terminator).</summary>
public sealed record NativeAnalysisEdit(uint Rva, string Kind, uint? End, string? Type)
{
    public const string Code = "code", Function = "function", Undefine = "undefine", Data = "data", Flow = "flow";

    /// <summary>The flow overrides kind=flow sets (Ghidra's); none clears one.</summary>
    public static readonly string[] FlowOverrides = ["none", "branch", "call", "call_return", "return"];
}

/// <summary>Display format of a 0-based operand; enum and struct take <see cref="Detail"/> (a name, struct optionally +delta).</summary>
public sealed record NativeOperandEdit(uint Rva, int Operand, string Display, string? Detail)
{
    public static readonly string[] Displays = ["hex", "dec", "oct", "bin", "char", "offset", "stack", "enum", "struct", "default"];
}

/// <summary>User types, applied in order: declarations, type edits, enum members, fields, analysis, prototypes and globals, frame, locals, deletions, operands.</summary>
public sealed record NativeUserTypeBatch(IReadOnlyList<string> Declarations, IReadOnlyList<NativePrototype> Types, IReadOnlyList<NativeStackVarEdit> StackVars,
    IReadOnlyList<NativeLocalEdit> Locals)
{
    public static readonly NativeUserTypeBatch Empty = new([], [], [], []);

    public IReadOnlyList<NativeEnumMemberEdit> EnumMembers { get; init; } = [];
    /// <summary>Null leaves the engine's kept type edits alone; a list replaces them and is applied in order (an edit whose type is gone does nothing).</summary>
    public IReadOnlyList<NativeTypeEdit>? TypeEdits { get; init; }
    public IReadOnlyList<NativeFieldEdit> Fields { get; init; } = [];
    public IReadOnlyList<NativeAnalysisEdit> Analysis { get; init; } = [];
    public IReadOnlyList<NativeOperandEdit> Operands { get; init; } = [];
}

/// <summary>A user type item's outcome; for operand items <see cref="Stack"/> is the operand index; <see cref="Resolved"/> is a local's previous name; <see cref="Text"/> is the type or name in effect.</summary>
public sealed record NativeUserTypeOutcome(string Kind, uint Rva, string Target, bool Applied, string? Error, string? Resolved, int? Stack, string? Text);

/// <summary>A user type result: declaration errors and messages, declared type names, and each item's outcome.</summary>
public sealed record UserTypeResult(int DeclarationErrors, IReadOnlyList<string> DeclarationMessages, IReadOnlyList<string> DeclaredTypes,
    IReadOnlyList<NativeUserTypeOutcome> Items, TimeSpan Elapsed);

/// <summary>A named type of the engine: kind struct, union, enum, typedef, func or other; size -1 when unknown; members of a struct, union or enum.</summary>
public sealed record NativeTypeEntry(string Name, string Kind, long Size, int Members);

/// <summary>Named types matching a query, one page of them.</summary>
public sealed record NativeTypeList(int Total, IReadOnlyList<NativeTypeEntry> Types);

/// <summary>A struct or union member at <see cref="Offset"/> bytes.</summary>
public sealed record NativeTypeMember(long Offset, string Name, string Type, long Size)
{
    /// <summary>A bit field's first bit in its storage unit (Offset, Size bytes) and its width; null for other members.</summary>
    public int? BitOffset { get; init; }
    public int? BitSize { get; init; }
    public string? Comment { get; init; }
}

/// <summary>One named type: its C declaration as the engine prints it, and its members (structs and unions).</summary>
public sealed record NativeTypeDetail(string Name, string Kind, long Size, string Declaration, IReadOnlyList<NativeTypeMember> Members)
{
    /// <summary>The engine's alignment of the type (null when it gives none) and whether members sit below their natural alignment.</summary>
    public long? Alignment { get; init; }
    public bool Packed { get; init; }
}

/// <summary>A stack frame member at <see cref="Offset"/> bytes from the frame's lowest address; <see cref="Kind"/> local, arg or special (return address, saved registers).</summary>
public sealed record NativeFrameMember(int Offset, string Name, string Type, int Size, string Kind);

/// <summary>One function's frame, or the error that stopped it.</summary>
public sealed record NativeFrameOutcome(uint Rva, NativeFrame? Frame, string? Error);

/// <summary>A decompiler local: its location (a register, or "stack" at <see cref="Stack"/>) and whether the user named or typed it.</summary>
public sealed record NativeLocal(string Name, string Type, string Location, int? Stack, bool IsArgument, bool UserName, bool UserType);

/// <summary>A function's stack frame and decompiler locals; <see cref="DecompilerError"/> says why there are no locals.</summary>
public sealed record NativeFrame(uint StartRva, string Name, int LocalSize, int SavedRegisters, int ReturnAddressOffset, IReadOnlyList<NativeFrameMember> Members,
    IReadOnlyList<NativeLocal> Locals, string? DecompilerError);

/// <summary>A use of a struct member at <see cref="Rva"/>: Kind operand (typed operand), read, write or address (pseudocode access).</summary>
public sealed record NativeFieldAccess(uint Rva, string Kind, uint? FunctionRva);

/// <summary>The member found and its uses, with counts of functions considered, scanned, failed and skipped.</summary>
public sealed record NativeFieldXrefs(string Type, string Member, int Offset, int Size, string MemberType, IReadOnlyList<NativeFieldAccess> Accesses,
    int Candidates, int Scanned, int Failed, int Skipped, bool DecompilerAvailable)
{
    /// <summary>Why functions were skipped (budget, deadline or cancelled), or null; <see cref="Next"/>: the first one skipped.</summary>
    public string? Partial { get; init; }
    public uint? Next { get; init; }
}

/// <summary>What a script printed and returned (the value of a final expression), or the exception it raised.</summary>
public sealed record NativeScriptResult(string? Result, string Stdout, string Stderr, string? Error);

/// <summary>A reference; <see cref="FromFunctionRva"/> is the start of the function containing the source, when any.</summary>
public sealed record NativeXref(uint FromRva, uint ToRva, NativeXrefKind Kind, uint? FromFunctionRva);

/// <summary>A memory block (segment) as the engine loaded it: VA, size, permissions (rwx) and whether it has file bytes.</summary>
public sealed record EngineMemoryBlock(string Name, ulong Start, ulong Size, string Permissions, bool Initialized);

/// <summary>The engine's view of an image; <see cref="Changed"/> null when unknown, <see cref="Analysis"/> complete, partial or running.</summary>
public sealed record EngineImageInfo(string Version, string Processor, string Language, string? Compiler, string Format, int PointerSize, string Endian,
    int Functions, int ExternalFunctions, IReadOnlyList<uint> EntryPoints, string? Md5, string? Sha256, IReadOnlyList<EngineMemoryBlock> Blocks, bool? Changed,
    string? Analysis);

/// <summary>A defined data item; <see cref="Label"/> null for a generated name, <see cref="Value"/> clipped.</summary>
public sealed record EngineDataItem(uint Rva, long Size, string Type, string? Label, string? Value, bool IsString);

/// <summary>Defined data items, the first <see cref="Items"/> of <see cref="Total"/>.</summary>
public sealed record EngineDataList(int Total, IReadOnlyList<EngineDataItem> Items);

/// <summary>A string the engine defined: its size in bytes, the engine's string type (e.g. string, unicode, utf8, C, C_16) and its text (clipped at 400 characters).</summary>
public sealed record EngineString(uint Rva, long Size, string Type, string Text);

/// <summary>A parameter as the engine stores it: name, type and storage (register, stack offset).</summary>
public sealed record EngineParameter(string Name, string Type, string Storage);

/// <summary>The engine's function record; ranges have exclusive ends; SignatureSource user, imported, analysis or default (IDA: user or guessed).</summary>
public sealed record EngineFunctionRecord(uint Start, string Name, string? Namespace, string? Prototype, string? CallingConvention, string? SignatureSource,
    IReadOnlyList<(uint Start, uint End)> Ranges, uint? ThunkTarget, string? ThunkTargetName, bool External, bool NoReturn, bool Library, int? StackPurge,
    IReadOnlyList<EngineParameter> Parameters, string? ReturnType, string? ReturnStorage, bool VarArgs);
/// <summary>An engine namespace: kind class, namespace or library, its direct function count and labeled vftable.</summary>
public sealed record EngineNamespace(string Name, string Kind, int Functions, uint? Vftable);