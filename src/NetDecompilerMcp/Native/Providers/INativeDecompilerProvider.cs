namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// An external engine that analyzes a native image and decompiles its functions (IDA via idalib, Ghidra via a Java worker).
/// Addresses in and out are RVAs relative to the image base the engine loaded, which the session verifies against
/// the PE header. Failures surface as <see cref="Core.ToolError"/>: ProviderUnavailable (engine missing, crashed or
/// unlicensed), Timeout, Unsupported (architecture or decompiler not available), NotFound, InvalidArgument,
/// MalformedInput, Conflict (input changed, database in use).
/// </summary>
public interface INativeDecompilerProvider : IDisposable
{
    /// <summary>Stable identifier ("ida", "ghidra").</summary>
    string Id { get; }

    string DisplayName { get; }

    /// <summary>Static checks only (install found, files present, interpreter found); cached after the first call.</summary>
    ProviderAvailability CheckAvailability();

    /// <summary>Static checks plus starting the engine once; reports load and version problems the static checks miss.</summary>
    Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens <paramref name="imagePath"/> for analysis. The provider works on a private copy whose SHA-256 must equal
    /// <paramref name="sha256"/> (computed from the file when null), and keeps its analysis database per hash so a
    /// later open of the same bytes skips auto-analysis.
    /// </summary>
    Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default);
}

/// <summary>
/// One analyzed image. Requests that change the database run one at a time in arrival order; an engine may run reads
/// in parallel (Ghidra). A request that times out or is cancelled stops the engine unless the engine can stop that
/// request alone; the next request restarts a stopped engine from the saved database and re-applies names and comments
/// set since the last save. Disposing closes the engine without waiting longer than the shutdown grace period.
/// </summary>
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

    Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default);

    /// <summary>The functions, with the number of code references to each start when <paramref name="withReferences"/> is set.</summary>
    Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(bool withReferences, CancellationToken cancellationToken = default) =>
        ListFunctionsAsync(cancellationToken);

    /// <summary>Pseudocode of the function containing <paramref name="rva"/>.</summary>
    Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>
    /// Pseudocode of the functions containing each RVA, in order, each within <paramref name="secondsPerItem"/> and all within
    /// <paramref name="budgetSeconds"/>: a failure is that item's, and items the budget does not reach are skipped. The default
    /// asks <see cref="DecompileAsync"/> once per item.
    /// </summary>
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

    /// <summary>
    /// Makes the bytes patched in the database exactly <paramref name="wanted"/> (bytes patched earlier and not wanted
    /// are restored to their original values) and decodes the touched code again, so the analysis reflects the patched
    /// image without a new auto-analysis. A result with missing or mismatched bytes means the database could not take
    /// the patch set; the caller analyzes the patched file instead.
    /// </summary>
    Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not apply byte patches.");

    /// <summary>
    /// Imports C declarations, applies function prototypes and builds C++ class types (vftable and class structs) in
    /// one request; failures are counted, not thrown. Stamp and save as in <see cref="ApplyNamesAsync"/>.
    /// </summary>
    Task<TypeBatchResult> ApplyTypesAsync(NativeTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not take types.");

    /// <summary>
    /// What the engine knows about the call instructions at <paramref name="sites"/>: its code references from them, and how its
    /// decompiler shows them in <paramref name="functions"/> (through a member of a vftable struct type, a function, or an
    /// untyped pointer), within <paramref name="seconds"/>.
    /// </summary>
    Task<NativeCallTargets> GetCallTargetsAsync(IReadOnlyList<uint> functions, IReadOnlyList<uint> sites, double seconds,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report call targets.");

    /// <summary>
    /// Loads <paramref name="pdbPath"/> with the engine's own PDB loader (types, prototypes, names). With
    /// <paramref name="trustAnalysisLoad"/>, a PDB the engine loaded itself during auto-analysis counts as this one and is
    /// not loaded again. On success the stamp is recorded under <paramref name="stampKey"/>, the names stamp is dropped
    /// (pushed names are replaced by the PDB's, so they are pushed again) and the database is saved.
    /// </summary>
    Task<PdbLoadResult> LoadPdbAsync(string pdbPath, string stampKey, string stamp, bool trustAnalysisLoad, CancellationToken cancellationToken = default) =>
        Task.FromResult(new PdbLoadResult(false, false, false, 0, 0, TimeSpan.Zero));

    /// <summary>
    /// Applies the user's types (see <see cref="NativeUserTypeBatch"/>); each item reports whether it took. User types are kept
    /// when <see cref="ApplyTypesAsync"/> pushes recovered types later. Stamp and save as in <see cref="ApplyNamesAsync"/>; an
    /// empty batch only records the stamp.
    /// </summary>
    Task<UserTypeResult> ApplyUserTypesAsync(NativeUserTypeBatch batch, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not take user types.");

    /// <summary>The stack frame and decompiler locals of the function containing <paramref name="rva"/>.</summary>
    Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report stack frames.");

    /// <summary>Named types whose name contains <paramref name="filter"/> (case-insensitive), of <paramref name="kind"/> when given, paged.</summary>
    Task<NativeTypeList> ListTypesAsync(string? filter, string? kind, int offset, int limit, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list types.");

    /// <summary>One named type (NotFound when there is none).</summary>
    Task<NativeTypeDetail> GetTypeAsync(string name, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not list types.");

    /// <summary>
    /// References to a member of a struct or union (the first of <paramref name="types"/> that exists), by name or by an
    /// offset it covers: operands typed as the member, and member accesses in the pseudocode of the functions whose type
    /// names the struct plus <paramref name="functions"/>, within <paramref name="seconds"/>. NotFound for no such type or member.
    /// </summary>
    Task<NativeFieldXrefs> GetFieldXrefsAsync(IReadOnlyList<string> types, string? member, int? offset, IReadOnlyList<uint> functions, double seconds,
        CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not report struct member references.");

    /// <summary>
    /// Runs a script in the engine's own language against the database (IDA: Python with IDAPython); its globals persist
    /// between calls unless <paramref name="reset"/>. Not journaled: a restart loses its unsaved changes.
    /// </summary>
    Task<NativeScriptResult> RunScriptAsync(string code, bool reset = false, CancellationToken cancellationToken = default) =>
        throw new Core.ToolError(Core.ErrorCode.Unsupported, $"The {ProviderId} engine does not run scripts.");

    /// <summary>References to <paramref name="rva"/> (ordinary flow excluded).</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>References from the instruction at <paramref name="rva"/>, or from every instruction of its function.</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default);

    /// <summary>Names <paramref name="rva"/>; an empty name removes a user name. Returns the name now in effect.</summary>
    Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default);

    /// <summary>Sets (or with empty text clears) the comment at <paramref name="rva"/>. Returns the comment now stored.</summary>
    Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applies many names and comments in one request (imported symbol sets: tens of thousands at once). Names are
    /// forced (a name taken elsewhere gets an engine-chosen suffix); failures are counted, not thrown. With
    /// <paramref name="stampKey"/> the database records <paramref name="stamp"/> under it (see <see cref="GetStampAsync"/>);
    /// <paramref name="save"/> writes the database afterwards.
    /// </summary>
    Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
        CancellationToken cancellationToken = default);

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

public sealed record NativeOpenOptions
{
    public SymbolMode Symbols { get; init; } = SymbolMode.Default;
    /// <summary>The image's PDB as located by the server (verified by GUID and age); the engine looks there first. Ignored with <see cref="SymbolMode.Off"/>.</summary>
    public string? PdbPath { get; init; }
    /// <summary>Limit for engine start plus loading or auto-analysis.</summary>
    public TimeSpan OpenTimeout { get; init; } = TimeSpan.FromMinutes(20);
    /// <summary>Limit for each request after the open.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromMinutes(2);
    /// <summary>Receives start and analysis progress (elapsed time and stage).</summary>
    public IProgress<NativeProviderProgress>? Progress { get; init; }
}

public sealed record NativeProviderProgress(string Stage, TimeSpan Elapsed);

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
}

/// <summary>
/// A function as the engine sees it; <see cref="EndRva"/> is exclusive and covers the main chunk only.
/// <see cref="References"/>: code references to the start, when asked for.
/// </summary>
public sealed record NativeFunctionInfo(uint StartRva, uint EndRva, string Name, NativeFunctionFlags Flags, int? References = null);

/// <summary>Pseudocode line (0-based) and the lowest instruction RVA it was generated from.</summary>
public sealed record PseudocodeLineAddress(int Line, uint Rva);

public sealed record DecompiledFunction(uint StartRva, string Name, string Text, IReadOnlyList<PseudocodeLineAddress> LineAddresses);

/// <summary>
/// A per-function slice asked of an engine. Seed: location (a register's value before <see cref="Rva"/> backward, from
/// its definition there forward), argument (<see cref="Index"/> of the call at Rva), parameter (Index of the function),
/// result (of the call at Rva), returns (the function's returned values), stored (the value the instruction at Rva
/// stores), loaded (the value the instruction at Rva loads). Registers use the engine's names ("rcx", "x0").
/// </summary>
public sealed record EngineSliceRequest(uint Function, string Seed, uint Rva, bool Forward, string? Register = null, int Index = -1, int MaxNodes = 256,
    double Seconds = 30);

/// <summary>
/// One node of an engine slice. Kind: constant, address, global, stack_address, unknown, merge, loop, field, parameter,
/// call_result; forward: origin, argument, store, field_store, return, compare, switch, dereference, call_target.
/// </summary>
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

/// <summary>
/// A basic block as the engine splits it: [<see cref="StartRva"/>, <see cref="EndRva"/>), its instruction count, how it
/// ends (engine kind: normal, indjump, ret, cndret, noret, enoret, error), its successors in the function, and whether
/// its last instruction is a switch the engine resolved.
/// </summary>
public sealed record NativeBlockInfo(uint StartRva, uint EndRva, int Instructions, string Kind, IReadOnlyList<uint> Successors, bool Switch)
{
    /// <summary>The engine's switch details, when it reports them.</summary>
    public NativeSwitchInfo? SwitchInfo { get; init; }
}

/// <summary>
/// A switch as the engine recovered it: the indirect jump, switched values per target, the default, the jump table (entry
/// size and count), a byte index table in front of it, and the bias (switched value = table index + bias).
/// </summary>
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
    IReadOnlyList<string> Failures, IReadOnlyDictionary<string, int> MethodSkips);

/// <summary>
/// What <see cref="INativeDecompilerSession.LoadPdbAsync"/> did: whether the PDB is in the database, whether that was
/// the engine's own load during auto-analysis, whether the engine's PDB loader ran at all (false: not available), and
/// the engine's type count before and after.
/// </summary>
public sealed record PdbLoadResult(bool Loaded, bool FromAnalysis, bool LoaderAvailable, int TypesBefore, int TypesAfter, TimeSpan Elapsed);

/// <summary>Bytes wanted at an RVA (a patch's replacement).</summary>
public sealed record NativeByteRange(uint Rva, byte[] Bytes);

/// <summary>
/// What <see cref="INativeDecompilerSession.SyncPatchesAsync"/> did: bytes patched and reverted, code ranges decoded
/// again and functions reanalyzed; bytes not in the database (<see cref="Missing"/>) or that would not take
/// (<see cref="Mismatches"/>), with up to 20 of their RVAs each in <see cref="Problems"/>.
/// </summary>
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

/// <summary>
/// One entry of <see cref="INativeDecompilerSession.ApplyNamesAsync"/>: a null name or comment is left as is, an empty
/// one removed; <see cref="MakeFunction"/> creates a function at <see cref="Rva"/> when none contains it. A comment at
/// a function start becomes the function comment.
/// </summary>
public sealed record NativeNameItem(uint Rva, string? Name, string? Comment, bool MakeFunction = false);

public sealed record NameBatchResult(int Named, int NameFailures, int Commented, int FunctionsCreated, TimeSpan Elapsed, IReadOnlyList<string> Failures);

/// <summary>
/// What an engine says about one call instruction: Kind "xref" (a code reference to the function at <see cref="Target"/>),
/// "vftable" (the decompiler calls through member offset <see cref="MemberOffset"/> of struct type <see cref="TypeName"/>),
/// "direct" (the decompiler calls the function at <see cref="Target"/>) or "other" (an untyped pointer; <see cref="TypeName"/> is the expression kind).
/// </summary>
public sealed record NativeCallTarget(uint Site, string Kind, uint? Target, string? TypeName, int? MemberOffset);

/// <summary>Result of <see cref="INativeDecompilerSession.GetCallTargetsAsync"/>: functions decompiled, failed (with the reason) and not reached in time.</summary>
public sealed record NativeCallTargets(IReadOnlyList<NativeCallTarget> Targets, int Decompiled, IReadOnlyList<(uint Function, string Reason)> Failed, int Skipped,
    bool DecompilerAvailable);

/// <summary>
/// A decompiler local of the function at <see cref="Function"/>, found by its stack offset when it has one, else by
/// <see cref="Local"/> (its name when first edited), else by <see cref="Name"/>; gets <see cref="Name"/> and/or <see cref="Type"/>.
/// </summary>
public sealed record NativeLocalEdit(uint Function, string Local, int? Stack, string? Name, string? Type);

/// <summary>The stack frame member at <see cref="Offset"/> (bytes from the frame's lowest address) gets <see cref="Name"/> and/or <see cref="Type"/>; created when none is there.</summary>
public sealed record NativeStackVarEdit(uint Function, int Offset, string? Name, string? Type);

/// <summary>
/// User types, applied in this order: C declarations; types of functions (prototypes) and globals by RVA, an empty one
/// clearing it; stack frame members; decompiler locals.
/// </summary>
public sealed record NativeUserTypeBatch(IReadOnlyList<string> Declarations, IReadOnlyList<NativePrototype> Types, IReadOnlyList<NativeStackVarEdit> StackVars,
    IReadOnlyList<NativeLocalEdit> Locals)
{
    public static readonly NativeUserTypeBatch Empty = new([], [], [], []);
}

/// <summary>
/// One item of a user type batch: <see cref="Kind"/> type, stack or local, at <see cref="Rva"/> (the address or function);
/// <see cref="Target"/> as asked; for a local the name it had before (<see cref="Resolved"/>) and its stack offset;
/// <see cref="Text"/>: the type or name now in effect.
/// </summary>
public sealed record NativeUserTypeOutcome(string Kind, uint Rva, string Target, bool Applied, string? Error, string? Resolved, int? Stack, string? Text);

/// <summary>
/// Result of <see cref="INativeDecompilerSession.ApplyUserTypesAsync"/>: declaration errors with the engine's messages, the
/// type names the declarations made, and each item's outcome.
/// </summary>
public sealed record UserTypeResult(int DeclarationErrors, IReadOnlyList<string> DeclarationMessages, IReadOnlyList<string> DeclaredTypes,
    IReadOnlyList<NativeUserTypeOutcome> Items, TimeSpan Elapsed);

/// <summary>A named type of the engine: kind struct, union, enum, typedef, func or other; size -1 when unknown; members of a struct, union or enum.</summary>
public sealed record NativeTypeEntry(string Name, string Kind, long Size, int Members);

/// <summary>Named types matching a query, one page of them.</summary>
public sealed record NativeTypeList(int Total, IReadOnlyList<NativeTypeEntry> Types);

/// <summary>A struct or union member at <see cref="Offset"/> bytes.</summary>
public sealed record NativeTypeMember(long Offset, string Name, string Type, long Size);

/// <summary>One named type: its C declaration as the engine prints it, and its members (structs and unions).</summary>
public sealed record NativeTypeDetail(string Name, string Kind, long Size, string Declaration, IReadOnlyList<NativeTypeMember> Members);

/// <summary>A stack frame member at <see cref="Offset"/> bytes from the frame's lowest address; <see cref="Kind"/> local, arg or special (return address, saved registers).</summary>
public sealed record NativeFrameMember(int Offset, string Name, string Type, int Size, string Kind);

/// <summary>A decompiler local: where it lives (a register, "stack" with its <see cref="Stack"/> offset), and whether the user named or typed it.</summary>
public sealed record NativeLocal(string Name, string Type, string Location, int? Stack, bool IsArgument, bool UserName, bool UserType);

/// <summary>
/// A function's stack frame (local and saved-register sizes, the return address's frame offset, members) and its decompiler
/// locals; <see cref="DecompilerError"/> says why there are no locals.
/// </summary>
public sealed record NativeFrame(uint StartRva, string Name, int LocalSize, int SavedRegisters, int ReturnAddressOffset, IReadOnlyList<NativeFrameMember> Members,
    IReadOnlyList<NativeLocal> Locals, string? DecompilerError);

/// <summary>A use of a struct member at <see cref="Rva"/>: Kind operand (typed operand), read, write or address (pseudocode access).</summary>
public sealed record NativeFieldAccess(uint Rva, string Kind, uint? FunctionRva);

/// <summary>
/// The member found (type, name, offset, size, type text) and its uses; functions considered for the pseudocode scan,
/// scanned, failed and not reached in time.
/// </summary>
public sealed record NativeFieldXrefs(string Type, string Member, int Offset, int Size, string MemberType, IReadOnlyList<NativeFieldAccess> Accesses,
    int Candidates, int Scanned, int Failed, int Skipped, bool DecompilerAvailable);

/// <summary>What a script printed and returned (the value of a final expression), or the exception it raised.</summary>
public sealed record NativeScriptResult(string? Result, string Stdout, string Stderr, string? Error);

/// <summary>A reference; <see cref="FromFunctionRva"/> is the start of the function containing the source, when any.</summary>
public sealed record NativeXref(uint FromRva, uint ToRva, NativeXrefKind Kind, uint? FromFunctionRva);
