namespace NetDecompilerMcp.Native.Providers;

/// <summary>
/// An external engine that analyzes a native image and decompiles its functions (IDA via idalib; Ghidra later).
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
/// One analyzed image. Requests run one at a time in arrival order. A request that times out or is cancelled stops
/// the engine; the next request restarts it from the saved database and re-applies names and comments set since the
/// last save. Disposing closes the engine without waiting longer than the shutdown grace period.
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

    Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default);

    /// <summary>Pseudocode of the function containing <paramref name="rva"/>.</summary>
    Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>Instructions of the function containing <paramref name="rva"/>, in address order including chunks.</summary>
    Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>References to <paramref name="rva"/> (ordinary flow excluded).</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default);

    /// <summary>References from the instruction at <paramref name="rva"/>, or from every instruction of its function.</summary>
    Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default);

    /// <summary>Names <paramref name="rva"/>; an empty name removes a user name. Returns the name now in effect.</summary>
    Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default);

    /// <summary>Sets (or with empty text clears) the comment at <paramref name="rva"/>. Returns the comment now stored.</summary>
    Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default);

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
}

/// <summary>A function as the engine sees it; <see cref="EndRva"/> is exclusive and covers the main chunk only.</summary>
public sealed record NativeFunctionInfo(uint StartRva, uint EndRva, string Name, NativeFunctionFlags Flags);

/// <summary>Pseudocode line (0-based) and the lowest instruction RVA it was generated from.</summary>
public sealed record PseudocodeLineAddress(int Line, uint Rva);

public sealed record DecompiledFunction(uint StartRva, string Name, string Text, IReadOnlyList<PseudocodeLineAddress> LineAddresses);

public sealed record DisassembledInstruction(uint Rva, byte[] Bytes, string Text, string? Comment);

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

/// <summary>A reference; <see cref="FromFunctionRva"/> is the start of the function containing the source, when any.</summary>
public sealed record NativeXref(uint FromRva, uint ToRva, NativeXrefKind Kind, uint? FromFunctionRva);
