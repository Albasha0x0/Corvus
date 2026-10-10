using System.Diagnostics;

namespace NetDecompilerMcp.Native.Msvc;

/// <summary>How a frame handles exceptions.</summary>
public enum MsvcEhScheme
{
    /// <summary>x64 __C_specific_handler: a scope table of __try ranges with filters, __except blocks and __finally handlers.</summary>
    CSpecific,
    /// <summary>C++ exceptions, FuncInfo version 1-3 (__CxxFrameHandler3; x86 through an __ehhandler$ stub).</summary>
    Cxx3,
    /// <summary>x64 C++ exceptions, compressed FuncInfo4 (__CxxFrameHandler4).</summary>
    Cxx4,
    /// <summary>x64 __GSHandlerCheck: only the stack cookie check, no handlers.</summary>
    GsOnly,
    /// <summary>x86 _except_handler3 scope table.</summary>
    Seh3,
    /// <summary>x86 _except_handler4 scope table (security cookie offsets, then the records).</summary>
    Seh4,
    /// <summary>A language-specific handler whose data is in no known format.</summary>
    Unknown,
}

/// <summary>How code reached only through exception metadata relates to the function that owns it.</summary>
public enum MsvcEhChildKind
{
    /// <summary>C++ catch block (x64: a funclet; x86: code in the parent run on its frame).</summary>
    Catch,
    /// <summary>C++ unwind action: destroys an object of the parent's frame.</summary>
    Unwind,
    /// <summary>SEH filter expression of an __except.</summary>
    Filter,
    /// <summary>Body of an __except block.</summary>
    ExceptBlock,
    /// <summary>__finally block (termination handler).</summary>
    Finally,
    /// <summary>Where execution resumes in the parent after a catch block.</summary>
    Continuation,
    /// <summary>x86 __ehhandler$ stub: loads the FuncInfo and jumps to __CxxFrameHandler3.</summary>
    HandlerStub,
    /// <summary>Code the linker separated from its function (x64 chained unwind information, FH4 separated segments).</summary>
    Fragment,
}

/// <summary>One catch clause. <see cref="TypeDescriptorRva"/> null is catch (...).</summary>
/// <param name="TypeName">Demangled caught type with its qualifiers ("const MyError &amp;"), null for catch (...).</param>
/// <param name="Continuations">FH4: where execution resumes after the catch (from the metadata).</param>
public sealed record MsvcEhCatch(
    uint HandlerRva,
    uint Adjectives,
    uint? TypeDescriptorRva,
    string? TypeName,
    string? DecoratedTypeName,
    int CatchObjectOffset,
    IReadOnlyList<uint> Continuations);

/// <summary>A try block: the states it covers, the states of its catch blocks, and the catch clauses in order.</summary>
public sealed record MsvcEhTryBlock(int TryLow, int TryHigh, int CatchHigh, IReadOnlyList<MsvcEhCatch> Catches);

public enum MsvcEhUnwindKind
{
    /// <summary>Nothing to do for this state.</summary>
    None,
    /// <summary>A funclet of the parent destroys the object.</summary>
    Funclet,
    /// <summary>FH4: the runtime calls a destructor on the object at a frame offset.</summary>
    DestructorWithObject,
    /// <summary>FH4: the runtime calls a destructor on the object a frame slot points to.</summary>
    DestructorWithPointer,
}

/// <summary>One state of the unwind map: what leaving it does and the state it leaves to (-1: none).</summary>
public sealed record MsvcEhUnwind(int State, int ToState, MsvcEhUnwindKind Kind, uint? ActionRva, int? ObjectOffset);

/// <summary>
/// One SEH scope. x64: the protected range [Begin, End), the filter (a funclet or a constant such as 1 =
/// EXCEPTION_EXECUTE_HANDLER) and the __except block, or the __finally funclet. x86: the enclosing level instead of a
/// range (-1 / -2 = outermost).
/// </summary>
public sealed record MsvcEhScope(int Index, uint? BeginRva, uint? EndRva, int EnclosingLevel, uint? FilterRva, int? FilterConstant, uint HandlerRva, bool IsFinally);

public sealed record MsvcEhIpState(uint Rva, int State);

public sealed record MsvcEhChild(uint Rva, MsvcEhChildKind Kind);

/// <summary>Exception handling of one function (or funclet) as its metadata describes it.</summary>
/// <param name="FunctionRva">The function the metadata belongs to (x64: the .pdata entry; x86: the function that installs the frame).</param>
/// <param name="HandlerRva">x64: the language-specific handler; x86: the frame handler pushed by the prologue (0 when set up by __SEH_prolog4).</param>
/// <param name="HandlerName">The handler's import or export name, when it has one.</param>
/// <param name="DataRva">The handler data: FuncInfo, FuncInfo4 or scope table.</param>
/// <param name="GsCookieOffset">Frame offset of the stack cookie the handler checks (GS handler variants, x86 SEH4).</param>
/// <param name="IsCatchFunclet">The function is itself a catch funclet of another frame.</param>
/// <param name="Children">Code reached through this metadata: catch blocks, unwind funclets, filters, handlers, stubs.</param>
public sealed record MsvcEhFrame(
    uint FunctionRva,
    MsvcEhScheme Scheme,
    uint HandlerRva,
    string? HandlerName,
    uint DataRva,
    int? GsCookieOffset,
    bool IsCatchFunclet,
    int MaxState,
    IReadOnlyList<MsvcEhTryBlock> TryBlocks,
    IReadOnlyList<MsvcEhUnwind> Unwind,
    IReadOnlyList<MsvcEhIpState> IpToState,
    IReadOnlyList<MsvcEhScope> Scopes,
    IReadOnlyList<MsvcEhChild> Children);

/// <summary>Metadata that failed a cross-check and was not used.</summary>
public sealed record MsvcEhReject(uint Rva, string Structure, string Reason);

public sealed record MsvcEhStats(
    int Frames,
    int CSpecific,
    int Cxx3,
    int Cxx4,
    int GsOnly,
    int Seh3,
    int Seh4,
    int Unknown,
    int Children,
    int Fragments,
    int Rejected,
    TimeSpan Elapsed);

public sealed record MsvcEhOptions
{
    public static readonly MsvcEhOptions Default = new();
    public int MaxFrames { get; init; } = 2_000_000;
    public int MaxRejectsReported { get; init; } = 1000;
    public int MaxStates { get; init; } = 1 << 16;
    public int MaxTryBlocks { get; init; } = 1 << 14;
    public int MaxCatches { get; init; } = 1024;
    public int MaxScopes { get; init; } = 4096;
    public int MaxIpStates { get; init; } = 1 << 20;
    /// <summary>x86: executable bytes scanned for frame setup when the image has no relocations.</summary>
    public long MaxScanBytes { get; init; } = 512L << 20;
}

/// <summary>
/// What x86 decoding needs from code analysis: which function contains an instruction, and a function's code. x64
/// metadata is keyed by .pdata entries and needs no view.
/// </summary>
public interface IMsvcEhCodeView
{
    /// <summary>Start of the function whose code contains <paramref name="rva"/>, or null.</summary>
    uint? FunctionContaining(uint rva);

    /// <summary>Code ranges (start, exclusive end) of the function starting at <paramref name="start"/>.</summary>
    IReadOnlyList<(uint Start, uint End)> RangesOf(uint start);
}

/// <summary>Result of <see cref="MsvcEh.Analyze"/>; immutable.</summary>
public sealed class MsvcEhResult
{
    private readonly Dictionary<uint, MsvcEhFrame> _byFunction;

    internal MsvcEhResult(List<MsvcEhFrame> frames, Dictionary<uint, List<(uint Parent, MsvcEhChildKind Kind)>> parents,
        Dictionary<uint, uint> fragments, List<MsvcEhReject> rejects, int rejectCount, MsvcEhStats stats, bool framesSorted = false)
    {
        // a saved result keeps its order exactly (the sort is not stable for frames of the same function)
        if (!framesSorted) frames.Sort((a, b) => a.FunctionRva.CompareTo(b.FunctionRva));
        Frames = frames;
        _byFunction = [];
        foreach (var f in frames) _byFunction.TryAdd(f.FunctionRva, f);
        Parents = parents.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<(uint, MsvcEhChildKind)>)kv.Value);
        Fragments = fragments;
        Rejects = rejects;
        RejectCount = rejectCount;
        Stats = stats;
    }

    /// <summary>Every frame with exception metadata, sorted by function.</summary>
    public IReadOnlyList<MsvcEhFrame> Frames { get; }

    /// <summary>
    /// Child code start -> the outermost functions that own it (several when the linker folded identical funclets),
    /// with how it relates. Nested catch funclets resolve to the function at the root.
    /// </summary>
    public IReadOnlyDictionary<uint, IReadOnlyList<(uint Parent, MsvcEhChildKind Kind)>> Parents { get; }

    /// <summary>x64: begin of a .pdata entry whose unwind information is chained -> the primary function's begin.</summary>
    public IReadOnlyDictionary<uint, uint> Fragments { get; }

    /// <summary>Rejected metadata (at most <see cref="MsvcEhOptions.MaxRejectsReported"/>; <see cref="RejectCount"/> counts all).</summary>
    public IReadOnlyList<MsvcEhReject> Rejects { get; }
    public int RejectCount { get; }
    public MsvcEhStats Stats { get; }

    public MsvcEhFrame? FrameOf(uint functionRva) => _byFunction.GetValueOrDefault(functionRva);

    public static MsvcEhResult Empty { get; } = new([], [], [], [], 0, new MsvcEhStats(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero));
}

/// <summary>
/// Decodes MSVC exception handling metadata. x64: the language-specific handler and data of each .pdata entry's
/// UNWIND_INFO (__C_specific_handler scope tables, __CxxFrameHandler3 FuncInfo, __CxxFrameHandler4 compressed
/// FuncInfo4, __GSHandlerCheck variants) and chained unwind information (fragments). x86: frames installed by
/// prologues (push offset scope table for _except_handler3/4 and __SEH_prolog4, push / mov eax offset of an
/// __ehhandler$ stub that loads a FuncInfo for __CxxFrameHandler3). Every structure is bounds-checked and
/// cross-checked (handlers in executable code, ranges inside the function, type descriptor names that decode);
/// what fails is reported as a reject, never thrown.
/// </summary>
public static partial class MsvcEh
{
    public static MsvcEhResult Analyze(INativeImage image, IMsvcEhCodeView? view = null, MsvcEhOptions? options = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var run = new Run(image, options ?? MsvcEhOptions.Default, ct);
        if (image.Arch == NativeArch.X64) run.X64();
        else if (image.Arch == NativeArch.X86 && view != null) run.X86(view);
        return run.Result(sw.Elapsed);
    }

    private sealed partial class Run(INativeImage image, MsvcEhOptions options, CancellationToken ct)
    {
        private readonly EhReader _r = new(image);
        private readonly List<MsvcEhFrame> _frames = [];
        private readonly Dictionary<uint, uint> _fragments = [];
        private readonly List<MsvcEhReject> _rejects = [];
        private int _rejectCount;
        private readonly Dictionary<uint, (string? Type, string? Decorated, string? Reason)> _types = [];

        private void Reject(uint rva, string structure, string reason)
        {
            _rejectCount++;
            if (_rejects.Count < options.MaxRejectsReported) _rejects.Add(new MsvcEhReject(rva, structure, reason));
        }

        private void AddFrame(MsvcEhFrame frame)
        {
            if (_frames.Count >= options.MaxFrames) { Reject(frame.FunctionRva, "frame", $"frame limit {options.MaxFrames} reached"); return; }
            _frames.Add(frame);
        }

        /// <summary>
        /// Type descriptor at <paramref name="rva"/>: its name (after the type_info vftable pointer and the spare
        /// pointer) must be a decorated type that decodes.
        /// </summary>
        private (string? Type, string? Decorated, string? Reason) TypeDescriptor(uint rva)
        {
            if (_types.TryGetValue(rva, out var cached)) return cached;
            (string?, string?, string?) result;
            uint nameRva = rva + 2u * (uint)(image.Is64Bit ? 8 : 4);
            var name = _r.CString(nameRva, 1024);
            if (name == null || name.Length < 2 || name[0] != '.') result = (null, null, "type descriptor has no decorated name");
            else if (MsvcDemangler.DemangleTypeDescriptorName(name) is { } d) result = (d.Name, name, null);
            else result = (null, name, $"type descriptor name '{name}' does not decode");
            _types[rva] = result;
            if (result.Item3 != null) Reject(rva, "type descriptor", result.Item3);
            return result;
        }

        /// <summary>The caught type with the qualifiers of the handler adjectives (const, volatile, reference).</summary>
        private static string CatchTypeText(string type, uint adjectives)
        {
            var text = type;
            if ((adjectives & 2) != 0) text = "volatile " + text;
            if ((adjectives & 1) != 0) text = "const " + text;
            if ((adjectives & 8) != 0) text += " &";
            return text;
        }

        /// <summary>Builds a catch clause; false (with a reject) when the type descriptor fails its checks.</summary>
        private MsvcEhCatch Catch(uint function, uint handler, uint adjectives, uint typeRva, int catchObject, IReadOnlyList<uint> continuations)
        {
            if (typeRva == 0) return new MsvcEhCatch(handler, adjectives, null, null, null, catchObject, continuations);
            var (type, decorated, _) = TypeDescriptor(typeRva);
            return new MsvcEhCatch(handler, adjectives, typeRva, type != null ? CatchTypeText(type, adjectives) : null, decorated, catchObject, continuations);
        }

        public MsvcEhResult Result(TimeSpan elapsed)
        {
            // child -> direct parents, then each resolved to the outermost function (not itself a child)
            var direct = new Dictionary<uint, List<(uint Parent, MsvcEhChildKind Kind)>>();
            foreach (var f in _frames)
                foreach (var c in f.Children)
                {
                    if (c.Rva == f.FunctionRva) continue;
                    if (!direct.TryGetValue(c.Rva, out var list)) direct[c.Rva] = list = [];
                    if (!list.Any(p => p.Parent == f.FunctionRva)) list.Add((f.FunctionRva, c.Kind));
                }
            var resolved = new Dictionary<uint, List<(uint, MsvcEhChildKind)>>();
            var roots = new List<uint>();
            var seen = new HashSet<uint>();
            foreach (var (child, parents) in direct)
            {
                var list = new List<(uint, MsvcEhChildKind)>();
                foreach (var (p, kind) in parents)
                {
                    roots.Clear();
                    seen.Clear();
                    seen.Add(child);
                    Roots(p, direct, roots, seen, 0);
                    foreach (var root in roots)
                        if (root != child && !list.Any(x => x.Item1 == root)) list.Add((root, kind));
                }
                if (list.Count > 0) resolved[child] = list;
                else Reject(child, "parent link", "the functions that own it form a cycle");
            }
            int children = resolved.Count;
            var stats = new MsvcEhStats(_frames.Count,
                _frames.Count(f => f.Scheme == MsvcEhScheme.CSpecific), _frames.Count(f => f.Scheme == MsvcEhScheme.Cxx3),
                _frames.Count(f => f.Scheme == MsvcEhScheme.Cxx4), _frames.Count(f => f.Scheme == MsvcEhScheme.GsOnly),
                _frames.Count(f => f.Scheme == MsvcEhScheme.Seh3), _frames.Count(f => f.Scheme == MsvcEhScheme.Seh4),
                _frames.Count(f => f.Scheme == MsvcEhScheme.Unknown), children, _fragments.Count, _rejectCount, elapsed);
            return new MsvcEhResult(_frames, resolved, _fragments, _rejects, _rejectCount, stats);
        }

        /// <summary>The outermost owners of <paramref name="node"/>: itself unless it is a child, then its parents' roots.</summary>
        private static void Roots(uint node, Dictionary<uint, List<(uint Parent, MsvcEhChildKind Kind)>> direct, List<uint> roots, HashSet<uint> seen, int depth)
        {
            if (!seen.Add(node) || depth > 64) return;
            if (!direct.TryGetValue(node, out var parents))
            {
                if (!roots.Contains(node)) roots.Add(node);
                return;
            }
            int before = roots.Count;
            foreach (var (p, _) in parents) Roots(p, direct, roots, seen, depth + 1);
            // every parent is already on the path (a funclet listed by its own frame): it is the root
            if (roots.Count == before && parents.All(p => seen.Contains(p.Parent)) && !roots.Contains(node)) roots.Add(node);
        }
    }
}
