namespace Corvus.Native.Code;

/// <summary>How an instruction transfers control.</summary>
public enum FlowKind : byte
{
    /// <summary>Continues with the next instruction.</summary>
    Next,
    Call,
    IndirectCall,
    Jump,
    IndirectJump,
    ConditionalJump,
    Return,
    /// <summary>Does not continue: int3, ud2, hlt, int 29h (__fastfail).</summary>
    Trap,
    /// <summary>The bytes do not decode (or run past the end of the code).</summary>
    Invalid,
}

/// <summary>How an instruction uses the address in its memory operand or immediate.</summary>
public enum OperandAccess : byte
{
    None,
    Read,
    Write,
    ReadWrite,
    /// <summary>The address itself is taken (lea, push offset, mov reg, offset).</summary>
    Address,
}

/// <summary>Decoded facts about one instruction; addresses are RVAs.</summary>
public sealed record InstructionFacts(
    uint Rva,
    int Length,
    FlowKind Flow,
    uint? BranchTarget,
    uint? MemoryTarget,
    bool MemoryIsRipRelative,
    OperandAccess MemoryAccess,
    uint? ImmediateTarget);

/// <summary>Where a function start came from (several can apply).</summary>
[Flags]
public enum FunctionSource : uint
{
    None = 0,
    /// <summary>Primary entry of the exception directory (.pdata).</summary>
    Pdata = 1,
    Export = 2,
    EntryPoint = 4,
    TlsCallback = 8,
    /// <summary>Target of a direct call.</summary>
    Call = 16,
    /// <summary>Target of a jump that is a tail call: out of the caller's ranges, a thunk, or to a standard prologue.</summary>
    TailJump = 32,
    /// <summary>Unreferenced code in a gap between known code, verified by decoding.</summary>
    CodeGap = 64,
    /// <summary>A relocated pointer in data (vtable, function table), verified by decoding.</summary>
    DataPointer = 128,
    /// <summary>Address taken by code (lea / push offset), verified by decoding.</summary>
    CodeAddress = 256,
    /// <summary>Listed in the Control Flow Guard function table of the load configuration.</summary>
    GuardCf = 512,
    /// <summary>x64: language-specific exception handler named by unwind information.</summary>
    ExceptionHandler = 1024,
    /// <summary>A function a loaded PDB or the image's own symbol table names.</summary>
    Symbol = 2048,
    /// <summary>Unwind tables of ELF and Mach-O images (.eh_frame, .ARM.exidx, compact unwind).</summary>
    Unwind = 4096,
    /// <summary>Mach-O LC_FUNCTION_STARTS.</summary>
    FunctionStarts = 8192,
    /// <summary>An initializer or finalizer array entry (.init_array, __mod_init_func).</summary>
    Initializer = 16384,
    /// <summary>The Go runtime's function table (pclntab).</summary>
    GoTable = 32768,
}

[Flags]
public enum FunctionFlags : byte
{
    None = 0,
    /// <summary>A single jmp through an import slot.</summary>
    Thunk = 1,
    NoReturn = 2,
    /// <summary>Has an indirect jump whose targets are not known.</summary>
    UnresolvedJumps = 4,
    /// <summary>Some path runs into bytes that do not decode.</summary>
    InvalidCode = 8,
    /// <summary>Stopped at the instruction cap; the rest of the function is missing.</summary>
    Truncated = 16,
    /// <summary>Some instructions are decoded at two overlapping offsets.</summary>
    OverlappingCode = 32,
    /// <summary>x86: runs in another function's frame, reached only through exception metadata.</summary>
    Funclet = 64,
    /// <summary>32-bit ARM: the ARM / Thumb state is a guess between two plausible readings.</summary>
    StateGuessed = 128,
}

/// <summary>A discovered function. Extents are the union of its basic blocks (functions can be non-contiguous).</summary>
public sealed class NativeFunction
{
    public uint Start { get; internal set; }
    public FunctionSource Sources { get; internal set; }
    public FunctionFlags Flags { get; internal set; }
    /// <summary>Export name, or for a thunk "module!name" of the import it jumps to; null otherwise.</summary>
    public string? KnownName { get; internal set; }
    /// <summary>For a thunk: the import it jumps to.</summary>
    public NativeImport? ThunkImport { get; internal set; }
    /// <summary>Highest end of its code (exclusive).</summary>
    public uint End { get; internal set; }
    /// <summary>Number of code bytes in its blocks.</summary>
    public uint Size { get; internal set; }
    public int BlockCount { get; internal set; }
    public int InstructionCount { get; internal set; }
    /// <summary>Code reached only through this function's exception metadata; part of its ranges, not functions of their own.</summary>
    public IReadOnlyList<FunctionChunk> Chunks { get; internal set; } = [];
    /// <summary>x64 C++ funclet: the first function whose exception metadata names it; null otherwise.</summary>
    public NativeFunction? Parent { get; internal set; }
    internal int Index { get; set; }
    internal int FirstRange { get; set; }
    internal int RangeCount { get; set; }

    /// <summary>The known name, or sub_&lt;rva&gt;.</summary>
    public string Name => KnownName ?? $"sub_{Start:X}";

    public override string ToString() => $"{Name} @ {Start:X}";
}

/// <summary>Kind of a cross-reference.</summary>
public enum XrefKind : byte
{
    /// <summary>Direct call (code -> function).</summary>
    Call,
    /// <summary>Unconditional jump inside a function.</summary>
    Jump,
    /// <summary>Conditional jump inside a function.</summary>
    ConditionalJump,
    /// <summary>Jump (conditional or not) to another function's start: a tail call.</summary>
    TailCall,
    /// <summary>Indirect jump through a resolved switch table to a case.</summary>
    SwitchCase,
    /// <summary>call [slot] through an import slot; the target is the slot RVA.</summary>
    ImportCall,
    /// <summary>jmp [slot] through an import slot; the target is the slot RVA.</summary>
    ImportJump,
    /// <summary>Code reads data at the target.</summary>
    Read,
    /// <summary>Code writes data at the target.</summary>
    Write,
    /// <summary>Code takes the target's address (lea, push offset, mov reg, offset).</summary>
    Address,
    /// <summary>Code reads a switch table at the target.</summary>
    JumpTable,
    /// <summary>A relocated pointer stored in data points at the target.</summary>
    Pointer,
    /// <summary>A virtual call whose only implementation is the target; not listed by RefsFrom / RefsTo.</summary>
    VirtualExact,
    /// <summary>A virtual call one of whose possible implementations is the target.</summary>
    VirtualPossible,
}

/// <summary>One cross-reference; From and To are RVAs.</summary>
public readonly record struct CodeXref(uint From, uint To, XrefKind Kind)
{
    public bool IsCodeFlow => Kind is XrefKind.Call or XrefKind.Jump or XrefKind.ConditionalJump or XrefKind.TailCall or XrefKind.SwitchCase;
    public bool IsCallLike => Kind is XrefKind.Call or XrefKind.TailCall or XrefKind.ImportCall or XrefKind.ImportJump;
    public bool IsVirtualCall => Kind is XrefKind.VirtualExact or XrefKind.VirtualPossible;
}

public enum StringEncoding : byte
{
    Ascii,
    Utf16,
    /// <summary>UTF-8 of a byte length that code or data gives, with no terminator (Rust &amp;str).</summary>
    Utf8,
    /// <summary>A Swift small string held in immediates: <see cref="StringLiteral.Rva"/> is the instruction that completes it.</summary>
    Inline,
}

/// <summary>A referenced string; <see cref="Length"/> counts characters for ASCII and UTF-16, bytes for UTF-8 and inline.</summary>
public readonly record struct StringLiteral(uint Rva, int Length, StringEncoding Encoding);

/// <summary>Kind of a control-flow edge between basic blocks.</summary>
public enum EdgeKind : byte
{
    FallThrough,
    Jump,
    ConditionalTaken,
    ConditionalFallThrough,
    Switch,
    /// <summary>Leaves the function (jump to another function's start, or falls into one).</summary>
    TailCall,
}

public readonly record struct CfgEdge(uint From, uint To, EdgeKind Kind);

/// <summary>How a basic block ends.</summary>
public enum BlockEnd : byte
{
    /// <summary>Falls into the next block (split by a branch target).</summary>
    FallThrough,
    Jump,
    ConditionalJump,
    Return,
    /// <summary>Indirect jump through a resolved switch table.</summary>
    Switch,
    /// <summary>Indirect jump with unknown targets.</summary>
    IndirectJump,
    TailCall,
    /// <summary>Call to a function that does not return.</summary>
    NoReturnCall,
    Trap,
    Invalid,
    /// <summary>Runs into another function's start.</summary>
    FunctionBoundary,
    /// <summary>Runs past the end of the executable code.</summary>
    EndOfCode,
    /// <summary>Stopped at the instruction cap.</summary>
    Truncated,
}

public sealed class BasicBlock
{
    public uint Start { get; internal init; }
    /// <summary>Exclusive end.</summary>
    public uint End { get; internal init; }
    public int InstructionCount { get; internal init; }
    public uint LastInstruction { get; internal init; }
    public BlockEnd EndKind { get; internal init; }
    public List<CfgEdge> Successors { get; } = [];
    public List<CfgEdge> Predecessors { get; } = [];
}

/// <summary>A switch target and the switched values that select it.</summary>
public sealed record SwitchCase(uint Target, IReadOnlyList<long> Values);

/// <summary>What a switch table entry holds.</summary>
public enum SwitchTableKind : byte
{
    /// <summary>The target's address (relocated).</summary>
    Absolute,
    /// <summary>The target's RVA.</summary>
    Rva,
    /// <summary>The target's offset from the table.</summary>
    TableRelative,
    /// <summary>ARM: the target's offset from a base address, scaled (base + (entry &lt;&lt; shift)).</summary>
    BaseRelative,
    /// <summary>ARM32: no table; the index selects one of a run of branches after the dispatch (base + index * 4).</summary>
    Indexed,
}

/// <summary>A resolved switch; <see cref="Cases"/> map values (index + <see cref="Bias"/>) to targets, default-target values in <see cref="DefaultValues"/>.</summary>
public sealed record SwitchTable(uint JumpRva, uint TableRva, int EntryCount, int EntrySize, uint? IndexTableRva, int IndexEntryCount, IReadOnlyList<uint> Targets)
{
    public IReadOnlyList<SwitchCase> Cases { get; init; } = [];
    /// <summary>Where an out-of-range value goes (the bounding branch's target); null when an and-mask bounds the index.</summary>
    public uint? Default { get; init; }
    public IReadOnlyList<long> DefaultValues { get; init; } = [];
    public long Bias { get; init; }
    public SwitchTableKind Kind { get; init; }
    /// <summary>False when the values are table indexes not bounded by a compare.</summary>
    public bool ValuesExact { get; init; } = true;
    /// <summary><see cref="SwitchTableKind.BaseRelative"/>: target = Base + (entry &lt;&lt; Shift).</summary>
    public uint? Base { get; init; }
    public int Shift { get; init; }
}

/// <summary>An indirect jump whose targets are unknown, and why.</summary>
public readonly record struct UnresolvedJump(uint Rva, string Reason);

/// <summary>Basic blocks and edges of one function, blocks sorted by start.</summary>
public sealed class FunctionGraph
{
    public required NativeFunction Function { get; init; }
    public required IReadOnlyList<BasicBlock> Blocks { get; init; }
    public required IReadOnlyList<SwitchTable> Switches { get; init; }
    /// <summary>Indirect jumps whose targets are unknown.</summary>
    public required IReadOnlyList<UnresolvedJump> UnresolvedJumps { get; init; }
    /// <summary>Targets of tail calls (jumps to other functions).</summary>
    public required IReadOnlyList<uint> TailCalls { get; init; }
    public bool Truncated { get; init; }

    public BasicBlock? BlockAt(uint rva)
    {
        int lo = 0, hi = Blocks.Count - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            var b = Blocks[mid];
            if (rva < b.Start) hi = mid - 1;
            else if (rva >= b.End) lo = mid + 1;
            else return b;
        }
        return null;
    }
}
