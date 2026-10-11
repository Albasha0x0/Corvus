using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>What a per-function slice starts from.</summary>
public enum SliceSeedKind : byte
{
    /// <summary>A register or stack / frame slot at an instruction: its value before it (backward), its uses from it on (forward).</summary>
    Location,
    /// <summary>The argument of the call at the address whose callee-entry location is <see cref="SliceSeed.Location"/> (backward).</summary>
    Argument,
    /// <summary>The incoming parameter at <see cref="SliceSeed.Location"/> of the function starting at the address (forward: its uses).</summary>
    Parameter,
    /// <summary>The value the call at the address returns (backward: one call-result node; forward: its uses after the call).</summary>
    Result,
    /// <summary>The values the function starting at the address returns in <see cref="SliceSeed.Location"/> (backward).</summary>
    Returns,
    /// <summary>The value the instruction at the address stores to memory (backward).</summary>
    Stored,
    /// <summary>The value the instruction at the address loads into its destination register (forward: its uses).</summary>
    Loaded,
}

/// <summary>
/// The start of a per-function slice. Locations are text so that any engine can take them: a register ("rcx", "ecx",
/// "xmm1"), a stack slot relative to the stack pointer at that point ("[rsp+28h]", "[esp+4h]") or a frame slot ("[rbp-8h]").
/// Parameter and argument locations are always as seen at the callee's entry (x64 "[rsp+28h]" is the fifth parameter).
/// </summary>
public sealed record SliceSeed(SliceSeedKind Kind, uint Address, string? Location = null);

/// <summary>A node of a per-function slice.</summary>
public enum SliceNodeKind : byte
{
    // backward values
    Constant,
    /// <summary>An address in the image (<see cref="SliceNode.Rva"/>): a string, a function, data.</summary>
    Address,
    /// <summary>The address of a local of the frame.</summary>
    StackAddress,
    /// <summary>A local whose address is taken: a call it is passed to may write it.</summary>
    TakenLocal,
    /// <summary>An import slot or a late-bound pointer: the function it holds (<see cref="SliceNode.Callee"/>).</summary>
    Import,
    Unknown,
    Merge,
    /// <summary>A value carried around a loop.</summary>
    Loop,
    /// <summary>A load from [base + <see cref="SliceNode.Value"/>]; the base is the node's input.</summary>
    Field,
    // boundaries the interprocedural driver continues across
    /// <summary>The incoming parameter at <see cref="SliceNode.Location"/> (callers bind it).</summary>
    Parameter,
    /// <summary>The return value of the call at <see cref="SliceNode.Site"/> (the callee's return values).</summary>
    CallResult,
    /// <summary>The contents of a writable global at <see cref="SliceNode.Rva"/> (its writers).</summary>
    Global,
    // forward uses
    /// <summary>The start of a forward slice.</summary>
    Origin,
    /// <summary>Passed as an argument (callee-entry <see cref="SliceNode.Location"/>) to the call at <see cref="SliceNode.Site"/>.</summary>
    Argument,
    /// <summary>Stored to the writable global at <see cref="SliceNode.Rva"/> (its readers).</summary>
    Store,
    /// <summary>Stored through a pointer ([reg+n]).</summary>
    FieldStore,
    /// <summary>Returned by the function (callers' uses of the result).</summary>
    Return,
    /// <summary>Compared (cmp / test); <see cref="SliceNode.Value"/> is the immediate compared with.</summary>
    Compare,
    /// <summary>Indexes a switch.</summary>
    Switch,
    /// <summary>Used as a pointer ([reg+n] read).</summary>
    Dereference,
    /// <summary>Called (the call target).</summary>
    CallTarget,
}

/// <param name="Address">The defining (backward) or using (forward) instruction; 0 when none.</param>
public sealed record SliceNode(SliceNodeKind Kind, uint Address, string Text, string Derivation)
{
    public ulong Value { get; init; }
    public uint Rva { get; init; }
    public uint Site { get; init; }
    public string? Location { get; init; }
    /// <summary>Parameter position (0-based) under the calling convention; -1 when the location has none (x86 ecx).</summary>
    public int Index { get; init; } = -1;
    public string? Callee { get; init; }
    public CalleeKind? CallKind { get; init; }
    /// <summary>The callee's start when it is a function of the image.</summary>
    public uint? Target { get; init; }
    /// <summary>Forward: the value was changed by arithmetic before this use.</summary>
    public bool Derived { get; init; }
    public bool Truncated { get; init; }
    /// <summary>Forward dereferences and field stores: the displacement of [base + offset] (no index register).</summary>
    public long? Offset { get; init; }
    /// <summary>Forward "stored to [base + offset]": the base register at the store (its type names the field).</summary>
    public string? Base { get; init; }
}

public enum SliceEdgeKind : byte { Copy, Merge, Loop, Field, Use }

/// <summary>A data-flow edge between slice nodes (indices), from the value's source to its use.</summary>
public readonly record struct SliceEdge(int From, int To, SliceEdgeKind Kind);

/// <summary>The slice of one function from one seed: local nodes and edges, with boundary nodes for the driver.</summary>
public sealed record FunctionSlice(NativeFunction Function, string Engine, int Root, IReadOnlyList<SliceNode> Nodes, IReadOnlyList<SliceEdge> Edges,
    int Steps, bool Truncated, string? Note);

/// <summary>
/// An engine's per-function value facts. Providers answer one function at a time; callers, callees, globals, budgets,
/// caching and paging stay in <see cref="ValueTrace"/>, so the trace behaves the same whichever engine supplies the slices.
/// </summary>
public interface IFunctionSliceProvider
{
    string Engine { get; }
    FunctionSlice Backward(NativeFunction function, SliceSeed seed, CancellationToken ct);
    FunctionSlice Forward(NativeFunction function, SliceSeed seed, CancellationToken ct);
}
