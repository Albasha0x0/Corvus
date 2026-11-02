using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>
/// A call or computed jump with the values it uses.
/// </summary>
/// <param name="At">Position among the function's instructions.</param>
/// <param name="Before">Position of the last earlier instruction that does not fall through; -1 for none.</param>
/// <param name="Arguments">Origins of the argument registers; null is unknown.</param>
/// <param name="Entry">Origin of the indirect target; null for a direct or unknown target.</param>
/// <param name="Reached">False when no path to the instruction is known.</param>
internal sealed record CallFact(int At, int Before, ulong Ip, FlowControl Flow, ulong Target, Origin?[] Arguments, Origin? Entry, bool Reached);

/// <summary>A conditional jump on a zero test, with the test.</summary>
internal sealed record GuardFact(ulong Branch, uint Target, ZeroTest Test);

/// <summary>A memory update of a page-derived value, with its shift.</summary>
internal sealed record PageUpdate(ulong Shift, ulong Update);

/// <summary>
/// Calls, zero-test jumps and page updates of one x64 function.
/// </summary>
internal sealed class RuntimeFacts
{
    public required IReadOnlyList<CallFact> Calls { get; init; }
    public required IReadOnlyList<GuardFact> Guards { get; init; }
    public required IReadOnlyList<PageUpdate> Updates { get; init; }

    /// <summary>
    /// The facts of <paramref name="fn"/>, or null when the image is not x64
    /// code. Calls, guards and updates are in address order.
    /// </summary>
    internal static RuntimeFacts? Build(NativeCodeIndex index, NativeFunction fn, CancellationToken ct)
    {
        var image = index.Image;
        if (image.Arch != NativeArch.X64) return null;
        bool windows = image.Format == ImageFormat.Pe;
        ulong imageBase = image.ImageBase;
        var code = FunctionInstructions.Decode(image, index.Ranges(fn), ct);
        var positions = new Dictionary<ulong, int>(code.Count);
        for (int i = 0; i < code.Count; i++) positions[code[i].IP] = i;
        var arguments = ValueProvenance.ArgumentRegisters(windows);
        var calls = new List<CallFact>();
        var guards = new List<GuardFact>();
        var updates = new List<PageUpdate>();
        int lastBreak = -1;
        int next = 0;
        ValueProvenance.Walk(code, index.GetGraph(fn, ct), imageBase, windows, (ins, state) =>
        {
            int at = positions[ins.IP];
            // Blocks are visited in address order, so the last break is
            // the nearest one above.
            while (next < at)
            {
                if (code[next].FlowControl != FlowControl.Next) lastBreak = next;
                next++;
            }
            var flow = ins.FlowControl;
            if (flow is FlowControl.Call or FlowControl.IndirectCall or FlowControl.IndirectBranch)
            {
                Origin? entry = null;
                if (flow != FlowControl.Call)
                    entry = ins.Op0Kind == OpKind.Register ? state.Get(ins.Op0Register)
                        : ins.Op0Kind == OpKind.Memory ? state.Memory(ins) : null;
                ulong target = ins.Op0Kind == OpKind.NearBranch64 ? ins.NearBranchTarget : 0;
                calls.Add(new CallFact(at, lastBreak, ins.IP, flow, target, [.. arguments.Select(r => state.Get(r))], entry, state.Reached));
            }
            else if (flow == FlowControl.ConditionalBranch && ins.Op0Kind == OpKind.NearBranch64
                && ins.Mnemonic is Mnemonic.Jne && state.Tested is { } test)
                guards.Add(new GuardFact(ins.IP, (uint)(ins.NearBranchTarget - imageBase), test));
            if (ins.Op0Kind == OpKind.Memory && ins.Op1Kind == OpKind.Register
                && ins.Mnemonic is Mnemonic.Bts or Mnemonic.Cmpxchg
                && state.Get(ins.Op1Register) is PageOrigin page)
                updates.Add(new PageUpdate(page.Ip, ins.IP));
        }, ct);
        return new RuntimeFacts { Calls = calls, Guards = guards, Updates = updates };
    }
}
