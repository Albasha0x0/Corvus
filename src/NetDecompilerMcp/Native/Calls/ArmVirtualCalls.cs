using System.Buffers.Binary;
using System.Collections.Concurrent;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Native.Calls;

/// <summary>
/// Virtual call shapes in ARM64 and ARM32 code: an indirect call or tail jump (blr / br, blx / bx) whose target the
/// backward resolver reads as [[object + o] + slot], the object being this (x0 / r0 at entry) or a value the function
/// does not know. The class model (<see cref="VirtualCallResolver.ResolveShapes"/>) picks the implementations.
/// </summary>
internal static class ArmVirtualCalls
{
    private const int ResolverBudget = 600;

    public static List<VirtualShape> Find(NativeCodeIndex index, CancellationToken ct)
    {
        var shapes = new ConcurrentBag<VirtualShape>();
        var po = new ParallelOptions { CancellationToken = ct, MaxDegreeOfParallelism = Environment.ProcessorCount };
        if (index.Image.Arch == NativeArch.Arm64)
        {
            var host = Arm64Trace.For(index);
            Parallel.ForEach(index.Functions.Where(f => (f.Flags & FunctionFlags.Thunk) == 0 && HasArm64IndirectBranch(index, f)), po, f =>
            {
                var code = new A64Function(index, f, ct);
                for (int b = 0; b < code.Blocks.Length; b++)
                    for (int k = 0; k < code.Blocks[b].Length; k++)
                    {
                        var s = code.Blocks[b][k];
                        if (!IsSite(s.Facts.Flow, s.Rva, code.Graph) || A64Function.Gpr(s.I, 0) is not (var reg and >= 0 and < 31)) continue;
                        var v = new Arm64Resolver(host, code) { Budget = ResolverBudget }.Before(A64Loc.Reg(reg), b, k);
                        if (v is { Kind: A64Kind.Field, Inputs: [{ Kind: A64Kind.Field, Inputs: [var obj] } vfptr] })
                            Add(shapes, s.Rva, f, vfptr.Num, v.Num, 8, obj is { Kind: A64Kind.Incoming, Loc: { IsSlot: false, Value: 0 } }, s.Facts.Flow);
                    }
            });
        }
        else if (index.Image.Arch == NativeArch.Arm)
        {
            var host = Arm32Trace.For(index);
            Parallel.ForEach(index.Functions.Where(f => (f.Flags & FunctionFlags.Thunk) == 0), po, f =>
            {
                var code = new A32Function(index, f, ct);
                for (int b = 0; b < code.Blocks.Length; b++)
                    for (int k = 0; k < code.Blocks[b].Length; k++)
                    {
                        var s = code.Blocks[b][k];
                        if (!IsSite(s.Facts.Flow, s.Rva, code.Graph) || s.I.OperandCount == 0
                            || s.I.Op(s.I.OperandCount - 1) is not { Kind: ArmOperandKind.Register } op || op.Reg >= A32Function.Sp) continue;
                        var v = new Arm32Resolver(host, code) { Budget = ResolverBudget }.Before(A32Loc.Reg(op.Reg), b, k);
                        if (v is { Kind: A64Kind.Field, Inputs: [{ Kind: A64Kind.Field, Inputs: [var obj] } vfptr] })
                            Add(shapes, s.Rva, f, vfptr.Num, v.Num, 4, obj is { Kind: A64Kind.Incoming, Loc: { IsSlot: false, Value: 0 } }, s.Facts.Flow);
                    }
            });
        }
        return [.. shapes.OrderBy(s => s.Rva)];
    }

    private static bool IsSite(FlowKind flow, uint rva, FunctionGraph graph) =>
        flow == FlowKind.IndirectCall || flow == FlowKind.IndirectJump && !graph.Switches.Any(t => t.JumpRva == rva);

    private static void Add(ConcurrentBag<VirtualShape> shapes, uint rva, NativeFunction f, ulong vfptr, ulong slot, int ptr, bool self, FlowKind flow)
    {
        long o = (long)vfptr, s = (long)slot;
        if (o is < 0 or > 0xFFFF || s < 0 || s % ptr != 0 || s / ptr > 0xFFFF) return;
        shapes.Add(new VirtualShape(rva, f.Start, (int)o, (int)(s / ptr), self, flow == FlowKind.IndirectJump));
    }

    /// <summary>Any blr / br (register forms, with or without pointer authentication) in the function's bytes: a cheap filter.</summary>
    private static bool HasArm64IndirectBranch(NativeCodeIndex index, NativeFunction f)
    {
        Span<byte> buffer = stackalloc byte[4096];
        foreach (var (start, end) in index.Ranges(f))
            for (uint at = start; at < end; at += 4096)
            {
                int n = index.Image.Read(at, buffer[..(int)Math.Min(4096, end - at)]);
                for (int i = 0; i + 4 <= n; i += 4)
                {
                    uint w = BinaryPrimitives.ReadUInt32LittleEndian(buffer[i..]);
                    // BR / BLR Xn (0xD61F0000 / 0xD63F0000) and the authenticating BRA* / BLRA* forms
                    if ((w & 0xFFDFFC1F) == 0xD61F0000 || (w & 0xFEDFF000) == 0xD61F0800) return true;
                }
            }
        return false;
    }
}
