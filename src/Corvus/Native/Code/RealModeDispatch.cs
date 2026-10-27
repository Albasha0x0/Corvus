using System.Buffers.Binary;
using Iced.Intel;

namespace Corvus.Native.Code;

/// <summary>Finds handlers behind <c>call/jmp word [reg+table]</c> dispatch in 16-bit DOS code; seeds for Ghidra, which resolves none; offsets are into the .COM file or the MZ load module.</summary>
public static class RealModeDispatch
{
    public const int MaxHandlers = 16_384;
    private const int MaxTable = 4096, MaxSteps = 1_000_000;

    /// <summary>The code of an x86-16 file: a near pointer p is at image offset <see cref="Segment"/> + p.</summary>
    public readonly record struct CodeImage(ReadOnlyMemory<byte> Code, long Segment, long Entry);

    /// <summary>The code of an x86-16 raw file or an MZ executable's load module; null for other layouts.</summary>
    public static CodeImage? Of(ReadOnlyMemory<byte> file, RawLayout layout)
    {
        if (layout.Isa.Name == "dos-mz")
        {
            var s = file.Span;
            if (s.Length < 0x1C || s[0] != 'M' || s[1] != 'Z') return null;
            int header = BinaryPrimitives.ReadUInt16LittleEndian(s[8..]) * 16;
            if (header >= s.Length) return null;
            long cs = BinaryPrimitives.ReadUInt16LittleEndian(s[0x16..]) * 16L, ip = BinaryPrimitives.ReadUInt16LittleEndian(s[0x14..]);
            return new CodeImage(file[header..], cs, cs + ip);
        }
        if (layout.Isa.Name != "x86-16") return null;
        return new CodeImage(file, -(long)layout.Base, layout.EntryOffset);
    }

    /// <summary>Image offsets of the handlers found through dispatch tables, ascending; at most <see cref="MaxHandlers"/>.</summary>
    public static IReadOnlyList<uint> Handlers(CodeImage image)
    {
        var code = image.Code.Span;
        var reader = new ByteArrayCodeReader(image.Code.ToArray());
        var decoder = Decoder.Create(16, reader);
        var visited = new HashSet<long>();
        var work = new Stack<long>();
        var handlers = new SortedSet<uint>();
        var tables = new List<(long Start, long End)>();
        work.Push(image.Entry);
        int steps = 0;
        while (work.Count > 0 && steps < MaxSteps && handlers.Count < MaxHandlers)
        {
            long at = work.Pop();
            while (at >= 0 && at < code.Length && visited.Add(at) && ++steps < MaxSteps)
            {
                reader.Position = (int)at;
                decoder.IP = (ulong)(at - image.Segment);
                var insn = decoder.Decode();
                if (insn.IsInvalid) break;
                long next = at + insn.Length;
                switch (insn.FlowControl)
                {
                    case FlowControl.Call:
                    case FlowControl.ConditionalBranch:
                        work.Push(image.Segment + (long)insn.NearBranchTarget);
                        break;
                    case FlowControl.UnconditionalBranch:
                        if (insn.Op0Kind is OpKind.NearBranch16) work.Push(image.Segment + (long)insn.NearBranchTarget);
                        next = -1;
                        break;
                    case FlowControl.IndirectCall:
                    case FlowControl.IndirectBranch:
                        if (insn.Op0Kind == OpKind.Memory && insn.MemorySize == MemorySize.WordOffset && insn.MemoryBase != Register.None)
                            foreach (var t in Table(code, image.Segment, image.Segment + (ushort)insn.MemoryDisplacement32, tables, decoder, reader))
                            {
                                if (handlers.Add((uint)t)) work.Push(t);
                            }
                        if (insn.FlowControl == FlowControl.IndirectBranch) next = -1;
                        break;
                    case FlowControl.Return:
                    case FlowControl.Exception:
                        next = -1;
                        break;
                }
                at = next;
            }
        }
        return [.. handlers.Take(MaxHandlers)];
    }

    /// <summary>The entries of the near-pointer table at <paramref name="start"/> up to the first that does not point at code.</summary>
    private static List<long> Table(ReadOnlySpan<byte> code, long segment, long start, List<(long Start, long End)> tables, Decoder decoder, ByteArrayCodeReader reader)
    {
        var targets = new List<long>();
        if (start < 0 || tables.Any(t => start >= t.Start && start < t.End)) return targets;
        long end = start;
        while (end + 2 <= code.Length && targets.Count < MaxTable)
        {
            long t = segment + BinaryPrimitives.ReadUInt16LittleEndian(code[(int)end..]);
            // A target inside the table ends it.
            if (t >= start && t < end + 2 || !LooksLikeCode(code, t, decoder, reader)) break;
            targets.Add(t);
            end += 2;
        }
        if (targets.Count < 2) return [];
        tables.Add((start, end));
        return targets;
    }

    /// <summary>Up to 8 instructions from <paramref name="at"/> decode inside the image, up to the first ret or jump.</summary>
    private static bool LooksLikeCode(ReadOnlySpan<byte> code, long at, Decoder decoder, ByteArrayCodeReader reader)
    {
        if (at < 0 || at >= code.Length) return false;
        reader.Position = (int)at;
        for (int i = 0; i < 8; i++)
        {
            var insn = decoder.Decode();
            if (insn.IsInvalid || reader.Position > code.Length) return false;
            // Two zero bytes (add [bx+si], al) open most padding and data.
            if (insn.Code == Iced.Intel.Code.Add_rm8_r8 && insn.Op0Kind == OpKind.Memory && insn.Op1Register == Register.AL && insn.MemoryBase == Register.BX && insn.MemoryIndex == Register.SI) return false;
            if (insn.FlowControl is FlowControl.Return or FlowControl.UnconditionalBranch or FlowControl.IndirectBranch) return true;
            if (!reader.CanReadByte) return false;
        }
        return true;
    }
}
