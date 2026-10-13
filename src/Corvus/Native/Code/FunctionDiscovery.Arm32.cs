using System.Buffers.Binary;

namespace Corvus.Native.Code;

/// <summary>
/// 32-bit ARM discovery without unwind tables: literal pools that known code loads end linear flow and are never function
/// starts, no start lies inside an IT block, and code right after a known function (past its padding and literal pool)
/// is tried as a function in that function's state.
/// </summary>
internal sealed partial class FunctionDiscovery
{
    // halfword addresses of literal pool entries explored code loads
    private readonly HashSet<uint> _literals = [];
    // A32 instruction starts explored code decoded
    private CodeBitmap? _armInsns;

    /// <summary>Records what the instruction <paramref name="dec"/> just decoded tells about the code: its state, the literal it loads.</summary>
    private void NoteArm32(ICodeDecoder dec, in Insn insn, long bit)
    {
        if (HybridDecoder.PrimaryOf(dec) is not Arm32Decoder arm) return;
        if (!arm.Thumb) (_armInsns ??= new CodeBitmap(_ctx.Code.TotalBytes))[bit] = true;
        if (insn.HasMem && arm.LastLiteralSize is > 0 and var size)
            for (uint a = insn.MemTarget & ~1u; a < insn.MemTarget + (uint)size; a += 2) _literals.Add(a);
    }

    /// <summary>A word-aligned start right after decoded code whose bytes read in both states takes that code's state.</summary>
    private void HintFromNeighbor(uint rva)
    {
        if (_armInsns == null || (rva & 3) != 0 || _ctx.Code.RegionAt(rva) is not { } region || rva - region.Rva < 4) return;
        long bit = region.BitBase + (rva - region.Rva);
        if (_starts[bit - 4] && _armInsns[bit - 4]) _ctx.ArmModes!.HintNeighbor(rva, false);
        else if (_starts[bit - 2] || _starts[bit - 4]) _ctx.ArmModes!.HintNeighbor(rva, true);
    }

    /// <summary>Bytes [<paramref name="rva"/>, + <paramref name="length"/>) overlap a known literal pool entry.</summary>
    private bool IsLiteral(uint rva, int length)
    {
        if (_literals.Count == 0) return false;
        for (uint a = rva & ~1u; a < rva + (uint)length; a += 2)
            if (_literals.Contains(a)) return true;
        return false;
    }

    /// <summary>Thumb: an IT instruction in the four halfwords before <paramref name="rva"/> makes it conditional, so no function starts there.</summary>
    private bool InsideItBlock(uint rva)
    {
        if (_ctx.ArmModes is not { } modes || (rva & 1) != 0 || !modes.StartMode(rva)) return false;
        Span<byte> b = stackalloc byte[10];
        if (rva < 10 || _ctx.Image.Read(rva - 10, b) < 10) return false;
        for (int back = 2; back <= 10; back += 2)
        {
            ushort h = BinaryPrimitives.ReadUInt16LittleEndian(b[(10 - back)..]);
            if ((h & 0xFF00) != 0xBF00 || (h & 15) == 0 || ((h >> 4) & 15) == 15) continue;
            // decoded code tells whether it is an instruction; else the halfword before must not start a 32-bit one (b.w ends in BFxx)
            uint it = rva - (uint)back;
            long bit = _ctx.Code.BitIndex(it);
            if (bit >= 0 && _covered[bit] ? !_starts[bit] : back < 10 && Arm32Decode.ThumbLength(BinaryPrimitives.ReadUInt16LittleEndian(b[(8 - back)..])) == 4
                || IsLiteral(it, 2) || _dataInCode.Contains(it & ~3u)) continue;
            // the instructions the IT covers, from the halfword after it
            int left = Arm32Decode.ItCount(h & 15), at = 10 - back + 2;
            while (left > 0 && at < 10)
            {
                at += Arm32Decode.ThumbLength(BinaryPrimitives.ReadUInt16LittleEndian(b[at..]));
                left--;
            }
            if (at == 10 && left > 0 || at > 10) return true;
        }
        return false;
    }

    /// <summary>
    /// ARM32: tries a function right after the known code ending at <paramref name="end"/> (a covered run's end), past
    /// alignment padding and the literal pool known code loads, in the state of the code before it. Not after an unresolved
    /// computed jump, whose targets likely follow it.
    /// </summary>
    private void TryAfterCode(ImageCode.Region region, int end)
    {
        long word = region.BitBase + end - 4, half = region.BitBase + end - 2;
        long last = _starts[word] && _armInsns?[word] == true ? word : _starts[half] ? half : _starts[word] ? word : -1;
        if (last < 0) return;
        uint lastRva = region.Rva + (uint)(last - region.BitBase);
        // the function before has a computed jump not resolved: what follows is likely its code
        uint from = _sortedStarts?.GetViewBetween(0, lastRva).Max ?? lastRva;
        if (_pendingSwitches.GetViewBetween(from, lastRva).Count > 0) return;
        // nor after a function whose state is a guess: the state of what follows would be one too
        if (_ctx.ArmModes!.IsUnsure(from)) return;
        bool arm = _armInsns?[last] == true;
        int p = (end + 1) & ~1;
        // unreachable calls to functions that do not return and traps the compiler leaves after such a call are skipped
        for (int n = 0; n < 4; n++)
        {
            p = AfterCode(region, p);
            if (p < 0 || arm && (p & 3) != 0) return;
            uint rva = region.Rva + (uint)p;
            if (_ctx.InsideDeclared(rva) || InDataInCode(rva)) return;
            if (HybridDecoder.PrimaryOf(_peek) is not Arm32Decoder peek) return;
            // the neighbour's state only where the bytes read in both
            _ctx.ArmModes!.HintNeighbor(rva, !arm);
            peek.BeginRun(IndexBound.None);
            peek.Pin(_ctx.ArmModes.StartMode(rva));
            if (!peek.Decode(rva, out var first) || first.Flow == FlowKind.Invalid) return;
            if (first.Flow == FlowKind.Trap || first.Flow == FlowKind.Call && first.HasTarget && IsNoReturnTarget(first.Target))
            {
                p += first.Length;
                continue;
            }
            // a jump to code that is no function is a case of a jump table not resolved; one to a function or stub is a tail call
            if (first.Flow == FlowKind.Jump && !(first.HasTarget && (_functions.ContainsKey(first.Target) || ThunkSlot(first.Target) != null || peek.IsStateSwitchStub(first.Target)))) return;
            if (TryCandidate(rva, FunctionSource.CodeGap)) Drain();
            return;
        }
    }

    /// <summary>The first offset from <paramref name="p"/> past alignment padding, barriers and known literals, or -1 when known code comes first.</summary>
    private int AfterCode(ImageCode.Region region, int p)
    {
        var bytes = region.Bytes;
        while (p + 2 <= bytes.Length)
        {
            if (_covered[region.BitBase + p]) return -1;
            ushort h = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(p));
            uint rva = region.Rva + (uint)p;
            // nop, mov r8, r8 and zero fill (no function starts with movs r0, r0)
            if (h is 0xBF00 or 0x46C0 or 0 || IsLiteral(rva, 2))
            {
                p += 2;
                continue;
            }
            // a word known code reads
            if (_dataInCode.Contains(rva))
            {
                p += 4;
                continue;
            }
            // Thumb dsb sy / isb sy (the straight-line-speculation barrier after a return); A32 nop, dsb sy, isb sy
            if (p + 4 <= bytes.Length && BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(p)) is var w
                && (w is 0x8F4FF3BF or 0x8F6FF3BF || (p & 3) == 0 && w is 0xE1A00000 or 0xE320F000 or 0xF57FF04F or 0xF57FF06F))
            {
                p += 4;
                continue;
            }
            return p;
        }
        return -1;
    }
}
