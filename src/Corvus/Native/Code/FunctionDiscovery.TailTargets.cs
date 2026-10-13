using Iced.Intel;

namespace Corvus.Native.Code;

internal sealed partial class FunctionDiscovery
{
    /// <summary>x86 / x64 / ARM64: unconditional jumps of functions without unwind ranges that may leave the function (site, target, function).</summary>
    private readonly List<(uint Site, uint Target, uint Root)> _jumps = [];

    private const int TailTargetLimit = 512;

    /// <summary>
    /// x86 / x64 / ARM64: a jump target outside its function's contiguous code (before its entry, or past another function's start)
    /// that decodes as a function of its own (stack balanced from its first instruction, ends in a return) is a tail-called
    /// function, not a block of the jumping one. Cold blocks a compiler moves out of line use their parent's frame or never
    /// return, so they stay blocks. Evaluated once discovery settles, in the order the jumps were found.
    /// </summary>
    private bool AddTailTargets()
    {
        if (_jumps.Count == 0 || (_x86Peek == null && !IsArm64)) return false;
        var starts = _functions.Keys.ToArray();
        Array.Sort(starts);
        var tried = new HashSet<uint>();
        bool added = false;
        foreach (var (site, target, root) in _jumps)
        {
            if (_functions.ContainsKey(target) || !tried.Add(target)) continue;
            int next = Array.BinarySearch(starts, site + 1);
            if (next < 0) next = ~next;
            bool outside = target < root || (next < starts.Length && starts[next] < target);
            // inside unwind ranges: a part of that function (x64 cold code has chained .pdata entries); with .pdata, separately
            // compiled functions are padded apart while cold blocks are packed together
            if (!outside || _ctx.PdataOwner(target) != null || (_ctx.PdataSorted.Length > 0 && !AfterPadding(target, IsArm64))
                || FallsInto(target) || !DecodesAsOwnFunction(target, starts)) continue;
            Add(target, FunctionSource.TailJump, strong: true);
            added = true;
        }
        _jumps.Clear();
        return added;
    }

    private bool IsArm64 => HybridDecoder.PrimaryOf(_peek) is Arm64Decoder;

    /// <summary>x86: int3 / nop fill before <paramref name="rva"/>; ARM64: a zero, nop or ret word.</summary>
    private bool AfterPadding(uint rva, bool arm64)
    {
        if (_ctx.Code.RegionAt(rva) is not { } region || rva - region.Rva < (arm64 ? 4u : 1u)) return false;
        int at = (int)(rva - region.Rva);
        return arm64 ? BitConverter.ToUInt32(region.Bytes, at - 4) is 0 or 0xD503201F or 0xD65F03C0 : region.Bytes[at - 1] is 0xCC or 0x90;
    }

    /// <summary>A decoded instruction ends at <paramref name="rva"/> and runs on into it: the target is a block of that code (a shared return), not a function.</summary>
    private bool FallsInto(uint rva)
    {
        for (uint k = 1; k <= 15 && k <= rva; k++)
        {
            long bit = _ctx.Code.BitIndex(rva - k);
            if (bit < 0 || !_starts[bit]) continue;
            if (!_peek.Decode(rva - k, out var insn) || insn.Length != k) continue;
            return insn.Flow is FlowKind.Next or FlowKind.ConditionalJump || (insn.Flow is FlowKind.Call or FlowKind.IndirectCall && !(insn.HasTarget && IsNoReturnTarget(insn.Target)));
        }
        return false;
    }

    /// <summary>
    /// The code at <paramref name="start"/>, up to the next known function start, runs on a frame of its own: every path
    /// pops only what it pushed and returns with the stack it was entered with, tail-calls a known function, or ends in a
    /// trap or a call that does not return; at least one path returns.
    /// </summary>
    private bool DecodesAsOwnFunction(uint start, uint[] starts)
    {
        var peek = _peek;
        bool arm64 = IsArm64;
        int at = Array.BinarySearch(starts, start + 1);
        if (at < 0) at = ~at;
        uint end = at < starts.Length ? starts[at] : uint.MaxValue;
        int pointer = peek.Is64 ? 8 : 4;
        Span<byte> word = stackalloc byte[4];
        var work = new Stack<(uint Rva, int Depth, int Frame)>();
        var seen = new HashSet<uint>();
        work.Push((start, 0, -1));
        bool returns = false;
        int count = 0;
        peek.BeginFunction(start);
        while (work.Count > 0)
        {
            var (a, depth, frame) = work.Pop();
            peek.BeginRun(IndexBound.None);
            while (seen.Add(a))
            {
                if (a < start || a >= end || ++count > TailTargetLimit || !peek.Decode(a, out var insn) || insn.Flow == FlowKind.Invalid) return false;
                bool balanced = arm64
                    ? _ctx.Read(a, word) == 4 && Arm64StackStep(BitConverter.ToUInt32(word), ref depth, ref frame)
                    : StackStep(in _x86Peek!.Last, insn.Flow, pointer, ref depth, ref frame);
                if (!balanced) return false;
                bool tail = insn.HasTarget && (_functions.ContainsKey(insn.Target) || ThunkSlot(insn.Target) != null);
                switch (insn.Flow)
                {
                    case FlowKind.Return:
                        if (depth != 0) return false;
                        returns = true;
                        goto next;
                    case FlowKind.Trap:
                        goto next;
                    case FlowKind.Call:
                        if (insn.HasTarget && insn.Target != insn.Next && IsNoReturnTarget(insn.Target)) goto next;
                        break;
                    case FlowKind.IndirectCall:
                        if (insn.HasMem && _ctx.NoReturn.Contains(insn.MemTarget)) goto next;
                        break;
                    case FlowKind.Jump:
                        if (!insn.HasTarget) return false;
                        if (tail) { if (depth != 0) return false; goto next; }
                        work.Push((insn.Target, depth, frame));
                        goto next;
                    case FlowKind.ConditionalJump:
                        if (!insn.HasTarget) return false;
                        if (tail) { if (depth != 0) return false; }
                        else work.Push((insn.Target, depth, frame));
                        break;
                    case FlowKind.IndirectJump:
                        // through an import slot or a register: a tail call, on the entry stack
                        if (depth != 0) return false;
                        goto next;
                }
                a = insn.Next;
            }
            next:;
        }
        return returns;
    }

    /// <summary>
    /// A64: bytes allocated since the entry after instruction <paramref name="w"/> (stp / str pre-index and sub on sp
    /// allocate, ldp / ldr post-index and add free, mov x29, sp and back); false when it frees below the entry or writes sp
    /// otherwise.
    /// </summary>
    private static bool Arm64StackStep(uint w, ref int depth, ref int frame)
    {
        static int Imm7(uint w, int scale) => ((int)(w << 10) >> 25) * scale;
        static int Imm9(uint w) => (int)(w << 11) >> 23;
        int delta;
        if ((w & 0x3E0) != 0x3E0 && (w & 0x1F) != 31) return true; // neither base nor destination is sp
        switch (w & 0xFFC003E0)
        {
            case 0xA98003E0: case 0x6D8003E0: delta = -Imm7(w, 8); break;  // stp x / d, [sp, #-n]!
            case 0xAD8003E0: delta = -Imm7(w, 16); break;                  // stp q
            case 0xA8C003E0: case 0x6CC003E0: delta = -Imm7(w, 8); break;  // ldp x / d, [sp], #n
            case 0xACC003E0: delta = -Imm7(w, 16); break;                  // ldp q
            default:
                if ((w & 0xFFE00FE0) is 0xF8000FE0 or 0xFC000FE0) delta = -Imm9(w);       // str x / d, [sp, #-n]!
                else if ((w & 0xFFE00FE0) is 0xF84007E0 or 0xFC4007E0) delta = -Imm9(w);  // ldr x / d, [sp], #n
                else if ((w & 0x7F8003FF) is 0x510003FF or 0x110003FF)                    // sub / add sp, sp, #n
                {
                    int imm = (int)((w >> 10) & 0xFFF) << ((w & 0x400000) != 0 ? 12 : 0);
                    delta = (w & 0x40000000) != 0 ? imm : -imm;
                }
                else if ((w & 0xFF8003FF) == 0x910003FD) { frame = depth - (int)((w >> 10) & 0xFFF); return true; } // add x29, sp, #n
                else if (w == 0x910003BF) { depth = frame; return frame >= 0; }                                      // mov sp, x29
                // other writes to sp: add / sub (immediate, extended) and logical immediate without flags (with flags register 31 is zr)
                else if ((w & 0x1F) == 31 && (w & 0x20000000) == 0
                    && ((w & 0x1F000000) == 0x11000000 || (w & 0x1FE00000) == 0x0B200000 || (w & 0x1F800000) == 0x12000000)) return false;
                else return true;
                break;
        }
        depth += delta;
        return depth >= 0;
    }

    /// <summary>
    /// Bytes pushed since the entry after <paramref name="x"/>; false when it pops below the entry (the parent's frame) or
    /// moves the stack pointer in a way not followed. <paramref name="frame"/>: the depth "mov rbp, rsp" saved, or -1.
    /// </summary>
    private static bool StackStep(in Instruction x, FlowKind flow, int pointer, ref int depth, ref int frame)
    {
        if (flow is FlowKind.Call or FlowKind.IndirectCall or FlowKind.Return) return true;
        bool sp = x.Op0Kind == Iced.Intel.OpKind.Register && x.Op0Register.GetFullRegister() == Register.RSP;
        if (sp && x.Mnemonic is Mnemonic.Sub or Mnemonic.Add && x.Op1Kind is Iced.Intel.OpKind.Immediate8to32 or Iced.Intel.OpKind.Immediate32 or Iced.Intel.OpKind.Immediate8to64 or Iced.Intel.OpKind.Immediate32to64)
        {
            depth += x.Mnemonic == Mnemonic.Sub ? (int)x.GetImmediate(1) : -(int)x.GetImmediate(1);
            return depth >= 0;
        }
        if (sp && x.Mnemonic == Mnemonic.Mov && x.Op1Kind == Iced.Intel.OpKind.Register && x.Op1Register.GetFullRegister() == Register.RBP)
        {
            depth = frame;
            return frame >= 0;
        }
        if (x.Mnemonic == Mnemonic.Mov && x.Op0Kind == Iced.Intel.OpKind.Register && x.Op0Register.GetFullRegister() == Register.RBP
            && x.Op1Kind == Iced.Intel.OpKind.Register && x.Op1Register.GetFullRegister() == Register.RSP)
        {
            frame = depth;
            return true;
        }
        if (x.Mnemonic == Mnemonic.Leave)
        {
            if (frame < pointer) return false;
            depth = frame - pointer;
            return true;
        }
        if (sp || x.Mnemonic == Mnemonic.Enter) return false;
        depth -= x.StackPointerIncrement;
        return depth >= 0;
    }
}
