using System.Buffers.Binary;
using Corvus.Native.Dwarf;
using Corvus.Native.Elf;

namespace Corvus.Native.Dump;

/// <summary>
/// Walks a core thread's stack: DWARF CFI from each module's .eh_frame (the CFA rule, then each saved register, DWARF
/// expressions evaluated against the frame's registers and the core's memory), else the frame chain (the frame record
/// at the frame pointer on x64, x86 and AArch64, below it on RISC-V, the back chain on PowerPC), else for the top frame
/// the link register. Frames are bounded by <c>maxFrames</c>, the thread's stack mapping and stack pointer progress.
/// </summary>
public sealed class CoreUnwinder(IProcessMemory memory, CoreArch arch, Func<ulong, CoreImage?> imageAt)
{
    private const ulong PacMask = 0x0000_FFFF_FFFF_FFFF;
    /// <summary>The ELF ABI's link register save slot above the back chain word (PowerPC64, ELFv1 and ELFv2).</summary>
    private const ulong PpcLrSave = 16;

    public WalkResult Walk(CoreRegisters start, ulong stackLow, ulong stackHigh, int maxFrames, CancellationToken ct = default)
    {
        maxFrames = Math.Clamp(maxFrames, 1, StackWalker.MaxFramesLimit);
        var frames = new List<WalkFrame> { new(start.Pc, start.Sp, FrameMethod.Context, false, false, start.Complete ? null : "register set is incomplete in the core") };
        var notes = new List<string>();
        if (!arch.Unwinds) return new WalkResult(frames, "unsupported_architecture", [$"unwinding not supported for {arch.Name}: only the context frame is listed"]);
        var regs = start.Clone();
        bool top = true;
        string stop = "max_frames";
        while (frames.Count < maxFrames)
        {
            ct.ThrowIfCancellationRequested();
            var (next, method, note, reason) = Step(regs, top);
            if (next == null)
            {
                stop = reason ?? "no_unwind_data";
                if (note != null) notes.Add(note);
                break;
            }
            if (next.Pc == 0)
            {
                stop = "end_of_stack";
                break;
            }
            if (next.Sp < regs.Sp || (next.Sp == regs.Sp && next.Pc == regs.Pc))
            {
                stop = "stack_pointer_did_not_advance";
                break;
            }
            if (stackHigh > stackLow && (next.Sp < stackLow || next.Sp > stackHigh))
            {
                stop = "left_the_stack";
                notes.Add($"the next frame's stack pointer 0x{next.Sp:X} is outside the thread's stack mapping 0x{stackLow:X}-0x{stackHigh:X}");
                break;
            }
            frames.Add(new WalkFrame(next.Pc, next.Sp, method, method == FrameMethod.Scan, true, note));
            regs = next;
            top = false;
        }
        if (frames.Count >= maxFrames && stop == "max_frames") notes.Add($"stopped after {maxFrames} frames (maxFrames)");
        return new WalkResult(frames, stop, notes);
    }

    private (CoreRegisters? Next, string Method, string? Note, string? Stop) Step(CoreRegisters regs, bool top)
    {
        ulong lookup = top ? regs.Pc : regs.Pc - 1;
        var image = imageAt(lookup);
        string why;
        if (image == null) why = memory.ModuleAt(lookup) is { } m ? $"no image of {m.FileName}" : $"0x{regs.Pc:X} is not in a module";
        else if (image.Row(lookup, out var failure) is { } row)
        {
            var (next, problem) = ApplyCfi(regs, row);
            if (next != null) return (next, FrameMethod.UnwindInfo, null, null);
            if (problem == "end_of_stack") return (null, "", null, "end_of_stack");
            why = problem!;
        }
        else why = failure ?? "no CFI";

        // generated code (an interceptor's trampoline) need not keep a frame record: its caller is found by a scan
        if (image == null && arch.Arch is NativeArch.X64 or NativeArch.X86 && memory.ModuleAt(lookup) == null && memory.RegionAt(regs.Pc) is { IsExecutable: true })
            return Scan(regs) is { } scanned
                ? (scanned, FrameMethod.Scan, $"0x{regs.Pc:X} is not in a module (generated code); scanned the stack for a return address", null)
                : (null, "", $"walk ended at 0x{regs.Pc:X}: generated code, and no return address on the stack above it", "no_unwind_data");
        if (FrameChain(regs) is { } chained) return (chained, FrameMethod.FramePointer, $"no CFI ({why}); followed the {ChainName}", null);
        if (top && arch.Link is int lr && regs.TryGet(lr, out ulong ra) && Strip(ra) is var target && target != 0 && target != regs.Pc && IsCode(target))
        {
            var leaf = regs.Clone();
            leaf.Pc = target;
            return (leaf, FrameMethod.Leaf, $"no CFI ({why}); the return address is the link register", null);
        }
        return (null, "", $"walk ended at 0x{regs.Pc:X}: {why}, and no usable {ChainName}", "no_unwind_data");
    }

    /// <summary>Most stack slots a scan reads.</summary>
    private const int MaxScanSlots = 0x4000;

    /// <summary>
    /// The first stack slot above the stack pointer holding a return address (an address in a module right after a call)
    /// whose call can lead to the generated code and whose own frame unwinds by CFI to another return address; failing
    /// that, the first such return address, then the same ranking without the call check. Other registers stay as they
    /// are (the scanned code is taken to keep the callee-saved ones).
    /// </summary>
    private CoreRegisters? Scan(CoreRegisters regs)
    {
        ulong ptr = (ulong)arch.PointerSize;
        ulong at = (regs.Sp + ptr - 1) & ~(ptr - 1);
        CoreRegisters? first = null, firstUnwinding = null, firstCalling = null;
        for (int slot = 0; slot < MaxScanSlots; slot++, at += ptr)
        {
            if (!ReadWord(at, out ulong value)) break;
            if (!IsReturnAddress(value, out var image)) continue;
            var next = regs.Clone();
            next.Pc = value;
            next.Sp = at + ptr;
            first ??= next;
            // a stale return address left below the live frames rarely unwinds any further
            bool unwinds = image.Row(value - 1, out _) is { } row && ApplyCfi(next, row).Next is { } caller
                && caller.Sp > next.Sp && IsReturnAddress(caller.Pc, out _);
            // registers an interceptor saved on the stack hold stale return addresses too; their direct calls name other code
            if (!CallMayReachGeneratedCode(value))
            {
                if (unwinds) firstUnwinding ??= next;
                continue;
            }
            if (unwinds) return next;
            firstCalling ??= next;
        }
        return firstCalling ?? firstUnwinding ?? first;
    }

    /// <summary>
    /// False when the call before <paramref name="returnAddress"/> is a direct call whose target, followed through an
    /// optional endbr and up to three jumps (a PLT entry, an interceptor's patch), stays in module code: such a call cannot
    /// have entered code outside every module. True for indirect calls and code that cannot be read.
    /// </summary>
    private bool CallMayReachGeneratedCode(ulong returnAddress)
    {
        Span<byte> b = stackalloc byte[16];
        if (ReadCode(returnAddress - 5, b[..5]) < 5 || b[0] != 0xE8) return true;
        ulong target = returnAddress + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(b[1..5]);
        if (!arch.Is64) target &= 0xFFFFFFFF;
        for (int hop = 0; hop <= 3; hop++)
        {
            if (memory.ModuleAt(target) == null) return memory.RegionAt(target) is not { } r || r.IsExecutable;
            if (ReadCode(target, b) < b.Length) return true;
            int i = b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && b[3] is 0xFA or 0xFB ? 4 : 0;
            if (b[i] == 0xF2) i++; // bnd
            if (b[i] == 0xE9) target += (ulong)i + 5 + (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(b[(i + 1)..]);
            else if (b[i] == 0xEB) target += (ulong)i + 2 + (ulong)(long)(sbyte)b[i + 1];
            else if (b[i] == 0xFF && b[i + 1] == 0x25)
            {
                ulong end = target + (ulong)i + 6;
                ulong disp = (ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(b[(i + 2)..]);
                if (!ReadWord(arch.Is64 ? end + disp : disp & 0xFFFFFFFF, out target)) return true;
            }
            else return false;
            if (!arch.Is64) target &= 0xFFFFFFFF;
        }
        return true;
    }

    private bool IsReturnAddress(ulong value, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out CoreImage? image)
    {
        Span<byte> before = stackalloc byte[8];
        image = value < 0x10000 ? null : imageAt(value - 1);
        return image != null && image.Read(value - 8, before) == 8 && StackWalker.FollowsCall(before);
    }

    /// <summary>Code bytes: the core's memory (where an interceptor patched them), else the module image.</summary>
    private int ReadCode(ulong address, Span<byte> destination)
    {
        int n = memory.ReadMemory(address, destination);
        return n == destination.Length ? n : imageAt(address)?.Read(address, destination) ?? n;
    }

    private string ChainName => arch.Arch == NativeArch.PowerPc ? "back chain" : "frame pointer";

    private (CoreRegisters? Next, string? Problem) ApplyCfi(CoreRegisters regs, CfiRow row)
    {
        ulong cfa;
        if (row.CfaExpression is { } cfaExpr)
        {
            if (!Evaluate(regs, cfaExpr, null, out cfa, out var why)) return (null, $"the CFA expression: {why}");
        }
        else if (regs.TryGet(arch.Slot(row.CfaRegister), out ulong cfaBase)) cfa = cfaBase + (ulong)row.CfaOffset;
        else return (null, $"the CFA register {row.CfaRegister} is not known");
        if (!arch.Is64) cfa &= 0xFFFFFFFF;
        if (row.Rules.TryGetValue(row.ReturnColumn, out var raRule) && raRule.Kind == CfiRuleKind.Undefined) return (null, "end_of_stack");
        var next = regs.Clone();
        foreach (var (reg, rule) in row.Rules)
        {
            int slot = arch.Slot(reg);
            if (slot < 0) continue;
            switch (rule.Kind)
            {
                case CfiRuleKind.Offset:
                    if (ReadWord(cfa + (ulong)rule.Operand, out ulong saved)) next.Set(slot, saved);
                    else if (reg == row.ReturnColumn) return (null, $"the return address slot 0x{cfa + (ulong)rule.Operand:X} is not in the core");
                    else next.Forget(slot);
                    break;
                case CfiRuleKind.ValOffset: next.Set(slot, cfa + (ulong)rule.Operand); break;
                case CfiRuleKind.Register:
                    if (regs.TryGet(arch.Slot((int)rule.Operand), out ulong value)) next.Set(slot, value); else next.Forget(slot);
                    break;
                case CfiRuleKind.Expression or CfiRuleKind.ValExpression:
                {
                    ulong result = 0;
                    bool ok = Evaluate(regs, rule.Expression ?? [], cfa, out ulong at, out string? why);
                    if (ok && rule.Kind == CfiRuleKind.ValExpression) result = at;
                    else if (ok && !ReadWord(at, out result)) (ok, why) = (false, $"0x{at:X} is not in the core");
                    if (ok) next.Set(slot, result);
                    else if (reg == row.ReturnColumn) return (null, $"the return address expression: {why}");
                    else next.Forget(slot);
                    break;
                }
                case CfiRuleKind.SameValue: break;
                default: next.Forget(slot); break;
            }
        }
        if (!row.Rules.ContainsKey(arch.Sp)) next.Sp = cfa;
        // without a rule the return column keeps its value: the link register on ARM, AArch64, PowerPC, s390x and RISC-V
        int raSlot = arch.Slot(row.ReturnColumn);
        if (raSlot < 0 || !next.TryGet(raSlot, out ulong ra) || (raSlot == arch.Pc && !row.Rules.ContainsKey(row.ReturnColumn)))
            return (null, "the return address has no rule");
        if (row.RaSigned) ra &= PacMask;
        next.Pc = Strip(ra);
        return (next, null);
    }

    private bool Evaluate(CoreRegisters regs, byte[] expr, ulong? cfa, out ulong value, out string? why) =>
        DwarfExpression.TryEvaluate(expr, arch.PointerSize, arch.BigEndian, (int dwarf, out ulong v) => regs.TryGet(arch.Slot(dwarf), out v), Read, cfa, out value, out why);

    private bool Read(ulong address, int size, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        value = 0;
        if (memory.ReadMemory(address, b[..size]) < size) return false;
        for (int i = 0; i < size; i++) value |= (ulong)b[arch.BigEndian ? size - 1 - i : i] << (8 * i);
        return true;
    }

    private bool ReadWord(ulong address, out ulong value) => Read(address, arch.PointerSize, out value);

    /// <summary>
    /// The caller from the frame chain: the record at the frame pointer (saved frame pointer, then return address) on x64,
    /// x86 and AArch64; the record just below it on RISC-V; PowerPC's back chain at the stack pointer with the link
    /// register saved two words above the caller's back chain. None on ARM and s390x (no chain in the default ABI).
    /// </summary>
    private CoreRegisters? FrameChain(CoreRegisters regs)
    {
        ulong ptr = (ulong)arch.PointerSize;
        var next = regs.Clone();
        switch (arch.Arch)
        {
            case NativeArch.PowerPc:
            {
                ulong sp = regs.Sp;
                if (sp % ptr != 0 || !ReadWord(sp, out ulong caller) || caller <= sp || !SameRegion(caller, sp) || !ReadWord(caller + PpcLrSave, out ulong lr)) return null;
                next.Sp = caller;
                next.Pc = lr;
                if (arch.Link is int link) next.Forget(link);
                return next;
            }
            case NativeArch.RiscV:
            {
                if (!regs.TryGet(arch.Fp, out ulong fp) || fp <= regs.Sp || fp % ptr != 0 || !SameRegion(fp - 1, regs.Sp)) return null;
                if (!ReadWord(fp - ptr, out ulong ra) || !ReadWord(fp - 2 * ptr, out ulong savedFp)) return null;
                next.Set(arch.Fp, savedFp);
                next.Sp = fp;
                next.Pc = ra;
                if (arch.Link is int link) next.Forget(link);
                return next;
            }
            case NativeArch.X64 or NativeArch.X86 or NativeArch.Arm64:
            {
                if (!regs.TryGet(arch.Fp, out ulong fp) || fp < regs.Sp || fp % ptr != 0 || !SameRegion(fp, regs.Sp)) return null;
                if (!ReadWord(fp, out ulong savedFp) || !ReadWord(fp + ptr, out ulong ra)) return null;
                next.Set(arch.Fp, savedFp);
                next.Sp = fp + 2 * ptr;
                next.Pc = Strip(ra);
                if (arch.Link is int link) next.Forget(link);
                return next;
            }
            default: return null;
        }
    }

    private bool SameRegion(ulong address, ulong sp) => memory.RegionAt(address) is { } region && region.Contains(sp);

    private ulong Strip(ulong address) => arch.Arch switch
    {
        NativeArch.Arm => address & ~1UL,
        NativeArch.Arm64 => address & PacMask,
        _ => address,
    };

    private bool IsCode(ulong address) => memory.RegionAt(address) is { IsExecutable: true } || memory.ModuleAt(address) != null;
}
