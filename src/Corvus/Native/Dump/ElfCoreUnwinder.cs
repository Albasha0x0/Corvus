using Corvus.Native.Elf;

namespace Corvus.Native.Dump;

/// <summary>
/// Walks a core thread's stack: DWARF CFI from each module's .eh_frame (the CFA rule, then each saved register;
/// expressions are not evaluated), else the frame pointer chain (x64, x86, AArch64), else for the top frame of ARM
/// and AArch64 the link register. Frames are bounded by <c>maxFrames</c>, the thread's stack mapping and stack
/// pointer progress.
/// </summary>
public sealed class ElfCoreUnwinder(IProcessMemory memory, ElfCoreArch arch, Func<ulong, ElfCoreImage?> imageAt)
{
    private const ulong PacMask = 0x0000_FFFF_FFFF_FFFF;

    public WalkResult Walk(ElfCoreRegisters start, ulong stackLow, ulong stackHigh, int maxFrames, CancellationToken ct = default)
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
            frames.Add(new WalkFrame(next.Pc, next.Sp, method, false, true, note));
            regs = next;
            top = false;
        }
        if (frames.Count >= maxFrames && stop == "max_frames") notes.Add($"stopped after {maxFrames} frames (maxFrames)");
        return new WalkResult(frames, stop, notes);
    }

    private (ElfCoreRegisters? Next, string Method, string? Note, string? Stop) Step(ElfCoreRegisters regs, bool top)
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

        if (FramePointer(regs) is { } chained) return (chained, FrameMethod.FramePointer, $"no CFI ({why}); followed the frame pointer", null);
        if (top && arch.Link is int lr && regs.TryGet(lr, out ulong ra) && Strip(ra) is var target && target != 0 && target != regs.Pc && IsCode(target))
        {
            var leaf = regs.Clone();
            leaf.Pc = target;
            return (leaf, FrameMethod.Leaf, $"no CFI ({why}); the return address is the link register", null);
        }
        return (null, "", $"walk ended at 0x{regs.Pc:X}: {why}, and no usable frame pointer", "no_unwind_data");
    }

    private (ElfCoreRegisters? Next, string? Problem) ApplyCfi(ElfCoreRegisters regs, CfiRow row)
    {
        if (row.CfaExpression) return (null, "the CFA is a DWARF expression");
        if (row.CfaRegister < 0 || row.CfaRegister >= arch.DwarfCount || !regs.TryGet(row.CfaRegister, out ulong cfaBase))
            return (null, $"the CFA register {row.CfaRegister} is not known");
        ulong cfa = cfaBase + (ulong)row.CfaOffset;
        if (!arch.Is64) cfa &= 0xFFFFFFFF;
        if (row.Rules.TryGetValue(row.ReturnColumn, out var raRule) && raRule.Kind == CfiRuleKind.Undefined) return (null, "end_of_stack");
        var next = regs.Clone();
        foreach (var (reg, rule) in row.Rules)
        {
            if (reg >= arch.DwarfCount) continue;
            switch (rule.Kind)
            {
                case CfiRuleKind.Offset:
                    if (memory.TryReadPointer(cfa + (ulong)rule.Operand, out ulong saved)) next.Set(reg, saved);
                    else if (reg == row.ReturnColumn) return (null, $"the return address slot 0x{cfa + (ulong)rule.Operand:X} is not in the core");
                    else next.Forget(reg);
                    break;
                case CfiRuleKind.ValOffset: next.Set(reg, cfa + (ulong)rule.Operand); break;
                case CfiRuleKind.Register:
                    if (regs.TryGet((int)rule.Operand, out ulong value)) next.Set(reg, value); else next.Forget(reg);
                    break;
                case CfiRuleKind.SameValue: break;
                default: next.Forget(reg); break;
            }
        }
        if (!row.Rules.ContainsKey(arch.Sp)) next.Sp = cfa;
        // without a rule the return column keeps its value: the link register on ARM and AArch64
        if (row.ReturnColumn >= arch.Count || !next.TryGet(row.ReturnColumn, out ulong ra) || (row.ReturnColumn == arch.Pc && !row.Rules.ContainsKey(arch.Pc)))
            return (null, "the return address has no rule");
        if (row.RaSigned) ra &= PacMask;
        next.Pc = Strip(ra);
        return (next, null);
    }

    /// <summary>The frame record at the frame pointer: the caller's frame pointer, then the return address.</summary>
    private ElfCoreRegisters? FramePointer(ElfCoreRegisters regs)
    {
        if (arch.Arch == NativeArch.Arm || !regs.TryGet(arch.Fp, out ulong fp)) return null;
        ulong ptr = (ulong)arch.PointerSize;
        if (fp < regs.Sp || fp % ptr != 0 || memory.RegionAt(fp) is not { } region || !region.Contains(regs.Sp)) return null;
        if (!memory.TryReadPointer(fp, out ulong savedFp) || !memory.TryReadPointer(fp + ptr, out ulong ra)) return null;
        var next = regs.Clone();
        next.Set(arch.Fp, savedFp);
        next.Sp = fp + 2 * ptr;
        next.Pc = Strip(ra);
        if (arch.Link is int lr) next.Forget(lr);
        return next;
    }

    private ulong Strip(ulong address) => arch.Arch switch
    {
        NativeArch.Arm => address & ~1UL,
        NativeArch.Arm64 => address & PacMask,
        _ => address,
    };

    private bool IsCode(ulong address) => memory.RegionAt(address) is { IsExecutable: true } || memory.ModuleAt(address) != null;
}
