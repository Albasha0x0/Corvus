using AsmArm64;

namespace Corvus.Native.Code;

/// <summary>One ARM64 instruction as <see cref="InspectedInstruction"/>, decoded from its block start so references resolve as in the code index.</summary>
internal static class Arm64Inspector
{
    private const int MaxRun = 256;
    private const int MaxPairDistance = 16;
    private static readonly string[] Nzcv = ["n", "z", "c", "v"];

    private sealed record Step(uint Rva, Arm64Instruction Instruction, Insn Facts);

    public static InspectedInstruction? Inspect(NativeCodeIndex index, uint rva, NativeDisassembler? disassembler, uint? runStart)
    {
        var image = index.Image;
        var dis = disassembler ?? index.CreateDisassembler();
        uint start = runStart is { } s && s <= rva && rva - s <= MaxRun * 4 && (rva - s) % 4 == 0 ? s : rva;
        var lines = dis.Disassemble(start, (int)((rva - start) / 4) + 1, rva + 4);
        var line = lines.Count > 0 && lines[^1].Rva == rva ? lines[^1] : dis.DecodeOne(rva);
        if (line == null) return null;
        if (index.NewDecoder() is not Arm64Decoder dec || line.Facts.Flow == FlowKind.Invalid)
            return new InspectedInstruction(rva, line.Facts.Length, line.Bytes, line.Text, null, "(bad)", []) { Flow = "invalid" };

        var run = Run(dec, start, rva);
        if (run.Count == 0 || run[^1].Rva != rva || run[^1].Facts.Flow == FlowKind.Invalid)
            return new InspectedInstruction(rva, line.Facts.Length, line.Bytes, line.Text, null, "(bad)", []) { Flow = "invalid" };
        var step = run[^1];
        var i = step.Instruction;
        var facts = step.Facts;

        // The adrp this instruction completes, or the instruction completing this adrp.
        uint? pair = null, formed = null;
        if (i.Id == Arm64InstructionId.ADRP_only_pcreladdr)
        {
            if (Completion(dec, run, rva) is { } c) (pair, formed) = (c.Rva, c.Facts.HasMem ? c.Facts.MemTarget : c.Facts.HasImm ? c.Facts.ImmTarget : null);
        }
        else if (facts.HasMem || facts.HasImm)
        {
            formed = facts.HasMem ? facts.MemTarget : facts.ImmTarget;
            if (BaseRegister(in i) is { } b && Writer(run, run.Count - 1, b) is { } w && w.Instruction.Id == Arm64InstructionId.ADRP_only_pcreladdr) pair = w.Rva;
        }
        string? comment = line.Comment;
        if (comment == null && formed is { } f) comment = index.NameAt(f) ?? NativeAddress.Va(image, f);

        var operands = new List<InspectedOperand>(i.OperandCount);
        var read = new List<string>();
        var written = new List<string>();
        var memory = new List<MemoryUse>();
        int? spDelta = null;
        bool branch = Arm64Extensions.IsBranch(i.Id);
        var access = MemoryAccess(in i);
        int size = AccessSize(in i);
        ulong pc = image.ImageBase + rva;
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.GetOperand(k);
            string text = OperandText(in i, op, image, index, pc);
            switch (op.Kind)
            {
                case Arm64OperandKind.Register:
                {
                    var r = ((Arm64RegisterOperand)op).Value;
                    var opAccess = branch ? "read" : Access(op.Flags);
                    Use(r, opAccess, read, written);
                    operands.Add(new InspectedOperand(k, "register", text)
                    {
                        Access = opAccess, Size = RegisterSize(r), Register = Name(r), FullRegister = FullName(r),
                    });
                    break;
                }
                case Arm64OperandKind.RegisterGroup:
                {
                    var g = ((Arm64RegisterGroupOperand)op).Value;
                    var list = Group(g);
                    foreach (var r in list) Use(r, access == "read" ? "write" : "read", read, written);
                    operands.Add(new InspectedOperand(k, "register_list", text)
                    {
                        Access = access == "read" ? "write" : "read", Size = list.Sum(RegisterSize),
                    });
                    break;
                }
                case Arm64OperandKind.Memory:
                {
                    var a = ((Arm64MemoryOperand)op).Accessor;
                    bool post = a.OffsetKind == Arm64MemoryOffsetKind.None && k + 1 < i.OperandCount && i.GetOperand(k + 1).Kind == Arm64OperandKind.Immediate;
                    string? writeback = a.IsPreIncrement ? "pre" : post ? "post" : null;
                    var baseReg = a.BaseRegister;
                    Use(baseReg, writeback != null ? "read_write" : "read", read, written);
                    if (a.HasIndexRegister) Use(a.IndexRegister, "read", read, written);
                    long disp = a.HasImmediate && !post ? a.Immediate : 0;
                    int amount = a.HasExtend ? a.Extend.Amount : 0;
                    string? extend = a.HasExtend ? ExtendText(a.Extend) : null;
                    uint? target = facts.HasMem ? facts.MemTarget : null;
                    if (writeback != null && baseReg.Kind == Arm64RegisterKind.SP)
                        spDelta = post ? (int)((Arm64ImmediateOperand)i.GetOperand(k + 1)).Value : a.Immediate;
                    operands.Add(new InspectedOperand(k, "memory", text)
                    {
                        Access = access, Size = size > 0 ? size : null, Base = Name(baseReg),
                        IndexRegister = a.HasIndexRegister ? Name(a.IndexRegister) : null,
                        Scale = a.HasIndexRegister ? 1 << amount : null, Displacement = disp, Extend = extend, Writeback = writeback,
                        Value = target is { } tv ? image.ImageBase + tv : null, Target = target,
                    });
                    if (access != "none")
                        memory.Add(new MemoryUse(null, Name(baseReg), a.HasIndexRegister ? Name(a.IndexRegister) : null, a.HasIndexRegister ? 1 << amount : 1, disp, size, access));
                    break;
                }
                case Arm64OperandKind.Label:
                {
                    long off = ((Arm64LabelOperand)op).Offset;
                    ulong va = (i.Id == Arm64InstructionId.ADRP_only_pcreladdr ? pc & ~0xFFFUL : pc) + (ulong)off;
                    uint? target = va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage ? (uint)(va - image.ImageBase) : null;
                    bool literal = !branch && i.Id != Arm64InstructionId.ADRP_only_pcreladdr && i.Id != Arm64InstructionId.ADR_only_pcreladdr;
                    operands.Add(new InspectedOperand(k, branch ? "near_branch" : "pc_relative", text)
                    {
                        Access = literal ? access : "read", Size = literal && size > 0 ? size : null, Value = va, SignedValue = off, Displacement = off,
                        RipRelative = true, Target = target,
                    });
                    if (literal && access != "none") memory.Add(new MemoryUse(null, "pc", null, 1, off, size, access));
                    break;
                }
                case Arm64OperandKind.Immediate:
                {
                    var im = (Arm64ImmediateOperand)op;
                    operands.Add(im.IsFloat
                        ? new InspectedOperand(k, "immediate", text) { Access = "read" }
                        : new InspectedOperand(k, "immediate", text) { Access = "read", Value = (ulong)im.Value, SignedValue = im.Value });
                    break;
                }
                case Arm64OperandKind.Shift:
                {
                    var sh = (Arm64ShiftOperand)op;
                    if (sh.IsDefault && sh.Amount == 0) continue;
                    operands.Add(new InspectedOperand(k, "shift", text) { Access = "read", Value = sh.Amount, Extend = Arm64Extensions.ToText(sh.ShiftKind, false) });
                    break;
                }
                case Arm64OperandKind.Extend:
                {
                    var ex = (Arm64ExtendOperand)op;
                    operands.Add(new InspectedOperand(k, "extend", text) { Access = "read", Value = ex.Amount, Extend = Arm64Extensions.ToText(ex.ExtendKind, false) });
                    break;
                }
                case Arm64OperandKind.Enum:
                {
                    var e = (Arm64EnumOperand)op;
                    bool condition = e.EnumKind is Arm64EnumKind.Conditional or Arm64EnumKind.InvertedConditional;
                    operands.Add(new InspectedOperand(k, condition ? "condition" : "enum", text) { Access = "read", Value = (ulong)e.Value });
                    break;
                }
                case Arm64OperandKind.SystemRegister:
                    operands.Add(new InspectedOperand(k, "system_register", text) { Access = Access(op.Flags), Register = text.ToLowerInvariant() });
                    break;
            }
        }
        if (i.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR or Arm64Mnemonic.BLRAA or Arm64Mnemonic.BLRAAZ or Arm64Mnemonic.BLRAB or Arm64Mnemonic.BLRABZ)
            Add(written, "x30");
        if (spDelta == null && StackAdjust(in i) is { } adjust) spDelta = adjust;

        var flow = facts.Flow;
        bool continues = flow is not (FlowKind.Jump or FlowKind.IndirectJump or FlowKind.Return or FlowKind.Trap or FlowKind.Invalid);
        var feature = i.FeatureExpressionId;
        return new InspectedInstruction(rva, 4, line.Bytes, line.Text, comment, Mnemonic(line.Text), operands)
        {
            Encoding = "a64",
            Prefixes = [],
            Cpuid = feature == Arm64FeatureExpressionId.None ? [] : [feature.ToString().ToLowerInvariant()],
            Privileged = i.Mnemonic is Arm64Mnemonic.HVC or Arm64Mnemonic.SMC or Arm64Mnemonic.ERET or Arm64Mnemonic.ERETAA or Arm64Mnemonic.ERETAB
                         or Arm64Mnemonic.DCPS1 or Arm64Mnemonic.DCPS2 or Arm64Mnemonic.DCPS3 or Arm64Mnemonic.DRPS,
            RegistersRead = read,
            RegistersWritten = written,
            MemoryAccesses = memory,
            FlagsRead = ReadsFlags(in i) ? Nzcv : [],
            FlagsWritten = WritesFlags(in i) ? Nzcv : [],
            FlagsUndefined = [],
            StackPointerDelta = spDelta ?? 0,
            Flow = InstructionInspector.FlowName(flow),
            Condition = Condition(in i),
            BranchTarget = facts.HasTarget ? facts.Target : null,
            Fallthrough = continues ? rva + 4 : null,
            PairRva = pair,
            FormedAddress = formed,
        };
    }

    /// <summary>Decodes [start, rva] in one run (stops at an invalid word).</summary>
    private static List<Step> Run(Arm64Decoder dec, uint start, uint rva)
    {
        var steps = new List<Step>();
        dec.BeginFunction();
        dec.BeginRun(IndexBound.None);
        for (uint a = start; a <= rva; a += 4)
        {
            if (!dec.DecodeMapped(a, out var insn)) break;
            steps.Add(new Step(a, dec.Last, insn));
            if (insn.Flow == FlowKind.Invalid && a != rva) { steps.Clear(); dec.BeginRun(IndexBound.None); }
        }
        return steps;
    }

    /// <summary>The instruction after an adrp that uses its register as an address base (add, load, store) before it changes.</summary>
    private static Step? Completion(Arm64Decoder dec, List<Step> run, uint rva)
    {
        var adrp = run[^1].Instruction;
        int reg = adrp.GetOperand(0) is { Kind: Arm64OperandKind.Register } d ? ((Arm64RegisterOperand)d).Value.Index : -1;
        for (uint a = rva + 4; a <= rva + MaxPairDistance * 4; a += 4)
        {
            if (!dec.DecodeMapped(a, out var insn) || insn.Flow != FlowKind.Next) return null;
            var x = dec.Last;
            if (BaseRegister(in x) == reg && (insn.HasMem || insn.HasImm)) return new Step(a, x, insn);
            if (Writes(in x, reg)) return null;
        }
        return null;
    }

    /// <summary>The X register an instruction forms an address from: an add's source, or a memory operand's base.</summary>
    private static int? BaseRegister(in Arm64Instruction i)
    {
        if (i.Id == Arm64InstructionId.ADD_64_addsub_imm && i.OperandCount > 1 && i.GetOperand(1) is { Kind: Arm64OperandKind.Register } src)
            return ((Arm64RegisterOperand)src).Value.Index;
        for (int k = 0; k < i.OperandCount; k++)
            if (i.GetOperand(k) is { Kind: Arm64OperandKind.Memory } m && ((Arm64MemoryOperand)m).Accessor.BaseRegister.Kind == Arm64RegisterKind.X)
                return ((Arm64MemoryOperand)m).Accessor.BaseRegister.Index;
        return null;
    }

    private static Step? Writer(List<Step> run, int before, int reg)
    {
        for (int k = before - 1; k >= 0; k--)
            if (Writes(run[k].Instruction, reg)) return run[k];
        return null;
    }

    private static bool Writes(in Arm64Instruction i, int reg)
    {
        if (Arm64Extensions.IsBranch(i.Id)) return i.Mnemonic is Arm64Mnemonic.BL or Arm64Mnemonic.BLR && reg is <= 18 or 30;
        for (int k = 0; k < i.OperandCount; k++)
            if (i.GetOperand(k) is { Kind: Arm64OperandKind.Register } op && (op.Flags & Arm64OperandFlags.Write) != 0
                && ((Arm64RegisterOperand)op).Value is { Kind: Arm64RegisterKind.X or Arm64RegisterKind.W } r && r.Index == reg)
                return true;
        return false;
    }

    private static string Access(Arm64OperandFlags flags) => (flags & Arm64OperandFlags.ReadWrite) switch
    {
        Arm64OperandFlags.ReadWrite => "read_write",
        Arm64OperandFlags.Write => "write",
        Arm64OperandFlags.Read => "read",
        _ => "none",
    };

    private static void Use(Arm64RegisterAny r, string access, List<string> read, List<string> written)
    {
        if (r.Kind == Arm64RegisterKind.Invalid) return;
        var name = FullName(r);
        if (access is "read" or "read_write") Add(read, name);
        if (access is "write" or "read_write") Add(written, name);
    }

    private static void Add(List<string> list, string name)
    {
        if (name is not ("xzr" or "wzr") && !list.Contains(name)) list.Add(name);
    }

    /// <summary>Load, store or atomic read-modify-write: how the instruction's memory operand is accessed.</summary>
    internal static string MemoryAccess(in Arm64Instruction i)
    {
        var m = i.Mnemonic.ToString();
        if (m.StartsWith("PRF", StringComparison.Ordinal)) return "none";
        if (m.StartsWith("SWP", StringComparison.Ordinal) || m.StartsWith("CAS", StringComparison.Ordinal)
            || m.StartsWith("LDADD", StringComparison.Ordinal) || m.StartsWith("LDCLR", StringComparison.Ordinal) || m.StartsWith("LDEOR", StringComparison.Ordinal)
            || m.StartsWith("LDSET", StringComparison.Ordinal) || m.StartsWith("LDSMAX", StringComparison.Ordinal) || m.StartsWith("LDSMIN", StringComparison.Ordinal)
            || m.StartsWith("LDUMAX", StringComparison.Ordinal) || m.StartsWith("LDUMIN", StringComparison.Ordinal)
            || m.StartsWith("STADD", StringComparison.Ordinal) || m.StartsWith("STCLR", StringComparison.Ordinal) || m.StartsWith("STEOR", StringComparison.Ordinal)
            || m.StartsWith("STSET", StringComparison.Ordinal) || m.StartsWith("STSMAX", StringComparison.Ordinal) || m.StartsWith("STSMIN", StringComparison.Ordinal)
            || m.StartsWith("STUMAX", StringComparison.Ordinal) || m.StartsWith("STUMIN", StringComparison.Ordinal))
            return "read_write";
        if (m.StartsWith("LD", StringComparison.Ordinal)) return "read";
        if (m.StartsWith("ST", StringComparison.Ordinal)) return "write";
        return "read";
    }

    /// <summary>Bytes the memory operand accesses: the transfer width, twice for pairs.</summary>
    internal static int AccessSize(in Arm64Instruction i)
    {
        var m = i.Mnemonic.ToString();
        int fromReg = 0, regs = 0;
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.GetOperand(k);
            if (op.Kind == Arm64OperandKind.Memory) break;
            if (op.Kind == Arm64OperandKind.RegisterGroup) return Group(((Arm64RegisterGroupOperand)op).Value).Sum(RegisterSize);
            if (op.Kind == Arm64OperandKind.Register) { fromReg = RegisterSize(((Arm64RegisterOperand)op).Value); regs++; }
        }
        bool pair = m.Contains('P', StringComparison.Ordinal) && (m.StartsWith("LDP", StringComparison.Ordinal) || m.StartsWith("STP", StringComparison.Ordinal)
                                                                 || m.StartsWith("LDNP", StringComparison.Ordinal) || m.StartsWith("STNP", StringComparison.Ordinal)
                                                                 || m.StartsWith("LDXP", StringComparison.Ordinal) || m.StartsWith("LDAXP", StringComparison.Ordinal)
                                                                 || m.StartsWith("STXP", StringComparison.Ordinal) || m.StartsWith("STLXP", StringComparison.Ordinal));
        if (m.EndsWith("SW", StringComparison.Ordinal)) return pair ? 8 : 4;
        if (m.EndsWith('B') && !m.StartsWith("LDADD", StringComparison.Ordinal) && m != "SB") return 1;
        if (m.EndsWith('H')) return 2;
        if (m.EndsWith("SB", StringComparison.Ordinal)) return 1;
        if (m.EndsWith("SH", StringComparison.Ordinal)) return 2;
        if (regs == 0) return 0;
        return pair ? fromReg * 2 : fromReg;
    }

    private static List<Arm64RegisterAny> Group(Arm64RegisterGroupAny g)
    {
        var list = new List<Arm64RegisterAny>();
        var r = g.BaseRegister;
        for (int n = 0; n < g.Count; n++, r = r.Next()) list.Add(r);
        return list;
    }

    private static int RegisterSize(Arm64RegisterAny r) => r.Kind switch
    {
        Arm64RegisterKind.X or Arm64RegisterKind.SP => 8,
        Arm64RegisterKind.W or Arm64RegisterKind.WSP => 4,
        Arm64RegisterKind.VPacked => r.ElementCount * ElementSize(r.VKind),
        Arm64RegisterKind.VScalar or Arm64RegisterKind.VTyped or Arm64RegisterKind.VTypedIndexed or Arm64RegisterKind.VPackedIndexed => ElementSize(r.VKind),
        Arm64RegisterKind.V or Arm64RegisterKind.VIndexed => 16,
        _ => 0,
    };

    private static int ElementSize(Arm64RegisterVKind k) => k switch
    {
        Arm64RegisterVKind.B => 1,
        Arm64RegisterVKind.H => 2,
        Arm64RegisterVKind.S => 4,
        Arm64RegisterVKind.D => 8,
        Arm64RegisterVKind.Q => 16,
        _ => 16,
    };

    private static string Name(Arm64RegisterAny r) => r.ToString();

    /// <summary>The architectural register a name is part of: x for w, v for the SIMD and floating-point views.</summary>
    private static string FullName(Arm64RegisterAny r) => r.Kind switch
    {
        Arm64RegisterKind.W => r.Index == 31 ? "xzr" : $"x{r.Index}",
        Arm64RegisterKind.X => r.Index == 31 ? "xzr" : $"x{r.Index}",
        Arm64RegisterKind.SP or Arm64RegisterKind.WSP => "sp",
        Arm64RegisterKind.C => r.ToString(),
        _ => $"v{r.Index}",
    };

    private static string ExtendText(Arm64MemoryExtend e)
    {
        var kind = Arm64Extensions.ToText(e.Kind, false);
        return e.Amount != 0 || e.HasExplicitZeroAmount ? $"{kind} #{e.Amount}" : kind;
    }

    private static string OperandText(in Arm64Instruction i, Arm64Operand op, INativeImage image, NativeCodeIndex index, ulong pc)
    {
        Span<char> buffer = stackalloc char[128];
        bool page = i.Id == Arm64InstructionId.ADRP_only_pcreladdr;
        bool Label(long offset, Span<char> destination, out int written)
        {
            ulong va = (page ? pc & ~0xFFFUL : pc) + (ulong)offset;
            string? name = !page && va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage ? index.NameAt((uint)(va - image.ImageBase)) : null;
            var s = name ?? $"0x{va:X}";
            written = 0;
            if (s.Length > destination.Length) return false;
            s.AsSpan().CopyTo(destination);
            written = s.Length;
            return true;
        }
        return op.TryFormat(i, buffer, out int n, out _, default, null, Label) ? buffer[..n].ToString() : op.ToString() ?? "";
    }

    private static string Mnemonic(string text)
    {
        int space = text.IndexOf(' ');
        return space < 0 ? text : text[..space];
    }

    /// <summary>The condition of a conditional branch, select or compare, as written (cset's inverted encoding undone).</summary>
    private static string? Condition(in Arm64Instruction i)
    {
        for (int k = 0; k < i.OperandCount; k++)
            if (i.GetOperand(k) is { Kind: Arm64OperandKind.Enum } op && ((Arm64EnumOperand)op) is { EnumKind: Arm64EnumKind.Conditional or Arm64EnumKind.InvertedConditional } e)
            {
                var c = e.AsConditional;
                if (e.EnumKind == Arm64EnumKind.InvertedConditional) c = Arm64Extensions.Invert(c);
                return c.ToString().ToLowerInvariant();
            }
        return null;
    }

    private static bool WritesFlags(in Arm64Instruction i) =>
        i.Mnemonic is Arm64Mnemonic.CMP or Arm64Mnemonic.CMN or Arm64Mnemonic.TST or Arm64Mnemonic.SUBS or Arm64Mnemonic.ADDS or Arm64Mnemonic.ANDS
            or Arm64Mnemonic.BICS or Arm64Mnemonic.ADCS or Arm64Mnemonic.SBCS or Arm64Mnemonic.NEGS or Arm64Mnemonic.NGCS or Arm64Mnemonic.CCMP
            or Arm64Mnemonic.CCMN or Arm64Mnemonic.FCMP or Arm64Mnemonic.FCMPE or Arm64Mnemonic.FCCMP or Arm64Mnemonic.FCCMPE or Arm64Mnemonic.SETF8
            or Arm64Mnemonic.SETF16 or Arm64Mnemonic.RMIF or Arm64Mnemonic.CFINV or Arm64Mnemonic.AXFLAG or Arm64Mnemonic.XAFLAG
        || i.Mnemonic == Arm64Mnemonic.MSR && i.ToString().Contains("nzcv", StringComparison.OrdinalIgnoreCase);

    private static bool ReadsFlags(in Arm64Instruction i) =>
        Condition(in i) != null && i.Mnemonic is not (Arm64Mnemonic.CCMP or Arm64Mnemonic.CCMN) || i.Mnemonic is Arm64Mnemonic.CCMP or Arm64Mnemonic.CCMN
            or Arm64Mnemonic.ADC or Arm64Mnemonic.ADCS or Arm64Mnemonic.SBC or Arm64Mnemonic.SBCS or Arm64Mnemonic.NGC or Arm64Mnemonic.NGCS or Arm64Mnemonic.CFINV
        || i.Mnemonic == Arm64Mnemonic.MRS && i.ToString().Contains("nzcv", StringComparison.OrdinalIgnoreCase);

    /// <summary>"sub sp, sp, #n" / "add sp, sp, #n": the stack pointer change in bytes.</summary>
    private static int? StackAdjust(in Arm64Instruction i)
    {
        if (i.Id is not (Arm64InstructionId.SUB_64_addsub_imm or Arm64InstructionId.ADD_64_addsub_imm) || i.OperandCount < 3) return null;
        if (i.GetOperand(0) is not { Kind: Arm64OperandKind.Register } d || ((Arm64RegisterOperand)d).Value.Kind != Arm64RegisterKind.SP) return null;
        if (i.GetOperand(1) is not { Kind: Arm64OperandKind.Register } s || ((Arm64RegisterOperand)s).Value.Kind != Arm64RegisterKind.SP) return null;
        if (i.GetOperand(2) is not { Kind: Arm64OperandKind.Immediate } imm) return null;
        int shift = i.OperandCount > 3 && i.GetOperand(3).Kind == Arm64OperandKind.Shift ? ((Arm64ShiftOperand)i.GetOperand(3)).Amount : 0;
        long v = ((Arm64ImmediateOperand)imm).Value << shift;
        return (int)(i.Id == Arm64InstructionId.SUB_64_addsub_imm ? -v : v);
    }
}
