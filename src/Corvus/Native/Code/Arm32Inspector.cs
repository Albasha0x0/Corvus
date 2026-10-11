namespace Corvus.Native.Code;

/// <summary>
/// One A32 / T32 instruction as <see cref="InspectedInstruction"/>: operands (registers, shifted registers, memory as
/// base, index with shift, offset and writeback, register lists, vector registers), core register and NZCV use, memory
/// accesses, stack pointer change, condition (IT blocks included) and flow. The run is decoded from the block start in
/// the function's state, so literal loads, PC-relative pairs and MOVW / MOVT pairs resolve as in the code index.
/// </summary>
internal static class Arm32Inspector
{
    private const int MaxRun = 512;
    private const int Pc = 15, Sp = 13;
    private static readonly string[] Nzcv = ["n", "z", "c", "v"];

    private sealed record Step(uint Rva, ArmInstruction Instruction, Insn Facts);

    public static InspectedInstruction? Inspect(NativeCodeIndex index, uint rva, NativeDisassembler? disassembler, uint? runStart)
    {
        var image = index.Image;
        var dis = disassembler ?? index.CreateDisassembler();
        bool thumb = dis.ThumbAt(rva) == true;
        rva &= ~1u;
        var line = dis.DecodeOne(rva | (thumb ? 1u : 0));
        if (line == null) return null;
        if (index.NewDecoder() is not Arm32Decoder dec || line.Facts.Flow == FlowKind.Invalid)
            return new InspectedInstruction(rva, line.Facts.Length, line.Bytes, line.Text, null, "(bad)", []) { Flow = "invalid" };
        uint start = runStart is { } s && s <= rva && rva - s <= MaxRun ? s : rva;
        var run = Run(dec, thumb, start, rva);
        if (run.Count == 0 || run[^1].Rva != rva) run = Run(dec, thumb, rva, rva);
        if (run.Count == 0 || run[^1].Facts.Flow == FlowKind.Invalid)
            return new InspectedInstruction(rva, line.Facts.Length, line.Bytes, line.Text, null, "(bad)", []) { Flow = "invalid" };
        var step = run[^1];
        var i = step.Instruction;
        var facts = step.Facts;
        // the text with the run's state (IT conditions, names of formed addresses)
        var text = run.Count > 1 ? dis.Disassemble(start | (thumb ? 1u : 0), run.Count, rva + (uint)facts.Length).LastOrDefault() ?? line : line;

        uint? formed = facts.HasImm ? facts.ImmTarget : facts.HasMem ? facts.MemTarget : null;
        uint? pair = formed != null && SourceRegister(in i) is { } src ? Writer(run, run.Count - 1, src)?.Rva : null;
        string? comment = text.Comment;
        if (comment == null && formed is { } f) comment = index.NameAt(f) ?? NativeAddress.Va(image, f);

        var operands = new List<InspectedOperand>(i.OperandCount);
        var memory = new List<MemoryUse>();
        var vectorRead = new List<string>();
        var vectorWritten = new List<string>();
        int? spDelta = null;
        string access = i.Loads && i.Stores ? "read_write" : i.Loads ? "read" : i.Stores ? "write" : "none";
        int size = i.AccessSize;
        bool branch = i.Flow is ArmFlow.Jump or ArmFlow.Call;
        for (int k = 0; k < i.OperandCount; k++)
        {
            var op = i.Operands[k];
            string opText = i.OperandText(k, va => va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage ? index.NameAt((uint)(va - image.ImageBase)) : null);
            switch (op.Kind)
            {
                case ArmOperandKind.Register:
                {
                    string name = ArmInstruction.RegisterNames[op.Reg & 15];
                    bool write = Destination(in i, k) && (i.Writes & (1 << op.Reg)) != 0;
                    bool read = (i.Reads & (1 << op.Reg)) != 0 && (!write || op.Text == "!" || ReadsDestination(in i));
                    operands.Add(new InspectedOperand(k, "register", opText)
                    {
                        Access = write && read ? "read_write" : write ? "write" : "read", Size = 4, Register = name, FullRegister = name,
                    });
                    break;
                }
                case ArmOperandKind.ShiftedRegister:
                {
                    string name = ArmInstruction.RegisterNames[op.Reg & 15];
                    string shift = op.Shift switch { ArmShift.Lsl => "lsl", ArmShift.Lsr => "lsr", ArmShift.Asr => "asr", ArmShift.Ror => "ror", _ => "rrx" };
                    operands.Add(new InspectedOperand(k, "register", opText)
                    {
                        Access = "read", Size = 4, Register = name, FullRegister = name,
                        Extend = op.Shift == ArmShift.Rrx ? shift : op.ShiftReg != ArmOperand.NoReg ? $"{shift} {ArmInstruction.RegisterNames[op.ShiftReg & 15]}" : $"{shift} #{op.Amount}",
                    });
                    break;
                }
                case ArmOperandKind.Immediate:
                    operands.Add(new InspectedOperand(k, "immediate", opText) { Access = "read", Value = (ulong)op.Value, SignedValue = op.Value });
                    break;
                case ArmOperandKind.Label:
                {
                    uint target = (uint)op.Value;
                    uint? rvaTarget = target >= image.ImageBase && target - image.ImageBase < image.SizeOfImage ? (uint)(target - image.ImageBase) : null;
                    operands.Add(new InspectedOperand(k, branch ? "near_branch" : "pc_relative", opText)
                    {
                        Access = "read", Value = target, SignedValue = (long)target - (i.Address + (i.Thumb ? 4 : 8)), RipRelative = true, Target = rvaTarget,
                    });
                    break;
                }
                case ArmOperandKind.Memory:
                {
                    string baseName = ArmInstruction.RegisterNames[op.Reg & 15];
                    string? indexName = op.Index != ArmOperand.NoReg ? ArmInstruction.RegisterNames[op.Index & 15] : null;
                    long disp = op.Index == ArmOperand.NoReg && op.Indexing != ArmIndexing.PostIndex ? (op.Subtract ? -op.Value : op.Value) : 0;
                    string? writeback = op.Indexing switch { ArmIndexing.PreIndex => "pre", ArmIndexing.PostIndex => "post", _ => null };
                    int total = MemorySize(in i);
                    if (writeback != null && op.Reg == Sp && op.Index == ArmOperand.NoReg) spDelta = (int)(op.Subtract ? -op.Value : op.Value);
                    operands.Add(new InspectedOperand(k, op.Reg == Pc ? "pc_relative" : "memory", opText)
                    {
                        Access = access, Size = total > 0 ? total : null, Base = baseName, IndexRegister = indexName,
                        Scale = indexName != null ? 1 << (op.Shift == ArmShift.Lsl ? op.Amount : 0) : null, Displacement = disp, Writeback = writeback,
                        Extend = indexName != null && op.Shift != ArmShift.None && op.Amount != 0 ? $"{op.Shift.ToString().ToLowerInvariant()} #{op.Amount}" : null,
                        RipRelative = op.Reg == Pc, Value = facts.HasMem ? image.ImageBase + facts.MemTarget : null, Target = facts.HasMem ? facts.MemTarget : null,
                    });
                    if (access != "none")
                        memory.Add(new MemoryUse(null, baseName, indexName, indexName != null ? 1 << (op.Shift == ArmShift.Lsl ? op.Amount : 0) : 1, disp, total, access));
                    break;
                }
                case ArmOperandKind.RegisterList:
                {
                    var names = Enumerable.Range(0, 16).Where(r => (op.Value & (1 << r)) != 0).Select(r => ArmInstruction.RegisterNames[r]).ToList();
                    operands.Add(new InspectedOperand(k, "register_list", opText) { Access = i.Loads ? "write" : "read", Size = names.Count * 4 });
                    if (i.Mnemonic is "push" or "pop")
                    {
                        spDelta = (i.Mnemonic == "push" ? -4 : 4) * names.Count;
                        memory.Add(new MemoryUse(null, "sp", null, 1, i.Mnemonic == "push" ? -4 * names.Count : 0, names.Count * 4, access));
                    }
                    else if (i.OperandCount > 0 && i.Op(0).Kind == ArmOperandKind.Register)
                        memory.Add(new MemoryUse(null, ArmInstruction.RegisterNames[i.Op(0).Reg & 15], null, 1, 0, names.Count * 4, access));
                    break;
                }
                case ArmOperandKind.VectorRegister:
                {
                    string name = opText;
                    bool write = k == 0 && !i.Stores && !i.Mnemonic.StartsWith("vcmp", StringComparison.Ordinal) && i.Mnemonic != "vmsr"
                        && !(i.Mnemonic == "vmov" && i.OperandCount > 1 && i.Op(1).Kind == ArmOperandKind.VectorRegister && i.Op(0).Kind == ArmOperandKind.Register);
                    (write ? vectorWritten : vectorRead).Add(name);
                    operands.Add(new InspectedOperand(k, "register", opText)
                    {
                        Access = write ? "write" : "read", Size = op.Vector switch { ArmVector.S => 4, ArmVector.D => 8, _ => 16 }, Register = name,
                    });
                    break;
                }
                case ArmOperandKind.VectorList:
                {
                    int regSize = op.Vector switch { ArmVector.S => 4, ArmVector.D => 8, _ => 16 };
                    operands.Add(new InspectedOperand(k, "register_list", opText) { Access = i.Loads ? "write" : "read", Size = op.Count * regSize });
                    if (i.Mnemonic is "vpush" or "vpop")
                    {
                        spDelta = (i.Mnemonic == "vpush" ? -1 : 1) * op.Count * regSize;
                        memory.Add(new MemoryUse(null, "sp", null, 1, i.Mnemonic == "vpush" ? -op.Count * regSize : 0, op.Count * regSize, access));
                    }
                    break;
                }
                case ArmOperandKind.Text:
                {
                    string kind = i.Mnemonic.StartsWith("it", StringComparison.Ordinal) ? "condition"
                        : op.Text is "apsr" or "apsr_nzcv" or "apsr_nzcvq" or "apsr_g" or "spsr" or "fpscr" or "fpexc" or "fpsid" ? "system_register" : "enum";
                    operands.Add(new InspectedOperand(k, kind, opText) { Access = "read", Register = kind == "system_register" ? op.Text : null });
                    break;
                }
            }
        }
        if (spDelta == null && i.Mnemonic is "add" or "sub" && i.OperandCount >= 2 && i.Op(0) is { Kind: ArmOperandKind.Register, Reg: Sp }
            && i.Op(i.OperandCount - 1).Kind == ArmOperandKind.Immediate && (i.OperandCount == 2 || i.Op(1) is { Kind: ArmOperandKind.Register, Reg: Sp }))
            spDelta = (int)(i.Mnemonic == "add" ? i.Op(i.OperandCount - 1).Value : -i.Op(i.OperandCount - 1).Value);

        var flow = facts.Flow;
        bool continues = flow is not (FlowKind.Jump or FlowKind.IndirectJump or FlowKind.Return or FlowKind.Trap or FlowKind.Invalid) || facts.Conditional;
        return new InspectedInstruction(rva, facts.Length, line.Bytes, text.Text, comment, i.Mnemonic, operands)
        {
            Encoding = !i.Thumb ? "a32" : i.Length == 2 ? "t16" : "t32",
            Prefixes = [],
            Cpuid = [],
            Privileged = i.Mnemonic is "smc" or "hvc" or "eret" or "cps" or "cpsid" or "cpsie" or "srsdb" or "srsia" or "rfedb" or "rfeia"
                || i.Mnemonic is "msr" or "mrs" && i.Operands[i.Mnemonic == "msr" ? 0 : 1].Text == "spsr",
            RegistersRead = [.. Names(i.Reads), .. vectorRead],
            RegistersWritten = [.. Names(i.Writes), .. vectorWritten],
            MemoryAccesses = memory,
            FlagsRead = i.ReadsFlags ? Nzcv : [],
            FlagsWritten = i.WritesFlags ? Nzcv : [],
            FlagsUndefined = [],
            StackPointerDelta = spDelta ?? 0,
            Flow = InstructionInspector.FlowName(flow),
            Condition = i.IsConditional ? ArmInstruction.ConditionNames[i.Cond] : i.Mnemonic is "cbz" ? "eq" : i.Mnemonic is "cbnz" ? "ne" : null,
            BranchTarget = facts.HasTarget ? facts.Target : null,
            Fallthrough = continues ? rva + (uint)facts.Length : null,
            PairRva = pair,
            FormedAddress = formed,
        };
    }

    private static IEnumerable<string> Names(ushort mask)
    {
        for (int r = 0; r < 16; r++)
            if ((mask & (1 << r)) != 0) yield return ArmInstruction.RegisterNames[r];
    }

    /// <summary>Operand <paramref name="k"/> (a register) is one the instruction writes rather than reads.</summary>
    private static bool Destination(in ArmInstruction i, int k)
    {
        if (i.Flow is not (ArmFlow.Next or ArmFlow.Return or ArmFlow.IndirectJump)) return false;
        if (i.Mnemonic is "cmp" or "cmn" or "tst" or "teq" || i.Mnemonic.StartsWith("bx", StringComparison.Ordinal)) return false;
        if (i.Stores) return k == 0 && i.Mnemonic is "strex" or "strexb" or "strexh" or "strexd" or "stlex" or "stlexb" or "stlexh" or "stlexd";
        if (k == 0) return true;
        // second destinations: long multiplies, doubleword loads, two-register moves
        return k == 1 && (i.Mnemonic is "umull" or "smull" or "umlal" or "smlal" or "umaal" or "ldrd" or "ldrexd" or "ldaexd" || i.Mnemonic.StartsWith("smlal", StringComparison.Ordinal)
            || i.Mnemonic == "vmov" && i.OperandCount == 3 && i.Op(1).Kind == ArmOperandKind.Register);
    }

    /// <summary>The destination is also a source (accumulating forms, bit-field inserts, MOVT).</summary>
    private static bool ReadsDestination(in ArmInstruction i) =>
        i.Mnemonic is "movt" or "bfi" or "bfc" or "umlal" or "smlal" or "umaal" || i.OperandCount == 2 && i.Mnemonic is "add" or "sub" or "and" or "orr" or "eor" or "bic"
            or "adc" or "sbc" or "lsl" or "lsr" or "asr" or "ror" || i.Thumb && i.Length == 2 && i.OperandCount == 2 && i.Mnemonic is not ("mov" or "mvn" or "cmp" or "cmn" or "tst");

    /// <summary>Bytes a single load or store moves (doublewords: both registers).</summary>
    private static int MemorySize(in ArmInstruction i) => i.Mnemonic is "ldrd" or "strd" or "ldrexd" or "strexd" ? 8 : i.AccessSize;

    /// <summary>The register an address-forming instruction builds on: a memory base, or the source of an add / movt.</summary>
    private static int? SourceRegister(in ArmInstruction i)
    {
        for (int k = 0; k < i.OperandCount; k++)
            if (i.Operands[k].Kind == ArmOperandKind.Memory) return i.Operands[k].Reg == Pc ? null : i.Operands[k].Reg;
        if (i.Mnemonic is "add" && i.OperandCount == 2 && i.Op(0).Kind == ArmOperandKind.Register) return i.Op(0).Reg;
        if (i.Mnemonic is "add" && i.OperandCount == 3 && i.Op(1).Kind == ArmOperandKind.Register)
            return i.Op(1).Reg == Pc && i.Op(2).Kind == ArmOperandKind.Register ? i.Op(2).Reg : i.Op(1).Reg;
        if (i.Mnemonic is "movt") return i.Op(0).Reg;
        if (i.Mnemonic is "bx" or "blx" && i.Op(0).Kind == ArmOperandKind.Register) return i.Op(0).Reg;
        return null;
    }

    private static Step? Writer(List<Step> run, int before, int reg)
    {
        for (int k = before - 1; k >= 0; k--)
            if ((run[k].Instruction.Writes & (1 << reg)) != 0) return run[k];
        return null;
    }

    /// <summary>Decodes [start, rva] in one run in the given state; empty when the walk does not land on <paramref name="rva"/>.</summary>
    private static List<Step> Run(Arm32Decoder dec, bool thumb, uint start, uint rva)
    {
        var steps = new List<Step>();
        dec.Pin(thumb);
        dec.BeginRun(IndexBound.None);
        for (uint a = start; a <= rva;)
        {
            if (!dec.DecodeMapped(a, out var insn)) break;
            steps.Add(new Step(a, dec.Last, insn));
            if (insn.Flow == FlowKind.Invalid && a != rva) { steps.Clear(); dec.BeginRun(IndexBound.None); }
            a += (uint)Math.Max(1, insn.Length);
        }
        return steps.Count > 0 && steps[^1].Rva == rva ? steps : [];
    }
}
