using Iced.Intel;

namespace NetDecompilerMcp.Native.Code;

/// <summary>
/// One operand. Fields an engine does not supply are null. <see cref="Target"/> is the RVA of a branch target or of a
/// memory operand's effective address when it is absolute or RIP-relative and inside the image.
/// </summary>
/// <param name="Kind">register, immediate, memory, near_branch or far_branch; ARM64 also pc_relative (adr / adrp / literal address), shift, extend,
/// condition, enum, system_register and register_list.</param>
public sealed record InspectedOperand(int Index, string Kind, string Text)
{
    /// <summary>Bytes the operand reads or writes (register width, memory access size, immediate size).</summary>
    public int? Size { get; init; }
    /// <summary>read, write, read_write, cond_read, cond_write, read_cond_write or none.</summary>
    public string? Access { get; init; }
    public string? Register { get; init; }
    /// <summary>The full register a partial one is part of (eax -> rax on x64).</summary>
    public string? FullRegister { get; init; }
    public ulong? Value { get; init; }
    public long? SignedValue { get; init; }
    public string? Segment { get; init; }
    public string? Base { get; init; }
    public string? IndexRegister { get; init; }
    public int? Scale { get; init; }
    public long? Displacement { get; init; }
    public bool RipRelative { get; init; }
    public uint? Target { get; init; }
    /// <summary>ARM64 memory index extend or shift (lsl #3, uxtw #2, sxtw).</summary>
    public string? Extend { get; init; }
    /// <summary>ARM64 base register writeback: pre or post.</summary>
    public string? Writeback { get; init; }
}

/// <summary>A memory access the instruction makes (explicit operands and implicit ones: push, pop, string instructions).</summary>
public sealed record MemoryUse(string? Segment, string? Base, string? Index, int Scale, long Displacement, int Size, string Access);

/// <summary>The decoded facts of one instruction. Lists an engine does not supply are null, never empty.</summary>
public sealed record InspectedInstruction(uint Rva, int Length, string Bytes, string Text, string? Comment, string Mnemonic, IReadOnlyList<InspectedOperand> Operands)
{
    /// <summary>legacy, vex, evex, xop, 3dnow or mvex; ARM64: a64.</summary>
    public string? Encoding { get; init; }
    public IReadOnlyList<string>? Prefixes { get; init; }
    /// <summary>CPUID feature sets the instruction needs (ARM64: the architecture feature, lse, pauth, ...).</summary>
    public IReadOnlyList<string>? Cpuid { get; init; }
    public bool Privileged { get; init; }
    public IReadOnlyList<string>? RegistersRead { get; init; }
    public IReadOnlyList<string>? RegistersWritten { get; init; }
    public IReadOnlyList<MemoryUse>? MemoryAccesses { get; init; }
    public IReadOnlyList<string>? FlagsRead { get; init; }
    public IReadOnlyList<string>? FlagsWritten { get; init; }
    public IReadOnlyList<string>? FlagsUndefined { get; init; }
    /// <summary>Change of the stack pointer in bytes (push: -8 on x64).</summary>
    public int? StackPointerDelta { get; init; }
    /// <summary>next, call, indirect_call, jump, indirect_jump, conditional_jump, return, trap or invalid.</summary>
    public string Flow { get; init; } = "next";
    /// <summary>Condition code of a conditional jump, set or move (e, ne, a, ...).</summary>
    public string? Condition { get; init; }
    public uint? BranchTarget { get; init; }
    /// <summary>The next instruction when control can continue there (null after jmp, ret, traps).</summary>
    public uint? Fallthrough { get; init; }
    /// <summary>ARM64: the other instruction of an ADRP pair (the adrp, or the add / load / store completing it).</summary>
    public uint? PairRva { get; init; }
    /// <summary>ARM64: the address an ADRP pair, an adr or a literal load forms.</summary>
    public uint? FormedAddress { get; init; }
}

/// <summary>Decodes one x86 / x64 instruction with Iced (ARM64: <see cref="Arm64Inspector"/>) into <see cref="InspectedInstruction"/>: operands, register and memory use, flags, flow.</summary>
public static class InstructionInspector
{
    // Iced formatters are not thread-safe: one per thread.
    [ThreadStatic] private static MasmFormatter? _plain;
    private static MasmFormatter Plain => _plain ??= CreateFormatter();

    private static MasmFormatter CreateFormatter()
    {
        var f = new MasmFormatter();
        f.Options.UppercaseHex = true;
        f.Options.SpaceAfterOperandSeparator = true;
        f.Options.RipRelativeAddresses = false;
        f.Options.ShowBranchSize = false;
        f.Options.BranchLeadingZeros = false;
        f.Options.LeadingZeros = false;
        return f;
    }

    /// <summary>
    /// The instruction at <paramref name="rva"/> (any mapped address), text and comment named through the index; null
    /// when nothing is mapped there. ARM64 decodes from <paramref name="runStart"/> (the block start) so ADRP pairs resolve.
    /// </summary>
    public static InspectedInstruction? Inspect(NativeCodeIndex index, uint rva, NativeDisassembler? disassembler = null, uint? runStart = null)
    {
        if (index.Image.Arch == NativeArch.Arm64) return Arm64Inspector.Inspect(index, rva, disassembler, runStart);
        if (index.Image.Arch == NativeArch.Arm) return Arm32Inspector.Inspect(index, rva, disassembler, runStart);
        var image = index.Image;
        var line = (disassembler ?? index.CreateDisassembler()).DecodeOne(rva);
        if (line == null) return null;
        var bytes = new byte[15];
        int n = image.Read(rva, bytes);
        var decoder = Decoder.Create(image.Is64Bit ? 64 : 32, new ByteArrayCodeReader(bytes, 0, n), image.ImageBase + rva, DecoderOptions.None);
        decoder.Decode(out var insn);
        if (insn.IsInvalid)
            return new InspectedInstruction(rva, line.Facts.Length, line.Bytes, line.Text, null, "(bad)", []) { Flow = "invalid" };
        var info = new InstructionInfoFactory().GetInfo(in insn);
        var output = new StringOutput();
        var operands = new List<InspectedOperand>(insn.OpCount);
        for (int i = 0; i < insn.OpCount; i++)
        {
            int fo = Plain.GetFormatterOperand(in insn, i);
            string text = "";
            if (fo >= 0) { Plain.FormatOperand(in insn, output, fo); text = output.ToStringAndReset(); }
            operands.Add(Operand(image, in insn, i, text, Access(info.GetOpAccess(i))));
        }
        var facts = line.Facts;
        bool continues = facts.Flow is not (FlowKind.Jump or FlowKind.IndirectJump or FlowKind.Return or FlowKind.Trap or FlowKind.Invalid);
        var prefixes = new List<string>();
        if (insn.HasLockPrefix) prefixes.Add("lock");
        if (insn.HasRepePrefix) prefixes.Add(insn.Code.IsStringInstruction() ? "rep" : "repe");
        if (insn.HasRepnePrefix) prefixes.Add("repne");
        if (insn.HasXacquirePrefix) prefixes.Add("xacquire");
        if (insn.HasXreleasePrefix) prefixes.Add("xrelease");
        // CET: a ds prefix on an indirect call or jump is notrack
        if (insn.SegmentPrefix == Register.DS && insn.FlowControl is FlowControl.IndirectBranch or FlowControl.IndirectCall) prefixes.Add("notrack");
        else if (insn.SegmentPrefix != Register.None) prefixes.Add(Name(insn.SegmentPrefix) + ":");
        return new InspectedInstruction(rva, insn.Length, line.Bytes, line.Text, line.Comment, insn.Mnemonic.ToString().ToLowerInvariant(), operands)
        {
            Encoding = insn.Encoding switch
            {
                EncodingKind.Legacy => "legacy",
                EncodingKind.VEX => "vex",
                EncodingKind.EVEX => "evex",
                EncodingKind.XOP => "xop",
                EncodingKind.D3NOW => "3dnow",
                _ => insn.Encoding.ToString().ToLowerInvariant(),
            },
            Prefixes = prefixes,
            Cpuid = insn.Code.CpuidFeatures().Select(c => c.ToString().ToLowerInvariant()).ToList(),
            Privileged = insn.Code.IsPrivileged(),
            RegistersRead = Registers(info, read: true),
            RegistersWritten = Registers(info, read: false),
            MemoryAccesses = info.GetUsedMemory().Select(m => new MemoryUse(
                m.Segment == Register.None ? null : Name(m.Segment), m.Base == Register.None ? null : Name(m.Base), m.Index == Register.None ? null : Name(m.Index),
                m.Scale, (long)m.Displacement, m.MemorySize.GetSize(), Access(m.Access))).ToList(),
            FlagsRead = Flags(insn.RflagsRead),
            FlagsWritten = Flags(insn.RflagsModified),
            FlagsUndefined = Flags(insn.RflagsUndefined),
            StackPointerDelta = insn.StackPointerIncrement,
            Flow = FlowName(facts.Flow),
            Condition = insn.ConditionCode == ConditionCode.None ? null : insn.ConditionCode.ToString(),
            BranchTarget = facts.BranchTarget,
            Fallthrough = continues ? rva + (uint)insn.Length : null,
        };
    }

    public static string FlowName(FlowKind flow) => flow switch
    {
        FlowKind.Next => "next",
        FlowKind.Call => "call",
        FlowKind.IndirectCall => "indirect_call",
        FlowKind.Jump => "jump",
        FlowKind.IndirectJump => "indirect_jump",
        FlowKind.ConditionalJump => "conditional_jump",
        FlowKind.Return => "return",
        FlowKind.Trap => "trap",
        _ => "invalid",
    };

    private static InspectedOperand Operand(INativeImage image, in Instruction insn, int i, string text, string access)
    {
        var kind = insn.GetOpKind(i);
        switch (kind)
        {
            case OpKind.Register:
                var reg = insn.GetOpRegister(i);
                return new InspectedOperand(i, "register", text)
                {
                    Access = access, Size = reg.GetSize(), Register = Name(reg),
                    FullRegister = Name(image.Is64Bit ? reg.GetFullRegister() : reg.GetFullRegister32()),
                };
            case OpKind.NearBranch16 or OpKind.NearBranch32 or OpKind.NearBranch64:
                return new InspectedOperand(i, "near_branch", text) { Access = access, Value = insn.NearBranchTarget, Target = Rva(image, insn.NearBranchTarget) };
            case OpKind.FarBranch16 or OpKind.FarBranch32:
                return new InspectedOperand(i, "far_branch", text) { Access = access, Value = kind == OpKind.FarBranch16 ? insn.FarBranch16 : insn.FarBranch32 };
            case OpKind.Memory:
            {
                bool rip = insn.IsIPRelativeMemoryOperand;
                ulong? ea = rip ? insn.IPRelativeMemoryAddress
                    : insn.MemoryBase == Register.None && insn.MemoryIndex == Register.None ? insn.MemoryDisplacement64 : null;
                return new InspectedOperand(i, "memory", text)
                {
                    Access = access, Size = insn.MemorySize.GetSize(),
                    Segment = Name(insn.MemorySegment),
                    Base = insn.MemoryBase == Register.None || rip ? null : Name(insn.MemoryBase),
                    IndexRegister = insn.MemoryIndex == Register.None ? null : Name(insn.MemoryIndex),
                    Scale = insn.MemoryIndex == Register.None ? null : insn.MemoryIndexScale,
                    Displacement = rip ? (long)(insn.IPRelativeMemoryAddress - insn.NextIP) : image.Is64Bit ? (long)insn.MemoryDisplacement64 : (int)insn.MemoryDisplacement32,
                    RipRelative = rip,
                    Value = ea,
                    Target = ea is { } a ? Rva(image, a) : null,
                };
            }
            case OpKind.Immediate8 or OpKind.Immediate8_2nd or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64
                or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64:
            {
                ulong value = insn.GetImmediate(i);
                int size = kind switch
                {
                    OpKind.Immediate8 or OpKind.Immediate8_2nd => 1,
                    OpKind.Immediate16 or OpKind.Immediate8to16 => 2,
                    OpKind.Immediate32 or OpKind.Immediate8to32 => 4,
                    _ => 8,
                };
                long signed = size switch { 1 => (sbyte)value, 2 => (short)value, 4 => (int)value, _ => (long)value };
                return new InspectedOperand(i, "immediate", text) { Access = access, Size = size, Value = value, SignedValue = signed };
            }
            default:
                // string instruction operands ([rsi], es:[rdi]) and other implicit memory
                return new InspectedOperand(i, "memory", text) { Access = access, Size = insn.MemorySize.GetSize() };
        }
    }

    private static uint? Rva(INativeImage image, ulong va)
    {
        if (!image.Is64Bit) va &= 0xFFFFFFFF;
        return va >= image.ImageBase && va - image.ImageBase < image.SizeOfImage ? (uint)(va - image.ImageBase) : null;
    }

    private static string Name(Register r) => r.ToString().ToLowerInvariant();

    private static List<string> Registers(InstructionInfo info, bool read)
    {
        var list = new List<string>();
        foreach (var u in info.GetUsedRegisters())
        {
            bool reads = u.Access is OpAccess.Read or OpAccess.CondRead or OpAccess.ReadWrite or OpAccess.ReadCondWrite;
            bool writes = u.Access is OpAccess.Write or OpAccess.CondWrite or OpAccess.ReadWrite or OpAccess.ReadCondWrite;
            if (read ? !reads : !writes) continue;
            bool conditional = read ? u.Access == OpAccess.CondRead : u.Access is OpAccess.CondWrite or OpAccess.ReadCondWrite;
            var name = Name(u.Register) + (conditional ? " (conditional)" : "");
            if (!list.Contains(name)) list.Add(name);
        }
        return list;
    }

    public static string Access(OpAccess access) => access switch
    {
        OpAccess.Read => "read",
        OpAccess.Write => "write",
        OpAccess.ReadWrite => "read_write",
        OpAccess.CondRead => "cond_read",
        OpAccess.CondWrite => "cond_write",
        OpAccess.ReadCondWrite => "read_cond_write",
        _ => "none",
    };

    private static readonly (RflagsBits Bit, string Name)[] FlagNames =
    [
        (RflagsBits.CF, "cf"), (RflagsBits.PF, "pf"), (RflagsBits.AF, "af"), (RflagsBits.ZF, "zf"), (RflagsBits.SF, "sf"),
        (RflagsBits.IF, "if"), (RflagsBits.DF, "df"), (RflagsBits.OF, "of"), (RflagsBits.AC, "ac"),
    ];

    private static List<string> Flags(RflagsBits bits) => FlagNames.Where(f => (bits & f.Bit) != 0).Select(f => f.Name).ToList();
}
