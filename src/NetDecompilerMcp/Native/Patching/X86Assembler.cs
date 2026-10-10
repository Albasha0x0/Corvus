using System.Globalization;
using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using IcedCode = Iced.Intel.Code;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// MASM/Intel-syntax x86 / x64 assembler on Iced's encoder, accepting the general-purpose / SSE / AVX forms the
/// <c>disassemble</c> tool prints, so a listed line can be edited and patched back. Each operand (register, immediate,
/// memory) is parsed and Iced's <see cref="IcedCode"/> table searched for a form whose operand kinds match, shortest
/// encoding first. <see cref="BlockEncoder"/> lays the block out at the patch address (near-branch sizes, relative and
/// RIP-relative displacements). Branch targets: labels, numbers, caller-resolved symbols; <c>db</c> emits raw bytes.
/// </summary>
public static class X86Assembler
{
    /// <param name="Bytes">The encoded block.</param>
    /// <param name="Constants">
    /// Displacements and immediates of the encoded instructions (not branch displacements or RIP-relative operands),
    /// flagged when the operand was written as a symbol or with 'offset': the base-relocation planning input.
    /// </param>
    public sealed record Result(byte[] Bytes, IReadOnlyList<OperandConstant> Constants);

    private sealed class ByteWriter : CodeWriter
    {
        public readonly List<byte> Bytes = new();
        public override void WriteByte(byte value) => Bytes.Add(value);
    }

    // Each assembled line becomes one Iced Instruction (db becomes a DeclareByte pseudo-instruction). A branch whose
    // target is a label/number/symbol keeps the token so it can be resolved once every item has an identifier IP.
    private sealed record Item(int Line, Instruction Instruction, string? BranchToken, bool ImmSymbol = false, bool DispSymbol = false);

    /// <param name="resolveSymbol">Resolves a name that is neither a label nor a number to a VA (e.g. an export).</param>
    public static Result Assemble(NativeArch arch, ulong startVa, string text, Func<string, ulong?>? resolveSymbol = null)
    {
        if (arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, $"Assembly is only supported for x86 and x64, not {arch}.");
        int bitness = arch == NativeArch.X64 ? 64 : 32;

        // Pass 1: strip comments, collect labels by item index, parse each instruction.
        var items = new List<Item>();
        var labelIndex = new Dictionary<string, int>(StringComparer.Ordinal);
        int lineNo = 0;
        foreach (var rawLine in text.Replace("\r\n", "\n").Split('\n'))
        {
            lineNo++;
            var line = StripComment(rawLine).Trim();
            while (line.Length > 0)
            {
                int colon = LabelColon(line);
                if (colon < 0) break;
                var label = line[..colon].Trim();
                if (label.Length == 0 || !IsName(label))
                    throw Error(lineNo, $"'{label}' is not a valid label.");
                if (!labelIndex.TryAdd(label, items.Count))
                    throw Error(lineNo, $"label '{label}' is defined more than once.");
                line = line[(colon + 1)..].Trim();
            }
            if (line.Length == 0) continue;
            items.Add(ParseLine(bitness, startVa, lineNo, line, resolveSymbol));
        }
        if (items.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, "No instructions to assemble.");

        // Give each item a unique identifier IP well outside any real VA, so BlockEncoder relocates in-block branch
        // targets (labels) while leaving external absolute targets alone. The real layout is recomputed by BlockEncoder.
        const ulong labelBase = 0xF000_0000_0000_0000UL;
        var list = new List<Instruction>(items.Count);
        for (int i = 0; i < items.Count; i++)
        {
            var instr = items[i].Instruction;
            instr.IP = labelBase + (ulong)i;
            if (items[i].BranchToken is { } token)
                SetBranchTarget(bitness, ref instr, items[i].Line, token, labelIndex, labelBase, resolveSymbol);
            list.Add(instr);
        }

        var writer = new ByteWriter();
        var block = new InstructionBlock(writer, list, startVa);
        if (!BlockEncoder.TryEncode(bitness, block, out var err, out var encoded, BlockEncoderOptions.ReturnNewInstructionOffsets))
            throw new ToolError(ErrorCode.InvalidArgument, $"Assembly failed to encode: {CleanError(err)}");
        var bytes = writer.Bytes.ToArray();
        var points = new List<(int, bool, bool)>();
        for (int i = 0; i < items.Count && i < encoded.NewInstructionOffsets.Length; i++)
        {
            uint off = encoded.NewInstructionOffsets[i];
            if (off == uint.MaxValue || items[i].BranchToken != null || items[i].Instruction.Code == IcedCode.DeclareByte) continue;
            points.Add(((int)off, items[i].ImmSymbol, items[i].DispSymbol));
        }
        return new Result(bytes, PatchRelocations.Decode(bitness, startVa, bytes, points));
    }

    private static void SetBranchTarget(int bitness, ref Instruction instr, int line, string token,
        Dictionary<string, int> labels, ulong labelBase, Func<string, ulong?>? resolve)
    {
        ulong target;
        if (labels.TryGetValue(token, out var index)) target = labelBase + (ulong)index;
        else if (NativeAddress.Number(token) is { } n) target = n;
        else if (resolve?.Invoke(token) is { } va) target = va;
        else throw Error(line, $"branch target '{token}' is neither a label, a number, nor a known symbol.");
        switch (instr.Op0Kind)
        {
            case OpKind.NearBranch64: instr.NearBranch64 = target; break;
            case OpKind.NearBranch32: instr.NearBranch32 = (uint)target; break;
            case OpKind.NearBranch16: instr.NearBranch16 = (ushort)target; break;
            default: throw Error(line, "this branch does not take a code address here.");
        }
    }

    private static Item ParseLine(int bitness, ulong startVa, int line, string text, Func<string, ulong?>? resolve)
    {
        // Leading prefixes: lock / rep* / bnd / notrack.
        bool lockp = false, rep = false, repe = false, repne = false, bnd = false, notrack = false;
        while (true)
        {
            int sp0 = text.IndexOfAny([' ', '\t']);
            if (sp0 < 0) break;
            var head = text[..sp0].ToLowerInvariant();
            bool consumed = true;
            switch (head)
            {
                case "lock": lockp = true; break;
                case "rep": rep = true; break;
                case "repe": case "repz": repe = true; break;
                case "repne": case "repnz": repne = true; break;
                case "bnd": bnd = true; break;
                case "notrack": notrack = true; break;
                default: consumed = false; break;
            }
            if (!consumed) break;
            text = text[(sp0 + 1)..].TrimStart();
        }

        _ = notrack; // 3E notrack is accepted and ignored (no encoder slot)
        int sp = text.IndexOfAny([' ', '\t']);
        var mnemText = (sp < 0 ? text : text[..sp]).ToLowerInvariant();
        var rest = sp < 0 ? "" : text[(sp + 1)..].Trim();
        var opTexts = SplitOperands(rest);

        if (mnemText == "db") return new Item(line, Instruction.CreateDeclareByte(ParseDb(line, rest)), null);

        // String instructions (movs/stos/lods/scas/cmps with a size suffix) use implicit [rsi]/[rdi] operands and are
        // built with Iced's dedicated factories so the operand kinds and rep prefix are set. Only when no explicit
        // operands were written, so "movsd xmm0, xmm1" still reaches the SSE form below.
        if (opTexts.Length == 0 && StringOp(bitness, mnemText, rep || repe, repne) is { } sins)
            return new Item(line, sins, null);

        var mnemonic = MapMnemonic(mnemText);
        if (mnemonic == Mnemonic.INVALID)
            throw Error(line, $"unknown mnemonic '{mnemText}'. Use a standard x86/x64 mnemonic, or 'db <hex>' for raw bytes.");

        // A branch / call with a single code-address operand (not a register or memory operand) is relative.
        if (opTexts.Length == 1 && IsBranchMnemonic(mnemonic) && !LooksLikeRegOrMem(opTexts[0]))
        {
            var bcode = BranchCode(bitness, mnemonic) ?? throw Error(line, $"{mnemText} has no relative form in {bitness}-bit mode.");
            var bins = Instruction.CreateBranch(bcode, 0);
            ApplyPrefixes(ref bins, line, lockp, rep, repe, repne, bnd, notrack);
            return new Item(line, bins, opTexts[0]);
        }

        // General case: parse operands, then search the Code table for a matching form.
        var operands = new Operand[opTexts.Length];
        for (int i = 0; i < opTexts.Length; i++) operands[i] = ParseOperand(bitness, line, opTexts[i], resolve);

        // "imul reg, imm" is the two-operand shorthand for "imul reg, reg, imm" (destination also the source).
        if (mnemonic == Mnemonic.Imul && operands is [{ Class: OpClass.Reg }, { Class: OpClass.Imm }])
            operands = [operands[0], operands[0], operands[1]];
        // xchg is commutative; the disassembler prints "xchg reg, [mem]" but the encoding is r/m first.
        if (mnemonic == Mnemonic.Xchg && operands is [{ Class: OpClass.Reg }, { Class: OpClass.Mem }])
            operands = [operands[1], operands[0]];

        var built = Select(bitness, startVa, line, mnemText, mnemonic, operands);
        ApplyPrefixes(ref built, line, lockp, rep, repe, repne, bnd, notrack);
        return new Item(line, built, null,
            operands.Any(o => o.Class == OpClass.Imm && o.Symbol), operands.Any(o => o.Class == OpClass.Mem && o.Symbol));
    }

    private static void ApplyPrefixes(ref Instruction instr, int line, bool lockp, bool rep, bool repe, bool repne, bool bnd, bool notrack)
    {
        _ = line; _ = notrack;
        if (lockp) instr.HasLockPrefix = true;
        if (rep || repe) instr.HasRepePrefix = true;
        if (repne || bnd) instr.HasRepnePrefix = true; // bnd shares the F2 prefix slot
    }

    private enum OpClass { Reg, Mem, Imm }

    private sealed record Operand(OpClass Class,
        Register Reg = Register.None,
        // memory
        Register Base = Register.None, Register Index = Register.None, int Scale = 1,
        long Disp = 0, bool Rip = false, Register Segment = Register.None, int? SizeBytes = null, bool Absolute = false, bool AutoRip = false,
        // immediate (Applied holds the value with any sign already folded in)
        ulong Applied = 0,
        // written as a symbol (or with 'offset'): an address the image's relocations must cover
        bool Symbol = false);

    private static Operand ParseOperand(int bitness, int line, string text, Func<string, ulong?>? resolve)
    {
        var t = text.Trim();
        if (t.Length == 0) throw Error(line, "empty operand.");

        // "offset <name>" is an immediate address.
        if (t.StartsWith("offset ", StringComparison.OrdinalIgnoreCase))
            return ImmediateOperand(line, t[7..].Trim(), resolve) with { Symbol = true };

        int? sizeBytes = null;
        foreach (var (word, bytes) in SizeWords)
            if (t.StartsWith(word, StringComparison.OrdinalIgnoreCase) && (t.Length == word.Length || !char.IsLetterOrDigit(t[word.Length])))
            {
                sizeBytes = bytes;
                t = t[word.Length..].TrimStart();
                break;
            }

        // Optional segment override before a memory operand: "fs:[...]".
        Register segment = Register.None;
        int bracket = t.IndexOf('[');
        if (bracket > 0 && t[bracket - 1] == ':')
        {
            var segText = t[..(bracket - 1)].Trim();
            if (TryRegister(segText, out var seg) && seg.IsSegmentRegister())
            {
                // DS is the default data segment; the disassembler writes "ds:[abs]" for absolute addressing but no
                // override prefix is emitted for it, so treat it as none to round-trip byte-for-byte.
                if (seg != Register.DS) segment = seg;
                t = t[bracket..];
            }
        }

        if (t.StartsWith('['))
            return ParseMemory(bitness, line, t, segment, sizeBytes, resolve);

        if (sizeBytes != null)
            throw Error(line, $"a size specifier must be followed by a memory operand: '{text}'.");

        if (TryRegister(t, out var reg)) return new Operand(OpClass.Reg, Reg: reg);

        return ImmediateOperand(line, t, resolve);
    }

    private static Operand ImmediateOperand(int line, string t, Func<string, ulong?>? resolve)
    {
        bool neg = false;
        var s = t;
        if (s.StartsWith('-')) { neg = true; s = s[1..].Trim(); }
        else if (s.StartsWith('+')) s = s[1..].Trim();
        if (NativeAddress.Number(s) is { } num)
            return new Operand(OpClass.Imm, Applied: neg ? (ulong)(-(long)num) : num);
        if (resolve?.Invoke(t) is { } va) return new Operand(OpClass.Imm, Applied: va, Symbol: true);
        throw Error(line, $"'{t}' is not a register, a number, or a known symbol.");
    }

    private static Operand ParseMemory(int bitness, int line, string t, Register segment, int? sizeBytes, Func<string, ulong?>? resolve)
    {
        int close = t.IndexOf(']');
        if (!t.StartsWith('[') || close < 0) throw Error(line, $"malformed memory operand '{t}'.");
        var inner = t[1..close].Trim();
        if (inner.Length == 0) throw Error(line, $"empty memory operand '{t}'.");

        Register bse = Register.None, index = Register.None;
        int scale = 1;
        long disp = 0;
        bool haveScaledIndex = false, symbol = false;

        foreach (var (termRaw, sign) in SplitTerms(inner))
        {
            var term = termRaw.Trim();
            if (term.Length == 0) continue;
            int star = term.IndexOf('*');
            if (star >= 0)
            {
                var regText = term[..star].Trim();
                var scaleText = term[(star + 1)..].Trim();
                if (!TryRegister(regText, out var ir) || !ir.IsGPR())
                    throw Error(line, $"'{regText}' is not an index register in '{t}'.");
                if (NativeAddress.Number(scaleText) is not { } sc || sc is not (1 or 2 or 4 or 8))
                    throw Error(line, $"index scale must be 1, 2, 4 or 8 in '{t}'.");
                index = ir; scale = (int)sc; haveScaledIndex = true;
                continue;
            }
            if (TryRegister(term, out var reg) && (reg.IsGPR() || reg == Register.RIP || reg == Register.EIP))
            {
                if (reg == Register.RIP || reg == Register.EIP) { bse = Register.RIP; }
                else if (bse == Register.None && !haveScaledIndex) bse = reg;
                else if (index == Register.None) { index = reg; scale = 1; }
                else throw Error(line, $"too many registers in '{t}'.");
                continue;
            }
            ulong value;
            var dt = term;
            bool dneg = sign < 0;
            if (dt.StartsWith('-')) { dneg = !dneg; dt = dt[1..].Trim(); }
            if (NativeAddress.Number(dt) is { } dn) value = dn;
            else if (resolve?.Invoke(term) is { } va) { value = va; symbol = true; }
            else throw Error(line, $"'{term}' is not a register, a number, or a known symbol in '{t}'.");
            disp += dneg ? -(long)value : (long)value;
        }

        bool rip = bse == Register.RIP;
        // x64 bare [addr] (the disassembler prints RIP-relative operands as absolute targets): SetMem picks the encoding.
        bool autoRip = false, absolute = false;
        if (!rip && bse == Register.None && index == Register.None)
        {
            if (bitness == 64 && segment == Register.None) autoRip = true;
            else absolute = true;
        }
        return new Operand(OpClass.Mem, Base: rip ? Register.RIP : bse, Index: index, Scale: scale,
            Disp: disp, Rip: rip, Segment: segment, SizeBytes: sizeBytes, Absolute: absolute, AutoRip: autoRip, Symbol: symbol);
    }

    private static Instruction Select(int bitness, ulong startVa, int line, string mnemText, Mnemonic mnemonic, Operand[] operands)
    {
        // Forms the disassembler prints like another instruction: 'int 3' is the one-byte breakpoint CC (CD 03 differs for
        // debuggers and in length), 'xchg ax, ax' is the two-byte 66 90.
        if (mnemonic == Mnemonic.Int && operands is [{ Class: OpClass.Imm, Applied: 3 }])
            return Instruction.Create(IcedCode.Int3);
        if (mnemonic == Mnemonic.Xchg && operands is [{ Class: OpClass.Reg, Reg: Register.AX }, { Class: OpClass.Reg, Reg: Register.AX }])
            return Instruction.Create(IcedCode.Nopw);

        var candidates = new List<(Instruction Instr, int Length, int RmRank, IcedCode Code)>();
        var memSizes = new HashSet<int>();
        bool anyMnemonic = false, anyArity = false;

        foreach (var code in CodesFor(mnemonic))
        {
            var oc = code.ToOpCode();
            if (!oc.IsInstruction) continue;
            anyMnemonic = true;
            if (bitness == 64 ? !oc.Mode64 : !oc.Mode32) continue;
            if (oc.OpCount != operands.Length) continue;
            anyArity = true;

            if (!TryBuild(bitness, startVa, code, oc, operands, out var instr)) continue;

            // Validate / collect the memory-operand size.
            int memSize = -1;
            if (operands.Any(o => o.Class == OpClass.Mem))
            {
                int sz = instr.MemorySize.GetInfo().Size;
                memSize = sz;
                var memOp = operands.First(o => o.Class == OpClass.Mem);
                if (sz != 0 && memOp.SizeBytes is { } want && want != sz) continue; // ptr specifier disagrees
                if (sz != 0) memSizes.Add(sz);
            }

            int len = EncodedLength(bitness, startVa, instr, out var encoded);
            if (len < 0) continue;
            // Reject obsolete / undocumented aliases (e.g. the 0F A7 cmpxchg486) whose bytes do not decode back to
            // this instruction; a legitimate form always round-trips through the decoder.
            if (!DecodesBackTo(bitness, encoded, startVa, code)) continue;
            // Prefer putting a register in the modrm.reg slot and the r/m slot in a later operand (the "load" form,
            // e.g. 8B/33 over 89/31) — this is what MSVC emits, so it maximizes byte-identity with Windows binaries.
            int rmRank = 0;
            for (int i = 0; i < operands.Length; i++)
                if (Classify(oc.GetOpKind(i)).Role is Role.Rm or Role.Mem) rmRank += operands.Length - i;
            candidates.Add((instr, len, rmRank, code));
        }

        // Instructions with only implicit operands (monitorx, mwaitx, ...) print those registers as operands: accept
        // the operand-less form when it formats exactly as written.
        if (candidates.Count == 0 && operands.All(o => o.Class == OpClass.Reg))
            foreach (var code in CodesFor(mnemonic))
            {
                var oc = code.ToOpCode();
                if (!oc.IsInstruction || oc.OpCount != 0 || (bitness == 64 ? !oc.Mode64 : !oc.Mode32)) continue;
                var instr = Instruction.Create(code);
                var output = new StringOutput();
                new MasmFormatter().Format(instr, output);
                var written = mnemText + " " + string.Join(", ", operands.Select(o => o.Reg.ToString().ToLowerInvariant()));
                if (string.Equals(Normalize(output.ToStringAndReset()), Normalize(written), StringComparison.OrdinalIgnoreCase))
                    return instr;
            }

        if (candidates.Count == 0)
        {
            if (!anyMnemonic) throw Error(line, $"'{mnemText}' is not an encodable instruction.");
            if (!anyArity) throw Error(line, $"{mnemText} does not take {operands.Length} operand(s) in {bitness}-bit mode.");
            throw Error(line, $"no {mnemText} form matches these operands (check register sizes, or add a size specifier such as 'dword ptr').");
        }

        // If a memory operand has no explicit size and the surviving forms disagree on it, the size is ambiguous.
        var memOperand = operands.FirstOrDefault(o => o.Class == OpClass.Mem);
        if (memOperand is { SizeBytes: null } && memSizes.Count > 1)
            throw Error(line, "operand size is ambiguous: add a size specifier such as 'byte ptr', 'word ptr', 'dword ptr' or 'qword ptr'.");

        // A 16-bit operand-size form (66 prefix) is shorter for immediates, but pushes, pops or truncates a different
        // width: use it only when an operand asks for 16 bits (a 16-bit register or 'word ptr').
        bool wantsWord = operands.Any(o => o.Class == OpClass.Reg && o.Reg.IsGPR16() || o.Class == OpClass.Mem && o.SizeBytes == 2);
        if (!wantsWord && candidates.Any(c => c.Code.ToOpCode().OperandSize != 16))
            candidates.RemoveAll(c => c.Code.ToOpCode().OperandSize == 16);

        // Prefer the shortest encoding; then the MSVC-style operand placement; then the lower Code value.
        candidates.Sort((a, b) =>
            a.Length != b.Length ? a.Length - b.Length :
            a.RmRank != b.RmRank ? a.RmRank - b.RmRank :
            ((int)a.Code).CompareTo((int)b.Code));
        return candidates[0].Instr;
    }

    /// <summary>Collapses whitespace so formatter output and written text compare by tokens.</summary>
    private static string Normalize(string text) => string.Join(" ", text.Replace(",", ", ").Split(' ', StringSplitOptions.RemoveEmptyEntries));

    private static bool TryBuild(int bitness, ulong startVa, IcedCode code, OpCodeInfo oc, Operand[] operands, out Instruction instr)
    {
        instr = default;
        instr.Code = code;
        for (int i = 0; i < operands.Length; i++)
        {
            var spec = Classify(oc.GetOpKind(i));
            var op = operands[i];
            switch (spec.Role)
            {
                case Role.Reg:
                    if (op.Class != OpClass.Reg || !RegClassMatches(op.Reg, spec.RC, spec.RegSize)) return false;
                    SetReg(ref instr, i, op.Reg);
                    break;
                case Role.Rm:
                    if (op.Class == OpClass.Reg)
                    {
                        if (!RegClassMatches(op.Reg, spec.RC, spec.RegSize)) return false;
                        SetReg(ref instr, i, op.Reg);
                    }
                    else if (op.Class == OpClass.Mem) { if (!SetMem(bitness, startVa, ref instr, i, op)) return false; }
                    else return false;
                    break;
                case Role.Mem:
                    if (op.Class != OpClass.Mem) return false;
                    if (!SetMem(bitness, startVa, ref instr, i, op)) return false;
                    break;
                case Role.Fixed:
                    if (op.Class != OpClass.Reg || op.Reg != spec.FixedReg) return false;
                    SetOpKind(ref instr, i, OpKind.Register);
                    SetReg(ref instr, i, op.Reg);
                    break;
                case Role.Imm:
                    if (op.Class != OpClass.Imm || !ImmFits(op.Applied, spec.ImmKind)) return false;
                    SetOpKind(ref instr, i, ImmOpKind(spec.ImmKind));
                    instr.SetImmediate(i, unchecked((long)op.Applied));
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    private static bool SetMem(int bitness, ulong startVa, ref Instruction instr, int i, Operand op)
    {
        SetOpKind(ref instr, i, OpKind.Memory);
        instr.MemoryBase = op.Base;
        instr.MemoryIndex = op.Index;
        instr.MemoryIndexScale = op.Scale;
        instr.SegmentPrefix = op.Segment;
        // An x64 bare [addr]: RIP-relative when reachable from the patch, otherwise a true absolute [disp32].
        bool rip = op.Rip || (op.AutoRip && Reachable((long)startVa, op.Disp));
        if (rip)
        {
            instr.MemoryBase = Register.RIP;
            instr.MemoryDisplacement64 = (ulong)op.Disp;
            instr.MemoryDisplSize = 8;
        }
        else if (op.AutoRip)
        {
            instr.MemoryBase = Register.None;
            instr.MemoryDisplacement64 = (ulong)op.Disp;
            instr.MemoryDisplSize = 8; // x64 SIB absolute disp32
        }
        else if (op.Base == Register.None && op.Index == Register.None)
        {
            instr.MemoryDisplacement64 = (ulong)op.Disp;
            instr.MemoryDisplSize = bitness == 64 ? 8 : 4;
        }
        else if (op.Base == Register.None) // index only -> disp32
        {
            instr.MemoryDisplacement64 = (ulong)op.Disp;
            instr.MemoryDisplSize = 4;
        }
        else
        {
            instr.MemoryDisplacement64 = (ulong)op.Disp;
            instr.MemoryDisplSize = op.Disp == 0 ? 0 : 1; // Iced grows disp8 -> disp32 and forces rbp/r13 as needed
        }
        return true;
    }

    /// <summary>Whether an absolute target is within a RIP-relative disp32 of the patch (with margin for the instruction).</summary>
    private static bool Reachable(long startVa, long target)
    {
        long diff = target - startVa;
        return diff >= int.MinValue + 0x20 && diff <= int.MaxValue - 0x20;
    }

    private static bool DecodesBackTo(int bitness, byte[] bytes, ulong startVa, IcedCode code)
    {
        var dec = Decoder.Create(bitness, new ByteArrayCodeReader(bytes), startVa, DecoderOptions.None);
        var insn = dec.Decode();
        return insn.Code == code;
    }

    private static int EncodedLength(int bitness, ulong startVa, Instruction instr, out byte[] bytes)
    {
        var w = new ByteWriter();
        // Measure at the real patch address so a RIP-relative displacement to a far absolute target still fits int32.
        try { int n = (int)Encoder.Create(bitness, w).Encode(instr, startVa); bytes = w.Bytes.ToArray(); return n; }
        catch (EncoderException) { bytes = []; return -1; }
    }

    private enum Role { Reg, Rm, Mem, Imm, Fixed, Unsupported }
    private enum RC { GPR, XMM, YMM, ZMM, MM, K, SEG, CR, DR, TR, BND, TMM, ST }

    private readonly record struct Spec(Role Role, RC RC = RC.GPR, int RegSize = 0,
        Register FixedReg = Register.None, OpCodeOperandKind ImmKind = OpCodeOperandKind.None);

    private static Spec Classify(OpCodeOperandKind k) => k switch
    {
        OpCodeOperandKind.r8_or_mem => new(Role.Rm, RC.GPR, 1),
        OpCodeOperandKind.r16_or_mem or OpCodeOperandKind.r16_reg_mem => new(Role.Rm, RC.GPR, 2),
        OpCodeOperandKind.r32_or_mem or OpCodeOperandKind.r32_or_mem_mpx or OpCodeOperandKind.r32_reg_mem => new(Role.Rm, RC.GPR, 4),
        OpCodeOperandKind.r64_or_mem or OpCodeOperandKind.r64_or_mem_mpx or OpCodeOperandKind.r64_reg_mem => new(Role.Rm, RC.GPR, 8),
        OpCodeOperandKind.mm_or_mem => new(Role.Rm, RC.MM),
        OpCodeOperandKind.xmm_or_mem => new(Role.Rm, RC.XMM),
        OpCodeOperandKind.ymm_or_mem => new(Role.Rm, RC.YMM),
        OpCodeOperandKind.zmm_or_mem => new(Role.Rm, RC.ZMM),
        OpCodeOperandKind.k_or_mem => new(Role.Rm, RC.K),
        OpCodeOperandKind.bnd_or_mem_mpx => new(Role.Rm, RC.BND),

        OpCodeOperandKind.r8_reg or OpCodeOperandKind.r8_opcode => new(Role.Reg, RC.GPR, 1),
        OpCodeOperandKind.r16_reg or OpCodeOperandKind.r16_rm or OpCodeOperandKind.r16_opcode => new(Role.Reg, RC.GPR, 2),
        OpCodeOperandKind.r32_reg or OpCodeOperandKind.r32_rm or OpCodeOperandKind.r32_opcode or OpCodeOperandKind.r32_vvvv => new(Role.Reg, RC.GPR, 4),
        OpCodeOperandKind.r64_reg or OpCodeOperandKind.r64_rm or OpCodeOperandKind.r64_opcode or OpCodeOperandKind.r64_vvvv => new(Role.Reg, RC.GPR, 8),
        OpCodeOperandKind.seg_reg => new(Role.Reg, RC.SEG),
        OpCodeOperandKind.k_reg or OpCodeOperandKind.kp1_reg or OpCodeOperandKind.k_rm or OpCodeOperandKind.k_vvvv => new(Role.Reg, RC.K),
        OpCodeOperandKind.mm_reg or OpCodeOperandKind.mm_rm => new(Role.Reg, RC.MM),
        OpCodeOperandKind.xmm_reg or OpCodeOperandKind.xmm_rm or OpCodeOperandKind.xmm_vvvv or OpCodeOperandKind.xmm_is4 or OpCodeOperandKind.xmm_is5 => new(Role.Reg, RC.XMM),
        OpCodeOperandKind.ymm_reg or OpCodeOperandKind.ymm_rm or OpCodeOperandKind.ymm_vvvv or OpCodeOperandKind.ymm_is4 or OpCodeOperandKind.ymm_is5 => new(Role.Reg, RC.YMM),
        OpCodeOperandKind.zmm_reg or OpCodeOperandKind.zmm_rm or OpCodeOperandKind.zmm_vvvv => new(Role.Reg, RC.ZMM),
        OpCodeOperandKind.cr_reg => new(Role.Reg, RC.CR),
        OpCodeOperandKind.dr_reg => new(Role.Reg, RC.DR),
        OpCodeOperandKind.tr_reg => new(Role.Reg, RC.TR),
        OpCodeOperandKind.bnd_reg => new(Role.Reg, RC.BND),
        OpCodeOperandKind.sti_opcode => new(Role.Reg, RC.ST),

        OpCodeOperandKind.es => new(Role.Fixed, FixedReg: Register.ES),
        OpCodeOperandKind.cs => new(Role.Fixed, FixedReg: Register.CS),
        OpCodeOperandKind.ss => new(Role.Fixed, FixedReg: Register.SS),
        OpCodeOperandKind.ds => new(Role.Fixed, FixedReg: Register.DS),
        OpCodeOperandKind.fs => new(Role.Fixed, FixedReg: Register.FS),
        OpCodeOperandKind.gs => new(Role.Fixed, FixedReg: Register.GS),
        OpCodeOperandKind.al => new(Role.Fixed, FixedReg: Register.AL),
        OpCodeOperandKind.cl => new(Role.Fixed, FixedReg: Register.CL),
        OpCodeOperandKind.ax => new(Role.Fixed, FixedReg: Register.AX),
        OpCodeOperandKind.dx => new(Role.Fixed, FixedReg: Register.DX),
        OpCodeOperandKind.eax => new(Role.Fixed, FixedReg: Register.EAX),
        OpCodeOperandKind.rax => new(Role.Fixed, FixedReg: Register.RAX),
        OpCodeOperandKind.st0 => new(Role.Fixed, FixedReg: Register.ST0),

        OpCodeOperandKind.mem or OpCodeOperandKind.sibmem or OpCodeOperandKind.mem_mpx or OpCodeOperandKind.mem_mib or OpCodeOperandKind.mem_offs => new(Role.Mem),

        OpCodeOperandKind.imm8 or OpCodeOperandKind.imm8_const_1 or OpCodeOperandKind.imm16 or OpCodeOperandKind.imm32
            or OpCodeOperandKind.imm64 or OpCodeOperandKind.imm8sex16 or OpCodeOperandKind.imm8sex32 or OpCodeOperandKind.imm8sex64
            or OpCodeOperandKind.imm32sex64 or OpCodeOperandKind.imm4_m2z => new(Role.Imm, ImmKind: k),

        _ => new(Role.Unsupported),
    };

    private static bool RegClassMatches(Register r, RC rc, int regSize) => rc switch
    {
        RC.GPR => r.IsGPR() && r.GetInfo().Size == regSize,
        RC.XMM => r.IsXMM(),
        RC.YMM => r.IsYMM(),
        RC.ZMM => r.IsZMM(),
        RC.MM => r.IsMM(),
        RC.K => r.IsK(),
        RC.SEG => r.IsSegmentRegister(),
        RC.CR => r.IsCR(),
        RC.DR => r.IsDR(),
        RC.TR => r.IsTR(),
        RC.BND => r.IsBND(),
        RC.TMM => r.IsTMM(),
        RC.ST => r >= Register.ST0 && r <= Register.ST7,
        _ => false,
    };

    private static (int Src, int Dst) ImmBits(OpCodeOperandKind k) => k switch
    {
        OpCodeOperandKind.imm8 or OpCodeOperandKind.imm8_const_1 or OpCodeOperandKind.imm4_m2z => (8, 8),
        OpCodeOperandKind.imm8sex16 => (8, 16),
        OpCodeOperandKind.imm8sex32 => (8, 32),
        OpCodeOperandKind.imm8sex64 => (8, 64),
        OpCodeOperandKind.imm16 => (16, 16),
        OpCodeOperandKind.imm32 => (32, 32),
        OpCodeOperandKind.imm32sex64 => (32, 64),
        OpCodeOperandKind.imm64 => (64, 64),
        _ => (64, 64),
    };

    private static bool ImmFits(ulong applied, OpCodeOperandKind k)
    {
        if (k == OpCodeOperandKind.imm8_const_1) return applied == 1;
        if (k == OpCodeOperandKind.imm4_m2z) return applied < 16;
        var (src, dst) = ImmBits(k);
        if (dst == 64)
        {
            long sv = unchecked((long)applied);
            return src switch { 8 => sv is >= sbyte.MinValue and <= sbyte.MaxValue, 32 => sv is >= int.MinValue and <= int.MaxValue, _ => true };
        }
        ulong dstMask = (1UL << dst) - 1;
        ulong v = applied & dstMask;
        bool neg = (v & (1UL << (dst - 1))) != 0;
        long val = neg ? (long)(v | ~dstMask) : (long)v;
        if (src == dst) return (applied & ~dstMask) == 0 || (applied | dstMask) == ~0UL; // fits unsigned or sign-filled
        long lim = 1L << (src - 1);
        return val >= -lim && val < lim;
    }

    private static OpKind ImmOpKind(OpCodeOperandKind k) => k switch
    {
        OpCodeOperandKind.imm8 or OpCodeOperandKind.imm8_const_1 or OpCodeOperandKind.imm4_m2z => OpKind.Immediate8,
        OpCodeOperandKind.imm8sex16 => OpKind.Immediate8to16,
        OpCodeOperandKind.imm8sex32 => OpKind.Immediate8to32,
        OpCodeOperandKind.imm8sex64 => OpKind.Immediate8to64,
        OpCodeOperandKind.imm16 => OpKind.Immediate16,
        OpCodeOperandKind.imm32 => OpKind.Immediate32,
        OpCodeOperandKind.imm32sex64 => OpKind.Immediate32to64,
        OpCodeOperandKind.imm64 => OpKind.Immediate64,
        _ => OpKind.Immediate32,
    };

    private static void SetOpKind(ref Instruction instr, int i, OpKind kind)
    {
        switch (i) { case 0: instr.Op0Kind = kind; break; case 1: instr.Op1Kind = kind; break; case 2: instr.Op2Kind = kind; break; case 3: instr.Op3Kind = kind; break; default: instr.Op4Kind = kind; break; }
    }

    private static void SetReg(ref Instruction instr, int i, Register reg)
    {
        SetOpKind(ref instr, i, OpKind.Register);
        switch (i) { case 0: instr.Op0Register = reg; break; case 1: instr.Op1Register = reg; break; case 2: instr.Op2Register = reg; break; case 3: instr.Op3Register = reg; break; default: instr.Op4Register = reg; break; }
    }

    private static Dictionary<Mnemonic, IcedCode[]>? _codesByMnemonic;

    private static IcedCode[] CodesFor(Mnemonic m)
    {
        var map = _codesByMnemonic ??= BuildCodeMap();
        return map.TryGetValue(m, out var codes) ? codes : [];
    }

    private static Dictionary<Mnemonic, IcedCode[]> BuildCodeMap()
    {
        var map = new Dictionary<Mnemonic, List<IcedCode>>();
        foreach (IcedCode c in Enum.GetValues<IcedCode>())
        {
            if (c == IcedCode.INVALID) continue;
            var m = c.Mnemonic();
            if (!map.TryGetValue(m, out var list)) map[m] = list = new();
            list.Add(c);
        }
        return map.ToDictionary(kv => kv.Key, kv => kv.Value.ToArray());
    }

    private static Mnemonic MapMnemonic(string m)
    {
        if (Aliases.TryGetValue(m, out var alias)) return alias;
        return Enum.TryParse<Mnemonic>(m, ignoreCase: true, out var mn) ? mn : Mnemonic.INVALID;
    }

    private static readonly Dictionary<string, Mnemonic> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["jz"] = Mnemonic.Je, ["jnz"] = Mnemonic.Jne,
        ["jc"] = Mnemonic.Jb, ["jnc"] = Mnemonic.Jae,
        ["jnae"] = Mnemonic.Jb, ["jnb"] = Mnemonic.Jae, ["jna"] = Mnemonic.Jbe, ["jnbe"] = Mnemonic.Ja,
        ["jng"] = Mnemonic.Jle, ["jnge"] = Mnemonic.Jl, ["jnl"] = Mnemonic.Jge, ["jnle"] = Mnemonic.Jg,
        ["jpe"] = Mnemonic.Jp, ["jpo"] = Mnemonic.Jnp,
        ["sal"] = Mnemonic.Shl, ["retn"] = Mnemonic.Ret, ["wait"] = Mnemonic.Wait, ["fwait"] = Mnemonic.Wait,
        ["setz"] = Mnemonic.Sete, ["setnz"] = Mnemonic.Setne, ["setc"] = Mnemonic.Setb, ["setnc"] = Mnemonic.Setae,
        ["setnae"] = Mnemonic.Setb, ["setnb"] = Mnemonic.Setae, ["setna"] = Mnemonic.Setbe, ["setnbe"] = Mnemonic.Seta,
        ["setng"] = Mnemonic.Setle, ["setnge"] = Mnemonic.Setl, ["setnl"] = Mnemonic.Setge, ["setnle"] = Mnemonic.Setg,
        ["setpe"] = Mnemonic.Setp, ["setpo"] = Mnemonic.Setnp,
        ["cmovz"] = Mnemonic.Cmove, ["cmovnz"] = Mnemonic.Cmovne, ["cmovc"] = Mnemonic.Cmovb, ["cmovnc"] = Mnemonic.Cmovae,
        ["cmovnae"] = Mnemonic.Cmovb, ["cmovnb"] = Mnemonic.Cmovae, ["cmovna"] = Mnemonic.Cmovbe, ["cmovnbe"] = Mnemonic.Cmova,
        ["cmovng"] = Mnemonic.Cmovle, ["cmovnge"] = Mnemonic.Cmovl, ["cmovnl"] = Mnemonic.Cmovge, ["cmovnle"] = Mnemonic.Cmovg,
        ["cmovpe"] = Mnemonic.Cmovp, ["cmovpo"] = Mnemonic.Cmovnp,
        ["xlat"] = Mnemonic.Xlatb,
    };

    private static bool IsBranchMnemonic(Mnemonic m) => m is Mnemonic.Jmp or Mnemonic.Call
        or Mnemonic.Je or Mnemonic.Jne or Mnemonic.Ja or Mnemonic.Jae or Mnemonic.Jb or Mnemonic.Jbe
        or Mnemonic.Jg or Mnemonic.Jge or Mnemonic.Jl or Mnemonic.Jle or Mnemonic.Jo or Mnemonic.Jno
        or Mnemonic.Js or Mnemonic.Jns or Mnemonic.Jp or Mnemonic.Jnp
        or Mnemonic.Jcxz or Mnemonic.Jecxz or Mnemonic.Jrcxz
        or Mnemonic.Loop or Mnemonic.Loope or Mnemonic.Loopne or Mnemonic.Xbegin;

    private static IcedCode? BranchCode(int bitness, Mnemonic m)
    {
        // Pick the relative form whose address size matches the mode (jrcxz/jecxz have both a 16- and a 64-bit
        // address form in 64-bit mode); among those, the largest displacement, which BlockEncoder shrinks as it fits.
        var want = bitness == 64 ? OpKind.NearBranch64 : OpKind.NearBranch32;
        IcedCode? best = null, fallback = null;
        int bestRel = -1, fbRel = -1;
        foreach (var c in CodesFor(m))
        {
            var oc = c.ToOpCode();
            if (!oc.IsInstruction || oc.OpCount != 1) continue;
            if (bitness == 64 ? !oc.Mode64 : !oc.Mode32) continue;
            int rel = oc.GetOpKind(0) switch
            {
                OpCodeOperandKind.br16_1 or OpCodeOperandKind.br32_1 or OpCodeOperandKind.br64_1 => 1,
                OpCodeOperandKind.br16_2 or OpCodeOperandKind.brdisp_2 or OpCodeOperandKind.xbegin_2 => 2,
                OpCodeOperandKind.br32_4 or OpCodeOperandKind.br64_4 or OpCodeOperandKind.brdisp_4 or OpCodeOperandKind.xbegin_4 => 4,
                _ => -1,
            };
            if (rel < 0) continue;
            if (fallback == null || rel > fbRel) { fbRel = rel; fallback = c; }
            if (Instruction.CreateBranch(c, 0).Op0Kind == want && rel > bestRel) { bestRel = rel; best = c; }
        }
        return best ?? fallback;
    }

    private static Instruction? StringOp(int bitness, string m, bool rep, bool repne)
    {
        var rk = rep ? RepPrefixKind.Repe : repne ? RepPrefixKind.Repne : RepPrefixKind.None;
        int asz = bitness; // address size follows the mode (no explicit a16/a32 override support)
        const Register seg = Register.None;
        return m switch
        {
            "movsb" => Instruction.CreateMovsb(asz, seg, rk),
            "movsw" => Instruction.CreateMovsw(asz, seg, rk),
            "movsd" => Instruction.CreateMovsd(asz, seg, rk),
            "movsq" => Instruction.CreateMovsq(asz, seg, rk),
            "stosb" => Instruction.CreateStosb(asz, rk),
            "stosw" => Instruction.CreateStosw(asz, rk),
            "stosd" => Instruction.CreateStosd(asz, rk),
            "stosq" => Instruction.CreateStosq(asz, rk),
            "lodsb" => Instruction.CreateLodsb(asz, seg, rk),
            "lodsw" => Instruction.CreateLodsw(asz, seg, rk),
            "lodsd" => Instruction.CreateLodsd(asz, seg, rk),
            "lodsq" => Instruction.CreateLodsq(asz, seg, rk),
            "scasb" => Instruction.CreateScasb(asz, rk),
            "scasw" => Instruction.CreateScasw(asz, rk),
            "scasd" => Instruction.CreateScasd(asz, rk),
            "scasq" => Instruction.CreateScasq(asz, rk),
            "cmpsb" => Instruction.CreateCmpsb(asz, seg, rk),
            "cmpsw" => Instruction.CreateCmpsw(asz, seg, rk),
            "cmpsd" => Instruction.CreateCmpsd(asz, seg, rk),
            "cmpsq" => Instruction.CreateCmpsq(asz, seg, rk),
            _ => null,
        };
    }

    private static readonly (string Word, int Bytes)[] SizeWords =
    [
        ("byte ptr", 1), ("word ptr", 2), ("dword ptr", 4), ("qword ptr", 8), ("tbyte ptr", 10),
        ("fword ptr", 6), ("mmword ptr", 8), ("xmmword ptr", 16), ("ymmword ptr", 32), ("zmmword ptr", 64),
        ("oword ptr", 16), ("tword ptr", 10),
    ];

    private static bool LooksLikeRegOrMem(string op)
    {
        var t = op.Trim();
        if (t.Contains('[')) return true;
        foreach (var (w, _) in SizeWords) if (t.StartsWith(w, StringComparison.OrdinalIgnoreCase)) return true;
        return TryRegister(t, out _);
    }

    private static bool TryRegister(string text, out Register reg)
    {
        reg = Register.None;
        var t = text.Trim();
        if (t.Length == 0 || !char.IsLetter(t[0])) return false; // reject numbers: Enum.TryParse would read them as enum values
        // st(0) -> st0, st -> st0
        if (t.Equals("st", StringComparison.OrdinalIgnoreCase)) t = "st0";
        else if (t.StartsWith("st(", StringComparison.OrdinalIgnoreCase) && t.EndsWith(')')) t = "st" + t[3..^1].Trim();
        // r8b..r15b -> r8l..r15l (Iced names the low byte 'l')
        if (t.Length is 3 or 4 && (t[0] is 'r' or 'R') && (t[^1] is 'b' or 'B') && char.IsDigit(t[1]))
            t = t[..^1] + "l";
        if (!Enum.TryParse<Register>(t, ignoreCase: true, out var r) || r == Register.None) return false;
        reg = r;
        return true;
    }

    private static string[] SplitOperands(string rest)
    {
        if (rest.Length == 0) return [];
        var result = new List<string>();
        int depth = 0, start = 0;
        for (int i = 0; i < rest.Length; i++)
        {
            char c = rest[i];
            if (c is '[' or '(') depth++;
            else if (c is ']' or ')') depth--;
            else if (c == ',' && depth == 0) { result.Add(rest[start..i].Trim()); start = i + 1; }
        }
        result.Add(rest[start..].Trim());
        return result.Where(s => s.Length > 0).ToArray();
    }

    private static IEnumerable<(string Term, int Sign)> SplitTerms(string inner)
    {
        int start = 0, sign = 1;
        for (int i = 0; i < inner.Length; i++)
        {
            char c = inner[i];
            if ((c == '+' || c == '-') && i > start)
            {
                yield return (inner[start..i], sign);
                sign = c == '-' ? -1 : 1;
                start = i + 1;
            }
        }
        if (start < inner.Length) yield return (inner[start..], sign);
    }

    private static byte[] ParseDb(int line, string rest)
    {
        // Accept "db 90 cc c3", "db 0x90, 0xCC" or "db 0x90cc".
        var tokens = rest.Replace(",", " ").Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
        var bytes = new List<byte>();
        foreach (var tok in tokens)
        {
            var t = tok.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? tok[2..] : tok;
            if (t.Length == 0 || t.Length % 2 != 0 || !t.All(Uri.IsHexDigit))
                throw Error(line, $"'{tok}' is not a hex byte sequence.");
            for (int i = 0; i < t.Length; i += 2) bytes.Add(Convert.ToByte(t.Substring(i, 2), 16));
        }
        if (bytes.Count == 0) throw Error(line, "db needs at least one byte.");
        return bytes.ToArray();
    }

    private static string StripComment(string line)
    {
        int c = line.IndexOf(';');
        return c < 0 ? line : line[..c];
    }

    /// <summary>Index of a label-defining ':' (a leading identifier directly followed by ':'), or -1.</summary>
    private static int LabelColon(string line)
    {
        int i = 0;
        while (i < line.Length && (char.IsLetterOrDigit(line[i]) || line[i] is '_' or '$' or '@' or '.')) i++;
        return i > 0 && i < line.Length && line[i] == ':' ? i : -1;
    }

    private static bool IsName(string s) => s.Length > 0 && (char.IsLetter(s[0]) || s[0] is '_' or '.')
        && s.All(c => char.IsLetterOrDigit(c) || c is '_' or '$' or '@' or '.');

    private static string CleanError(string? err)
    {
        if (string.IsNullOrWhiteSpace(err)) return "the operands could not be encoded at this address.";
        // BlockEncoder appends the formatted instruction after a ':'; keep the diagnostic part.
        int colon = err.IndexOf(" : ", StringComparison.Ordinal);
        return colon > 0 ? err[..colon] : err;
    }

    private static ToolError Error(int line, string message) =>
        new(ErrorCode.InvalidArgument, $"Assembly error on line {line}: {message}");
}
