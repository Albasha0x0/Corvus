using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using IcedCode = Iced.Intel.Code;

namespace NetDecompilerMcp.Native.Patching;

/// <summary>
/// A small MASM/NASM-ish text assembler for x86 / x64, built on Iced's encoder. It assembles multi-line input at a
/// fixed virtual address so branch displacements and RIP-relative references are correct for that address. Labels,
/// numeric targets and caller-resolved symbols are all valid branch/call targets; a <c>db</c> escape emits raw bytes.
/// The supported mnemonic set is deliberately narrow (control flow, stack, moves, common ALU ops); anything else is
/// rejected with a clear message pointing at <c>db</c>.
/// </summary>
public static class X86Assembler
{
    public sealed record Result(byte[] Bytes);

    private sealed class ByteWriter : CodeWriter
    {
        public readonly List<byte> Bytes = new();
        public override void WriteByte(byte value) => Bytes.Add(value);
    }

    private abstract record Item(int Line);
    private sealed record Raw(int Line, byte[] Bytes) : Item(Line);
    private sealed record Built(int Line, Instruction Instruction, string? TargetLabel) : Item(Line);

    /// <param name="resolveSymbol">Resolves a name that is neither a label nor a number to a VA (e.g. an export).</param>
    public static Result Assemble(NativeArch arch, ulong startVa, string text, Func<string, ulong?>? resolveSymbol = null)
    {
        if (arch is not (NativeArch.X86 or NativeArch.X64))
            throw new ToolError(ErrorCode.Unsupported, $"Assembly is only supported for x86 and x64, not {arch}.");
        int bitness = arch == NativeArch.X64 ? 64 : 32;

        // Pass 1: parse lines, collect label positions by item index.
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
                if (colon >= 0)
                {
                    var label = line[..colon].Trim();
                    if (label.Length == 0 || !IsName(label))
                        throw Error(lineNo, $"'{label}' is not a valid label.");
                    if (!labelIndex.TryAdd(label, items.Count))
                        throw Error(lineNo, $"label '{label}' is defined more than once.");
                    line = line[(colon + 1)..].Trim();
                    continue;
                }
                break;
            }
            if (line.Length == 0) continue;
            items.Add(Parse(bitness, lineNo, line, out _));
        }
        if (items.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, "No instructions to assemble.");

        // Pass 2: iterate to a fixed point, resolving label targets to their current addresses.
        var starts = new ulong[items.Count + 1];
        for (int pass = 0; pass < 8; pass++)
        {
            bool stable = Layout(bitness, startVa, items, labelIndex, resolveSymbol, starts);
            if (stable) break;
        }
        // Final encode.
        Layout(bitness, startVa, items, labelIndex, resolveSymbol, starts);
        var output = new List<byte>();
        for (int i = 0; i < items.Count; i++)
        {
            if (items[i] is Raw raw) { output.AddRange(raw.Bytes); continue; }
            var built = (Built)items[i];
            var instr = WithTarget(bitness, built, labelIndex, resolveSymbol, starts);
            var writer = new ByteWriter();
            try { Encoder.Create(bitness, writer).Encode(instr, starts[i]); }
            catch (EncoderException ex) { throw Error(built.Line, $"cannot encode: {ex.Message}"); }
            output.AddRange(writer.Bytes);
        }
        return new Result(output.ToArray());
    }

    /// <summary>Lays out item start addresses; returns whether they are unchanged from <paramref name="starts"/>.</summary>
    private static bool Layout(int bitness, ulong startVa, List<Item> items, Dictionary<string, int> labels,
        Func<string, ulong?>? resolve, ulong[] starts)
    {
        bool stable = true;
        ulong at = startVa;
        for (int i = 0; i < items.Count; i++)
        {
            if (starts[i] != at) { stable = false; starts[i] = at; }
            int size;
            if (items[i] is Raw raw) size = raw.Bytes.Length;
            else
            {
                var built = (Built)items[i];
                // Near branches/calls are fixed size (rel32), so for sizing we aim the branch at itself to stay in range;
                // the final encode uses the resolved target. This avoids an out-of-range throw while targets settle.
                var instr = built.Instruction;
                if (built.TargetLabel != null) instr.NearBranch64 = at;
                var writer = new ByteWriter();
                try { Encoder.Create(bitness, writer).Encode(instr, at); }
                catch (EncoderException ex) { throw Error(built.Line, $"cannot encode: {ex.Message}"); }
                size = writer.Bytes.Count;
            }
            at += (uint)size;
        }
        if (starts[items.Count] != at) { stable = false; starts[items.Count] = at; }
        return stable;
    }

    private static Instruction WithTarget(int bitness, Built built, Dictionary<string, int> labels,
        Func<string, ulong?>? resolve, ulong[] starts)
    {
        if (built.TargetLabel == null) return built.Instruction;
        ulong target = ResolveTarget(built.Line, built.TargetLabel, labels, resolve, starts);
        var instr = built.Instruction;
        instr.NearBranch64 = target;
        return instr;
    }

    private static ulong ResolveTarget(int line, string token, Dictionary<string, int> labels,
        Func<string, ulong?>? resolve, ulong[] starts)
    {
        if (labels.TryGetValue(token, out var index)) return starts[index];
        if (NativeAddress.Number(token) is { } n) return n;
        if (resolve?.Invoke(token) is { } va) return va;
        throw Error(line, $"branch target '{token}' is neither a label, a number, nor a known symbol.");
    }

    // ---- parsing one instruction ----

    private static Item Parse(int bitness, int line, string text, out string mnemonic)
    {
        int sp = text.IndexOfAny([' ', '\t']);
        mnemonic = (sp < 0 ? text : text[..sp]).ToLowerInvariant();
        var rest = sp < 0 ? "" : text[(sp + 1)..].Trim();
        var ops = rest.Length == 0 ? [] : rest.Split(',').Select(o => o.Trim()).ToArray();

        if (mnemonic == "db") return new Raw(line, ParseDb(line, ops, rest));

        // Zero-operand instructions.
        if (ops.Length == 0 && ZeroOperand(bitness, mnemonic) is { } zcode)
            return new Built(line, Instruction.Create(zcode), null);

        // Near branches / calls.
        if (Branch(bitness, mnemonic) is { } bcode)
        {
            if (ops.Length != 1) throw Error(line, $"{mnemonic} takes one target.");
            // The actual target address is filled in during layout; start with a placeholder near branch.
            return new Built(line, Instruction.CreateBranch(bcode, 0), ops[0]);
        }

        // ret imm16
        if (mnemonic is "ret" or "retn" && ops.Length == 1)
        {
            if (NativeAddress.Number(ops[0]) is not { } imm || imm > ushort.MaxValue) throw Error(line, "ret operand must be a 16-bit immediate.");
            return new Built(line, Instruction.Create(bitness == 64 ? IcedCode.Retnq_imm16 : IcedCode.Retnd_imm16, (int)imm), null);
        }

        // push / pop
        if (mnemonic == "push" && ops.Length == 1)
        {
            if (Reg(ops[0]) is { } pr) return new Built(line, Instruction.Create(bitness == 64 ? IcedCode.Push_r64 : IcedCode.Push_r32, pr.Reg), null);
            if (NativeAddress.Number(ops[0]) is { } imm && imm <= int.MaxValue)
                return new Built(line, Instruction.Create(bitness == 64 ? IcedCode.Pushq_imm32 : IcedCode.Pushd_imm32, (int)imm), null);
            throw Error(line, "push takes a register or a 32-bit immediate (use db for other forms).");
        }
        if (mnemonic == "pop" && ops.Length == 1 && Reg(ops[0]) is { } por)
            return new Built(line, Instruction.Create(bitness == 64 ? IcedCode.Pop_r64 : IcedCode.Pop_r32, por.Reg), null);

        // mov reg, imm | reg, reg
        if (mnemonic == "mov" && ops.Length == 2 && Reg(ops[0]) is { } md)
        {
            if (Reg(ops[1]) is { } ms)
                return new Built(line, Instruction.Create(EnumCode(line, $"Mov_rm{md.Bits}_r{md.Bits}"), md.Reg, ms.Reg), null);
            if (NativeAddress.Number(ops[1]) is { } imm)
                return new Built(line, MovImm(line, md.Reg, md.Bits, imm), null);
            throw Error(line, "mov source must be a register or an immediate (use db for memory forms).");
        }

        // one-operand ALU: inc/dec/neg/not reg
        if (mnemonic is "inc" or "dec" or "neg" or "not" && ops.Length == 1 && Reg(ops[0]) is { } ur)
            return new Built(line, Instruction.Create(EnumCode(line, $"{Cap(mnemonic)}_rm{ur.Bits}"), ur.Reg), null);

        // two-operand ALU: add/sub/and/or/xor/cmp/test reg, reg|imm
        if (mnemonic is "add" or "sub" or "and" or "or" or "xor" or "cmp" or "test" && ops.Length == 2 && Reg(ops[0]) is { } ar)
        {
            if (Reg(ops[1]) is { } asrc)
                return new Built(line, Instruction.Create(EnumCode(line, $"{Cap(mnemonic)}_rm{ar.Bits}_r{ar.Bits}"), ar.Reg, asrc.Reg), null);
            if (NativeAddress.Number(ops[1]) is { } imm && imm <= int.MaxValue)
                return new Built(line, Instruction.Create(EnumCode(line, $"{Cap(mnemonic)}_rm{ar.Bits}_imm{(ar.Bits >= 32 ? 32 : ar.Bits)}"), ar.Reg, (int)imm), null);
            throw Error(line, $"{mnemonic} source must be a register or a 32-bit immediate (use db otherwise).");
        }

        throw Error(line, $"unsupported instruction '{mnemonic}'. Supported: control flow (jmp/call/jcc), ret, push, pop, mov, " +
                          "inc/dec/neg/not, add/sub/and/or/xor/cmp/test, and 'db <hex bytes>' for anything else.");
    }

    private static Instruction MovImm(int line, Register dst, int bits, ulong imm) => bits switch
    {
        64 => Instruction.Create(IcedCode.Mov_r64_imm64, dst, imm),
        32 => Instruction.Create(IcedCode.Mov_r32_imm32, dst, (uint)imm),
        16 => Instruction.Create(IcedCode.Mov_r16_imm16, dst, (uint)(ushort)imm),
        _ => Instruction.Create(IcedCode.Mov_r8_imm8, dst, (uint)(byte)imm),
    };

    private static byte[] ParseDb(int line, string[] ops, string rest)
    {
        // Accept "db 90 cc c3" or "db 0x90, 0xCC" or "db 0x90cc".
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

    private static IcedCode EnumCode(int line, string name) =>
        Enum.TryParse<IcedCode>(name, out var code) ? code : throw Error(line, $"this operand combination is not supported ({name}).");

    private static IcedCode? ZeroOperand(int bitness, string m) => m switch
    {
        "nop" => IcedCode.Nopd,
        "ret" or "retn" => bitness == 64 ? IcedCode.Retnq : IcedCode.Retnd,
        "retf" => bitness == 64 ? IcedCode.Retfq : IcedCode.Retfd,
        "leave" => bitness == 64 ? IcedCode.Leaveq : IcedCode.Leaved,
        "int3" => IcedCode.Int3,
        "ud2" => IcedCode.Ud2,
        "hlt" => IcedCode.Hlt,
        "pause" => IcedCode.Pause,
        "cdq" => IcedCode.Cdq,
        "cqo" => IcedCode.Cqo,
        "cwde" => IcedCode.Cwde,
        "stc" => IcedCode.Stc,
        "clc" => IcedCode.Clc,
        "cld" => IcedCode.Cld,
        "std" => IcedCode.Std,
        "cmc" => IcedCode.Cmc,
        "sti" => IcedCode.Sti,
        "cli" => IcedCode.Cli,
        _ => null,
    };

    private static IcedCode? Branch(int bitness, string m)
    {
        string? baseName = m switch
        {
            "jmp" => "Jmp",
            "call" => "Call",
            "je" or "jz" => "Je",
            "jne" or "jnz" => "Jne",
            "jg" or "jnle" => "Jg",
            "jge" or "jnl" => "Jge",
            "jl" or "jnge" => "Jl",
            "jle" or "jng" => "Jle",
            "ja" or "jnbe" => "Ja",
            "jae" or "jnb" or "jnc" => "Jae",
            "jb" or "jnae" or "jc" => "Jb",
            "jbe" or "jna" => "Jbe",
            "jo" => "Jo",
            "jno" => "Jno",
            "js" => "Js",
            "jns" => "Jns",
            "jp" or "jpe" => "Jp",
            "jnp" or "jpo" => "Jnp",
            _ => null,
        };
        if (baseName == null) return null;
        return Enum.Parse<IcedCode>($"{baseName}_rel32_{bitness}");
    }

    private static (Register Reg, int Bits)? Reg(string text)
    {
        if (!Enum.TryParse<Register>(text.Trim(), ignoreCase: true, out var reg) || reg == Register.None) return null;
        int bits = reg.GetInfo().Size * 8;
        return bits is 8 or 16 or 32 or 64 ? (reg, bits) : null;
    }

    // ---- lexing helpers ----

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

    private static string Cap(string s) => char.ToUpperInvariant(s[0]) + s[1..];

    private static ToolError Error(int line, string message) =>
        new(ErrorCode.InvalidArgument, $"Assembly error on line {line}: {message}");
}
