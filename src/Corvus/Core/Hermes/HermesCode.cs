using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Corvus.Core.Hermes;

/// <summary>
/// One decoded instruction: its offset in the function, the operation and up to six operand values (registers, immediates,
/// ids and jump targets as absolute offsets in the function; a Double operand's bits in <see cref="Double"/>).
/// </summary>
public readonly struct HermesInstruction
{
    public int Offset { get; init; }
    public HermesOperation Op { get; init; }
    public long A { get; init; }
    public long B { get; init; }
    public long C { get; init; }
    public long D { get; init; }
    public long E { get; init; }
    public long F { get; init; }
    public double Double { get; init; }

    public int Size => Op.Size;
    public int End => Offset + Op.Size;
    public string Name => Op.Name;

    public long this[int i] => i switch { 0 => A, 1 => B, 2 => C, 3 => D, 4 => E, _ => F };
}

/// <summary>A SwitchImm jump table: the case values min..max, each case's target and the default, as offsets in the function.</summary>
public sealed record HermesSwitch(int Offset, long Min, long Max, int Default, int[] Targets);

/// <summary>Decodes a function's bytecode with the file's opcode table; SwitchImm jump tables after the code are read, not decoded.</summary>
public static class HermesCode
{
    /// <summary>The instructions of <paramref name="f"/>; an unknown opcode or a truncated instruction ends the list with an issue.</summary>
    public static List<HermesInstruction> Decode(HermesFile file, HermesFunction f, List<string>? issues = null, List<HermesSwitch>? switches = null)
    {
        var list = new List<HermesInstruction>(Math.Max(4, f.Size / 3));
        if (file.Opcodes is not { } table || f.Size == 0) return list;
        var code = file.Bytes.Span.Slice(f.Offset, f.Size);
        int end = code.Length, at = 0;
        Span<long> v = stackalloc long[6];
        while (at < end)
        {
            var op = table[code[at]];
            if (op == null) { issues?.Add($"function {f.Index}: unknown opcode 0x{code[at]:x2} at offset {at}"); break; }
            if (at + op.Size > code.Length) { issues?.Add($"function {f.Index}: {op.Name} at offset {at} runs past the function"); break; }
            v.Clear();
            double d = 0;
            int p = at + 1;
            for (int i = 0; i < op.Operands.Length; i++)
            {
                var o = op.Operands[i];
                var s = code[p..];
                v[i] = o.Type switch
                {
                    HermesOperandType.Reg8 or HermesOperandType.UInt8 => s[0],
                    HermesOperandType.Addr8 => at + (sbyte)s[0],
                    HermesOperandType.UInt16 => BinaryPrimitives.ReadUInt16LittleEndian(s),
                    HermesOperandType.Reg32 or HermesOperandType.UInt32 => BinaryPrimitives.ReadUInt32LittleEndian(s),
                    HermesOperandType.Addr32 => at + (long)BinaryPrimitives.ReadInt32LittleEndian(s),
                    HermesOperandType.Imm32 => BinaryPrimitives.ReadInt32LittleEndian(s),
                    _ => BinaryPrimitives.ReadInt64LittleEndian(s),
                };
                if (o.Type == HermesOperandType.Double) d = BitConverter.Int64BitsToDouble(v[i]);
                p += o.Size;
            }
            var ins = new HermesInstruction { Offset = at, Op = op, A = v[0], B = v[1], C = v[2], D = v[3], E = v[4], F = v[5], Double = d };
            list.Add(ins);
            if (op.Name == "SwitchImm" && Switch(file.Bytes.Span, ins, f.Offset) is { } sw)
            {
                switches?.Add(sw);
                // a table inside the function's bytes ends its code
                int tableAt = TableAt(ins, f.Offset);
                if (tableAt > at && tableAt < end) end = tableAt;
            }
            at += op.Size;
        }
        return list;
    }

    // the table is aligned in the file (the interpreter aligns the absolute address), not in the function
    private static int TableAt(in HermesInstruction ins, int functionOffset) => (int)(((functionOffset + ins.Offset + ins.B + 3) & ~3L) - functionOffset);

    /// <summary>The jump table of a SwitchImm: read from the file, since it may follow the function's counted bytes.</summary>
    private static HermesSwitch? Switch(ReadOnlySpan<byte> file, in HermesInstruction ins, int functionOffset)
    {
        long min = (uint)ins.D, max = (uint)ins.E;
        long count = max - min + 1;
        long tableAt = functionOffset + (long)TableAt(ins, functionOffset);
        if (count <= 0 || count > 65536 || tableAt < 0 || tableAt + count * 4 > file.Length) return null;
        var targets = new int[count];
        for (int i = 0; i < count; i++) targets[i] = ins.Offset + BinaryPrimitives.ReadInt32LittleEndian(file[(int)(tableAt + i * 4)..]);
        return new HermesSwitch(ins.Offset, min, max, (int)ins.C, targets);
    }

    /// <summary>
    /// One instruction as text: name padded to 18, then operands — registers rN, strings quoted, functions
    /// Function&lt;name&gt;N, jumps as L_offset, builtins by name, doubles as JavaScript numbers.
    /// </summary>
    public static string Text(HermesFile file, in HermesInstruction ins)
    {
        var sb = new StringBuilder();
        sb.Append(ins.Name.Length < 18 ? ins.Name.PadRight(18) : ins.Name + " ");
        var ops = ins.Op.Operands;
        for (int i = 0; i < ops.Length; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append(Operand(file, ins, i));
        }
        return sb.ToString().TrimEnd();
    }

    public static string Operand(HermesFile file, in HermesInstruction ins, int i)
    {
        var o = ins.Op.Operands[i];
        long v = ins[i];
        if (o.IsRegister) return "r" + v.ToString(CultureInfo.InvariantCulture);
        if (o.IsJump) return Label((int)v);
        if (o.Type == HermesOperandType.Double) return Number(ins.Double);
        switch (o.Id)
        {
            case HermesIdKind.String: return file.String(v) is { } s ? Quote(s, 120) : $"string#{v}";
            case HermesIdKind.Function: return $"Function<{file.FunctionName((int)v)}>{v}";
            case HermesIdKind.BigInt: return $"bigint#{v}";
        }
        if (i == 1 && ins.Name is "CallBuiltin" or "CallBuiltinLong" or "GetBuiltinClosure" && file.Opcodes is { } t && v < t.Builtins.Count)
            return t.Builtins[(int)v];
        return v.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Whether the first operand is a register the instruction writes (a destination), not one it only reads.</summary>
    public static bool WritesFirst(HermesOperation op)
    {
        if (op.Operands.Length == 0 || !op.Operands[0].IsRegister) return false;
        var n = op.Name;
        return !(n.StartsWith("Put", StringComparison.Ordinal) || n.StartsWith("TryPut", StringComparison.Ordinal) || n.StartsWith("Store", StringComparison.Ordinal)
                 || n is "Ret" or "Throw" or "SwitchImm" or "IteratorClose" or "ThrowIfUndefinedInst");
    }

    public static string Label(int offset) => "L_" + offset.ToString("x4", CultureInfo.InvariantCulture);

    /// <summary>A double as JavaScript prints it (shortest round-trip, with Infinity and NaN).</summary>
    public static string Number(double d) => double.IsNaN(d) ? "NaN" : double.IsPositiveInfinity(d) ? "Infinity" : double.IsNegativeInfinity(d) ? "-Infinity"
        : d == 0 && double.IsNegative(d) ? "-0" : d.ToString("R", CultureInfo.InvariantCulture).Replace("E+", "e+", StringComparison.Ordinal).Replace("E-", "e-", StringComparison.Ordinal);

    /// <summary>A JavaScript string literal; text past <paramref name="max"/> characters is cut with an ellipsis.</summary>
    public static string Quote(string s, int max = int.MaxValue)
    {
        var sb = new StringBuilder(Math.Min(s.Length, max) + 2).Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            if (i >= max) { sb.Append("\"..."); return sb.ToString(); }
            char ch = s[i];
            sb.Append(ch switch
            {
                '"' => "\\\"", '\\' => "\\\\", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                < ' ' or (>= (char)0x7f and < (char)0xa0) or (char)0x2028 or (char)0x2029 => $"\\u{(int)ch:x4}",
                _ when char.IsSurrogate(ch) && !(char.IsHighSurrogate(ch) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) && !(char.IsLowSurrogate(ch) && i > 0 && char.IsHighSurrogate(s[i - 1])) => $"\\u{(int)ch:x4}",
                _ => ch.ToString(),
            });
        }
        return sb.Append('"').ToString();
    }
}
