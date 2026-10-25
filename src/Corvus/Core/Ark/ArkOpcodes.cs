using System.Buffers.Binary;

namespace Corvus.Core.Ark;

/// <summary>An operand's encoding: kind letter (v register, u/i immediate, f double, j jump, s string, m method, l literal array) and width in bits.</summary>
internal readonly record struct ArkOperandType(char Kind, int Bits);

/// <summary>One instruction encoding: prefix byte (0 for none), opcode byte, mnemonic and operands.</summary>
internal sealed record ArkOperation(byte Prefix, byte Code, string Name, ArkOperandType[] Operands)
{
    /// <summary>Encoded size in bytes: opcode, prefix and operands; two 4-bit operands share a byte.</summary>
    public int Size { get; } = (Prefix != 0 ? 2 : 1) + (Operands.Sum(o => o.Bits) + 7) / 8;

    public bool IsJump => Operands.Length == 1 && Operands[0].Kind == 'j';
}

/// <summary>A decoded instruction: offset in the body, its encoding and operand values (ids and jumps as raw numbers).</summary>
internal sealed record ArkInstruction(int Offset, ArkOperation Operation, long[] Values, double? Double)
{
    public int Size => Operation.Size;
}

/// <summary>The dynamic (ECMAScript) Ark instruction set, generated from the vendor's isa.yaml (ArkOpcodes.g.cs).</summary>
internal static partial class ArkOpcodes
{
    private static readonly ArkOperation?[] Plain = new ArkOperation?[256];
    private static readonly Dictionary<byte, ArkOperation?[]> Prefixed = [];

    static ArkOpcodes()
    {
        foreach (var raw in Table.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = raw.Split(' ');
            byte prefix = parts[0] == "--" ? (byte)0 : Convert.ToByte(parts[0], 16), code = Convert.ToByte(parts[1], 16);
            var operands = parts.Skip(3).Select(p => new ArkOperandType(p[0], int.Parse(p.AsSpan(1)))).ToArray();
            var op = new ArkOperation(prefix, code, parts[2], operands);
            if (prefix == 0) Plain[code] = op;
            else
            {
                if (!Prefixed.TryGetValue(prefix, out var table)) Prefixed[prefix] = table = new ArkOperation?[256];
                table[code] = op;
            }
        }
    }

    /// <summary>The encoding at <paramref name="at"/>; null for an undefined opcode or one cut short.</summary>
    public static ArkOperation? At(ReadOnlySpan<byte> code, int at)
    {
        if (at >= code.Length) return null;
        if (Prefixed.TryGetValue(code[at], out var table)) return at + 1 < code.Length ? table[code[at + 1]] : null;
        return Plain[code[at]];
    }

    /// <summary>
    /// The instructions of a method body in order; decoding stops at an undefined opcode or a truncated instruction,
    /// and <paramref name="stopped"/> names the offset (-1 when the whole body decoded).
    /// </summary>
    public static List<ArkInstruction> Decode(ReadOnlySpan<byte> code, out int stopped)
    {
        var list = new List<ArkInstruction>();
        stopped = -1;
        for (int pc = 0; pc < code.Length;)
        {
            var op = At(code, pc);
            if (op == null || pc + op.Size > code.Length) { stopped = pc; break; }
            int p = pc + (op.Prefix != 0 ? 2 : 1);
            var values = new long[op.Operands.Length];
            double? dbl = null;
            for (int i = 0; i < op.Operands.Length; i++)
            {
                var t = op.Operands[i];
                if (t.Bits == 4)
                {
                    // Two 4-bit operands share a byte, the first in the low nibble.
                    values[i] = (code[p] >> (i % 2 == 0 ? 0 : 4)) & 0xF;
                    if (i % 2 == 1 || i == op.Operands.Length - 1) p++;
                    continue;
                }
                var bytes = code.Slice(p, t.Bits / 8);
                values[i] = (t.Bits, t.Kind is 'i' or 'j') switch
                {
                    (8, true) => (sbyte)bytes[0],
                    (8, false) => bytes[0],
                    (16, true) => BinaryPrimitives.ReadInt16LittleEndian(bytes),
                    (16, false) => BinaryPrimitives.ReadUInt16LittleEndian(bytes),
                    (32, true) => BinaryPrimitives.ReadInt32LittleEndian(bytes),
                    (32, false) => BinaryPrimitives.ReadUInt32LittleEndian(bytes),
                    _ => BinaryPrimitives.ReadInt64LittleEndian(bytes),
                };
                if (t.Kind == 'f') dbl = BitConverter.Int64BitsToDouble(values[i]);
                p += t.Bits / 8;
            }
            list.Add(new ArkInstruction(pc, op, values, dbl));
            pc += op.Size;
        }
        return list;
    }
}
