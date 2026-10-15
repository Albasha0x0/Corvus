using System.Collections.Frozen;

namespace Corvus.Core.Hermes;

/// <summary>An operand's encoding, as BytecodeList.def names it.</summary>
public enum HermesOperandType : byte { Reg8, Reg32, UInt8, UInt16, UInt32, Addr8, Addr32, Imm32, Double }

/// <summary>What an id operand indexes: nothing, the string table, the function table or the bigint table.</summary>
public enum HermesIdKind : byte { None, String, Function, BigInt }

public readonly record struct HermesOperand(HermesOperandType Type, HermesIdKind Id)
{
    public int Size => Type switch
    {
        HermesOperandType.Reg8 or HermesOperandType.UInt8 or HermesOperandType.Addr8 => 1,
        HermesOperandType.UInt16 => 2,
        HermesOperandType.Double => 8,
        _ => 4,
    };

    public bool IsJump => Type is HermesOperandType.Addr8 or HermesOperandType.Addr32;
    public bool IsRegister => Type is HermesOperandType.Reg8 or HermesOperandType.Reg32;
}

/// <summary>One opcode of a bytecode version: its number, name, operands and encoded size (opcode byte included).</summary>
public sealed record HermesOperation(byte Code, string Name, HermesOperand[] Operands)
{
    public int Size { get; } = 1 + Operands.Sum(o => o.Size);

    /// <summary>Jmp*, J* compare-and-jump, SaveGenerator: the first operand is a relative target.</summary>
    public bool IsJump => Operands.Length > 0 && Operands[0].IsJump;
}

/// <summary>The opcode table and builtin names of one bytecode version.</summary>
public sealed class HermesOpcodeTable
{
    private readonly HermesOperation?[] _byCode = new HermesOperation?[256];
    private readonly FrozenDictionary<string, HermesOperation> _byName;

    /// <summary>The version the table was generated for; differs from the file's when the nearest older table is used.</summary>
    public int Version { get; }
    public IReadOnlyList<string> Builtins { get; }

    internal HermesOpcodeTable(int version, IEnumerable<HermesOperation> operations, IReadOnlyList<string> builtins)
    {
        Version = version;
        foreach (var op in operations) _byCode[op.Code] = op;
        _byName = _byCode.OfType<HermesOperation>().ToFrozenDictionary(o => o.Name, StringComparer.Ordinal);
        Builtins = builtins;
    }

    public HermesOperation? this[byte code] => _byCode[code];
    public HermesOperation? Find(string name) => _byName.GetValueOrDefault(name);
    public int Count => _byName.Count;
}

/// <summary>Opcode tables per bytecode version, generated from Hermes's BytecodeList.def (HermesOpcodes.g.cs).</summary>
internal static partial class HermesOpcodes
{
    /// <summary>The oldest and newest bytecode versions with a table; a version between two tables reads with the older one.</summary>
    public const int Oldest = 59, Newest = 96;

    private static readonly Lazy<SortedDictionary<int, HermesOpcodeTable>> All = new(Build);

    /// <summary>Versions with a table of their own (released Hermes compilers).</summary>
    public static IReadOnlyCollection<int> Versions => All.Value.Keys;

    /// <summary>The table for <paramref name="version"/>: its own, else the nearest older one (exact=false); null outside 59–96.</summary>
    public static HermesOpcodeTable? For(int version, out bool exact)
    {
        exact = false;
        if (version < Oldest || version > Newest) return null;
        HermesOpcodeTable? found = null;
        foreach (var (v, t) in All.Value)
        {
            if (v > version) break;
            found = t;
            exact = v == version;
        }
        return found;
    }

    // closures and direct calls name a function; versions before 89 do not mark it in BytecodeList.def
    private static readonly FrozenDictionary<string, int> FunctionOperands = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["CreateClosure"] = 2, ["CreateClosureLongIndex"] = 2, ["CreateGeneratorClosure"] = 2, ["CreateGeneratorClosureLongIndex"] = 2,
        ["CreateAsyncClosure"] = 2, ["CreateAsyncClosureLongIndex"] = 2, ["CreateGenerator"] = 2, ["CreateGeneratorLongIndex"] = 2,
        ["CallDirect"] = 2, ["CallDirectLongIndex"] = 2,
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static SortedDictionary<int, HermesOpcodeTable> Build()
    {
        var builtins = new Dictionary<int, string[]>();
        foreach (var (versions, names) in BuiltinTables)
            foreach (var v in versions) builtins[v] = names.Split(' ');
        var result = new SortedDictionary<int, HermesOpcodeTable>();
        foreach (var (versions, table) in Tables)
        {
            var ops = new List<HermesOperation>();
            foreach (var line in table.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split(' ');
                var operands = parts.Skip(1).Select(Operand).ToArray();
                if (FunctionOperands.TryGetValue(parts[0], out var index) && index < operands.Length)
                    operands[index] = operands[index] with { Id = HermesIdKind.Function };
                ops.Add(new HermesOperation((byte)ops.Count, parts[0], operands));
            }
            foreach (var v in versions) result[v] = new HermesOpcodeTable(v, ops, builtins.GetValueOrDefault(v) ?? []);
        }
        return result;
    }

    private static HermesOperand Operand(string s) => new(s[0] switch
    {
        'r' => HermesOperandType.Reg8, 'R' => HermesOperandType.Reg32, 'b' => HermesOperandType.UInt8, 'h' => HermesOperandType.UInt16,
        'w' => HermesOperandType.UInt32, 'j' => HermesOperandType.Addr8, 'J' => HermesOperandType.Addr32, 'i' => HermesOperandType.Imm32,
        _ => HermesOperandType.Double,
    }, s.Length < 2 ? HermesIdKind.None : s[1] switch { '$' => HermesIdKind.String, '@' => HermesIdKind.Function, _ => HermesIdKind.BigInt });
}
