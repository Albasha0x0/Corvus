using System.Globalization;

namespace Corvus.Core.Python;

/// <summary>One CPython release's opcodes: each opcode's name, argument kinds and inline cache entries.</summary>
internal sealed partial class PyOpcodes
{
    [Flags]
    public enum Kinds : ushort
    {
        None = 0, Const = 1, Name = 2, JumpRelative = 4, JumpAbsolute = 8, Local = 16, Compare = 32, Free = 64, HasArgument = 128, Backward = 256,
    }

    private sealed record Release(string Version, string Changes, int? HaveArgument = null, string[]? CompareOps = null, string[]? BinaryOps = null,
        string[]? Intrinsic1 = null, string[]? Intrinsic2 = null);

    private static readonly Lazy<Dictionary<(int, int), PyOpcodes>> Tables = new(Build);

    private readonly string?[] _names = new string?[256];
    private readonly Kinds[] _kinds = new Kinds[256];
    private readonly byte[] _caches = new byte[256];
    private readonly Dictionary<string, int> _ops = new(StringComparer.Ordinal);

    public (int Major, int Minor) Version { get; private init; }
    /// <summary>Opcodes from this one up take an argument (before 3.12, where each opcode says so).</summary>
    public int HaveArgument { get; private init; }
    public string[] CompareOps { get; private init; } = [];
    public string[] BinaryOps { get; private init; } = [];
    public string[] Intrinsic1 { get; private init; } = [];
    public string[] Intrinsic2 { get; private init; } = [];

    /// <summary>The table of <paramref name="version"/>; null outside 2.7 and 3.0 to 3.13.</summary>
    public static PyOpcodes? For((int Major, int Minor) version) => Tables.Value.GetValueOrDefault(version);

    /// <summary>The opcode named <paramref name="name"/>, or -1 when this release has none.</summary>
    public int Op(string name) => _ops.GetValueOrDefault(name, -1);

    /// <summary>The name dis prints: unknown opcodes read &lt;N&gt;.</summary>
    public string Name(int op) => _names[op] ?? $"<{op}>";

    public bool Is(int op, Kinds kind) => (_kinds[op] & kind) != 0;
    public int Caches(int op) => _caches[op];
    public bool HasArgument(int op) => PyVersion.AtLeast(Version, 3, 12) ? Is(op, Kinds.HasArgument) : op >= HaveArgument;

    private static Dictionary<(int, int), PyOpcodes> Build()
    {
        var tables = new Dictionary<(int, int), PyOpcodes>();
        var ops = new Dictionary<string, (int Op, Kinds Kinds, byte Caches)>(StringComparer.Ordinal);
        int have = 90;
        string[] compare = [], binary = [], intrinsic1 = [], intrinsic2 = [];
        foreach (var r in History)
        {
            foreach (var token in r.Changes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (token[0] == '-')
                {
                    ops.Remove(token[1..]);
                    continue;
                }
                int eq = token.LastIndexOf('=');
                var rest = token[(eq + 1)..];
                byte caches = 0;
                if (rest.IndexOf('/') is var slash and >= 0)
                {
                    caches = byte.Parse(rest[(slash + 1)..], CultureInfo.InvariantCulture);
                    rest = rest[..slash];
                }
                int digits = 0;
                while (digits < rest.Length && char.IsAsciiDigit(rest[digits])) digits++;
                var kinds = Kinds.None;
                foreach (var c in rest[digits..])
                    kinds |= c switch
                    {
                        'c' => Kinds.Const, 'n' => Kinds.Name, 'r' => Kinds.JumpRelative, 'a' => Kinds.JumpAbsolute, 'l' => Kinds.Local,
                        'm' => Kinds.Compare, 'f' => Kinds.Free, 'g' => Kinds.HasArgument, 'b' => Kinds.Backward, _ => Kinds.None,
                    };
                ops[token[..eq]] = (int.Parse(rest[..digits], CultureInfo.InvariantCulture), kinds, caches);
            }
            have = r.HaveArgument ?? have;
            compare = r.CompareOps ?? compare;
            binary = r.BinaryOps ?? binary;
            intrinsic1 = r.Intrinsic1 ?? intrinsic1;
            intrinsic2 = r.Intrinsic2 ?? intrinsic2;
            var parts = r.Version.Split('.');
            var t = new PyOpcodes
            {
                Version = (int.Parse(parts[0], CultureInfo.InvariantCulture), int.Parse(parts[1], CultureInfo.InvariantCulture)),
                HaveArgument = have, CompareOps = compare, BinaryOps = binary, Intrinsic1 = intrinsic1, Intrinsic2 = intrinsic2,
            };
            foreach (var (name, (op, kinds, caches)) in ops)
            {
                t._names[op] = name;
                t._kinds[op] = kinds;
                t._caches[op] = caches;
                t._ops[name] = op;
            }
            tables[t.Version] = t;
        }
        return tables;
    }
}
