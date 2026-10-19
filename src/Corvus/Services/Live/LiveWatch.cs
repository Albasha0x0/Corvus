using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Pdb;

namespace Corvus.Services;

/// <summary>
/// One recorded argument: <see cref="Kind"/> is what the session script reads (int, uint, hex, bool, ptr, cstr, wstr,
/// proc, skip); <see cref="Size"/> the integer's bytes; <see cref="Names"/> names its values (an enum or flag set).
/// </summary>
public sealed record LiveWatchArg(string Name, string Type, string Kind, int Size, Func<ulong, string?>? Names = null);

/// <summary>How a watched function's calls are decoded, and where the decoding came from.</summary>
public sealed record LiveWatchPlan(string Function, IReadOnlyList<LiveWatchArg> Args, LiveWatchArg? Return, string Source)
{
    /// <summary>The kinds the session script reads, one per argument slot.</summary>
    public IReadOnlyList<string> ScriptKinds => Args.Select(a => a.Kind).ToList();

    /// <summary>"int AddLine(Order * o, int qty)"; types left out where none is known.</summary>
    public string Prototype =>
        $"{(Return == null ? "void " : Return.Type.Length > 0 ? Return.Type + " " : "")}{Function}({string.Join(", ", Args.Select(a => a.Type.Length > 0 ? $"{a.Type} {a.Name}" : a.Name))})";
}

public sealed class LiveWatchState(string id, string where, ulong address, LiveFrameName at, LiveWatchPlan plan, int perSecond)
{
    public string Id { get; } = id;
    public string Where { get; } = where;
    public ulong Address { get; } = address;
    public LiveFrameName At { get; } = at;
    public LiveWatchPlan Plan { get; } = plan;
    public int PerSecond { get; } = perSecond;
    /// <summary>Set when the location was a jump and the watch went where it leads.</summary>
    public string? Followed { get; init; }
    public long Calls { get; set; }
    /// <summary>Calls over the rate limit: counted by the session script, not recorded.</summary>
    public long Skipped { get; set; }
    /// <summary>Program clock (ms) of the first and last recorded call.</summary>
    public long FirstMs { get; set; }
    public long LastMs { get; set; }
    public bool Cleared { get; set; }

    /// <summary>Recorded calls per second between the first and the last; null under two calls or one millisecond.</summary>
    public double? Rate => Calls > 1 && LastMs > FirstMs ? (Calls - 1) * 1000.0 / (LastMs - FirstMs) : null;
}

/// <summary>
/// Decode plans for watched functions: the known-API table (names, strings, flags and enums by name), else the PDB
/// prototype (parameter names from the procedure's frame, types from the type stream, enums by name), else DWARF
/// parameter names, else raw pointer-size values.
/// </summary>
public static class LiveWatchPlans
{
    public const int DefaultRawArguments = 4;

    /// <param name="function">The function's name (a known API is found by it, module and decoration ignored).</param>
    /// <param name="native">The loaded image holding it, for its PDB or DWARF; null when none matched.</param>
    public static LiveWatchPlan Build(string function, LoadedNative? native, uint rva, bool x64, ApiOs os, int rawArguments)
    {
        if (ApiSignatures.ForOs(ApiSignatures.Find(function), os) is { } api)
            return FromApi(ApiSignatures.BareName(function), api, x64);
        if (native != null && PdbService.StateOf(native)?.Pdb is { } pdb)
        {
            var symbol = pdb.Symbols.FirstOrDefault(s => s.Rva == rva && s.IsFunction && (s.TypeIndex != 0 || s.ParameterNames != null));
            if (symbol != null && pdb.Format == DebugInfoFormat.Pdb && symbol.TypeIndex != 0 && FromPdb(function, pdb, symbol, x64) is { } typed)
                return typed;
            if (symbol?.ParameterNames is { Count: > 0 } names)
                return new(function, names.Select((n, i) => Raw(n ?? $"a{i}")).ToList(), Raw("ret"), "DWARF parameter names");
        }
        return new(function, Enumerable.Range(0, Math.Clamp(rawArguments, 0, 16)).Select(i => Raw($"a{i}")).ToList(), Raw("ret"), "raw values");
    }

    private static LiveWatchArg Raw(string name) => new(name, "", "hex", 8);

    private static LiveWatchPlan FromApi(string function, ApiSignature api, bool x64)
    {
        var args = new List<LiveWatchArg>();
        foreach (var p in api.Params)
        {
            // x86 passes 64-bit values in two stack slots; x64 passes floating point in vector registers the script does not read
            if (!x64 && p.Slots32 > 1)
            {
                args.Add(new(p.Name, p.TypeName, "skip", 0));
                for (int i = 1; i < p.Slots32; i++) args.Add(new($"{p.Name}+{i}", "", "skip", 0));
                continue;
            }
            var (kind, size) = p.Type switch
            {
                ApiParamType.Int => ("int", 4),
                ApiParamType.UInt => ("uint", 4),
                ApiParamType.Size => ("uint", x64 ? 8 : 4),
                ApiParamType.Hex => ("hex", 4),
                ApiParamType.Bool => ("bool", 4),
                ApiParamType.Int64 => ("int", 8),
                ApiParamType.AnsiString or ApiParamType.AnsiFormat => ("cstr", 0),
                ApiParamType.WideString or ApiParamType.WideFormat => ("wstr", 0),
                ApiParamType.ProcName => ("proc", 0),
                ApiParamType.Float or ApiParamType.Double or ApiParamType.FloatPair => ("skip", 0),
                ApiParamType.Enum => ("hex", 4),
                _ => ("hex", 8),
            };
            args.Add(new(p.Name, p.TypeName, kind, size, p.Enum is { } e ? e.Describe : null));
        }
        var ret = ApiSignatures.FindReturn(function);
        return new(function, args, new("ret", ret?.Enum?.Name ?? "", "hex", 8, ret?.Enum is { } re ? re.Describe : null), "known API table");
    }

    private static LiveWatchPlan? FromPdb(string function, PdbFile pdb, PdbSymbol symbol, bool x64)
    {
        var model = PdbTypeModel.Of(pdb, x64 ? 8 : 4);
        if (model.Node(model.FunctionTypeOf(symbol.TypeIndex))?.Function is not { } f) return null;
        var types = new List<uint>();
        if (f.This != 0) types.Add(f.This);
        types.AddRange(f.Parameters);
        var names = symbol.FrameNames ?? [];
        var args = new List<LiveWatchArg>();
        for (int i = 0; i < types.Count; i++)
        {
            var name = i < names.Count ? names[i] : f.This != 0 && i == 0 ? "this" : $"a{i}";
            foreach (var a in FromType(model, types[i], name, x64)) args.Add(a);
        }
        if (f.Variadic) args.Add(new("...", "", "skip", 0));
        var ret = model.Node(f.Return) is { Kind: PdbTypeKind.Simple, Name: "void" } ? null : FromType(model, f.Return, "ret", x64).FirstOrDefault();
        return new(function, args, ret, "PDB prototype");
    }

    /// <summary>The slots one parameter takes; a 64-bit value on x86 takes two (left unread).</summary>
    private static IEnumerable<LiveWatchArg> FromType(PdbTypeModel model, uint type, string name, bool x64)
    {
        var spelled = model.Spell(type);
        var node = Unmodified(model, type);
        if (node == null) return [new(name, spelled, "hex", 8)];
        long size = node.Size;
        if (node.Kind == PdbTypeKind.Pointer)
        {
            var pointee = Unmodified(model, node.Element);
            var kind = pointee is { Kind: PdbTypeKind.Simple, Name: "char" or "signed char" or "unsigned char" } ? "cstr"
                : pointee is { Kind: PdbTypeKind.Simple, Name: "wchar_t" or "char16_t" } ? "wstr" : "ptr";
            return [new(name, spelled, kind, 8)];
        }
        if (node.Kind == PdbTypeKind.Simple && node.Name is "float" or "double" or "long double")
            return x64 ? [new(name, spelled, "skip", 0)] : Slots(name, spelled, size);
        if (node.Kind == PdbTypeKind.Enum)
        {
            var values = node.Enumerators;
            int bytes = (int)Math.Clamp(size, 1, 8);
            return [new(name, spelled, "int", bytes, v => values.FirstOrDefault(e => (ulong)e.Value == Truncate(v, bytes) || e.Value == Signed(v, bytes))?.Name)];
        }
        if (node.IsAggregate)
            // by value up to the pointer size; larger ones go by address on x64 and by stack copy on x86
            return size is 1 or 2 or 4 or 8 && (x64 || size <= 4) ? [new(name, spelled, "hex", (int)size)] : x64 ? [new(name, spelled, "ptr", 8)] : Slots(name, spelled, size);
        if (!x64 && size == 8) return Slots(name, spelled, size);
        var n = node.Name;
        bool unsigned = n.StartsWith("unsigned", StringComparison.Ordinal) || n is "bool" or "char16_t" or "char32_t" or "wchar_t";
        return [new(name, spelled, n == "bool" ? "bool" : unsigned ? "uint" : "int", (int)Math.Clamp(size <= 0 ? 8 : size, 1, 8))];
    }

    private static IEnumerable<LiveWatchArg> Slots(string name, string spelled, long size)
    {
        yield return new(name, spelled, "skip", 0);
        for (int i = 1; i < (size + 3) / 4; i++) yield return new($"{name}+{i}", "", "skip", 0);
    }

    private static PdbTypeNode? Unmodified(PdbTypeModel model, uint type)
    {
        var node = model.Node(type);
        for (int i = 0; i < 8 && node is { Kind: PdbTypeKind.Modifier }; i++) node = model.Node(node.Element);
        return node is { Forward: true } ? model.Node(model.DefinitionOf(node.Index)) ?? node : node;
    }

    private static ulong Truncate(ulong v, int bytes) => bytes >= 8 ? v : v & ((1UL << (bytes * 8)) - 1);
    private static long Signed(ulong v, int bytes) => bytes >= 8 ? (long)v : (long)(Truncate(v, bytes) << (64 - bytes * 8)) >> (64 - bytes * 8);

    /// <summary>"AddLine(o=0x14FD20, qty=3) -> 3" for one recorded call: values as the script sent them (strings, or 0x numbers).</summary>
    public static string Describe(LiveWatchPlan plan, IReadOnlyList<string?> values, string? returned)
    {
        var sb = new StringBuilder(plan.Function).Append('(');
        bool first = true;
        for (int i = 0; i < plan.Args.Count; i++)
        {
            var a = plan.Args[i];
            if (a.Kind == "skip" && a.Type == "") continue; // the second slot of a two-slot value
            if (!first) sb.Append(", ");
            first = false;
            sb.Append(a.Name).Append('=').Append(Value(a, i < values.Count ? values[i] : null));
        }
        sb.Append(')');
        if (plan.Return != null) sb.Append(" -> ").Append(Value(plan.Return, returned));
        return sb.ToString();
    }

    private static string Value(LiveWatchArg a, string? v)
    {
        if (a.Kind == "skip") return "?";
        if (a.Kind is "cstr" or "wstr" or "proc" && v != null && !v.StartsWith("0x", StringComparison.Ordinal) && !v.StartsWith("<unreadable", StringComparison.Ordinal))
            return Quote(v);
        if (v == null) return a.Kind is "cstr" or "wstr" ? "NULL" : "?";
        if (!v.StartsWith("0x", StringComparison.Ordinal) || !ulong.TryParse(v.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var x)) return v;
        // the upper half of a register holding a 32-bit argument is whatever was there before
        if (a.Names?.Invoke(Truncate(x, a.Size)) is { } named) return named;
        return a.Kind switch
        {
            "int" => Signed(x, a.Size).ToString(CultureInfo.InvariantCulture),
            "uint" => Truncate(x, a.Size).ToString(CultureInfo.InvariantCulture),
            "bool" => Truncate(x, 4) == 0 ? "false" : "true",
            "hex" when a.Size < 8 => $"0x{Truncate(x, a.Size):X}",
            _ => $"0x{x:X}",
        };
    }

    private static string Quote(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var c in s)
            sb.Append(c switch { '\\' => "\\\\", '"' => "\\\"", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", < ' ' => $"\\x{(int)c:X2}", _ => c.ToString() });
        return sb.Append('"').ToString();
    }
}
