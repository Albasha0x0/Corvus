using System.Globalization;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Reads the metadata attributes that Il2CppDumper / Cpp2IL inject into "dummy" DLLs
/// ([Address(RVA=..., Offset=..., VA=..., Slot=...)], [FieldOffset(Offset=...)], [Token(Token=...)])
/// and maps native addresses back to managed methods, for cross-referencing with IDA/Ghidra.
/// </summary>
public sealed class Il2CppService(AssemblyWorkspace workspace)
{
    private static readonly string[] KnownAttributes =
        ["AddressAttribute", "FieldOffsetAttribute", "TokenAttribute", "MetadataOffsetAttribute", "Il2CppAddressAttribute"];

    private readonly Dictionary<LoadedAssembly, (int Generation, List<MethodAddress> Index)> _indexes = new();

    public sealed record Il2CppAttribute(string Name, IReadOnlyDictionary<string, string> Values)
    {
        public override string ToString() => $"[{Name.Replace("Attribute", "")}({string.Join(", ", Values.Select(kv => $"{kv.Key}={kv.Value}"))})]";
    }

    public sealed record MethodAddress(LoadedAssembly Assembly, MethodDef Method, ulong? Rva, ulong? Va, ulong? Offset, ulong? Length, string? Slot);

    public sealed record AddressMatch(MethodAddress Entry, string Field, ulong Start, string Relation);

    public static List<Il2CppAttribute> GetAttributes(IHasCustomAttribute member)
    {
        var list = new List<Il2CppAttribute>();
        foreach (var ca in member.CustomAttributes)
        {
            var name = ca.AttributeType?.Name?.String;
            if (name == null || !KnownAttributes.Contains(name)) continue;
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < ca.ConstructorArguments.Count; i++)
                values[$"arg{i}"] = ValueString(ca.ConstructorArguments[i].Value);
            foreach (var na in ca.NamedArguments)
                values[na.Name.String] = ValueString(na.Argument.Value);
            list.Add(new Il2CppAttribute(name, values));
        }
        return list;
    }

    private static string ValueString(object? v) => v switch
    {
        null => "null",
        UTF8String u => u.String,
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };

    public static ulong? ParseNumber(string? s)
    {
        if (string.IsNullOrWhiteSpace(s) || s == "-1" || s == "null") return null;
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : null;
        return ulong.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    /// <summary>User-entered address: hex by default (IDA style), optional 0x / h suffix / backtick separator; "d:" prefix for decimal.</summary>
    public static ulong? ParseAddress(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim().Replace("`", "").Replace("_", "");
        if (s.StartsWith("d:", StringComparison.OrdinalIgnoreCase))
            return ulong.TryParse(s[2..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) ? d : null;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        if (s.EndsWith('h') || s.EndsWith('H')) s = s[..^1];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var h) ? h : null;
    }

    public IReadOnlyList<MethodAddress> GetIndex(LoadedAssembly asm)
    {
        lock (_indexes)
        {
            if (_indexes.TryGetValue(asm, out var e) && e.Generation == workspace.Generation)
                return e.Index;
        }
        var index = new List<MethodAddress>();
        foreach (var type in asm.Module.GetTypes())
            foreach (var m in type.Methods)
            {
                var addr = GetAttributes(m).FirstOrDefault(a => a.Name.Contains("Address", StringComparison.Ordinal));
                if (addr == null) continue;
                addr.Values.TryGetValue("RVA", out var rva);
                addr.Values.TryGetValue("VA", out var va);
                addr.Values.TryGetValue("Offset", out var off);
                addr.Values.TryGetValue("Length", out var len);
                addr.Values.TryGetValue("Slot", out var slot);
                index.Add(new MethodAddress(asm, m, ParseNumber(rva), ParseNumber(va), ParseNumber(off), ParseNumber(len), slot));
            }
        lock (_indexes)
            _indexes[asm] = (workspace.Generation, index);
        return index;
    }

    /// <summary>
    /// Finds the method at a native address. field = rva | va | offset | auto.
    /// Exact starts win; otherwise reports the closest preceding method (likely containing function).
    /// </summary>
    public List<AddressMatch> FindByAddress(ulong address, string field, IReadOnlyList<LoadedAssembly> scope)
    {
        var fields = field.ToLowerInvariant() switch
        {
            "rva" => new[] { "rva" },
            "va" => ["va"],
            "offset" or "fileoffset" => ["offset"],
            "auto" or "any" or "" => ["rva", "va", "offset"],
            _ => throw new ToolError($"Unknown address kind '{field}'. Use rva, va, offset or auto."),
        };

        var all = scope.SelectMany(GetIndex).ToList();
        if (all.Count == 0)
            throw new ToolError("No Il2Cpp address attributes found in the selected assemblies. This only works on Il2CppDumper/Cpp2IL dummy DLLs that carry [Address] attributes.");

        var matches = new List<AddressMatch>();
        foreach (var f in fields)
        {
            Func<MethodAddress, ulong?> get = f switch { "rva" => e => e.Rva, "va" => e => e.Va, _ => e => e.Offset };
            var sorted = all.Where(e => get(e).HasValue).OrderBy(e => get(e)!.Value).ToList();
            if (sorted.Count == 0) continue;

            var exact = sorted.Where(e => get(e) == address).ToList();
            if (exact.Count > 0)
            {
                // Several managed methods can share one native body (generic sharing, identical code folding).
                matches.AddRange(exact.Select(e => new AddressMatch(e, f, address, "exact start")));
                continue;
            }

            int lo = 0, hi = sorted.Count - 1, best = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (get(sorted[mid])!.Value <= address) { best = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (best < 0) continue;
            var entry = sorted[best];
            ulong start = get(entry)!.Value;
            ulong delta = address - start;
            ulong? next = best + 1 < sorted.Count ? get(sorted[best + 1]) : null;
            string relation = entry.Length is { } len
                ? (delta < len ? $"inside (+0x{delta:X} of 0x{len:X} bytes)" : $"after end (+0x{delta:X}; length 0x{len:X})")
                : next is { } n
                    ? $"probably inside (+0x{delta:X}; next method starts at 0x{n:X})"
                    : $"after the last known method (+0x{delta:X})";
            matches.Add(new AddressMatch(entry, f, start, relation));
        }
        return matches;
    }
}
