using System.Globalization;
using dnlib.DotNet;
using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Reads the metadata attributes that Il2CppDumper / Cpp2IL add to "dummy" DLLs
/// ([Address(RVA=..., Offset=..., VA=..., Slot=...)], [FieldOffset(Offset=...)], [Token(Token=...)])
/// and maps native addresses back to managed methods, for cross-referencing with IDA/Ghidra.
/// </summary>
public sealed class Il2CppService(AssemblyWorkspace workspace)
{
    private static readonly string[] KnownAttributes =
        ["AddressAttribute", "FieldOffsetAttribute", "TokenAttribute", "MetadataOffsetAttribute", "Il2CppAddressAttribute"];

    private readonly Dictionary<LoadedAssembly, (int Generation, List<MethodAddress> Index)> _indexes = new();

    public sealed record Il2CppMetadata(string Name, IReadOnlyDictionary<string, string> Values)
    {
        /// <summary>
        /// An [Address] whose numbers cannot be a real location (see <see cref="IsInvalidAddress"/>): dumpers write such
        /// values for some generic methods that have no native code of their own.
        /// </summary>
        public bool InvalidAddress => Name.Contains("Address", StringComparison.Ordinal)
            && IsInvalidAddress(ParseNumber(Values.GetValueOrDefault("RVA")), ParseNumber(Values.GetValueOrDefault("Offset")), ParseNumber(Values.GetValueOrDefault("VA")));

        public override string ToString() => $"[{Name.Replace("Attribute", "")}({string.Join(", ", Values.Select(kv => $"{kv.Key}={kv.Value}"))})]" +
            (InvalidAddress ? " (not a real address: no native code of its own, e.g. a generic method only used through shared instantiations)" : "");
    }

    /// <summary>
    /// Address numbers that cannot point into a module: an RVA beyond 32 bits (a PE image is under 4 GB), an RVA without
    /// a file offset, or a VA below the RVA.
    /// </summary>
    public static bool IsInvalidAddress(ulong? rva, ulong? offset, ulong? va) =>
        rva > uint.MaxValue || (rva > 0 && offset == 0) || (va != null && rva != null && va < rva);

    public sealed record MethodAddress(LoadedAssembly Assembly, MethodDef Method, ulong? Rva, ulong? Va, ulong? Offset, ulong? Length, string? Slot);

    public static List<Il2CppMetadata> GetAttributes(IHasCustomAttribute member)
    {
        var list = new List<Il2CppMetadata>();
        foreach (var ca in member.CustomAttributes)
        {
            var name = ca.AttributeType?.Name?.String;
            if (name == null || !KnownAttributes.Contains(name)) continue;
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < ca.ConstructorArguments.Count; i++)
                values[$"arg{i}"] = ValueString(ca.ConstructorArguments[i].Value);
            foreach (var na in ca.NamedArguments)
                values[na.Name.String] = ValueString(na.Argument.Value);
            list.Add(new Il2CppMetadata(name, values));
        }
        return list;
    }

    /// <summary>Compact "RVA=0x.. Offset=0x.." summary for listings, or null when the member has no Il2Cpp metadata.</summary>
    public static string? CompactSummary(IHasCustomAttribute member)
    {
        var parts = GetAttributes(member)
            .Where(a => a.Name is "AddressAttribute" or "FieldOffsetAttribute" && !a.InvalidAddress)
            .SelectMany(a => a.Values.Where(kv => kv.Key is "RVA" or "Offset" or "VA" or "Slot" && kv.Value != "-1").Select(kv => $"{kv.Key}={kv.Value}"))
            .ToList();
        return parts.Count == 0 ? null : string.Join(" ", parts);
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
                if (addr == null || addr.InvalidAddress) continue; // no native code: kept out of lookups and exports
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
    /// The largest distance from a function's start still reported as "inside" it when its length is unknown. Larger
    /// gaps are unmapped space (or the address belongs to another module / address kind), not a containing function.
    /// </summary>
    public const ulong MaxFunctionSpan = 0x40000;
}
