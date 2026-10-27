using System.Text;
using Corvus.Native.Swift;

namespace Corvus.Native.MachO;

/// <summary>Swift names as the compiler's mangled symbols (descriptors, accessors, witness tables, vtable implementations), each checked by demangling.</summary>
public static class AppleSwiftNames
{
    private const int FieldsListed = 8;

    public static AppleNameSet Build(MachOFile image, AppleSwiftMetadata swift)
    {
        var names = new Dictionary<uint, string>();
        var comments = new Dictionary<uint, string>();
        var starts = new List<uint>();
        var known = new HashSet<string>(image.Symbols.Select(s => s.Name).Concat(image.Exports.Select(e => e.Name ?? "")), StringComparer.Ordinal);
        var exportsAt = new Dictionary<uint, string>();
        foreach (var e in image.Exports)
            if (e.Name != null && e.ForwardedTo == null) exportsAt.TryAdd(e.Rva, e.Name);
        int methods = 0;

        bool Add(ulong va, string? name, string? comment, bool function = false)
        {
            if (va == 0 || !image.TryVaToRva(va, out uint rva)) return false;
            if (comment != null) comments.TryAdd(rva, comment);
            if (function) starts.Add(rva);
            if (name == null || known.Contains(name) || names.ContainsKey(rva) || SwiftDemangler.Demangle(name) == null) return false;
            names[rva] = name;
            return true;
        }
        static string? Symbol(string? entity, string suffix) => entity != null ? "_$s" + entity + suffix : null;

        foreach (var t in swift.Types)
        {
            var comment = new StringBuilder($"Swift {t.Kind} {t.Name}");
            if (t.Superclass != null) comment.Append(" : ").Append(t.Superclass);
            if (t.Fields.Count > 0)
            {
                comment.Append(t.Kind == "enum" ? "; cases: " : "; fields: ");
                comment.Append(string.Join(", ", t.Fields.Take(FieldsListed).Select(f => f.Type != null ? $"{f.Name}: {f.Type}" : f.Name)));
                if (t.Fields.Count > FieldsListed) comment.Append($" (+{t.Fields.Count - FieldsListed} more)");
            }
            Add(t.DescriptorVa, Symbol(t.Symbol, "Mn"), comment.ToString());
            Add(t.AccessorVa, Symbol(t.Symbol, "Ma"), $"type metadata accessor for {t.Name}", function: true);
            Add(t.FieldDescriptorVa, Symbol(t.Symbol, "MF"), $"field descriptor of {t.Name}");
            for (int k = 0; k < t.Methods.Count; k++)
            {
                var m = t.Methods[k];
                if (m.Impl == 0 || !image.TryVaToRva(m.DescriptorVa, out uint descriptor)) continue;
                string slot = $"vtable slot {k} of {t.Name} ({(m.IsInstance ? "" : "static ")}{m.Kind}{(m.IsAsync ? ", async" : "")})";
                // An async implementation is an async function pointer, not code.
                string? name = exportsAt.TryGetValue(descriptor, out var d) && d.EndsWith("Tq", StringComparison.Ordinal) && !m.IsAsync ? d[..^2] : null;
                if (Add(m.Impl, name, slot, function: !m.IsAsync)) methods++;
            }
        }
        foreach (var p in swift.Protocols) Add(p.DescriptorVa, Symbol(p.Symbol, "Mp"), $"Swift protocol {p.Name}");
        var bySymbol = new Dictionary<string, SwiftType>(StringComparer.Ordinal);
        foreach (var t in swift.Types)
            if (t.Symbol != null) bySymbol.TryAdd(t.Symbol, t);
        foreach (var c in swift.Conformances)
        {
            var type = c.TypeSymbol != null ? bySymbol.GetValueOrDefault(c.TypeSymbol) : null;
            string? entity = type != null && c.ProtocolSymbol != null && type.Module is { Length: > 0 } module && module != "__C" && Identifier(module) is { } m
                ? c.TypeSymbol + c.ProtocolSymbol + m : null;
            string what = $"{c.Type} : {c.Protocol}";
            Add(c.Va, Symbol(entity, "Mc"), $"protocol conformance {what}");
            Add(c.WitnessTableVa, type is { IsGeneric: false } ? Symbol(entity, "WP") : null, $"protocol witness table for {what}");
        }
        return new AppleNameSet(names, comments, [.. starts.Distinct().Order()], methods, swift.Types.Count);
    }

    private static string? Identifier(string name) =>
        name.Length > 0 && !char.IsAsciiDigit(name[0]) && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? name.Length + name : null;
}
