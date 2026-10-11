using System.ComponentModel;
using System.Text;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Core.Mobile;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Elf;

namespace NetDecompilerMcp.Services.Mobile;

public sealed record JniBinding(
    [property: Description("The Java native method (Lpkg/C;->name(sig)ret); for a registered entry whose class is not known, ?->name(sig)ret.")] string? JavaMethod,
    [property: Description("The library entry (lib/<abi>/libname.so); null for an unresolved method.")] string? Library,
    [property: Description("The exported symbol (Java_pkg_C_name, or the overload form with __ and the mangled parameters).")] string? Symbol,
    [property: Description("Virtual address of the native function in the library.")] string? Address,
    [property: Description("static_export (bound by its exported name), registered (a RegisterNatives table entry), unresolved (a native method with no " +
                           "export or table entry), or export_only (a Java_ export with no native method in the DEX code).")] string Kind,
    [property: Description("registered entries: how the class was found: class_string (the FindClass name in the function that passes the table), " +
                           "name_and_signature (the only native method with that name and signature), or unknown.")] string? Confidence,
    [property: Description("registered entries: virtual address of the table.")] string? Table);

public sealed record JniLibrary(string Library, string Abi, int JavaExports, bool HasJniOnLoad, int RegisterNativesTables, int RegisteredMethods);

public sealed record JniBindingList(IReadOnlyList<JniBinding> Items, int Offset, int Total, bool Truncated,
    [property: Description("The libraries read that have Java_ exports, JNI_OnLoad or RegisterNatives tables, with their counts.")] IReadOnlyList<JniLibrary> Libraries,
    IReadOnlyList<string> Notes);

/// <summary>
/// Java native methods of an Android package paired with their native code: exported Java_ symbols by the JNI name
/// mangling (short form, then the overload form), and JNINativeMethod tables passed to RegisterNatives, found in the
/// libraries' data (name and signature string pointers followed by a code pointer) and tied to their class by the
/// FindClass string of the function that references the table, or by the native method's name and signature.
/// </summary>
public sealed partial class JniBindings(DexService dex)
{
    public const int DefaultLimit = 200;
    private const int MaxNameLength = 256, MaxSignatureLength = 1024;
    private const uint AccNative = 0x100;

    private sealed record NativeMethod(string Class, string Name, string Signature, string Id);
    private sealed record Entry(string Name, string Signature, uint Function);
    private sealed record Table(uint Rva, List<Entry> Entries);

    public JniBindingList List(string path, string? abi, string? @class, string? kind, int offset, int limit, CancellationToken ct)
    {
        offset = Math.Max(0, offset);
        limit = Math.Clamp(limit, 1, 2000);
        var index = dex.Index(path, ct);
        var natives = new List<NativeMethod>();
        foreach (var m in index.Methods.Values)
            if ((m.Encoded.Access & AccNative) != 0)
                natives.Add(new(m.Ref.Class, m.Ref.Name, m.Ref.Proto.Descriptor, m.Descriptor));
        var bySignature = natives.ToLookup(n => (n.Name, n.Signature));
        var byShortName = natives.ToLookup(n => ShortName(n.Class, n.Name), StringComparer.Ordinal);
        var byLongName = natives.GroupBy(n => LongName(n.Class, n.Name, n.Signature), StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);

        using var package = AndroidPackage.Open(path);
        var notes = new List<string>();
        var abis = package.Abis;
        var wanted = (abi ?? "").Trim() switch
        {
            "" => abis.Contains("arm64-v8a") ? ["arm64-v8a"] : abis.Take(1).ToList(),
            "all" => abis.ToList(),
            var a when abis.Contains(a) => [a],
            var a => throw new ToolError(ErrorCode.NotFound, $"the package has no libraries for ABI '{a}'; it has: {(abis.Count == 0 ? "none" : string.Join(", ", abis))}."),
        };
        if (abis.Count > wanted.Count) notes.Add($"Libraries of {string.Join(", ", wanted)} are read; abi=all reads {string.Join(", ", abis)}.");
        if (package.SplitApks.Count > 0) notes.Add("Native libraries in split APKs (config.<abi>.apk) are not read; pass the split APK itself.");

        var rows = new List<JniBinding>();
        var libraries = new List<JniLibrary>();
        var bound = new HashSet<string>(StringComparer.Ordinal);
        foreach (var name in package.Entries.Where(e => e.StartsWith("lib/", StringComparison.Ordinal) && e.EndsWith(".so", StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var parts = name.Split('/');
            if (parts.Length != 3 || !wanted.Contains(parts[1])) continue;
            ElfFile elf;
            try { elf = ElfFile.FromBytes(package.Read(name) ?? [], name); }
            catch (ToolError ex) { notes.Add($"{name}: not read ({ex.Message})."); continue; }

            var exports = elf.Exports.Where(e => e.Name != null).GroupBy(e => e.Name!, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First().Rva, StringComparer.Ordinal);
            int javaExports = 0;
            foreach (var (symbol, rva) in exports)
            {
                if (!symbol.StartsWith("Java_", StringComparison.Ordinal)) continue;
                javaExports++;
                // the VM looks up the short name first, so an exported short name binds every overload
                var matches = byLongName.TryGetValue(symbol, out var overload) ? [overload] : byShortName[symbol].ToList();
                if (matches.Count == 0) rows.Add(new(null, name, symbol, Va(elf, rva), "export_only", null, null));
                foreach (var match in matches)
                {
                    rows.Add(new(match.Id, name, symbol, Va(elf, rva), "static_export", null, null));
                    bound.Add(match.Id);
                }
            }

            var tables = Tables(elf, ct);
            NativeCodeIndex? code = null;
            int registered = 0;
            foreach (var table in tables)
            {
                string? owner = null, confidence = null;
                // the function that passes the table to RegisterNatives names its class with FindClass
                if (!Unique(table, bySignature, out var byName))
                {
                    code ??= BuildIndex(elf, notes, name, ct);
                    owner = code != null ? ClassString(code, table, natives) : null;
                }
                if (owner == null && byName != null) (owner, confidence) = (byName, "name_and_signature");
                else if (owner != null) confidence = "class_string";
                foreach (var e in table.Entries)
                {
                    registered++;
                    var cls = owner ?? (bySignature[(e.Name, e.Signature)].ToList() is [var only] ? only.Class : null);
                    var id = $"{cls ?? "?"}->{e.Name}{e.Signature}";
                    if (cls != null) bound.Add(id);
                    rows.Add(new(id, name, null, Va(elf, e.Function), "registered", owner != null ? confidence : cls != null ? "name_and_signature" : "unknown", Va(elf, table.Rva)));
                }
            }
            libraries.Add(new(name, parts[1], javaExports, exports.ContainsKey("JNI_OnLoad"), tables.Count, registered));
        }
        if (libraries.Count == 0) notes.Add(abis.Count == 0 ? "The package has no native libraries (lib/<abi>/*.so)." : "No library of the selected ABI.");
        foreach (var n in natives)
            if (!bound.Contains(n.Id)) rows.Add(new(n.Id, null, null, null, "unresolved", null, null));
        if (rows.Any(r => r.Kind == "unresolved") && libraries.Any(l => l.HasJniOnLoad))
            notes.Add("Unresolved methods may be registered from code this reader does not follow (tables built at run time, or in another library).");

        IEnumerable<JniBinding> filtered = rows;
        if (@class is { Length: > 0 } c)
        {
            var needle = c.Trim().Replace('.', '/');
            filtered = filtered.Where(r => (r.JavaMethod ?? r.Symbol ?? "").Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        if (kind is { Length: > 0 } k)
        {
            var kinds = new[] { "static_export", "registered", "unresolved", "export_only" };
            var want = k.Trim().ToLowerInvariant();
            if (!kinds.Contains(want)) throw new ToolError(ErrorCode.InvalidArgument, $"kind '{k}' is not one of {string.Join(", ", kinds)}.");
            filtered = filtered.Where(r => r.Kind == want);
        }
        var all = filtered.ToList();
        var page = all.Skip(offset).Take(limit).ToList();
        // .NET for Android ships hundreds of libaot-*.so per ABI: only libraries with JNI content are listed.
        var listed = libraries.Where(l => l.JavaExports > 0 || l.HasJniOnLoad || l.RegisterNativesTables > 0).ToList();
        if (listed.Count < libraries.Count)
            notes.Add($"{libraries.Count - listed.Count} of {libraries.Count} libraries have no Java_ export, JNI_OnLoad or RegisterNatives table and are not listed.");
        return new JniBindingList(page, offset, all.Count, offset + page.Count < all.Count, listed, notes);
    }

    private static string Va(INativeImage image, uint rva) => $"0x{image.ImageBase + rva:X}";

    /// <summary>True when every entry has exactly one native method with its name and signature, all in one class (<paramref name="owner"/>).</summary>
    private static bool Unique(Table table, ILookup<(string, string), NativeMethod> bySignature, out string? owner)
    {
        owner = null;
        string? found = null;
        foreach (var e in table.Entries)
        {
            if (bySignature[(e.Name, e.Signature)].ToList() is not [var only] || (found != null && found != only.Class)) return false;
            found = only.Class;
        }
        owner = found;
        return found != null;
    }

    private static NativeCodeIndex? BuildIndex(ElfFile elf, List<string> notes, string name, CancellationToken ct)
    {
        try { return NativeCodeIndex.Build(elf, ct: ct); }
        catch (ToolError ex)
        {
            notes.Add($"{name}: no code index ({ex.Message}); registered classes come from names and signatures only.");
            return null;
        }
    }

    /// <summary>The class descriptor among the strings the referencing functions load, preferring one whose native methods match the table.</summary>
    private static string? ClassString(NativeCodeIndex code, Table table, List<NativeMethod> natives)
    {
        var candidates = new List<string>();
        foreach (var xref in code.RefsTo(table.Rva, 64))
        {
            if (code.FunctionAt(xref.From) is not { } f) continue;
            foreach (var r in code.RefsFrom(f))
                if (code.StringAt(r.To) is { } s && code.ReadString(s, MaxNameLength) is var text && ClassName().IsMatch(text) && !candidates.Contains(text))
                    candidates.Add(text);
        }
        var matching = candidates.Where(c => table.Entries.All(e => natives.Any(n => n.Class == $"L{c};" && n.Name == e.Name && n.Signature == e.Signature))).ToList();
        if (matching is [var one]) return $"L{one};";
        return candidates is [var single] ? $"L{single};" : null;
    }

    /// <summary>JNINativeMethod arrays in the library's data: {name, signature, function} pointer triples, relocations applied.</summary>
    private static List<Table> Tables(INativeImage image, CancellationToken ct)
    {
        int ptr = image.Is64Bit ? 8 : 4;
        var tables = new List<Table>();
        var strings = new Dictionary<uint, string?>();
        string? Text(ulong va, int max)
        {
            if (va < image.ImageBase || va - image.ImageBase >= image.SizeOfImage) return null;
            var rva = (uint)(va - image.ImageBase);
            if (strings.TryGetValue(rva, out var known)) return known;
            var buffer = new byte[max + 1];
            int n = image.Read(rva, buffer);
            int end = Array.IndexOf(buffer, (byte)0, 0, n);
            string? s = end > 0 && buffer.AsSpan(0, end).IndexOfAnyExceptInRange((byte)0x21, (byte)0x7E) < 0 ? Encoding.ASCII.GetString(buffer, 0, end) : null;
            return strings[rva] = s;
        }
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable || section.MappedSize < 3u * (uint)ptr || section.RawSize == 0) continue;
            ct.ThrowIfCancellationRequested();
            var data = new byte[section.MappedSize];
            int got = image.Read(section.Rva, data);
            ulong P(int at) => ptr == 8 ? BitConverter.ToUInt64(data, at) : BitConverter.ToUInt32(data, at);
            Table? open = null;
            int start = (int)((ptr - section.Rva % (uint)ptr) % (uint)ptr);
            for (int at = start; at + 3 * ptr <= got;)
            {
                ulong fn = P(at + 2 * ptr);
                if (image.Arch == NativeArch.Arm) fn &= ~1UL;
                if (fn >= image.ImageBase && fn - image.ImageBase < image.SizeOfImage && image.SectionAt((uint)(fn - image.ImageBase)) is { IsExecutable: true }
                    && Text(P(at), MaxNameLength) is { } name && MethodName().IsMatch(name)
                    && Text(P(at + ptr), MaxSignatureLength) is { } sig && Signature().IsMatch(sig))
                {
                    open ??= new Table(section.Rva + (uint)at, []);
                    open.Entries.Add(new(name, sig, (uint)(fn - image.ImageBase)));
                    at += 3 * ptr;
                    continue;
                }
                if (open != null) { tables.Add(open); open = null; }
                at += ptr;
            }
            if (open != null) tables.Add(open);
        }
        return tables;
    }

    /// <summary>The JNI short name: Java_, the mangled class, _, the mangled method.</summary>
    public static string ShortName(string classDescriptor, string method) =>
        "Java_" + Mangle(classDescriptor.StartsWith('L') && classDescriptor.EndsWith(';') ? classDescriptor[1..^1] : classDescriptor) + "_" + Mangle(method);

    /// <summary>The JNI long name of an overloaded method: the short name, __, and the mangled parameter descriptors.</summary>
    public static string LongName(string classDescriptor, string method, string signature)
    {
        int close = signature.IndexOf(')');
        var parameters = signature.StartsWith('(') && close > 0 ? signature[1..close] : "";
        return ShortName(classDescriptor, method) + "__" + Mangle(parameters);
    }

    /// <summary>JNI name mangling: / to _, _ to _1, ; to _2, [ to _3, other characters outside [A-Za-z0-9] to _0xxxx.</summary>
    public static string Mangle(string name)
    {
        var sb = new StringBuilder(name.Length + 8);
        foreach (char c in name)
            sb.Append(c switch
            {
                '/' => "_",
                '_' => "_1",
                ';' => "_2",
                '[' => "_3",
                _ when char.IsAsciiLetterOrDigit(c) => c.ToString(),
                _ => $"_0{(int)c:x4}",
            });
        return sb.ToString();
    }

    [GeneratedRegex(@"^[A-Za-z_$][A-Za-z0-9_$]*$")]
    private static partial Regex MethodName();

    [GeneratedRegex(@"^\((\[*([ZBCSIJFD]|L[^;()\[]+;))*\)(V|\[*([ZBCSIJFD]|L[^;()\[]+;))$")]
    private static partial Regex Signature();

    [GeneratedRegex(@"^[A-Za-z_$][A-Za-z0-9_$]*(/[A-Za-z_$][A-Za-z0-9_$]*)+$")]
    private static partial Regex ClassName();
}
