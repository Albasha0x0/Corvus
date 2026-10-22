using System.ComponentModel;
using System.Globalization;
using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

public sealed record DexClassRow(string Descriptor, string DexFile, string Access, string? Super,
    [property: Description("The first 3 interfaces.")] IReadOnlyList<string> Interfaces,
    [property: Description("How many interfaces in all, when more than 3.")] int? InterfacesTotal,
    int Methods, int Fields, string? SourceFile)
{
    [Description(DexService.OriginalDescription)]
    public string? Original { get; init; }
}

public sealed record DexClassList(IReadOnlyList<DexClassRow> Items, int Offset, int Total, IReadOnlyList<string> Notes,
    [property: Description("Without a filter, on the first page: the packages with the most classes ('pkg n'), to narrow with package.")] IReadOnlyList<string>? Packages);

public sealed record DexFieldInfo(
    [property: Description("Exact field id: Lpkg/C;->name:type.")] string Id, string Name, string Type, string Access,
    [property: Description("Static initial value from the DEX, when it has one.")] string? Value, string? GenericSignature, IReadOnlyList<string> Annotations)
{
    public string? Original { get; init; }
}

public sealed record DexMethodInfo(
    [property: Description("Exact method id: Lpkg/C;->name(params)ret, what disassemble_dex, decompile_java and find_dex_references take.")] string Id,
    string Name, [property: Description("Java form: modifiers, return type, name and parameter types.")] string Signature, string Access,
    [property: Description("16-bit code units; null for abstract and native methods.")] int? CodeUnits, int? Registers,
    string? GenericSignature, IReadOnlyList<string> Annotations, IReadOnlyList<string?> ParameterNames)
{
    public string? Original { get; init; }
}

public sealed record DexClassDetail(string Descriptor, string JavaName, string DexFile, string Access, string? Super, IReadOnlyList<string> Interfaces,
    string? SourceFile, string? GenericSignature, string? EnclosingClass, string? EnclosingMethod, IReadOnlyList<string> InnerClasses,
    [property: Description("Kotlin @Metadata: the kind and the names it records.")] string? Kotlin,
    IReadOnlyList<string> Annotations, IReadOnlyList<DexFieldInfo> Fields, IReadOnlyList<DexMethodInfo> Methods)
{
    public string? Original { get; init; }
    public IReadOnlyList<string> Notes { get; init; } = [];
}

public sealed record DexMember(
    [property: Description("field or method.")] string Kind,
    [property: Description("Exact id: Lpkg/C;->name:type, or Lpkg/C;->name(params)ret (what disassemble_dex, decompile_java and find_dex_references take).")] string Id,
    string Access,
    [property: Description("Java form: the field's type and name, or the method's modifiers, return type, name and parameter types.")] string Declaration,
    [property: Description("Static initial value from the DEX, when it has one.")] string? Value,
    [property: Description("16-bit code units; absent for abstract and native methods.")] int? CodeUnits, int? Registers, string? GenericSignature,
    IReadOnlyList<string>? Annotations, IReadOnlyList<string?>? ParameterNames)
{
    [Description(DexService.OriginalDescription)]
    public string? Original { get; init; }
}

/// <summary>A DEX class with one page of its members (fields first, then methods).</summary>
public sealed record DexClassPage(string Descriptor, string JavaName, string DexFile, string Access, string? Super, IReadOnlyList<string> Interfaces,
    string? SourceFile, string? GenericSignature, string? EnclosingClass, string? EnclosingMethod, IReadOnlyList<string> InnerClasses,
    [property: Description("Kotlin @Metadata: the kind and the names it records.")] string? Kotlin,
    IReadOnlyList<string> Annotations, int Fields, int Methods, IReadOnlyList<DexMember> Items, int Offset, int Total)
{
    [Description(DexService.OriginalDescription)]
    public string? Original { get; init; }
}

public sealed record DexHit(
    [property: Description("string, type, method, field, const or opcode; class for a defined class; recovered: the string the decoder call at offset returns; opcode names the decoder method.")] string Kind,
    [property: Description("The string, descriptor or value found.")] string Value,
    [property: Description("The method containing the instruction (exact id); null for a definition.")] string? Method,
    [property: Description("Code offset in 16-bit units.")] int? Offset, string? Opcode,
    [property: Description("Uses in code (method and field hits).")] int? Uses)
{
    [Description(DexService.OriginalDescription)]
    public string? Original { get; init; }

    public string? InOriginal { get; init; }
}

public sealed record DexHitList(IReadOnlyList<DexHit> Items, int Offset, int Total, IReadOnlyList<string> Notes);

public sealed record DexReference(
    [property: Description("call, read, write, string or type.")] string Kind,
    [property: Description("The method holding the instruction (exact id).")] string Method,
    [property: Description("Code offset in 16-bit units.")] int Offset,
    [property: Description("What the instruction refers to (exact id or the string).")] string Target, string Opcode);

public sealed record DexReferenceList(string Target, string TargetKind, string Direction, IReadOnlyList<DexReference> Items, int Offset, int Total,
    IReadOnlyList<string> Notes);

/// <summary>DEX classes, members, search and cross-references of Android packages; indexes are kept per file while it is unchanged.</summary>
public sealed class DexService
{
    public const string OriginalDescription = "Original name (mapping or recovered).";
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<DexIndex, DexNames> _names = [];

    /// <summary>
    /// The name layer of a package: <paramref name="mapping"/> read and kept for later calls on the same package, else the one
    /// kept, else the names recovered from Kotlin metadata and source files; null when there are none.
    /// </summary>
    public DexNames? Names(DexIndex index, string? mapping, CancellationToken ct)
    {
        if (mapping is { Length: > 0 } m)
        {
            var full = SafeFile.FullPath(m);
            lock (_names)
                if (_names.TryGetValue(index, out var kept) && kept.Mapping != null && InputFiles.SamePath(kept.Mapping, full)) return kept;
            var read = DexNames.Read(full, index, ct);
            lock (_names) _names.AddOrUpdate(index, read);
            return read;
        }
        DexNames names;
        lock (_names)
            if (!_names.TryGetValue(index, out names!)) _names.Add(index, names = DexNames.Recovered(index));
        return names.IsEmpty ? null : names;
    }

    /// <summary>A class or member spec as the package's id: as given when the package defines it, else translated from original names.</summary>
    internal static string Resolve(DexIndex index, DexNames? names, string spec)
    {
        if (names == null) return spec;
        bool member = spec.Contains("->", StringComparison.Ordinal) || spec.Contains("::", StringComparison.Ordinal) || spec.Contains('(', StringComparison.Ordinal);
        if (!member && index.FindClass(spec) != null) return spec;
        if (member && (index.FindMethods(spec).Count > 0 || index.FindFields(spec).Count > 0)) return spec;
        return names.Translate(spec);
    }
    private const int CacheCapacity = 4;
    private readonly LinkedList<(string Path, long Length, DateTime Written, DexIndex Index)> _cache = new();
    private readonly object _lock = new();

    public DexIndex Index(string path, CancellationToken ct)
    {
        var full = InputFiles.RequireRegularFile(path, "Android package or DEX file");
        var info = new FileInfo(full);
        if (!info.Exists) throw Targets.FileNotFound(full);
        lock (_lock)
            for (var n = _cache.First; n != null; n = n.Next)
                if (InputFiles.SamePath(n.Value.Path, full) && n.Value.Length == info.Length && n.Value.Written == info.LastWriteTimeUtc)
                {
                    _cache.Remove(n);
                    _cache.AddFirst(n);
                    return n.Value.Index;
                }
        var index = DexIndex.Load(full, AnalysisLimits.Default, ct);
        lock (_lock)
        {
            _cache.AddFirst((full, info.Length, info.LastWriteTimeUtc, index));
            while (_cache.Count > CacheCapacity) _cache.RemoveLast();
        }
        return index;
    }

    /// <summary>The indexes read so far and still cached, most recent first.</summary>
    public IReadOnlyList<DexIndex> Cached()
    {
        lock (_lock) return [.. _cache.Select(n => n.Index)];
    }

    /// <summary>
    /// A wildcard (* ?) or substring test, case-insensitive, without a regex (a NonBacktracking automaton refuses a long
    /// query); null for no query.
    /// </summary>
    private static Func<string, bool>? Pattern(string? query)
    {
        if (query is not { Length: > 0 }) return null;
        var q = query.Trim();
        return Wildcard.IsPattern(q) ? s => Wildcard.Matches(s, q) : s => s.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    public DexClassList ListClasses(string path, string? query, string? package, int offset, int limit, CancellationToken ct, string? mapping = null)
    {
        var index = Index(path, ct);
        var names = Names(index, mapping, ct);
        var pattern = Pattern(query);
        var prefix = package?.Trim().Replace('.', '/').Trim('/') is { Length: > 0 } p ? "L" + p + "/" : null;
        var rows = index.Classes.Values
            .Where(e => prefix == null || e.Class.Descriptor.StartsWith(prefix, StringComparison.Ordinal) || names?.Descriptor(e.Class.Descriptor)?.StartsWith(prefix, StringComparison.Ordinal) == true)
            .Where(e => pattern == null || pattern(DexFile.JavaName(e.Class.Descriptor)) || pattern(e.Class.Descriptor)
                        || names?.Display(e.Class.Descriptor) is { } original && pattern(original))
            .OrderBy(e => e.Class.Descriptor, StringComparer.Ordinal).ToList();
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var r8 = new HashSet<string>(StringComparer.Ordinal);
        var page = rows.Skip(offset).Take(limit).Select(e =>
        {
            var (fields, methods) = e.File.ClassData(e.Class);
            var interfaces = e.Class.Interfaces;
            // R8 writes its map id as every class's source file: said once in a note instead of on each row.
            var source = e.Class.SourceFile;
            if (source?.StartsWith("r8-map-id-", StringComparison.Ordinal) == true) { r8.Add(source); source = null; }
            return new DexClassRow(e.Class.Descriptor, e.File.Name, DexFile.Access(e.Class.Access, 0), e.Class.SuperClass,
                [.. interfaces.Take(3)], interfaces.Count > 3 ? interfaces.Count : null, methods.Count, fields.Count, source) { Original = names?.Display(e.Class.Descriptor) };
        }).ToList();
        List<string>? packages = null;
        if (offset == 0 && pattern == null && prefix == null)
            packages = [.. rows.GroupBy(e => e.Class.Descriptor.LastIndexOf('/') is var slash and > 0 ? DexFile.JavaName(e.Class.Descriptor[..slash] + ";") : "(default)")
                .OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal).Take(20).Select(g => $"{g.Key} {g.Count()}")];
        var notes = offset == 0 ? [.. index.Notes, .. names?.Notes ?? []] : new List<string>();
        if (r8.Count > 0) notes.Add($"Source file attributes {string.Join(", ", r8)} are R8 map ids, left out of the rows.");
        return new DexClassList(page, offset, rows.Count, notes, packages);
    }

    public DexClassDetail GetClass(string path, string name, CancellationToken ct, string? mapping = null)
    {
        var index = Index(path, ct);
        var names = Names(index, mapping, ct);
        var entry = index.FindClass(Resolve(index, names, name)) ?? throw index.ClassNotFound(name);
        var (f, c) = (entry.File, entry.Class);
        var (fields, methods) = f.ClassData(c);
        var annotations = f.Annotations(c);
        var statics = f.StaticValues(c);
        int staticIndex = 0;
        var fieldInfos = fields.Select(x =>
        {
            var r = f.Field(x.FieldIndex);
            var a = annotations.Fields.GetValueOrDefault(x.FieldIndex) ?? [];
            string? value = x.IsStatic && staticIndex < statics.Count ? statics[staticIndex].ToString() : null;
            if (x.IsStatic) staticIndex++;
            return new DexFieldInfo(r.Descriptor, r.Name, r.Type, DexFile.Access(x.Access, 1), value, Signature(a), Shown(a)) { Original = names?.Display(r.Descriptor) };
        }).ToList();
        var methodInfos = methods.Select(x =>
        {
            var r = f.Method(x.MethodIndex);
            var a = annotations.Methods.GetValueOrDefault(x.MethodIndex) ?? [];
            var code = x.CodeOffset != 0 ? f.Code(x.CodeOffset) : null;
            var parameterNames = code != null ? f.Debug(code.DebugInfoOffset).ParameterNames : [];
            return new DexMethodInfo(r.Descriptor, r.Name, JavaSignature(r, x.Access), DexFile.Access(x.Access, 2), code?.Instructions.Length, code?.Registers,
                Signature(a), Shown(a), parameterNames) { Original = names?.Display(r.Descriptor) };
        }).ToList();
        var system = annotations.Class;
        string? Element(string type, string name) => system.FirstOrDefault(a => a.Type == type)?.Elements.FirstOrDefault(e => e.Name == name).Value?.Value?.ToString();
        var inner = system.FirstOrDefault(a => a.Type == "Ldalvik/annotation/MemberClasses;")?.Elements.FirstOrDefault().Value?.Value as IReadOnlyList<DexValue> ?? [];
        return new DexClassDetail(c.Descriptor, DexFile.JavaName(c.Descriptor), f.Name, DexFile.Access(c.Access, 0), c.SuperClass, c.Interfaces, c.SourceFile,
            Signature(system), Element("Ldalvik/annotation/EnclosingClass;", "value"), Element("Ldalvik/annotation/EnclosingMethod;", "value"),
            [.. inner.Select(v => v.Value?.ToString() ?? "")], Kotlin(system), Shown(system), fieldInfos, methodInfos)
        { Original = names?.Display(c.Descriptor), Notes = names?.Notes ?? [] };
    }

    private static string? Signature(IReadOnlyList<DexAnnotation> annotations) =>
        annotations.FirstOrDefault(a => a.Type == "Ldalvik/annotation/Signature;")?.Elements.FirstOrDefault().Value?.Value is IReadOnlyList<DexValue> parts
            ? string.Concat(parts.Select(p => p.Value as string)) : null;

    /// <summary>Annotations other than the dalvik/annotation system ones (already decoded into their own fields).</summary>
    private static List<string> Shown(IReadOnlyList<DexAnnotation> annotations) =>
        [.. annotations.Where(a => !a.Type.StartsWith("Ldalvik/annotation/", StringComparison.Ordinal) && a.Type != "Lkotlin/Metadata;")
            .Select(a => $"@{DexFile.JavaName(a.Type)}({string.Join(", ", a.Elements.Select(e => $"{e.Name}={e.Value}"))}) [{a.Visibility}]")];

    private static string? Kotlin(IReadOnlyList<DexAnnotation> annotations)
    {
        if (annotations.FirstOrDefault(a => a.Type == "Lkotlin/Metadata;") is not { } m) return null;
        var kind = m.Elements.FirstOrDefault(e => e.Name == "k").Value?.Value is int k
            ? k switch { 1 => "class", 2 => "file facade", 3 => "synthetic class", 4 => "multi-file facade", 5 => "multi-file part", _ => $"kind {k}" }
            : "class";
        var names = m.Elements.FirstOrDefault(e => e.Name == "d2").Value?.Value is IReadOnlyList<DexValue> d2 ? d2.Select(v => v.Value as string).OfType<string>().ToList() : [];
        return $"{kind}; names: {string.Join(", ", names.Take(60))}{(names.Count > 60 ? ", ..." : "")}";
    }

    public static string JavaSignature(DexMethodRef r, uint access)
    {
        var modifiers = DexFile.Access(access & ~0x10000u & ~0x1000u, 2);
        var parameters = string.Join(", ", r.Proto.Parameters.Select(DexFile.JavaName));
        var head = modifiers.Length > 0 ? modifiers + " " : "";
        return r.Name == "<init>" ? $"{head}{DexFile.JavaName(r.Class)}({parameters})" : $"{head}{DexFile.JavaName(r.Proto.ReturnType)} {r.Name}({parameters})";
    }

    public DexHitList Search(string path, string kind, string query, int offset, int limit, CancellationToken ct, string? mapping = null)
    {
        var index = Index(path, ct);
        var names = Names(index, mapping, ct);
        bool Original(string id) => names?.Display(id) is { } o && Pattern(query)!(o);
        var pattern = Pattern(query) ?? throw new ToolError(ErrorCode.InvalidArgument, "query is empty.");
        index.EnsureCode(ct);
        var hits = new List<DexHit>();
        var notes = new List<string>();
        const int MaxHits = 200_000;
        string Op(byte op) => Dalvik.Ops[op].Name;
        switch (kind.Trim().ToLowerInvariant())
        {
            case "string":
                var used = new HashSet<string>(StringComparer.Ordinal);
                foreach (var r in index.Refs.Where(r => r.Kind == DexRefKind.String))
                {
                    var text = index.KeyText(r.Target);
                    if (!pattern(text)) continue;
                    used.Add(text);
                    if (hits.Count < MaxHits) hits.Add(new("string", text, index.KeyText(r.From), r.Offset, Op(r.Opcode), null));
                }
                int poolOnly = index.Files.Sum(f => Enumerable.Range(0, f.StringCount).Select(f.String).Count(s => pattern(s) && !used.Contains(s)));
                if (poolOnly > 0) notes.Add($"{poolOnly} more matching string(s) are in the pools but not loaded by code (names, descriptors, annotation values).");
                Recovered(index, pattern, hits, notes, MaxHits, ct);
                break;
            case "type" or "class":
                foreach (var c in index.Classes.Values.Where(c => pattern(c.Class.Descriptor) || pattern(DexFile.JavaName(c.Class.Descriptor)) || Original(c.Class.Descriptor)))
                    hits.Add(new("class", c.Class.Descriptor, null, null, null, null));
                foreach (var r in index.Refs.Where(r => r.Kind == DexRefKind.Type))
                {
                    var t = index.KeyText(r.Target);
                    if (hits.Count < MaxHits && (pattern(t) || pattern(DexFile.JavaName(t)) || Original(t))) hits.Add(new("type", t, index.KeyText(r.From), r.Offset, Op(r.Opcode), null));
                }
                break;
            case "method" or "field":
                bool method = kind.Trim().Equals("method", StringComparison.OrdinalIgnoreCase);
                var uses = index.Refs.Where(r => method ? r.Kind == DexRefKind.Call : r.Kind is DexRefKind.Read or DexRefKind.Write)
                    .GroupBy(r => r.Target).ToDictionary(g => index.KeyText(g.Key), g => g.Count(), StringComparer.Ordinal);
                IEnumerable<string> defined = method ? index.Methods.Keys
                    : index.Classes.Values.SelectMany(c => c.File.ClassData(c.Class).Fields.Select(x => c.File.Field(x.FieldIndex).Descriptor));
                foreach (var d in defined.Concat(uses.Keys).Distinct(StringComparer.Ordinal))
                {
                    var arrow = d.IndexOf("->", StringComparison.Ordinal);
                    var name = d[(arrow + 2)..];
                    name = name[..name.IndexOfAny(['(', ':'])];
                    if (pattern(name) || pattern(d) || Original(d))
                        hits.Add(new(method ? "method" : "field", d, null, null, null, uses.GetValueOrDefault(d)));
                }
                hits.Sort((a, b) => string.CompareOrdinal(a.Value, b.Value));
                break;
            case "const":
                var text2 = query.Trim();
                var values = ConstValues(text2);
                if (values.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, $"'{query}' is not a number; use 42, -1, 0x7f010000 or 1.5.");
                foreach (var c in index.Consts.Where(c => values.Contains(c.Value)))
                    if (hits.Count < MaxHits) hits.Add(new("const", text2, index.KeyText(c.From), c.Offset, Op(c.Opcode), null));
                break;
            case "opcode":
                foreach (var m in index.Methods.Values)
                {
                    ct.ThrowIfCancellationRequested();
                    if (m.Encoded.CodeOffset == 0 || m.File.Code(m.Encoded.CodeOffset) is not { } code) continue;
                    foreach (var i in Dalvik.Decode(code.Instructions))
                        if (!i.IsPayload && (i.Name.Equals(query.Trim(), StringComparison.OrdinalIgnoreCase) || pattern(i.Name)) && hits.Count < MaxHits)
                            hits.Add(new("opcode", i.Name, m.Descriptor, i.Offset, i.Name, null));
                }
                break;
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown kind '{kind}'; use string, type, method, field, const or opcode.");
        }
        if (hits.Count >= MaxHits) notes.Add($"Stopped at {MaxHits} hits: refine the query.");
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = hits.Skip(offset).Take(limit).ToList();
        if (names != null)
        {
            page = [.. page.Select(h => h with
            {
                Original = h.Kind is "class" or "type" or "method" or "field" ? names.Display(h.Value) : null,
                InOriginal = h.Method != null ? names.Display(h.Method) : null,
            })];
            if (offset == 0) notes.AddRange(names.Notes);
        }
        return new DexHitList(page, offset, hits.Count, notes);
    }

    /// <summary>Hits for the strings decoder calls return: kind recovered, the call's opcode with its decoder; a note counts the calls not simplified.</summary>
    private static void Recovered(DexIndex index, Func<string, bool> pattern, List<DexHit> hits, List<string> notes, int maxHits, CancellationToken ct)
    {
        var folds = DexStringFolding.For(index).Package(ct);
        // A decoder that returns a literal argument as it is recovers nothing the literal hit does not show.
        var literals = hits.Select(h => (h.Method, h.Value)).ToHashSet();
        int recovered = 0;
        foreach (var site in folds.Sites)
            if (site.Fold is { Status: DexFoldStatus.Simplified, Value: { } value } && pattern(value) && hits.Count < maxHits && !literals.Contains((site.Method, value)))
            {
                hits.Add(new("recovered", value, site.Method, site.Offset, "invoke-static " + site.Decoder, null));
                recovered++;
            }
        int other = folds.Sites.Count(s => s.Evaluated && s.Fold.Status != DexFoldStatus.Simplified);
        if (recovered > 0 || other > 0)
            notes.Add($"{recovered} matching string(s) recovered from string decoder calls; {other} call(s) with constant arguments not simplified (disassemble_dex format=simplified says why).");
        if (folds.MethodsLeft > 0)
            notes.Add($"{folds.MethodsLeft} method(s) with decoder calls not evaluated within {DexStringFolding.PackageTimeLimit.TotalSeconds:0} s; search again to continue.");
    }

    /// <summary>The raw values a const instruction would hold for <paramref name="text"/>: integers, and float / double bit patterns.</summary>
    private static HashSet<long> ConstValues(string text)
    {
        var values = new HashSet<long>();
        bool negative = text.StartsWith('-');
        var digits = negative ? text[1..] : text;
        if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(digits[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            values.Add(negative ? -(long)hex : (long)hex);
        else if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec)) values.Add(dec);
        if (double.TryParse(text.TrimEnd('f', 'F', 'd', 'D'), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && text.Contains('.', StringComparison.Ordinal))
        {
            values.Add(BitConverter.SingleToInt32Bits((float)d));
            values.Add(BitConverter.DoubleToInt64Bits(d));
        }
        return values;
    }

    /// <summary>
    /// Smali of one method (exact id or a single overload) or of a whole class; <paramref name="simplified"/> adds the string each
    /// decoder call returns, or why it is not known, after the call.
    /// </summary>
    public string Disassemble(string path, string symbol, bool annotated, CancellationToken ct, string? mapping = null, bool simplified = false)
    {
        if (JvmClasses.IsClassInput(path)) return JvmClasses.Listing(path, symbol, ct);
        var index = Index(path, ct);
        var names = Names(index, mapping, ct);
        var text = Disassemble(index, Resolve(index, names, symbol.Trim()), annotated, simplified, ct);
        return names == null ? text : string.Concat(names.Notes.Select(n => $"# {n}\n")) + names.Annotate(text);
    }

    private static string Disassemble(DexIndex index, string symbol, bool annotated, bool simplified, CancellationToken ct)
    {
        var folding = simplified ? DexStringFolding.For(index) : null;
        var counts = new int[4];
        IReadOnlyDictionary<int, string>? Notes(DexFile file, DexEncodedMethod encoded)
        {
            if (folding == null || !index.Methods.TryGetValue(file.Method(encoded.MethodIndex).Descriptor, out var m) || m.File != file) return null;
            var notes = new Dictionary<int, string>();
            foreach (var site in folding.Method(m))
            {
                ct.ThrowIfCancellationRequested();
                counts[site.Evaluated ? (int)site.Fold.Status : 3]++;
                notes[site.Offset] = site.Fold.Status == DexFoldStatus.Simplified ? "simplified: " + Quoted(site.Fold.Value!) : $"not simplified: {site.Fold.Reason}";
            }
            return notes;
        }
        string Counts() => folding == null ? "" : $"# string decoder calls: {counts[0]} simplified, {counts[1]} partial, {counts[2]} unknown, {counts[3]} with arguments that are not constants\n";
        bool member = symbol.Contains("->", StringComparison.Ordinal) || symbol.Contains("::", StringComparison.Ordinal) || symbol.Contains('(', StringComparison.Ordinal);
        if (!member && index.FindClass(symbol) is { } cls)
        {
            // The method ids first, so a large class can be read one method at a time.
            var (_, methods) = cls.File.ClassData(cls.Class);
            var head = new System.Text.StringBuilder($"# {cls.Class.Descriptor} in {cls.File.Name}: {methods.Count} methods (symbol=<id> disassembles one)\n");
            foreach (var x in methods)
                head.Append("#   ").Append(cls.File.Method(x.MethodIndex).Descriptor)
                    .Append(x.CodeOffset != 0 && cls.File.Code(x.CodeOffset) is { } code ? $"  {code.Instructions.Length} units" : "").Append('\n');
            var smali = new DalvikDisassembler(cls.File) { Annotated = annotated, Notes = e => Notes(cls.File, e) }.Class(cls.Class);
            return head + Counts() + smali;
        }
        var id = index.ResolveMethod(symbol, ct);
        if (!index.Methods.TryGetValue(id, out var m))
            throw new ToolError(ErrorCode.NotFound, $"{id} is called by the package but not defined in it (a framework or library method).",
                "find_dex_references with direction=to lists its callers");
        var text = new DalvikDisassembler(m.File) { Annotated = annotated, Notes = e => Notes(m.File, e) }.Method(m.Encoded, m.File.Annotations(m.Class));
        return $"# {id} in {m.File.Name}\n{Counts()}{text}";
    }

    /// <summary>A recovered string quoted in smali escapes; a longer one shows its first 1,000 characters.</summary>
    private static string Quoted(string value) =>
        value.Length <= 1_000 ? $"\"{DexFile.Escape(value)}\"" : $"\"{DexFile.Escape(value[..1_000])}\" ... ({value.Length:N0} characters)";

    public DexReferenceList References(string path, string target, string? kind, string? direction, int offset, int limit, CancellationToken ct)
    {
        var index = Index(path, ct);
        bool from = (direction ?? "to").Trim().ToLowerInvariant() switch
        {
            "to" or "" => false,
            "from" => true,
            var d => throw new ToolError(ErrorCode.InvalidArgument, $"unknown direction '{d}'; use to (who refers to the target) or from (what the target refers to)."),
        };
        index.EnsureCode(ct);
        if (!target.Trim().StartsWith('"')) target = Resolve(index, Names(index, null, ct), target.Trim());
        var (targetKind, keys, label) = ResolveTarget(index, target.Trim(), (kind ?? "auto").Trim().ToLowerInvariant(), from);
        var notes = new List<string>();
        IEnumerable<DexRef> refs;
        if (from) refs = index.Refs.Where(r => keys.Contains(r.From));
        else if (targetKind == "class")
        {
            var prefix = label + "->";
            refs = index.Refs.Where(r => keys.Contains(r.Target) || (r.Kind is DexRefKind.Call or DexRefKind.Read or DexRefKind.Write && index.KeyText(r.Target).StartsWith(prefix, StringComparison.Ordinal)));
            notes.Add("Type uses of the class and calls / field accesses on its members as written in the code (the static receiver type).");
        }
        else refs = index.Refs.Where(r => keys.Contains(r.Target));
        if (targetKind == "method" && !from)
            notes.Add("Calls name the method through the receiver's static type: a call on a subclass or interface descriptor is listed under that descriptor.");
        var rows = refs.OrderBy(r => index.KeyText(r.From), StringComparer.Ordinal).ThenBy(r => r.Offset)
            .Select(r => new DexReference(r.Kind.ToString().ToLowerInvariant(), index.KeyText(r.From), r.Offset, index.KeyText(r.Target), Dalvik.Ops[r.Opcode].Name)).ToList();
        limit = Math.Clamp(limit, 1, 5_000);
        offset = Math.Max(0, offset);
        var page = rows.Skip(offset).Take(limit).ToList();
        return new DexReferenceList(label, targetKind, from ? "from" : "to", page, offset, rows.Count, notes);
    }

    private static (string Kind, HashSet<int> Keys, string Label) ResolveTarget(DexIndex index, string target, string kind, bool from)
    {
        _ = index.Refs; // keys exist once the code index is built
        HashSet<int> Keys(IEnumerable<string> names) => [.. names.Select(index.FindKey).OfType<int>()];
        if (kind == "string" || (kind == "auto" && target.Length >= 2 && target.StartsWith('"') && target.EndsWith('"')))
        {
            var text = kind == "string" ? target : target[1..^1];
            return ("string", Keys([text]), text);
        }
        bool member = target.Contains("->", StringComparison.Ordinal) || target.Contains("::", StringComparison.Ordinal);
        var referenced = !member && kind is "class" or "auto" && index.FindClass(target) is null ? ReferencedClass(index, target) : null;
        if (kind is "class" || (kind == "auto" && !member && (index.FindClass(target) is not null || referenced != null)) || (kind == "auto" && !member && target.StartsWith('L') && target.EndsWith(';')))
        {
            var entry = index.FindClass(target);
            var descriptor = entry?.Class.Descriptor ?? referenced ?? DexIndex.ToDescriptor(target).First();
            if (from)
            {
                if (entry == null) throw index.ClassNotFound(target);
                return ("class", Keys(index.Methods.Values.Where(m => m.Class.Descriptor == descriptor).Select(m => m.Descriptor)), descriptor);
            }
            return ("class", Keys([descriptor]), descriptor);
        }
        if (kind is "field" || (kind == "auto" && target.Contains("->", StringComparison.Ordinal) && target.Contains(':', StringComparison.Ordinal) && !target.Contains('(', StringComparison.Ordinal)))
            return Field(index, target);
        if (kind is "method" or "auto")
        {
            var methods = index.FindMethods(target);
            if (methods.Count == 1) return ("method", Keys(methods), methods[0]);
            if (methods.Count > 1) index.ResolveMethod(target); // ambiguous error with the overloads
            if (kind == "auto" && index.FindFields(target).Count > 0) return Field(index, target);
            throw new ToolError(ErrorCode.NotFound, $"no class, method or field {target} in {index.Path}.",
                "use a class name, an exact id from get_dex_class (Lpkg/C;->m(I)V, Lpkg/C;->f:I), Class::member, or a quoted string with kind=string");
        }
        throw new ToolError(ErrorCode.InvalidArgument, $"unknown kind '{kind}'; use auto, class, method, field or string.");
    }

    private static string ReferenceClassOf(string key) => key.IndexOf("->", StringComparison.Ordinal) is var arrow and > 0 ? key[..arrow] : key;

    /// <summary>The descriptor of a class the code refers to without defining it (a framework class), given in any name form; null when none.</summary>
    private static string? ReferencedClass(DexIndex index, string target)
    {
        var candidates = DexIndex.ToDescriptor(target).ToList();
        var owners = index.Refs.Select(r => r.Target).Distinct().Select(k => ReferenceClassOf(index.KeyText(k))).ToHashSet(StringComparer.Ordinal);
        return candidates.FirstOrDefault(owners.Contains);
    }

    private static (string, HashSet<int>, string) Field(DexIndex index, string target)
    {
        var fields = index.FindFields(target);
        if (fields.Count == 0) throw new ToolError(ErrorCode.NotFound, $"no field {target} in {index.Path}.", "get_dex_class lists a class's fields with their ids");
        if (fields.Count > 1) throw new ToolError(ErrorCode.Ambiguous, $"{target} names {fields.Count} fields: {string.Join(", ", fields)}.", "pass the exact id Lpkg/C;->name:type");
        return ("field", [.. fields.Select(index.FindKey).OfType<int>()], fields[0]);
    }
}
