using System.Text;
using System.Text.RegularExpressions;
using dnlib.DotNet;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Navigation between Il2Cpp metadata and native addresses. Address to entity: function starts from the dump's
/// script.json bound each function (it ends where the next one starts), named by the dummy-DLL methods whose [Address]
/// RVA starts there and by the script.json names (generic instantiations have no dummy method); literal, ScriptMetadata
/// and MethodInfo slots are named too. Without script.json, the dummy methods' own RVAs are the only function starts.
/// Entity to address: a method's function and MethodInfo slot, the instantiations of a generic method, a type's
/// metadata slots, the method implementing a vtable slot.
/// </summary>
public sealed class Il2CppNavigator(AssemblyWorkspace workspace, Il2CppService il2cpp, Il2CppStringService strings)
{
    private readonly object _lock = new();
    private (int Generation, Dictionary<string, Il2CppStringService.MethodStarts> Maps) _undumped = (-1, new());
    private (int Generation, Dictionary<string, Dictionary<int, List<ResolvedSymbol>>> Maps) _typeKeys = (-1, new());

    /// <summary>The dummy assemblies of one dump in a scope, or those without dump files, with what navigation uses.</summary>
    public sealed class Image
    {
        internal Image(Il2CppStringIndex? dump, IReadOnlyList<LoadedAssembly> assemblies, Il2CppStringService.MethodStarts methods)
        {
            Dump = dump;
            Assemblies = assemblies;
            Methods = methods;
            if (dump?.Files.HasScript != true) return;
            try { Script = dump.Script; }
            catch (Exception ex) when (ex is System.Text.Json.JsonException or IOException or UnauthorizedAccessException)
            {
                Problem = $"cannot read {dump.Files.ScriptSource}: {ex.Message}";
            }
        }

        public Il2CppStringIndex? Dump { get; }
        public IReadOnlyList<LoadedAssembly> Assemblies { get; }
        /// <summary>Dummy methods by RVA (of every loaded assembly of the dump).</summary>
        public Il2CppStringService.MethodStarts Methods { get; }
        public Il2CppScript? Script { get; }
        /// <summary>Why script.json could not be used.</summary>
        public string? Problem { get; }
        public uint[] Starts => Script?.FunctionStarts ?? Methods.Starts;
        public List<NativeCodeScanner.Section>? Sections => Dump?.Binary?.Sections;

        /// <summary>Image bases a VA may be relative to: the dumper's (from the methods' VAs) and the binary's preferred one.</summary>
        public IEnumerable<ulong> ImageBases => new[] { Methods.ImageBase, Dump?.Binary?.ImageBase }.OfType<ulong>().Where(b => b > 0).Distinct();

        public ulong? OffsetToRva(ulong offset)
        {
            if (Sections is { } sections)
            {
                var s = sections.FirstOrDefault(s => offset >= s.RawOffset && offset < (ulong)s.RawOffset + s.RawSize);
                return s != null ? s.Rva + (offset - s.RawOffset) : null;
            }
            return Methods.OffsetToRva(offset);
        }

        public ArraySegment<Il2CppService.MethodAddress> MethodsAt(uint rva) => Methods.At(rva);
    }

    public enum SlotKind { Literal, Metadata, MethodInfo }

    /// <summary>A data slot: <see cref="Entry"/> indexes the dump's literals, ScriptMetadata or ScriptMetadataMethod entries.</summary>
    public sealed record DataSlot(SlotKind Kind, uint Address, int Entry);

    /// <summary>A function: its start, where it ends (the next function start or the section end) when known, and how the address relates.</summary>
    public sealed record FunctionAt(uint Start, uint? End, string Relation)
    {
        public bool IsExactStart => Relation == "exact start";
    }

    /// <summary>What an address is in one image: a function with the methods sharing its code, or a data slot.</summary>
    public sealed record AddressResult(Image Image, string Kind, ulong Address, ulong Rva, FunctionAt? Function, DataSlot? Slot,
        IReadOnlyList<Il2CppService.MethodAddress> Methods, IReadOnlyList<int> ScriptMethods)
    {
        public int Total => Methods.Count + ScriptMethods.Count;
        /// <summary>The address in the queried kind of an RVA in the same section.</summary>
        public ulong InKind(ulong rva) => (ulong)((long)rva + ((long)Address - (long)Rva));
    }

    /// <summary>The images of the Il2Cpp dummy assemblies in <paramref name="scope"/>.</summary>
    public List<Image> ImagesFor(IReadOnlyList<LoadedAssembly> scope)
    {
        var result = new List<Image>();
        var dumps = strings.DumpsFor(scope);
        foreach (var (dump, assemblies) in dumps)
            result.Add(new Image(dump, assemblies, strings.MethodsByRva(dump)));
        var rest = scope.Where(a => il2cpp.GetIndex(a).Count > 0 && !dumps.Any(d => d.Assemblies.Contains(a))).ToList();
        if (rest.Count > 0) result.Add(new Image(null, rest, UndumpedMethods(rest)));
        return result;
    }

    private Il2CppStringService.MethodStarts UndumpedMethods(List<LoadedAssembly> assemblies)
    {
        var key = string.Join("|", assemblies.Select(a => a.Id));
        lock (_lock)
        {
            if (_undumped.Generation != workspace.Generation) _undumped = (workspace.Generation, new());
            if (!_undumped.Maps.TryGetValue(key, out var map))
                _undumped.Maps[key] = map = Il2CppStringService.MethodStarts.Of(assemblies.SelectMany(il2cpp.GetIndex));
            return map;
        }
    }

    /// <summary>
    /// What a native address is, per image. kind = rva | va | offset | auto. Auto reads an address at or above an image
    /// base as a VA, any other as an RVA, and as a file offset only when the RVA reading finds nothing.
    /// </summary>
    public List<AddressResult> Locate(ulong address, string kind, IReadOnlyList<LoadedAssembly> scope)
    {
        var mode = kind.ToLowerInvariant() switch
        {
            "rva" => "rva",
            "va" => "va",
            "offset" or "fileoffset" => "offset",
            "auto" or "any" or "" => "auto",
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown address kind '{kind}'. Use rva, va, offset or auto."),
        };
        var images = ImagesFor(scope);
        if (images.Count == 0)
            throw new ToolError(ErrorCode.Unsupported, "No Il2Cpp address attributes found in the selected assemblies. This works on Il2Cpp dummy DLLs that carry [Address] attributes.", "load_assembly the game folder or its global-metadata.dat (built-in reader), or an Il2CppDumper / Cpp2IL DummyDll folder");

        var results = new List<AddressResult>();
        foreach (var image in images)
            foreach (var (readingKind, rva) in Readings(image, address, mode))
                if (Classify(image, readingKind, address, rva) is { } found) { results.Add(found); break; }
        return results;
    }

    private static IEnumerable<(string Kind, ulong Rva)> Readings(Image image, ulong address, string mode)
    {
        var vas = image.ImageBases.Where(b => address >= b && address - b <= uint.MaxValue).Select(b => ("va", address - b)).ToList();
        if (mode is "va" or "auto") foreach (var r in vas) yield return r;
        if (mode == "auto" && vas.Count > 0) yield break;
        if (mode is "rva" or "auto") yield return ("rva", address);
        if (mode is "offset" or "auto" && image.OffsetToRva(address) is { } fromOffset) yield return ("offset", fromOffset);
    }

    private AddressResult? Classify(Image image, string kind, ulong address, ulong rva)
    {
        if (rva > uint.MaxValue) return null;
        var r = (uint)rva;
        if (Slot(image, r) is { } slot)
            return new AddressResult(image, kind, address, rva, null, slot, [], []);
        if (Function(image, r) is not { } function) return null;
        var (methods, scriptMethods) = MethodsSharing(image, function.Start);
        return new AddressResult(image, kind, address, rva, function, null, methods, scriptMethods);
    }

    private static DataSlot? Slot(Image image, uint rva)
    {
        if (image.Dump is not { } dump) return null;
        if (dump.Files.HasLiterals)
        {
            try { if (dump.LiteralAt(rva) is { } literal) return new DataSlot(SlotKind.Literal, rva, literal); }
            catch (ToolError) { } // unreadable literal file: still answer for code
        }
        if (image.Script is not { } script) return null;
        if (script.MetadataAt(rva) is { } metadata) return new DataSlot(SlotKind.Metadata, script.MetadataAddress(metadata), metadata);
        if (script.MethodInfoAt(rva) is { } info) return new DataSlot(SlotKind.MethodInfo, script.MethodInfoAddress(info), info);
        return null;
    }

    /// <summary>
    /// The function containing <paramref name="rva"/>. With script.json every function start is known, so a function ends
    /// where the next starts (or at the end of its section); with dummy methods only, instantiations without one can sit
    /// between them, so a containing method is only probable. Null beyond <see cref="Il2CppService.MaxFunctionSpan"/>
    /// from the last start, outside the executable sections, and before the first start.
    /// </summary>
    public static FunctionAt? Function(Image image, uint rva)
    {
        var starts = image.Starts;
        int i = Array.BinarySearch(starts, rva);
        if (i < 0) i = ~i - 1;
        if (i < 0) return null;
        uint start = starts[i];
        uint? next = i + 1 < starts.Length ? starts[i + 1] : null;
        uint? end = next;
        string bound = "the next function start";
        if (image.Sections is { } sections)
        {
            var section = sections.FirstOrDefault(s => s.Executable && s.Contains(rva));
            if (section == null || !section.Contains(start)) return null;
            uint sectionEnd = section.Rva + Math.Max(section.VirtualSize, section.RawSize);
            if (end == null || sectionEnd < end) { end = sectionEnd; bound = $"the end of {section.Name}"; }
        }
        uint delta = rva - start;
        if (delta == 0) return new FunctionAt(start, end, "exact start");
        if (image.Script == null)
        {
            if (image.MethodsAt(start).Select(m => m.Length).FirstOrDefault(l => l > 0) is { } length)
                return delta < length ? new FunctionAt(start, start + (uint)length, $"inside (+0x{delta:X} of 0x{length:X} bytes)")
                    : delta < length + Il2CppService.MaxFunctionSpan ? new FunctionAt(start, start + (uint)length, $"after end (+0x{delta:X}; length 0x{length:X})")
                    : null;
            if (delta >= Il2CppService.MaxFunctionSpan) return null;
            return new FunctionAt(start, end, next is { } n
                ? $"probably inside (+0x{delta:X}; next method starts at 0x{n:X})"
                : $"after the last known method (+0x{delta:X})");
        }
        if (end is not { } e) return delta < Il2CppService.MaxFunctionSpan ? new FunctionAt(start, null, $"after the last known function start (+0x{delta:X})") : null;
        if (e - start <= Il2CppService.MaxFunctionSpan) return new FunctionAt(start, end, $"inside (+0x{delta:X} of 0x{e - start:X} bytes up to {bound})");
        return delta < Il2CppService.MaxFunctionSpan
            ? new FunctionAt(start, end, $"probably inside (+0x{delta:X}; {bound} is 0x{e - start:X} bytes from its start)")
            : null;
    }

    /// <summary>
    /// The methods whose code starts at <paramref name="start"/>: dummy-DLL methods of the image's assemblies, and the
    /// script.json entries there that are not one of them (generic instantiations).
    /// </summary>
    public static (List<Il2CppService.MethodAddress> Methods, List<int> ScriptMethods) MethodsSharing(Image image, uint start)
    {
        var inImage = image.Assemblies.ToHashSet();
        var methods = image.MethodsAt(start).Where(m => inImage.Contains(m.Assembly)).ToList();
        var scriptMethods = new List<int>();
        if (image.Script is { } script)
        {
            var (first, count) = script.MethodRange(start);
            var dummyNames = image.MethodsAt(start).Select(m => Il2CppNames.MethodKey(m.Method)).ToHashSet(StringComparer.Ordinal);
            for (int k = first; k < first + count; k++)
                if (!dummyNames.Contains(script.MethodName(k))) scriptMethods.Add(k);
        }
        return (methods, scriptMethods);
    }

    /// <summary>The image holding <paramref name="asm"/>, when it is an Il2Cpp dummy assembly.</summary>
    public Image? ImageOf(LoadedAssembly asm) => ImagesFor([asm]).FirstOrDefault();

    /// <summary>The MethodInfo slots named after a dummy method; those describing <paramref name="rva"/> first.</summary>
    public static List<int> MethodInfos(Il2CppScript script, MethodDef method, ulong? rva)
    {
        var found = script.MethodInfosNamed($"Method${Il2CppNames.TypeKey(method.DeclaringType)}.{method.Name}()");
        var own = found.Where(e => rva != null && script.MethodInfoTarget(e) == rva).ToList();
        return own.Count > 0 ? own : found;
    }

    /// <summary>
    /// The script.json entries instantiating a generic method or a method of a generic type: each with its match among
    /// the methods sharing its script.json name (<see cref="Il2CppOverloads"/>); entries resolved to another overload are
    /// left out, ambiguous ones kept. <c>Unmatched</c> counts the entries of the name no overload's signature fits.
    /// </summary>
    public sealed record InstantiationList(List<(int Entry, Il2CppOverloads.Match Match)> Entries, int Overloads, int Unmatched);

    public InstantiationList Instantiations(Image image, MethodDef method, CancellationToken ct = default)
    {
        if (image.Script is not { } script || !method.HasGenericParameters && !IsInGenericType(method.DeclaringType)) return new([], 1, 0);
        var typeKey = Il2CppNames.TypeKey(method.DeclaringType);
        var name = method.Name.String;
        var entries = script.FindMethods(t => Il2CppNames.StripArgs(t) == typeKey, m => Il2CppNames.StripArgs(m) == name, ct);
        var overloads = MethodsNamed(image, typeKey, name);
        if (!overloads.Contains(method)) overloads.Add(method);
        var list = new List<(int, Il2CppOverloads.Match)>();
        int unmatched = 0;
        using var reader = overloads.Count > 1 ? script.OpenMethods() : null;
        foreach (var e in entries)
        {
            ct.ThrowIfCancellationRequested();
            var match = Exact(script, e, overloads) ?? Il2CppOverloads.Resolve(overloads, script.MethodTypeName(e), script.MethodShortName(e), () => reader!.Read(e));
            if (match.Includes(method)) list.Add((e, match));
            else if (match.Outcome == Il2CppOverloads.Outcome.Unmatched) unmatched++;
        }
        return new InstantiationList(list, overloads.Count, unmatched);
    }

    /// <summary>The dummy method a script.json entry instantiates (or is), among the methods sharing its name.</summary>
    public Il2CppOverloads.Match DefinitionOf(Image image, int entry)
    {
        var script = image.Script!;
        var type = script.MethodTypeName(entry);
        var name = script.MethodShortName(entry);
        var candidates = MethodsNamed(image, Il2CppNames.StripArgs(type), Il2CppNames.StripArgs(name));
        return Exact(script, entry, candidates) ?? Il2CppOverloads.Resolve(candidates, type, name, () => script.ReadMethod(entry));
    }

    /// <summary>
    /// The candidate a script built from the metadata names as the entry's definition (image and [Token]); null when
    /// the script has no definitions (script.json) or no single candidate carries that token.
    /// </summary>
    private static Il2CppOverloads.Match? Exact(Il2CppScript script, int entry, IReadOnlyList<MethodDef> candidates)
    {
        if (candidates.Count == 0 || script.Definition(entry) is not var (image, token)) return null;
        var assembly = Path.GetFileNameWithoutExtension(image);
        var found = candidates.Where(m => TokenOf(m) == token && string.Equals(m.Module?.Assembly?.Name, assembly, StringComparison.OrdinalIgnoreCase)).ToList();
        return found.Count == 1 ? new Il2CppOverloads.Match(Il2CppOverloads.Outcome.Resolved, found, "the metadata definition", candidates.Count) : null;
    }

    /// <summary>The original metadata token of a dummy member ([Token(Token = "0x...")]).</summary>
    public static uint? TokenOf(IHasCustomAttribute member) =>
        Il2CppService.GetAttributes(member).FirstOrDefault(a => a.Name == "TokenAttribute")?.Values.GetValueOrDefault("Token") is { } s
        && Il2CppService.ParseNumber(s) is { } n && n <= uint.MaxValue ? (uint)n : null;

    /// <summary>The image's methods named <paramref name="name"/> in the types whose script.json name is <paramref name="typeKey"/> (any arity).</summary>
    public List<MethodDef> MethodsNamed(Image image, string typeKey, string name) =>
        TypesByKey(image).GetValueOrDefault(typeKey.GetHashCode())?.Select(t => (TypeDef)t.Member).Where(t => Il2CppNames.TypeKey(t) == typeKey)
            .SelectMany(t => t.Methods.Where(m => m.Name == name)).ToList() ?? [];

    private static bool IsInGenericType(TypeDef? t)
    {
        for (; t != null; t = t.DeclaringType)
            if (t.HasGenericParameters) return true;
        return false;
    }

    /// <summary>
    /// ScriptMetadata slots of a type: its class (Ns.Type_TypeInfo), Il2CppType (_var) and array class, and for a
    /// generic type those of every instantiation.
    /// </summary>
    public static List<int> TypeMetadata(Il2CppScript script, TypeDef type)
    {
        var key = Il2CppNames.TypeKey(type);
        if (IsInGenericType(type))
            return Enumerable.Range(0, script.MetadataCount).Where(e => Il2CppNames.MetadataSubject(script.MetadataName(e)) is { } s && s != key && Il2CppNames.StripArgs(s) == key).ToList();
        return new[] { "_TypeInfo", "_var", "[]_TypeInfo" }.SelectMany(suffix => script.MetadataNamed(key + suffix)).Order().ToList();
    }

    /// <summary>The dummy type a ScriptMetadata name ("Ns.Type&lt;args&gt;_TypeInfo") describes (its definition for an instantiation).</summary>
    public IReadOnlyList<ResolvedSymbol> TypeOfMetadata(Image image, string metadataName)
    {
        if (Il2CppNames.MetadataSubject(metadataName) is not { } subject) return [];
        var key = Il2CppNames.StripArgs(subject.EndsWith("[]", StringComparison.Ordinal) ? subject[..^2] : subject);
        if (key.Length == 0 || key.Contains('[')) return [];
        return TypesByKey(image).GetValueOrDefault(key.GetHashCode())?.Where(t => Il2CppNames.TypeKey((TypeDef)t.Member) == key).ToList() ?? [];
    }

    /// <summary>The image's types by the hash of their script.json name (names are not kept: matches are checked).</summary>
    private Dictionary<int, List<ResolvedSymbol>> TypesByKey(Image image)
    {
        var key = string.Join("|", image.Assemblies.Select(a => a.Id));
        lock (_lock)
        {
            if (_typeKeys.Generation != workspace.Generation) _typeKeys = (workspace.Generation, new());
            if (_typeKeys.Maps.TryGetValue(key, out var map)) return map;
            map = new Dictionary<int, List<ResolvedSymbol>>();
            foreach (var asm in image.Assemblies)
                foreach (var t in asm.Module.GetTypes())
                {
                    int hash = Il2CppNames.TypeKey(t).GetHashCode();
                    (map.TryGetValue(hash, out var list) ? list : map[hash] = []).Add(new ResolvedSymbol(asm, t));
                }
            return _typeKeys.Maps[key] = map;
        }
    }

    /// <summary>The method implementing vtable slot <paramref name="slot"/> of a type: its own, else the nearest base type's.</summary>
    public static MethodDef? SlotMethod(TypeDef type, int slot) => VTable(type).GetValueOrDefault(slot);

    /// <summary>Every vtable slot of a type that its methods or its base types' methods declare, with the most derived implementation.</summary>
    public static SortedDictionary<int, MethodDef> VTable(TypeDef type)
    {
        var slots = new SortedDictionary<int, MethodDef>();
        int depth = 0;
        for (var t = type; t != null && depth++ < 64; t = MetadataUtil.Try(() => t.BaseType?.ResolveTypeDef()))
            foreach (var m in t.Methods)
                if (SlotOf(m) is { } s) slots.TryAdd(s, m);
        return slots;
    }

    public static int? SlotOf(MethodDef method) =>
        Il2CppService.GetAttributes(method).FirstOrDefault(a => a.Name.Contains("Address", StringComparison.Ordinal))?.Values.GetValueOrDefault("Slot") is { } s
        && Il2CppService.ParseNumber(s) is { } n && n <= int.MaxValue ? (int)n : null;

    /// <summary>
    /// script.json entries for a method or instantiation name as a user would write it: "List`1&lt;int&gt;::Add",
    /// "System.Collections.Generic.List&lt;int&gt;$$Add", "List&lt;System.Int32&gt;.Add", or a type alone for all its methods.
    /// Exact names first, then names ending in the query at a '.', then with generic arguments compared by simple name.
    /// </summary>
    public static List<int> FindScriptMethods(Il2CppScript script, string query, CancellationToken ct = default)
    {
        var q = Il2CppNames.NormalizeQuery(query);
        if (q.Length == 0) return [];
        var splits = new List<(string Type, string? Method)>();
        int sep = q.IndexOf("$$", StringComparison.Ordinal);
        if (sep >= 0) splits.Add((q[..sep], q[(sep + 2)..]));
        else
        {
            splits.Add((q, null));
            if (Il2CppNames.SplitMember(q) is { } split) splits.Add(split);
        }
        foreach (var (type, method) in splits)
        {
            if (type.Length == 0) continue;
            var looseType = Il2CppNames.Loose(type);
            var typeLevels = new Func<string, bool>[]
            {
                t => t == type,
                t => t.EndsWith("." + type, StringComparison.Ordinal),
                t => string.Equals(Il2CppNames.Loose(t), looseType, StringComparison.OrdinalIgnoreCase),
                t => Il2CppNames.Loose(t).EndsWith("." + looseType, StringComparison.OrdinalIgnoreCase),
            };
            var methodLevels = method == null ? [null] : new Func<string, bool>?[]
            {
                m => m == method,
                m => string.Equals(Il2CppNames.Loose(m), Il2CppNames.Loose(method), StringComparison.OrdinalIgnoreCase),
            };
            foreach (var methodLevel in methodLevels)
                foreach (var typeLevel in typeLevels)
                    if (script.FindMethods(typeLevel, methodLevel, ct) is { Count: > 0 } found) return found;
        }
        return [];
    }

    /// <summary>ScriptMetadata / ScriptMetadataMethod entries named exactly <paramref name="query"/> ("Ns.Type_TypeInfo", "Method$Ns.Type.M()").</summary>
    public static (List<int> Metadata, List<int> MethodInfos) FindSlots(Il2CppScript script, string query)
    {
        var q = query.Trim();
        return (script.MetadataNamed(q), q.StartsWith("Method$", StringComparison.Ordinal) ? script.MethodInfosNamed(q) : []);
    }
}

/// <summary>Il2CppDumper's naming in script.json, and the forms of it users type.</summary>
public static partial class Il2CppNames
{
    /// <summary>A dummy type as script.json names it: nested types joined with '.', no arity suffixes.</summary>
    public static string TypeKey(TypeDef type) => type.DeclaringType is { } outer
        ? TypeKey(outer) + "." + Format.StripArity(type.Name)
        : (type.Namespace.Length > 0 ? type.Namespace + "." : "") + Format.StripArity(type.Name);

    /// <summary>A dummy method as script.json names it: "Ns.Type$$Method".</summary>
    public static string MethodKey(MethodDef method) => TypeKey(method.DeclaringType) + "$$" + method.Name;

    /// <summary>
    /// A name without its trailing generic argument list: "List&lt;int&gt;" → "List", "&lt;&gt;c&lt;X&gt;" → "&lt;&gt;c";
    /// names that are themselves in angle brackets ("&lt;Module&gt;") stay.
    /// </summary>
    public static string StripArgs(string name)
    {
        if (!name.EndsWith('>')) return name;
        int depth = 0;
        for (int i = name.Length - 1; i >= 0; i--)
        {
            if (name[i] == '>') depth++;
            else if (name[i] == '<' && --depth == 0)
                return i > 0 && name[i - 1] != '.' ? name[..i] : name;
        }
        return name;
    }

    /// <summary>The trailing generic argument list of a name, split at its top-level commas: "Dictionary&lt;int, List&lt;int&gt;&gt;" → [int, List&lt;int&gt;].</summary>
    public static List<string> GenericArguments(string name)
    {
        var stripped = StripArgs(name);
        if (stripped.Length == name.Length) return [];
        var list = new List<string>();
        int depth = 0, start = stripped.Length + 1;
        for (int i = start; i < name.Length - 1; i++)
        {
            if (name[i] == '<') depth++;
            else if (name[i] == '>') depth--;
            else if (name[i] == ',' && depth == 0) { list.Add(name[start..i].Trim()); start = i + 1; }
        }
        list.Add(name[start..^1].Trim());
        return list;
    }

    /// <summary>The type a ScriptMetadata name describes: "Ns.Type_TypeInfo" / "Ns.Type_var" → "Ns.Type"; null for other entries.</summary>
    public static string? MetadataSubject(string metadataName) =>
        metadataName.EndsWith("_TypeInfo", StringComparison.Ordinal) ? metadataName[..^"_TypeInfo".Length]
        : metadataName.EndsWith("_var", StringComparison.Ordinal) ? metadataName[..^"_var".Length]
        : null;

    /// <summary>Whether a name has script.json's "$$" or a generic argument list ("List&lt;int&gt;", not "&lt;&gt;c").</summary>
    public static bool LooksInstantiated(string name) => name.Contains("$$", StringComparison.Ordinal) || Instantiated().IsMatch(name);

    /// <summary>A user's method or type name in script.json form: "::" → "$$", no arity suffixes or parameter list, ", " between arguments.</summary>
    public static string NormalizeQuery(string query)
    {
        var q = query.Trim();
        if (q.EndsWith(')') && TopLevelIndex(q, '(') is var paren and > 0) q = q[..paren].TrimEnd();
        q = Arity().Replace(q, "");
        q = q.Replace("::", "$$").Replace('/', '.').Replace('+', '.');
        q = Comma().Replace(q, ", ");
        return Bracket().Replace(q, "$1");
    }

    /// <summary>Splits "Type.Method" at the last '.' outside angle brackets, keeping ".ctor" / ".cctor" whole.</summary>
    public static (string Type, string Method)? SplitMember(string name)
    {
        foreach (var ctor in new[] { "..ctor", "..cctor" })
            if (name.EndsWith(ctor, StringComparison.Ordinal)) return (name[..^ctor.Length], ctor[1..]);
        int depth = 0;
        for (int i = name.Length - 1; i > 0; i--)
        {
            if (name[i] == '>') depth++;
            else if (name[i] == '<') depth--;
            else if (name[i] == '.' && depth == 0) return (name[..i], name[(i + 1)..]);
        }
        return null;
    }

    private static int TopLevelIndex(string s, char c)
    {
        int depth = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '<') depth++;
            else if (s[i] == '>') depth--;
            else if (s[i] == c && depth == 0) return i;
        }
        return -1;
    }

    private static readonly Dictionary<string, string> Keywords = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Boolean"] = "bool", ["Byte"] = "byte", ["SByte"] = "sbyte", ["Char"] = "char", ["Int16"] = "short", ["UInt16"] = "ushort",
        ["Int32"] = "int", ["UInt32"] = "uint", ["Int64"] = "long", ["UInt64"] = "ulong", ["Single"] = "float", ["Double"] = "double",
        ["Decimal"] = "decimal", ["String"] = "string", ["Object"] = "object", ["IntPtr"] = "nint", ["UIntPtr"] = "nuint",
    };

    /// <summary>
    /// A comparison form of a name: inside generic argument lists, names lose their qualifiers ("System.Int32" and
    /// "Int32" become "int", "Ns.Outer.Inner" becomes "Inner"); spaces are dropped.
    /// </summary>
    public static string Loose(string name)
    {
        var sb = new StringBuilder(name.Length);
        int depth = 0;
        for (int i = 0; i < name.Length;)
        {
            char c = name[i];
            if (depth > 0 && (char.IsLetterOrDigit(c) || c == '_'))
            {
                int j = i;
                while (j < name.Length && (char.IsLetterOrDigit(name[j]) || name[j] is '_' or '.' or '`')) j++;
                var ident = name[i..j];
                ident = ident[(ident.LastIndexOf('.') + 1)..];
                sb.Append(Keywords.GetValueOrDefault(ident, ident));
                i = j;
                continue;
            }
            if (c == '<') depth++;
            else if (c == '>') depth--;
            if (c != ' ') sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    [GeneratedRegex(@"[\w`]<[^>]")]
    private static partial Regex Instantiated();
    [GeneratedRegex(@"`\d+")]
    private static partial Regex Arity();
    [GeneratedRegex(@"\s*,\s*")]
    private static partial Regex Comma();
    [GeneratedRegex(@"\s*([<>\[\]])\s*")]
    private static partial Regex Bracket();
}
