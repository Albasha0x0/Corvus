using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Checks P/Invoke declarations ([DllImport] / ImplMap rows) against the exports of the native DLLs they bind to,
/// with the Windows runtime's lookup rules: DLL search order, API set redirection, A/W suffixes, x86 stdcall
/// decoration (_Name@N with N computed from the signature), ordinals and export forwarders.
/// </summary>
public sealed class NativeImportVerifier(Func<string, INativeImage> open)
{
    public sealed record Check(string Method, string Module, string EntryPoint, string CharSet, bool ExactSpelling, string CallingConvention,
        string Status, string? ResolvedFile, string? Export, string Detail);

    /// <summary>Statuses, from best to worst.</summary>
    public const string Verified = "verified", Decorated = "decorated", Forwarded = "forwarded", Ordinal = "ordinal",
        MissingExport = "missing_export", DllNotFound = "dll_not_found", NotChecked = "not_checked";

    private const int MaxForwarderDepth = 8;
    private readonly Dictionary<string, INativeImage?> _images = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<INativeImage, Dictionary<string, NativeExport>> _exportsByName = new(ReferenceEqualityComparer.Instance);
    private ApiSetSchema? _apiSets;
    private bool _apiSetsLoaded;

    public List<Check> Verify(LoadedAssembly asm, CancellationToken ct)
    {
        var checks = new List<Check>();
        bool x86 = IsX86(asm.Module);
        foreach (var type in asm.Module.GetTypes())
            foreach (var method in type.Methods)
            {
                ct.ThrowIfCancellationRequested();
                if (method.ImplMap is { } map)
                    checks.Add(CheckOne(asm, method, map, x86));
            }
        return checks;
    }

    /// <summary>32-bit when the module requires it (x86, or AnyCPU with "prefer 32-bit").</summary>
    private static bool IsX86(ModuleDef module) =>
        module.Machine == dnlib.PE.Machine.I386 && (module.Is32BitRequired || module.Is32BitPreferred);

    private Check CheckOne(LoadedAssembly asm, MethodDef method, ImplMap map, bool x86)
    {
        string label = Format.MemberLabel(method);
        string module = map.Module?.Name?.String ?? "";
        string entry = map.Name?.String is { Length: > 0 } n ? n : method.Name.String;
        string charSet = map.IsCharSetUnicode || map.IsCharSetAuto ? "Unicode" : map.IsCharSetAnsi ? "Ansi" : "None";
        string callConv = map.IsCallConvCdecl ? "Cdecl" : map.IsCallConvStdcall ? "StdCall" : map.IsCallConvThiscall ? "ThisCall"
            : map.IsCallConvFastcall ? "FastCall" : "Winapi";
        Check Result(string status, string? file, string? export, string detail) =>
            new(label, module, entry, charSet, map.IsNoMangle, callConv, status, file, export, detail);

        if (module.Length == 0) return Result(NotChecked, null, null, "the ImplMap row names no module");
        if (module is "QCall" or "__Internal" || module.StartsWith("libSystem.", StringComparison.Ordinal))
            return Result(NotChecked, null, null, "resolved by the runtime itself (QCall, __Internal or a runtime native library)");
        if (!OperatingSystem.IsWindows()) return Result(NotChecked, null, null, "DLL lookup is checked on Windows hosts only");

        var (file, searched) = Locate(module, asm.FilePath, x86);
        if (file == null)
            return IsRuntimeLibrary(module)
                ? Result(NotChecked, null, null, "a .NET runtime native library that the runtime links in on this platform (no separate DLL)")
                : Result(DllNotFound, null, null, "searched " + string.Join("; ", searched));
        var image = Open(file);
        if (image == null) return Result(DllNotFound, file, null, $"{file} is not a readable PE image");

        if (entry.StartsWith('#'))
        {
            if (!uint.TryParse(entry.AsSpan(1), out var ordinal)) return Result(MissingExport, file, null, $"'{entry}' is not an ordinal");
            var byOrdinal = image.Exports.FirstOrDefault(e => e.Ordinal == ordinal);
            return byOrdinal != null
                ? Result(Ordinal, file, byOrdinal.Name ?? entry, $"ordinal {ordinal}" + (byOrdinal.Name != null ? $" ({byOrdinal.Name})" : ""))
                : Result(MissingExport, file, null, $"no export with ordinal {ordinal}");
        }

        foreach (var (candidate, exact) in Candidates(entry, charSet, map.IsNoMangle, x86 && callConv is "StdCall" or "Winapi" ? StackBytes(method) : null))
        {
            if (!ByName(image).TryGetValue(candidate, out var export)) continue;
            if (export.ForwardedTo is { } forward)
            {
                var (target, chain) = Follow(forward, file, 0);
                return target != null
                    ? Result(Forwarded, file, candidate, $"forwarded: {chain}")
                    : Result(MissingExport, file, candidate, $"forwarder does not resolve: {chain}");
            }
            return Result(exact ? Verified : Decorated, file, candidate, exact ? "exported" : $"exported as {candidate}");
        }
        return Result(MissingExport, file, null, NearMisses(image, entry));
    }

    /// <summary>System.*.Native libraries: shipped as separate files on some platforms, linked into the runtime on others.</summary>
    private static bool IsRuntimeLibrary(string module) =>
        module.StartsWith("System.", StringComparison.Ordinal) && module.EndsWith(".Native", StringComparison.Ordinal);

    /// <summary>Export names the runtime tries, in order; Exact is false for suffixed or decorated forms.</summary>
    internal static IEnumerable<(string Name, bool Exact)> Candidates(string entry, string charSet, bool exactSpelling, int? stdcallBytes)
    {
        var names = new List<(string, bool)>();
        if (exactSpelling) names.Add((entry, true));
        else if (charSet == "Unicode") { names.Add((entry + "W", false)); names.Add((entry, true)); }
        else { names.Add((entry, true)); names.Add((entry + "A", false)); }
        if (stdcallBytes is { } bytes)
            foreach (var (name, _) in names.ToArray())
                names.Add(($"_{name}@{bytes}", false));
        return names;
    }

    /// <summary>Bytes of x86 stack arguments for stdcall decoration, or null when a parameter's size is unknown.</summary>
    internal static int? StackBytes(MethodDef method)
    {
        int total = 0;
        foreach (var p in method.Parameters)
        {
            if (p.IsHiddenThisParameter) continue;
            if (p.ParamDef?.MarshalType is { } marshal && marshal.NativeType is NativeType.Struct or NativeType.FixedArray or NativeType.SafeArray)
                return null;
            var size = ArgumentSize(p.Type);
            if (size == null) return null;
            total += size.Value;
        }
        return total;
    }

    private static int? ArgumentSize(TypeSig type)
    {
        type = type.RemovePinnedAndModifiers();
        switch (type.ElementType)
        {
            case ElementType.I8: case ElementType.U8: case ElementType.R8:
                return 8;
            case ElementType.Boolean: case ElementType.Char: case ElementType.I1: case ElementType.U1: case ElementType.I2: case ElementType.U2:
            case ElementType.I4: case ElementType.U4: case ElementType.R4: case ElementType.I: case ElementType.U:
            case ElementType.Ptr: case ElementType.FnPtr: case ElementType.ByRef: case ElementType.String: case ElementType.Object:
            case ElementType.Class: case ElementType.SZArray: case ElementType.Array:
                return 4;
            case ElementType.ValueType:
                var def = type.ToTypeDefOrRef().ResolveTypeDef();
                if (def == null) return null;
                if (def.IsEnum) return def.GetEnumUnderlyingType() is { } underlying ? ArgumentSize(underlying) : null;
                // Structs by value need the marshaled layout; only explicit sizes are trusted.
                return def.ClassLayout is { ClassSize: > 0 } layout ? (int)((layout.ClassSize + 3) & ~3u) : null;
            default:
                return null;
        }
    }

    /// <summary>The file the Windows loader would bind for a DllImport module name, and the places searched.</summary>
    private (string? File, List<string> Searched) Locate(string module, string requester, bool x86)
    {
        var searched = new List<string>();
        var name = module.Trim();
        if (ApiSetSchema.IsApiSetName(name))
        {
            var host = ApiSets()?.Resolve(name, requester);
            searched.Add(host != null ? $"API set {name} -> {host}" : $"API set {name} (not in this system's map)");
            if (host == null) return (null, searched);
            name = host;
        }
        if (!Path.HasExtension(name) || !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            && !name.EndsWith(".drv", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            name += ".dll";
        if (Path.IsPathFullyQualified(name))
        {
            searched.Add(name);
            return (File.Exists(name) ? name : null, searched);
        }
        string system = x86 && Environment.Is64BitOperatingSystem
            ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
            : Environment.GetFolderPath(Environment.SpecialFolder.System);
        string[] dirs =
        [
            Path.GetDirectoryName(requester) ?? "",
            system,
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            // Runtime-shipped native libraries (e.g. System.IO.Compression.Native) live next to the runtime.
            Path.GetDirectoryName(typeof(object).Assembly.Location) ?? "",
        ];
        foreach (var dir in dirs.Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var candidate = Path.Combine(dir, name);
            searched.Add(dir);
            if (File.Exists(candidate)) return (candidate, searched);
        }
        return (null, searched);
    }

    private (string? Target, string Chain) Follow(string forward, string fromFile, int depth)
    {
        int dot = forward.LastIndexOf('.');
        if (dot <= 0 || depth >= MaxForwarderDepth) return (null, forward);
        var module = forward[..dot];
        var name = forward[(dot + 1)..];
        var (file, _) = Locate(module, fromFile, false);
        if (file == null || Open(file) is not { } image) return (null, $"{forward} (module not found)");
        if (name.StartsWith('#'))
        {
            bool found = uint.TryParse(name.AsSpan(1), out var ordinal) && image.Exports.Any(e => e.Ordinal == ordinal);
            return (found ? file : null, forward);
        }
        if (!ByName(image).TryGetValue(name, out var export)) return (null, $"{forward} (no such export in {Path.GetFileName(file)})");
        if (export.ForwardedTo is { } next)
        {
            var (target, chain) = Follow(next, file, depth + 1);
            return (target, $"{forward} -> {chain}");
        }
        return (file, $"{Path.GetFileName(file)}!{name}");
    }

    private static string NearMisses(INativeImage image, string entry)
    {
        var close = image.Exports.Select(e => e.Name).OfType<string>()
            .Where(n => n.Contains(entry, StringComparison.OrdinalIgnoreCase) || entry.Contains(n.TrimEnd('A', 'W'), StringComparison.OrdinalIgnoreCase) && n.Length > 3)
            .Take(8).ToList();
        return close.Count > 0 ? $"not exported; similar exports: {string.Join(", ", close)}" : $"not exported ({image.Exports.Count} exports checked)";
    }

    private Dictionary<string, NativeExport> ByName(INativeImage image)
    {
        if (_exportsByName.TryGetValue(image, out var map)) return map;
        map = new Dictionary<string, NativeExport>(StringComparer.Ordinal);
        foreach (var e in image.Exports)
            if (e.Name != null) map.TryAdd(e.Name, e);
        return _exportsByName[image] = map;
    }

    private INativeImage? Open(string file)
    {
        if (_images.TryGetValue(file, out var image)) return image;
        try { image = open(file); }
        catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { image = null; }
        return _images[file] = image;
    }

    private ApiSetSchema? ApiSets()
    {
        if (!_apiSetsLoaded)
        {
            _apiSets = ApiSetSchema.FromSystem(path => Open(path) ?? throw new ToolError(ErrorCode.MalformedInput, path));
            _apiSetsLoaded = true;
        }
        return _apiSets;
    }
}
