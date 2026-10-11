namespace Corvus.Native.Linking;

/// <summary>One step of a binding: an export of a file, and where it leads (its RVA, or the forwarder string).</summary>
/// <param name="Export">The export name, or "#ordinal" for an export without a name.</param>
/// <param name="Via">How this hop was reached: "import", "forwarder", "thunk" (a jmp through an import slot) or "pinvoke".</param>
public sealed record LinkHop(string File, string Export, uint Ordinal, uint? Rva, string? ForwardedTo, string Via)
{
    public string Module => Path.GetFileName(File);
    public string Label => $"{Module}!{Export}";

    /// <summary>Identity of the code reached: file and RVA (forwarders have none, they compare by name).</summary>
    public string Key => Rva is { } rva ? $"{File.ToLowerInvariant()}|{rva:X}" : $"{File.ToLowerInvariant()}|{Export}";
}

/// <summary>
/// Outcome of binding an import or a P/Invoke: <see cref="Status"/> is <see cref="NativeLinker.Resolved"/> with the hops
/// from the first export to the code (forwarders followed), or an unresolved reason code with <see cref="Detail"/>.
/// </summary>
public sealed record LinkResult(string Status, string Module, string? File, IReadOnlyList<LinkHop> Hops, string Detail)
{
    public bool IsResolved => Status == NativeLinker.Resolved;
    /// <summary>The hop with the code (or data) the binding ends at; null unless resolved.</summary>
    public LinkHop? Final => IsResolved && Hops.Count > 0 ? Hops[^1] : null;
    public string Chain => string.Join(" -> ", Hops.Select(h => h.Label));
}

/// <summary>
/// Binds imported names to exports the way the Windows loader does: locates the providing DLL (API set map, the
/// importer's folder, images the caller has loaded, the system folder of the importer's bitness, the Windows folder),
/// finds the export by name or ordinal and follows forwarder chains. Images are opened through the given delegate,
/// which may serve them from a cache; results are memoized per instance. Not thread-safe.
/// </summary>
public sealed partial class NativeLinker
{
    /// <summary>Statuses: resolved, or the reason binding stopped.</summary>
    public const string Resolved = "resolved", DllNotFound = "dll_not_found", ApiSetUnmapped = "api_set_unmapped", MissingExport = "missing_export",
        MissingOrdinal = "missing_ordinal", ForwarderBroken = "forwarder_broken", ForwarderTooDeep = "forwarder_too_deep", NotChecked = "not_checked",
        NotAnImage = "not_an_image";

    private const int MaxForwarderDepth = 8;
    private readonly Func<string, INativeImage?> _open;
    private readonly Func<string, bool, string?>? _loadedByName;
    private readonly Dictionary<INativeImage, Dictionary<string, NativeExport>> _byName = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<INativeImage, Dictionary<uint, NativeExport>> _byOrdinal = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<string, (string? File, List<string> Searched)> _located = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, LinkResult> _exports = new(StringComparer.OrdinalIgnoreCase);
    private ApiSetSchema? _apiSets;
    private bool _apiSetsLoaded;

    /// <param name="open">Opens a PE file by full path; null (or a thrown ToolError / IOException) when it cannot be read.</param>
    /// <param name="loadedByName">
    /// The path of an image the caller has loaded under this file name with this bitness (true = 32-bit), or null;
    /// searched after the importer's folder and before the system folders.
    /// </param>
    public NativeLinker(Func<string, INativeImage?> open, Func<string, bool, string?>? loadedByName = null)
    {
        _open = open;
        _loadedByName = loadedByName;
    }

    /// <summary>The API set map of this system (null off Windows or when unreadable).</summary>
    public ApiSetSchema? ApiSets
    {
        get
        {
            if (!_apiSetsLoaded)
            {
                _apiSetsLoaded = true;
                try { _apiSets = ApiSetSchema.FromSystem(path => Open(path) ?? throw new Core.ToolError(Core.ErrorCode.MalformedInput, path)); }
                catch (Exception ex) when (ex is Core.ToolError or IOException or UnauthorizedAccessException) { _apiSets = null; }
            }
            return _apiSets;
        }
    }

    public INativeImage? Open(string file)
    {
        try { return _open(file); }
        catch (Exception ex) when (ex is Core.ToolError or IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// The file the loader binds for <paramref name="module"/> imported by <paramref name="requester"/> (a path, or null),
    /// and the places searched. <paramref name="x86"/> selects SysWOW64 on a 64-bit system; <paramref name="runtimeFolder"/>
    /// adds the .NET runtime folder last (P/Invoke lookups of runtime-shipped native libraries).
    /// </summary>
    public (string? File, List<string> Searched) Locate(string module, string? requester, bool x86, bool runtimeFolder = false)
    {
        var key = $"{module}|{(requester != null ? Path.GetDirectoryName(requester) : "")}|{Path.GetFileName(requester)}|{x86}|{runtimeFolder}";
        if (_located.TryGetValue(key, out var hit)) return (hit.File, [.. hit.Searched]);
        var result = LocateCore(module, requester, x86, runtimeFolder);
        _located[key] = result;
        return (result.File, [.. result.Searched]);
    }

    private (string? File, List<string> Searched) LocateCore(string module, string? requester, bool x86, bool runtimeFolder)
    {
        var searched = new List<string>();
        var name = module.Trim();
        if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidPathChars()) >= 0) { searched.Add("(invalid module name)"); return (null, searched); }
        if (ApiSetSchema.IsApiSetName(name))
        {
            var host = ApiSets?.Resolve(name, requester);
            searched.Add(host != null ? $"API set {name} -> {host}" : $"API set {name} (not in this system's map)");
            if (host == null) return (null, searched);
            name = host;
        }
        if (!HasImageExtension(name)) name += ".dll";
        if (Path.IsPathFullyQualified(name))
        {
            searched.Add(name);
            return (File.Exists(name) ? name : null, searched);
        }
        if (name.Contains('\\') || name.Contains('/')) name = Path.GetFileName(name);

        string? requesterDir = requester != null ? Path.GetDirectoryName(requester) : null;
        if (!string.IsNullOrEmpty(requesterDir))
        {
            searched.Add(requesterDir);
            var candidate = Path.Combine(requesterDir, name);
            if (File.Exists(candidate)) return (Canonical(candidate), searched);
        }
        if (_loadedByName?.Invoke(name, x86) is { } loaded)
        {
            searched.Add("loaded images");
            return (loaded, searched);
        }
        if (!OperatingSystem.IsWindows()) return (null, searched);
        string system = x86 && Environment.Is64BitOperatingSystem
            ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
            : Environment.GetFolderPath(Environment.SpecialFolder.System);
        var dirs = new List<string> { system, Environment.GetFolderPath(Environment.SpecialFolder.Windows) };
        // Runtime-shipped native libraries (e.g. System.IO.Compression.Native) live next to the runtime.
        if (runtimeFolder) dirs.Add(Path.GetDirectoryName(typeof(object).Assembly.Location) ?? "");
        foreach (var dir in dirs.Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (string.Equals(dir, requesterDir, StringComparison.OrdinalIgnoreCase)) continue;
            searched.Add(dir);
            var candidate = Path.Combine(dir, name);
            if (File.Exists(candidate)) return (Canonical(candidate), searched);
        }
        return (null, searched);
    }

    /// <summary>The path with the file name spelled as on disk (import names are often upper-cased: NTDLL.dll).</summary>
    private static string Canonical(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            return dir != null ? Directory.EnumerateFiles(dir, Path.GetFileName(path)).FirstOrDefault() ?? path : path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return path; }
    }

    private static bool HasImageExtension(string name) =>
        Path.HasExtension(name) && (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                                    || name.EndsWith(".drv", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)
                                    || name.EndsWith(".ocx", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".cpl", StringComparison.OrdinalIgnoreCase)
                                    || name.EndsWith(".dylib", StringComparison.Ordinal) || SharedObject().IsMatch(name));

    /// <summary>ELF shared object names: lib.so, libc.so.6, libQt5Core.so.5.15.</summary>
    [System.Text.RegularExpressions.GeneratedRegex(@"\.so(\.\d+)*$")]
    private static partial System.Text.RegularExpressions.Regex SharedObject();

    /// <summary>Binds one import of <paramref name="importer"/> (a file path) to the code it reaches.</summary>
    public LinkResult BindImport(string importer, bool x86, NativeImport import)
    {
        // an unversioned ELF symbol names no library: the first DT_NEEDED library that exports it, as the dynamic loader searches
        if (import.Module == "*" && import.Name != null && Open(importer) is Elf.ElfFile { Dependencies: { Count: > 0 } needed })
            foreach (var library in needed)
                if (Bind(library, importer, x86, import.Name, null, "import") is { IsResolved: true } found) return found;
        return Bind(import.Module, importer, x86, import.Name, import.Name == null ? import.Ordinal : null, "import");
    }

    /// <summary>
    /// Binds <paramref name="name"/> (or <paramref name="ordinal"/>) of <paramref name="module"/> as imported by
    /// <paramref name="requester"/>, following forwarders.
    /// </summary>
    public LinkResult Bind(string module, string? requester, bool x86, string? name, uint? ordinal, string via, bool runtimeFolder = false)
    {
        var (file, searched) = Locate(module, requester, x86, runtimeFolder);
        if (file == null)
            return new LinkResult(searched.Any(s => s.EndsWith("(not in this system's map)", StringComparison.Ordinal)) ? ApiSetUnmapped : DllNotFound,
                module, null, [], "searched " + string.Join("; ", searched));
        return Export(module, file, x86, name, ordinal, via, 0);
    }

    /// <summary>
    /// Binds the first of <paramref name="candidates"/> that <paramref name="module"/> exports (P/Invoke rules: A/W
    /// suffixes and stdcall decoration are tried by the caller's candidate list); the result's Detail names the
    /// spelling found.
    /// </summary>
    public (LinkResult Result, string? Matched) BindFirst(string module, string? requester, bool x86, IEnumerable<string> candidates, string via, bool runtimeFolder)
    {
        var (file, searched) = Locate(module, requester, x86, runtimeFolder);
        if (file == null)
            return (new LinkResult(searched.Any(s => s.EndsWith("(not in this system's map)", StringComparison.Ordinal)) ? ApiSetUnmapped : DllNotFound,
                module, null, [], "searched " + string.Join("; ", searched)), null);
        var image = Open(file);
        if (image == null) return (new LinkResult(NotAnImage, module, file, [], $"{file} is not a readable PE image"), null);
        var names = ByName(image);
        foreach (var candidate in candidates)
            if (names.ContainsKey(candidate))
                return (Export(module, file, x86, candidate, null, via, 0), candidate);
        return (new LinkResult(MissingExport, module, file, [], NearMisses(image, candidates.FirstOrDefault() ?? "")), null);
    }

    private LinkResult Export(string module, string file, bool x86, string? name, uint? ordinal, string via, int depth)
    {
        var key = $"{file}|{name ?? "#" + ordinal}|{x86}";
        if (_exports.TryGetValue(key, out var cached))
            return cached with { Module = module, Hops = Revia(cached.Hops, via) };
        var result = ExportCore(module, file, x86, name, ordinal, via, depth);
        _exports[key] = result;
        return result;
    }

    private static IReadOnlyList<LinkHop> Revia(IReadOnlyList<LinkHop> hops, string via) =>
        hops.Count == 0 || hops[0].Via == via ? hops : [hops[0] with { Via = via }, .. hops.Skip(1)];

    private LinkResult ExportCore(string module, string file, bool x86, string? name, uint? ordinal, string via, int depth)
    {
        var image = Open(file);
        if (image == null) return new LinkResult(NotAnImage, module, file, [], $"{file} is not a readable PE image");
        NativeExport? export;
        if (name != null)
        {
            if (!ByName(image).TryGetValue(name, out export))
                return new LinkResult(MissingExport, module, file, [], NearMisses(image, name));
        }
        else if (ordinal is { } ord)
        {
            if (!ByOrdinal(image).TryGetValue(ord, out export))
                return new LinkResult(MissingOrdinal, module, file, [], $"{Path.GetFileName(file)} has no export with ordinal {ord}");
        }
        else return new LinkResult(MissingExport, module, file, [], "the import names neither a function nor an ordinal");

        var hop = new LinkHop(file, export.Name ?? $"#{export.Ordinal}", export.Ordinal, export.ForwardedTo == null ? export.Rva : null, export.ForwardedTo, via);
        if (export.ForwardedTo is not { } forward) return new LinkResult(Resolved, module, file, [hop], "exported");
        if (depth >= MaxForwarderDepth) return new LinkResult(ForwarderTooDeep, module, file, [hop], $"more than {MaxForwarderDepth} forwarders");

        // "MODULE.Name" or "MODULE.#ordinal"; the module part may itself contain dots (api-ms-win-core-x-l1-1-0).
        int dot = forward.LastIndexOf('.');
        if (dot <= 0 || dot == forward.Length - 1)
            return new LinkResult(ForwarderBroken, module, file, [hop], $"forwarder '{forward}' is not MODULE.name");
        var targetModule = forward[..dot];
        var targetName = forward[(dot + 1)..];
        var (targetFile, searched) = Locate(targetModule, file, x86);
        if (targetFile == null)
            return new LinkResult(ForwarderBroken, module, file, [hop], $"forwarder {forward}: module not found (searched {string.Join("; ", searched)})");
        uint? targetOrdinal = null;
        if (targetName.StartsWith('#'))
        {
            if (!uint.TryParse(targetName.AsSpan(1), out var o))
                return new LinkResult(ForwarderBroken, module, file, [hop], $"forwarder '{forward}' has a bad ordinal");
            targetOrdinal = o;
        }
        var next = Export(targetModule, targetFile, x86, targetOrdinal == null ? targetName : null, targetOrdinal, "forwarder", depth + 1);
        var hops = new List<LinkHop> { hop };
        hops.AddRange(next.Hops);
        return next.IsResolved
            ? new LinkResult(Resolved, module, file, hops, "forwarded")
            : new LinkResult(next.Status is ForwarderTooDeep ? ForwarderTooDeep : ForwarderBroken, module, file, hops, $"forwarder {forward}: {next.Detail}");
    }

    /// <summary>The export of <paramref name="image"/> with this name (null when none).</summary>
    public NativeExport? ExportNamed(INativeImage image, string name) => ByName(image).GetValueOrDefault(name);

    public NativeExport? ExportByOrdinal(INativeImage image, uint ordinal) => ByOrdinal(image).GetValueOrDefault(ordinal);

    private Dictionary<string, NativeExport> ByName(INativeImage image)
    {
        if (_byName.TryGetValue(image, out var map)) return map;
        map = new Dictionary<string, NativeExport>(StringComparer.Ordinal);
        foreach (var e in image.Exports)
            if (e.Name != null) map.TryAdd(e.Name, e);
        return _byName[image] = map;
    }

    private Dictionary<uint, NativeExport> ByOrdinal(INativeImage image)
    {
        if (_byOrdinal.TryGetValue(image, out var map)) return map;
        map = new Dictionary<uint, NativeExport>();
        foreach (var e in image.Exports) map.TryAdd(e.Ordinal, e);
        return _byOrdinal[image] = map;
    }

    internal static string NearMisses(INativeImage image, string entry)
    {
        var close = image.Exports.Select(e => e.Name).OfType<string>()
            .Where(n => n.Contains(entry, StringComparison.OrdinalIgnoreCase) || entry.Contains(n.TrimEnd('A', 'W'), StringComparison.OrdinalIgnoreCase) && n.Length > 3)
            .Take(8).ToList();
        return close.Count > 0 ? $"not exported; similar exports: {string.Join(", ", close)}" : $"not exported ({image.Exports.Count} exports checked)";
    }
}
