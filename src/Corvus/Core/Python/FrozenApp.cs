namespace Corvus.Core.Python;

/// <summary>A file of a frozen Python program: its path in the extracted layout, size, role and a loader for its bytes (null: listed only).</summary>
public sealed record FrozenEntry(string Path, long Size, string Role, Func<byte[]?>? Load = null);

/// <summary>
/// What a frozen Python program holds, as one freezer's reader found it: the Python version and where it came from,
/// the entry scripts, every file with its role (module, package, native module, runtime, data), and notes.
/// </summary>
public sealed class FrozenApp(string freezer, string kind)
{
    public const string Script = "entry script", Bootstrap = "bootstrap script", Module = "module", Package = "package", Native = "native module",
        Runtime = "Python runtime", Data = "data", Encrypted = "encrypted module", Archive = "module archive";

    /// <summary>PyInstaller, py2exe, cx_Freeze, Nuitka, or a Python library zip.</summary>
    public string Freezer { get; } = freezer;
    /// <summary>The container kind reported.</summary>
    public string Kind { get; } = kind;
    public (int Major, int Minor)? Version { get; set; }
    /// <summary>Where <see cref="Version"/> came from (archive header, runtime library name, .pyc magic).</summary>
    public string? VersionSource { get; set; }
    public List<string> EntryScripts { get; } = [];
    public List<FrozenEntry> Entries { get; } = [];
    public List<string> Notes { get; } = [];
    /// <summary>True when the program's own code was compiled to native code (Nuitka): no bytecode to read.</summary>
    public bool Compiled { get; set; }
    /// <summary>
    /// Modules compiled into a Nuitka binary, named by its constants, with the string bound to __version__ in each (null:
    /// none read).
    /// </summary>
    public List<(string Module, string? Version)> CompiledModules { get; } = [];

    public int Count(params string[] roles) => Entries.Count(e => roles.Contains(e.Role));

    /// <summary>The first note of the container: freezer, version, entry scripts and counts by role.</summary>
    public string Headline()
    {
        var parts = new List<string>();
        if (Version is { } v) parts.Add($"Python {PyVersion.Label(v)}{(VersionSource != null ? $" ({VersionSource})" : "")}");
        if (EntryScripts.Count > 0) parts.Add("entry " + string.Join(", ", EntryScripts.Take(3)) + (EntryScripts.Count > 3 ? $" and {EntryScripts.Count - 3} more" : ""));
        var counts = Entries.GroupBy(e => e.Role).OrderByDescending(g => g.Count()).ThenBy(g => g.Key, StringComparer.Ordinal)
            .Select(g => $"{g.Count():N0} {(g.Count() == 1 ? g.Key : Plural(g.Key))}");
        return $"{Freezer}: {string.Join("; ", parts.Append(string.Join(", ", counts)).Where(p => p.Length > 0))}.";
    }

    /// <summary>"native modules (beside the executable)", "binaries", "data".</summary>
    private static string Plural(string role)
    {
        int cut = role.IndexOf(" (", StringComparison.Ordinal);
        var (head, tail) = cut < 0 ? (role, "") : (role[..cut], role[cut..]);
        return (head == Data ? head : head.EndsWith("ary", StringComparison.Ordinal) ? head[..^1] + "ies" : head + "s") + tail;
    }

    /// <summary>The container view: every file as an entry; items for every file (<paramref name="allFiles"/>) or the binaries and archives only.</summary>
    public ContainerContents ToContainer(bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var items = new List<ExtractedItem>();
        var notes = new List<string> { Headline() };
        notes.AddRange(Notes);
        long total = 0;
        int failed = 0;
        foreach (var e in Entries)
        {
            ct.ThrowIfCancellationRequested();
            if (e.Load == null || !(allFiles || Containers.IsInteresting(e.Path))) continue;
            if (items.Count >= limits.MaxItems || total + e.Size > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached; some files were not extracted."); break; }
            var bytes = e.Load();
            if (bytes == null) { if (failed++ < 3) notes.Add($"{e.Path}: unreadable (damaged or over the item limit); not extracted."); continue; }
            total += bytes.Length;
            items.Add(new ExtractedItem(e.Path, bytes, $"{Freezer} {e.Role}"));
        }
        if (failed > 3) notes.Add($"{failed - 3} more files unreadable.");
        return new ContainerContents(Kind, items, notes) { Entries = [.. Entries.Select(e => new ContainerEntry(e.Path, e.Size, e.Role))] };
    }

    /// <summary>A role for a bundled binary by its name: the Python runtime library, a native extension module, or another binary.</summary>
    public static string BinaryRole(string path)
    {
        var file = System.IO.Path.GetFileName(path);
        if (PyVersion.FromLibraryName(file) != null) return Runtime;
        var lower = file.ToLowerInvariant();
        if (lower.EndsWith(".pyd", StringComparison.Ordinal) || lower.Contains(".cpython-", StringComparison.Ordinal) || lower.Contains(".abi3.", StringComparison.Ordinal)
            || (lower.EndsWith(".so", StringComparison.Ordinal) && !lower.StartsWith("lib", StringComparison.Ordinal))) return Native;
        return System.IO.Path.GetExtension(lower) is ".dll" or ".so" or ".dylib" or ".exe" || lower.Contains(".so.", StringComparison.Ordinal) || !lower.Contains('.') ? "binary" : Data;
    }

    /// <summary>Whether <paramref name="path"/> is a distribution's metadata: a .dist-info METADATA or .egg-info PKG-INFO, its top_level.txt, or an .egg-info file.</summary>
    public static bool IsPackageMetadata(string path)
    {
        var parts = path.Replace('\\', '/').Split('/');
        var folder = parts.Length > 1 ? parts[^2] : "";
        return parts[^1] switch
        {
            "METADATA" => folder.EndsWith(".dist-info", StringComparison.OrdinalIgnoreCase),
            "PKG-INFO" => folder.EndsWith(".egg-info", StringComparison.OrdinalIgnoreCase),
            "top_level.txt" => folder.EndsWith(".dist-info", StringComparison.OrdinalIgnoreCase) || folder.EndsWith(".egg-info", StringComparison.OrdinalIgnoreCase),
            var file => file.EndsWith(".egg-info", StringComparison.OrdinalIgnoreCase),
        };
    }

    /// <summary>The module name of a .pyc path in a library: "a/b/__init__.pyc" is package a.b, "a/b.pyc" module a.b.</summary>
    public static (string Name, bool Package)? ModuleOf(string path)
    {
        if (!path.EndsWith(".pyc", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".pyo", StringComparison.OrdinalIgnoreCase)) return null;
        var parts = path[..^4].Replace('\\', '/').Split('/');
        if (parts.Contains("__pycache__")) return null;
        bool package = parts[^1] == "__init__";
        var name = string.Join('.', package ? parts[..^1] : parts);
        return name.Length == 0 ? null : (name, package);
    }
}
