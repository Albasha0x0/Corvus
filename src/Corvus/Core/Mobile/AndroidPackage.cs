using System.IO.Compression;
using Corvus.Native;

namespace Corvus.Core.Mobile;

/// <summary>One value of a resource in one configuration, as text.</summary>
public sealed record ResourceRow(uint Id, string Type, string Name, string Config, string ValueType, string Value, bool IsPublic);

/// <summary>A compiled resource table: resources.arsc of an APK or resources.pb of an app bundle.</summary>
public interface IResourceTable
{
    IEnumerable<ResourceRow> Rows { get; }
    /// <summary>"@type/name" (own package) or "@package:type/name"; null when unknown.</summary>
    string? Name(uint id);
    /// <summary>The value for the default configuration (else the first), references followed; null for a bag or an unknown id.</summary>
    string? DefaultText(uint id);
    /// <summary>The id of type/name in the app's own package.</summary>
    uint? Find(string type, string name);
    IReadOnlyList<ParseIssue> Issues { get; }
}

/// <summary>resources.arsc as an <see cref="IResourceTable"/>; bags are rendered as "name=value" lists.</summary>
public sealed class ArscResources(ArscTable table) : IResourceTable
{
    public ArscTable Table { get; } = table;
    public IReadOnlyList<ParseIssue> Issues => Table.Issues;
    public string? Name(uint id) => Table.Name(id);
    public string? DefaultText(uint id) => Table.DefaultText(id);

    private Dictionary<(string, string), uint>? _byName;

    public uint? Find(string type, string name)
    {
        _byName ??= Table.Packages.Where(p => p.Id == 0x7F || Table.Packages.Count == 1).SelectMany(p => p.Entries)
            .GroupBy(e => (e.Type, e.Key)).ToDictionary(g => g.Key, g => g.First().Id);
        return _byName.TryGetValue((type, name), out var id) ? id : null;
    }

    public IEnumerable<ResourceRow> Rows => Table.Packages.SelectMany(p => p.Entries).Select(Row);

    private ResourceRow Row(ArscEntry e)
    {
        if (e.Value is { } v)
            return new(e.Id, e.Type, e.Key, e.Config.Qualifiers, v.DataType == ResValue.String && e.Type is not "string" && Table.Strings.Get(v.Data) is { } s && s.StartsWith("res/", StringComparison.Ordinal) ? "file" : v.TypeName,
                Table.Format(v), e.IsPublic);
        var items = (e.Map ?? []).Select(m => $"{BagKey(m.Name)}={Table.Format(m.Value)}");
        var parent = e.Parent != 0 ? $"parent={Table.Name(e.Parent) ?? $"@0x{e.Parent:x8}"}; " : "";
        return new(e.Id, e.Type, e.Key, e.Config.Qualifiers, "bag", parent + string.Join("; ", items), e.IsPublic);
    }

    /// <summary>Array items are numbered, plural quantities named, attributes by resource name.</summary>
    public string BagKey(uint name) => name switch
    {
        >= 0x02000000 and < 0x03000000 => $"[{name - 0x02000000}]",
        0x01000004 => "other", 0x01000005 => "zero", 0x01000006 => "one", 0x01000007 => "two", 0x01000008 => "few", 0x01000009 => "many",
        _ => Table.Name(name) ?? (AndroidAttributes.Name(name) is { } a ? "android:" + a : $"0x{name:x8}"),
    };
}

/// <summary>
/// An Android package opened for reading: an APK, an app bundle (.aab, its base module), or a split set (.apks, .xapk, .apkm)
/// read through its base APK. Entries are read on demand, each bounded by <see cref="AnalysisLimits.MaxItemBytes"/>.
/// Paths are given in APK form ("classes.dex", "res/...", "lib/arm64-v8a/..."); a bundle maps them to its base module.
/// </summary>
public sealed class AndroidPackage : IDisposable
{
    public string Path { get; }
    /// <summary>"apk", "aab" or "split set".</summary>
    public string Kind { get; }
    /// <summary>For a split set: the APKs in it (base first); else empty.</summary>
    public IReadOnlyList<string> SplitApks { get; }
    public IReadOnlyList<string> Notes => _notes;

    private readonly ZipArchive _zip;
    private readonly Dictionary<string, ZipArchiveEntry> _entries;
    private readonly AnalysisLimits _limits;
    private readonly List<string> _notes = [];
    private readonly bool _bundle;

    private AndroidPackage(string path, string kind, ZipArchive zip, IReadOnlyList<string> splits, AnalysisLimits limits)
    {
        Path = path;
        Kind = kind;
        _zip = zip;
        _limits = limits;
        _bundle = kind == "aab";
        SplitApks = splits;
        _entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.Ordinal);
        foreach (var e in zip.Entries) _entries.TryAdd(e.FullName, e);
    }

    /// <summary>Opens a package file; a file that is not a zip with an Android manifest is a typed error.</summary>
    public static AndroidPackage Open(string path, AnalysisLimits? limits = null)
    {
        limits ??= AnalysisLimits.Default;
        var full = InputFiles.RequireRegularFile(path, "Android package");
        if (!File.Exists(full)) throw new ToolError(ErrorCode.NotFound, $"file not found: {full}");
        ZipArchive zip;
        FileStream? stream = null;
        try { stream = File.OpenRead(full); zip = new ZipArchive(stream, ZipArchiveMode.Read); _ = zip.Entries; }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            stream?.Dispose(); // a corrupt archive leaves it open until finalization, holding the file
            throw new ToolError(ErrorCode.MalformedInput, $"{full} is not a readable zip ({ex.Message}); pass an .apk, .aab, .apks, .xapk or .apkm file.");
        }
        var names = zip.Entries.Select(e => e.FullName).ToHashSet(StringComparer.Ordinal);
        if (names.Contains("AndroidManifest.xml")) return new AndroidPackage(full, "apk", zip, [], limits);
        if (names.Contains("base/manifest/AndroidManifest.xml")) return new AndroidPackage(full, "aab", zip, [], limits);
        var apks = zip.Entries.Where(e => e.FullName.EndsWith(".apk", StringComparison.OrdinalIgnoreCase)).ToList();
        if (apks.Count > 0)
        {
            // The base APK: "base.apk" or "base-master.apk" by convention, else the largest.
            var base_ = apks.FirstOrDefault(e => System.IO.Path.GetFileName(e.FullName) is "base.apk" or "base-master.apk")
                        ?? apks.FirstOrDefault(e => !System.IO.Path.GetFileName(e.FullName).StartsWith("split", StringComparison.OrdinalIgnoreCase) && !e.FullName.Contains("config.", StringComparison.Ordinal))
                        ?? apks.MaxBy(e => e.Length)!;
            byte[] bytes;
            using (var s = base_.Open()) bytes = Blob.ReadBounded(s, limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{base_.FullName} in {full} is larger than {limits.MaxItemBytes} bytes.");
            var inner = new ZipArchive(new MemoryStream(bytes, writable: false), ZipArchiveMode.Read);
            if (!inner.Entries.Any(e => e.FullName == "AndroidManifest.xml"))
                throw new ToolError(ErrorCode.MalformedInput, $"{base_.FullName} in {full} has no AndroidManifest.xml.");
            var splits = new List<string> { base_.FullName };
            splits.AddRange(apks.Where(e => e != base_).Select(e => e.FullName));
            zip.Dispose();
            var package = new AndroidPackage(full, "split set", inner, splits, limits);
            package._notes.Add($"A split set of {apks.Count} APK(s); read through its base APK {base_.FullName}.");
            return package;
        }
        zip.Dispose();
        throw new ToolError(ErrorCode.Unsupported, $"{full} is a zip without an Android manifest (AndroidManifest.xml, base/manifest/AndroidManifest.xml or nested APKs).",
            "pass an .apk, .aab, .apks, .xapk or .apkm file");
    }

    /// <summary>The package's entries in APK form, in archive order.</summary>
    public IEnumerable<string> Entries => _bundle
        ? _entries.Keys.Where(k => k.StartsWith("base/", StringComparison.Ordinal)).Select(FromBundle).OfType<string>()
        : _entries.Keys;

    private static string? FromBundle(string name)
    {
        var rest = name["base/".Length..];
        if (rest == "manifest/AndroidManifest.xml") return "AndroidManifest.xml";
        if (rest.StartsWith("dex/", StringComparison.Ordinal)) return rest["dex/".Length..];
        if (rest.StartsWith("root/", StringComparison.Ordinal)) return rest["root/".Length..];
        return rest; // res/, lib/, assets/, resources.pb
    }

    private string ToArchive(string name)
    {
        if (!_bundle) return name;
        if (name == "AndroidManifest.xml") return "base/manifest/AndroidManifest.xml";
        if (name.StartsWith("classes", StringComparison.Ordinal) && name.EndsWith(".dex", StringComparison.Ordinal)) return "base/dex/" + name;
        if (name.StartsWith("res/", StringComparison.Ordinal) || name.StartsWith("lib/", StringComparison.Ordinal) || name.StartsWith("assets/", StringComparison.Ordinal) || name == "resources.pb")
            return "base/" + name;
        return _entries.ContainsKey("base/root/" + name) ? "base/root/" + name : "base/" + name;
    }

    public bool Contains(string name) => _entries.ContainsKey(ToArchive(name));

    /// <summary>Uncompressed size of an entry, or -1.</summary>
    public long Length(string name) => _entries.TryGetValue(ToArchive(name), out var e) ? e.Length : -1;

    /// <summary>An entry's bytes; null when absent. Larger than the item limit, damaged or encrypted: a typed error.</summary>
    public byte[]? Read(string name)
    {
        if (!_entries.TryGetValue(ToArchive(name), out var e)) return null;
        try
        {
            using var s = e.Open();
            return Blob.ReadBounded(s, _limits.MaxItemBytes) ?? throw new ToolError(ErrorCode.LimitExceeded, $"{name} is larger than {_limits.MaxItemBytes} bytes.");
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{name} in {Path} cannot be read: {ex.Message}");
        }
    }

    private AxmlDocument? _manifest;
    private IResourceTable? _resources;
    private bool _resourcesRead;

    /// <summary>The decoded manifest (binary XML; a bundle's protobuf manifest converted to the same tree).</summary>
    public AxmlDocument Manifest => _manifest ??= ReadManifest();

    private AxmlDocument ReadManifest()
    {
        var bytes = Read("AndroidManifest.xml") ?? throw new ToolError(ErrorCode.MalformedInput, $"{Path} has no AndroidManifest.xml.");
        if (_bundle) return AabProto.ReadManifest(bytes);
        if (!AxmlDocument.IsAxml(bytes)) throw new ToolError(ErrorCode.MalformedInput, $"AndroidManifest.xml in {Path} is not binary XML (it starts with 0x{(bytes.Length >= 2 ? bytes[0] | bytes[1] << 8 : 0):x4}).");
        return AxmlDocument.Read(bytes);
    }

    /// <summary>The resource table, or null when the package has none.</summary>
    public IResourceTable? Resources
    {
        get
        {
            if (_resourcesRead) return _resources;
            _resourcesRead = true;
            if (_bundle) _resources = Read("resources.pb") is { } pb ? AabProto.ReadResources(pb) : null;
            else _resources = Read("resources.arsc") is { } arsc ? new ArscResources(ArscTable.Read(arsc)) : null;
            return _resources;
        }
    }

    /// <summary>classes.dex, classes2.dex, ... in loading order.</summary>
    public IReadOnlyList<string> DexFiles => [.. Entries.Where(IsDex).OrderBy(n => n.Length).ThenBy(n => n, StringComparer.Ordinal)];

    private static bool IsDex(string n) => n.StartsWith("classes", StringComparison.Ordinal) && n.EndsWith(".dex", StringComparison.Ordinal) && !n.Contains('/');

    /// <summary>Native library ABIs present under lib/.</summary>
    public IReadOnlyList<string> Abis => [.. Entries.Where(n => n.StartsWith("lib/", StringComparison.Ordinal)).Select(n => n.Split('/')).Where(p => p.Length >= 3)
        .Select(p => p[1]).Distinct().Order(StringComparer.Ordinal)];

    public void Dispose() => _zip.Dispose();
}
