using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Corvus.Core.Installers;

/// <summary>A ClickOnce deployment or application manifest, listing files with size and digest; nothing is extracted.</summary>
internal sealed class ClickOnceManifestReader : IContainerReader
{
    public string Kind => "clickonce";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => ClickOnceManifest.Looks(data, name) && ClickOnceManifest.TryParse(data.ToArray()) != null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var m = ClickOnceManifest.TryParse(data) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: not a ClickOnce manifest.");
        var notes = new List<string> { m.Summary(), "Listed from the manifest; unpack_container with the .application file or its folder extracts the files beside it." };
        notes.AddRange(m.Prerequisites.Select(p => $"Requires {p}."));
        var entries = m.Files.Select(f => new ContainerEntry(f.Path, f.Size, f.Detail(m))).ToList();
        return new ContainerContents(m.Deployment ? "ClickOnce deployment manifest" : "ClickOnce application manifest", [], notes) { Entries = entries };
    }
}

/// <summary>A ClickOnce deployment on disk: every file its manifests list, read from beside them and checked against its digest.</summary>
internal static class ClickOnceDeployment
{
    private const string Folder = "Application Files";

    /// <summary>The deployment manifest a path names: a .application file, or the one at the top of a publish folder; null otherwise.</summary>
    public static string? Find(string path)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        IEnumerable<string> candidates;
        try
        {
            candidates = File.Exists(full) ? [full]
                : Directory.Exists(full) ? Directory.EnumerateFiles(full, "*.application").Order(StringComparer.OrdinalIgnoreCase)
                    // A versioned copy (App_1_0_0_0.application) is the manifest of one older publish.
                    .OrderBy(f => System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(f), @"_\d+_\d+_\d+_\d+\.application$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)).ToList()
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        foreach (var file in candidates)
        {
            if (!file.EndsWith(".application", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                if (new FileInfo(file).Length > ClickOnceManifest.MaxBytes) continue;
                if (ClickOnceManifest.TryParse(File.ReadAllBytes(file)) is { Deployment: true }) return file;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    /// <summary>The manifests and every file they list, named by install path; missing or differing files are noted.</summary>
    public static ContainerContents Open(string deploymentManifest, AnalysisLimits limits, CancellationToken ct)
    {
        var root = Path.GetDirectoryName(Path.GetFullPath(deploymentManifest))!;
        var deployBytes = File.ReadAllBytes(deploymentManifest);
        var deploy = ClickOnceManifest.TryParse(deployBytes) ?? throw new ToolError(ErrorCode.MalformedInput, $"{deploymentManifest}: not a ClickOnce deployment manifest.");
        var items = new List<ExtractedItem> { new(Path.GetFileName(deploymentManifest), deployBytes, "deployment manifest") };
        var entries = new List<ContainerEntry> { new(Path.GetFileName(deploymentManifest), deployBytes.Length, "deployment manifest") };
        var notes = new List<string>();
        int missing = 0, differ = 0;
        long total = deployBytes.Length;

        var appRef = deploy.Files.FirstOrDefault(f => f.Kind == RefKind.Manifest)
            ?? throw new ToolError(ErrorCode.MalformedInput, $"{deploymentManifest}: the deployment manifest names no application manifest.");
        var (appPath, appBytes) = Read(root, root, appRef, deploy.MapFileExtensions, limits);
        if (appBytes == null || ClickOnceManifest.TryParse(appBytes) is not { Deployment: false } app)
        {
            notes.Add(deploy.Summary());
            notes.Add($"The application manifest {appRef.Path} is {(appBytes == null ? "missing from the folder" : "not a ClickOnce application manifest")}: only the deployment manifest is read.");
            entries.Add(new ContainerEntry(appRef.Path, appRef.Size, "application manifest, missing"));
            return new ContainerContents("ClickOnce deployment", items, notes) { Entries = entries };
        }
        if (!appRef.Matches(appBytes)) differ++;
        var appName = appRef.Path.Replace('\\', '/');
        items.Add(new ExtractedItem(appName, appBytes, "application manifest"));
        entries.Add(new ContainerEntry(appName, appBytes.Length, "application manifest"));
        total += appBytes.Length;

        var appDir = Path.GetDirectoryName(appPath!)!;
        var listed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Path.GetFullPath(appPath!) };
        foreach (var f in app.Files)
        {
            ct.ThrowIfCancellationRequested();
            if (f.Kind == RefKind.Remote) { entries.Add(new ContainerEntry(f.Path, f.Size, f.Detail(app))); continue; }
            var (file, bytes) = Read(root, appDir, f, deploy.MapFileExtensions, limits);
            if (file != null) listed.Add(file);
            if (bytes == null)
            {
                missing++;
                entries.Add(new ContainerEntry(f.Path, f.Size, "missing from the folder"));
                continue;
            }
            if (items.Count >= limits.MaxItems || (total += bytes.Length) > limits.MaxTotalBytes)
            {
                notes.Add("Stopped: the extraction limit was reached; some files were not extracted.");
                break;
            }
            bool same = f.Matches(bytes);
            if (!same) differ++;
            var name = f.Path.Replace('\\', '/');
            items.Add(new ExtractedItem(name, bytes, Path.GetRelativePath(root, file!)));
            entries.Add(new ContainerEntry(name, bytes.Length, same ? f.Detail(app) : "differs from its manifest digest"));
        }

        notes.Add(app.Summary(deploy, Path.GetRelativePath(root, appDir), app.Files.Count));
        notes.AddRange(app.Prerequisites.Select(p => $"Requires {p}."));
        if (missing > 0) notes.Add($"{missing} listed file(s) missing from the folder.");
        if (differ > 0) notes.Add($"{differ} file(s) differ from their manifest digest or size.");
        var unlisted = Unlisted(root, appDir, listed, deploymentManifest);
        if (unlisted.Count > 0) notes.Add($"Not listed by the manifests: {string.Join(", ", unlisted.Take(8))}{(unlisted.Count > 8 ? $" and {unlisted.Count - 8} more" : "")}.");
        var versions = OtherVersions(root, appDir);
        if (versions.Count > 0) notes.Add($"{Folder} also holds {versions.Count} other publish(es): {string.Join(", ", versions.Take(8))}.");
        return new ContainerContents("ClickOnce deployment", items, notes) { Entries = entries };
    }

    /// <summary>A listed file's path and bytes (its .deploy copy when extensions are mapped); nulls when absent or outside the publish folder.</summary>
    private static (string? Path, byte[]? Bytes) Read(string root, string dir, ClickOnceManifest.Ref f, bool mapped, AnalysisLimits limits)
    {
        string path;
        try { path = Path.GetFullPath(Path.Combine(dir, f.Path.Replace('\\', Path.DirectorySeparatorChar))); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return (null, null); }
        if (!path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return (null, null);
        foreach (var candidate in mapped ? new[] { path + ".deploy", path } : [path, path + ".deploy"])
        {
            try
            {
                if (!File.Exists(candidate)) continue;
                if (new FileInfo(candidate).Length > limits.MaxItemBytes)
                    throw new ToolError(ErrorCode.LimitExceeded, $"{f.Path} is over the {limits.MaxItemBytes:N0}-byte item limit.");
                return (candidate, File.ReadAllBytes(candidate));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return (path, null);
    }

    private static List<string> Unlisted(string root, string appDir, HashSet<string> listed, string deploymentManifest)
    {
        var found = new List<string>();
        try
        {
            foreach (var file in Directory.EnumerateFiles(root).Concat(Directory.EnumerateFiles(appDir, "*", SearchOption.AllDirectories)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var full = Path.GetFullPath(file);
                if (listed.Contains(full) || string.Equals(full, Path.GetFullPath(deploymentManifest), StringComparison.OrdinalIgnoreCase)) continue;
                found.Add(Path.GetRelativePath(root, full).Replace('\\', '/'));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        found.Sort(StringComparer.OrdinalIgnoreCase);
        return found;
    }

    private static List<string> OtherVersions(string root, string appDir)
    {
        var folder = Path.Combine(root, Folder);
        try
        {
            return !Directory.Exists(folder) ? []
                : Directory.EnumerateDirectories(folder).Where(d => !string.Equals(Path.GetFullPath(d), appDir, StringComparison.OrdinalIgnoreCase))
                    .Select(Path.GetFileName).OfType<string>().Order(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }
}

internal enum RefKind { Manifest, Assembly, File, Remote }

/// <summary>One ClickOnce manifest: identity, description, deployment options, entry point, trust and the files it lists.</summary>
internal sealed class ClickOnceManifest
{
    public const int MaxBytes = 16 << 20;

    public bool Deployment { get; private init; }
    public string? Name { get; private init; }
    public string? Version { get; private init; }
    public string? Publisher { get; private init; }
    public string? Product { get; private init; }
    public bool Install { get; private init; }
    public bool MapFileExtensions { get; private init; }
    public string? UpdateFrom { get; private init; }
    public string? EntryPoint { get; private init; }
    public string? Trust { get; private init; }
    public string? Signer { get; private init; }
    public List<Ref> Files { get; } = [];
    public List<string> Prerequisites { get; } = [];

    /// <summary>A listed file: its path, size and digest (algorithm name and bytes; null when not given or not checkable).</summary>
    internal sealed record Ref(string Path, long Size, RefKind Kind, string? Algorithm, byte[]? Digest, string? Identity)
    {
        public bool Matches(byte[] bytes) => (Size <= 0 || Size == bytes.Length) && (Digest == null || Hash(Algorithm!, bytes) is not { } h || h.AsSpan().SequenceEqual(Digest));

        public string? Detail(ClickOnceManifest m) =>
            Kind == RefKind.Remote ? $"not in the folder (downloaded from {Path})"
            : string.Equals(Path, m.EntryPoint, StringComparison.OrdinalIgnoreCase) ? "entry point"
            : Kind == RefKind.Manifest ? "application manifest"
            : Identity;
    }

    /// <summary>Cheap check before parsing: a manifest's extension and XML text naming both assembly manifest namespaces.</summary>
    public static bool Looks(ReadOnlySpan<byte> data, string name) =>
        data.Length is > 64 and <= MaxBytes
        && (name.EndsWith(".application", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".manifest", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".manifest.deploy", StringComparison.OrdinalIgnoreCase))
        && data.IndexOf("urn:schemas-microsoft-com:asm.v1"u8) >= 0 && data.IndexOf("urn:schemas-microsoft-com:asm.v2"u8) >= 0;

    /// <summary>The manifest, or null when the bytes are not an assembly manifest with a deployment or entry point element.</summary>
    public static ClickOnceManifest? TryParse(byte[] data)
    {
        XDocument doc;
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(data, writable: false),
                new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = MaxBytes });
            doc = XDocument.Load(reader);
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException or ArgumentException) { return null; }
        var root = doc.Root;
        if (root is not { Name.LocalName: "assembly" } || root.Name.NamespaceName != "urn:schemas-microsoft-com:asm.v1") return null;
        var deployment = Child(root, "deployment");
        var entry = Child(root, "entryPoint");
        if (deployment == null && entry == null) return null;
        var identity = Child(root, "assemblyIdentity");
        var description = Child(root, "description");
        var m = new ClickOnceManifest
        {
            Deployment = deployment != null,
            Name = Attr(identity, "name"),
            Version = Attr(identity, "version"),
            Publisher = Attr(description, "publisher"),
            Product = Attr(description, "product"),
            Install = string.Equals(Attr(deployment, "install"), "true", StringComparison.OrdinalIgnoreCase),
            MapFileExtensions = string.Equals(Attr(deployment, "mapFileExtensions"), "true", StringComparison.OrdinalIgnoreCase),
            UpdateFrom = Attr(Child(deployment, "deploymentProvider"), "codebase"),
            EntryPoint = Attr(Child(entry, "commandLine"), "file"),
            Trust = TrustOf(root),
            Signer = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "publisherIdentity") is { } p ? Attr(p, "name") ?? "unnamed"
                : root.Elements().Any(e => e.Name.LocalName == "Signature") ? "unnamed" : null,
        };
        foreach (var dep in root.Elements().Where(e => e.Name.LocalName == "dependency").Select(e => Child(e, "dependentAssembly")).OfType<XElement>())
        {
            var depIdentity = Child(dep, "assemblyIdentity");
            var codebase = Attr(dep, "codebase");
            if (Attr(dep, "dependencyType") == "preRequisite" || codebase == null)
            {
                if (Attr(depIdentity, "name") is { } pre) m.Prerequisites.Add(Attr(depIdentity, "version") is { } v ? $"{pre} {v}" : pre);
                continue;
            }
            var kind = codebase.Contains("://", StringComparison.Ordinal) ? RefKind.Remote
                : m.Deployment || codebase.EndsWith(".manifest", StringComparison.OrdinalIgnoreCase) ? RefKind.Manifest : RefKind.Assembly;
            var (alg, digest) = DigestOf(dep);
            var name = Attr(depIdentity, "name");
            m.Files.Add(new Ref(codebase, Size(dep), kind, alg, digest,
                kind == RefKind.Assembly && name != null ? $"assembly {name}{(Attr(depIdentity, "version") is { } v2 ? " " + v2 : "")}" : null));
        }
        foreach (var file in root.Elements().Where(e => e.Name.LocalName == "file"))
        {
            if (Attr(file, "name") is not { Length: > 0 } name) continue;
            var (alg, digest) = DigestOf(file);
            m.Files.Add(new Ref(name, Size(file), name.Contains("://", StringComparison.Ordinal) ? RefKind.Remote : RefKind.File, alg, digest,
                Attr(file, "writeableType") is { } w ? $"data file ({w})" : null));
        }
        return m;
    }

    /// <summary>The note line: "ClickOnce deployment {Product} {Version} by {Publisher}: ...".</summary>
    public string Summary() =>
        $"ClickOnce {(Deployment ? "deployment" : "application")} manifest {Title(this)}: {Files.Count} file(s) listed{Options(this, this)}.";

    public string Summary(ClickOnceManifest deploy, string folder, int files) =>
        $"ClickOnce deployment {Title(deploy)}: {files} file(s) in {folder.Replace('\\', '/')}{Options(deploy, this)}.";

    private static string Title(ClickOnceManifest m)
    {
        var title = new StringBuilder(m.Product ?? m.Name ?? "(unnamed)");
        if (m.Version != null) title.Append(' ').Append(m.Version);
        if (m.Publisher != null) title.Append(" by ").Append(m.Publisher);
        return title.ToString();
    }

    private static string Options(ClickOnceManifest deploy, ClickOnceManifest app)
    {
        var parts = new List<string>();
        if (deploy.Deployment) parts.Add(deploy.Install ? "installed (available offline)" : "online only");
        if (deploy.UpdateFrom != null) parts.Add($"updates from {deploy.UpdateFrom}");
        if (app.EntryPoint != null) parts.Add($"entry point {app.EntryPoint}");
        if (app.Trust != null) parts.Add(app.Trust);
        parts.Add(deploy.Signer is { } s ? $"signed ({s})" : "unsigned");
        return ", " + string.Join(", ", parts);
    }

    private static string? TrustOf(XElement root)
    {
        var set = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "PermissionSet");
        var level = Attr(root.Descendants().FirstOrDefault(e => e.Name.LocalName == "requestedExecutionLevel"), "level");
        var trust = set == null ? null : string.Equals(Attr(set, "Unrestricted"), "true", StringComparison.OrdinalIgnoreCase) ? "full trust" : "partial trust";
        return (trust, level) switch
        {
            (null, null) => null,
            (_, null) => trust,
            (null, _) => $"runs {level}",
            _ => $"{trust}, runs {level}",
        };
    }

    /// <summary>The digest when its transforms are identity only (anything else hashes a normalized form not checked here).</summary>
    private static (string? Algorithm, byte[]? Digest) DigestOf(XElement e)
    {
        if (Child(e, "hash") is not { } hash) return (null, null);
        if (hash.Descendants().Where(d => d.Name.LocalName == "Transform").Any(t => Attr(t, "Algorithm") != "urn:schemas-microsoft-com:HashTransforms.Identity")) return (null, null);
        var alg = Attr(hash.Descendants().FirstOrDefault(d => d.Name.LocalName == "DigestMethod"), "Algorithm");
        var value = hash.Descendants().FirstOrDefault(d => d.Name.LocalName == "DigestValue")?.Value;
        if (alg == null || value == null) return (null, null);
        try { return (alg, Convert.FromBase64String(value.Trim())); }
        catch (FormatException) { return (null, null); }
    }

    private static byte[]? Hash(string algorithm, byte[] bytes) =>
        algorithm.EndsWith("sha256", StringComparison.OrdinalIgnoreCase) ? SHA256.HashData(bytes)
        : algorithm.EndsWith("sha384", StringComparison.OrdinalIgnoreCase) ? SHA384.HashData(bytes)
        : algorithm.EndsWith("sha512", StringComparison.OrdinalIgnoreCase) ? SHA512.HashData(bytes)
        : algorithm.EndsWith("sha1", StringComparison.OrdinalIgnoreCase) ? SHA1.HashData(bytes)
        : null;

    private static long Size(XElement e) => long.TryParse(Attr(e, "size"), out var s) ? s : 0;

    private static XElement? Child(XElement? e, string local) => e?.Elements().FirstOrDefault(c => c.Name.LocalName == local);

    private static string? Attr(XElement? e, string local) => e?.Attributes().FirstOrDefault(a => a.Name.LocalName == local)?.Value;
}
