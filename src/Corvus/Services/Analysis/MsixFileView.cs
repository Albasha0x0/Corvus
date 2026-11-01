using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=msix: an MSIX or AppX package or bundle's identity, entry points,
/// extensions, capabilities, Package Support Framework scripts, signature
/// and block map.
/// </summary>
internal sealed class MsixFileView(long maxHashBytes) : IFileSummaryView
{
    // Bounds the zip entries read so a crafted archive cannot stall the call.
    private const int MaxEntries = 50_000;
    private const int MaxListed = 20;
    private const int MaxManifest = 4 << 20;
    private const int MaxConfig = 1 << 20;
    private const int BlockSize = 64 << 10;

    // Bounds block hashing so a large package cannot stall the call.
    private const long MaxHashBytes = 256L << 20;

    private static readonly string[] TargetAttributes =
        ["Executable", "EntryPoint", "Name", "TaskId", "Alias", "StartAccount"];

    private static readonly HashSet<string> Special =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "[Content_Types].xml", "AppxBlockMap.xml", "AppxSignature.p7x",
        };

    public MsixFileView() : this(MaxHashBytes)
    {
    }

    /// <summary>
    /// The view's result: package or bundle facts. Signature is unsigned
    /// when absent; BlockMap is null when no map is readable; Notes name
    /// every read limit or failure.
    /// </summary>
    public sealed record Facts(
        string Kind, string? Name, string? Publisher, string? Version,
        string? Architecture, string? DisplayName, string? PublisherDisplayName,
        IReadOnlyList<string> Families, IReadOnlyList<Application> Applications,
        IReadOnlyList<Extension> Extensions, IReadOnlyList<Capability> Capabilities,
        IReadOnlyList<BundledPackage> Packages, Psf? Psf,
        SignatureRecord Signature, BlockMapCheck? BlockMap,
        IReadOnlyList<string> Notes);

    /// <summary>An Application element: its entry point and the extensions it declares.</summary>
    public sealed record Application(
        string? Id, string? Executable, string? EntryPoint,
        IReadOnlyList<Extension> Extensions);

    /// <summary>An Extension element: its Category and the executables, names and aliases it targets.</summary>
    public sealed record Extension(string Category, IReadOnlyList<string> Targets);

    /// <summary>A declared capability; Restricted when it comes from the restricted capabilities namespace.</summary>
    public sealed record Capability(string Name, string Kind, bool Restricted);

    /// <summary>A Package entry of a bundle manifest; fields are null when absent.</summary>
    public sealed record BundledPackage(
        string? FileName, string? Type, string? Architecture, string? Version);

    /// <summary>
    /// The Package Support Framework launcher and its config.json: one
    /// entry per application, with its start and end scripts.
    /// </summary>
    public sealed record Psf(
        string? Launcher, string? Config,
        IReadOnlyList<PsfApplication> Applications,
        IReadOnlyList<string> Fixups);

    /// <summary>One config.json application: its program, arguments and scripts.</summary>
    public sealed record PsfApplication(
        string? Id, string? Executable, string? Arguments,
        string? WorkingDirectory, IReadOnlyList<PsfScript> Scripts);

    /// <summary>A PSF script: phase start or end, its path, whether the package holds it (null: unknown) and its options.</summary>
    public sealed record PsfScript(
        string Phase, string Path, bool? InPackage, string? Arguments,
        string? Options);

    /// <summary>
    /// AppxSignature.p7x: status unsigned, signed (signature verifies,
    /// chain not evaluated), invalid or unreadable; PublisherMatches is
    /// null when unknown.
    /// </summary>
    public sealed record SignatureRecord(
        string Status, string? Subject, string? Issuer, string? Thumbprint,
        string? NotBefore, string? NotAfter, bool? Timestamped,
        bool? PublisherMatches);

    /// <summary>
    /// The package files compared with AppxBlockMap.xml: sizes of every
    /// file, SHA-256 block hashes up to a byte budget. The lists keep the
    /// first entries; the counts are complete. NotInPackageCount is -1
    /// when the entries were not all scanned.
    /// </summary>
    public sealed record BlockMapCheck(
        int Files, int Hashed,
        IReadOnlyList<string> Modified, int ModifiedCount,
        IReadOnlyList<string> NotInMap, int NotInMapCount,
        IReadOnlyList<string> NotInPackage, int NotInPackageCount,
        string? Partial);

    public string Name => "msix";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Kind != "zip" || !file.HasZipEntry(n => n is "AppxManifest.xml"
                or "AppxBundleManifest.xml"
                or "AppxMetadata/AppxBundleManifest.xml")) return null;
        ZipArchive zip;
        try { zip = new ZipArchive(file.OpenRead(), ZipArchiveMode.Read); }
        catch (InvalidDataException) { return null; }
        using (zip)
        {
            var entries = new Dictionary<string, ZipArchiveEntry>(
                StringComparer.OrdinalIgnoreCase);
            foreach (var e in zip.Entries.Take(MaxEntries))
                entries.TryAdd(e.FullName, e);
            var notes = new List<string>();
            string? cut = null;
            if (zip.Entries.Count > MaxEntries)
            {
                cut = $"scanned {MaxEntries} of {zip.Entries.Count} entries; "
                    + "the block map comparison is incomplete";
                notes.Add(cut);
            }
            var bundle = !entries.ContainsKey("AppxManifest.xml");
            var manifestName = !bundle ? "AppxManifest.xml"
                : entries.ContainsKey("AppxBundleManifest.xml")
                    ? "AppxBundleManifest.xml"
                    : "AppxMetadata/AppxBundleManifest.xml";
            var kind = bundle ? "MSIX bundle" : "MSIX package";
            if (Read(entries, manifestName, MaxManifest, notes) is not { } manifestBytes)
                return Unreadable(kind, manifestName, notes);
            XElement root;
            try { root = BoundedXml.Load(manifestBytes); }
            catch (XmlException e)
            {
                notes.Add($"{manifestName}: {e.Message}");
                return Unreadable(kind, manifestName, notes);
            }
            var identity = Child(root, "Identity");
            var facts = bundle
                ? ReadBundle(root, identity)
                : ReadPackage(root, identity, entries, notes, ct);
            var signature = ReadSignature(entries, Attr(identity, "Publisher"), notes);
            var map = ReadBlockMap(entries, notes, cut, ct);
            var result = facts with { Signature = signature, BlockMap = map, Notes = notes };
            return new FileView(result, Highlights(result));
        }
    }

    private static FileView Unreadable(string kind, string manifestName, List<string> notes)
    {
        var facts = new Facts(kind, null, null, null, null, null, null, [], [], [], [], [],
            null, new SignatureRecord("unsigned", null, null, null, null, null, null, null),
            null, notes);
        if (notes.Count == 0) notes.Add($"{manifestName}: not found in the scanned entries");
        var h = new List<string> { $"{kind}: {manifestName}: unreadable." };
        h.AddRange(notes.Select(n => $"Partial: {n}."));
        return new FileView(facts, h);
    }

    private static Facts ReadBundle(XElement root, XElement? identity)
    {
        var packages = Child(root, "Packages")?.Elements()
            .Where(e => e.Name.LocalName == "Package")
            .Select(p => new BundledPackage(
                Attr(p, "FileName"), Attr(p, "Type"),
                Attr(p, "Architecture"), Attr(p, "Version")))
            .ToList() ?? [];
        return new Facts("MSIX bundle", Attr(identity, "Name"),
            Attr(identity, "Publisher"), Attr(identity, "Version"),
            null, null, null, [], [], [], [], packages, null,
            new SignatureRecord("unsigned", null, null, null, null, null, null, null),
            null, []);
    }

    private static Facts ReadPackage(
        XElement root, XElement? identity,
        Dictionary<string, ZipArchiveEntry> entries, List<string> notes,
        CancellationToken ct)
    {
        var properties = Child(root, "Properties");
        var dependencies = Child(root, "Dependencies");
        var families = dependencies?.Elements()
            .Where(e => e.Name.LocalName == "TargetDeviceFamily")
            .Select(f => $"{Attr(f, "Name")} {Attr(f, "MinVersion")}"
                + (Attr(f, "MaxVersionTested") is { } max ? $"-{max}" : ""))
            .ToList() ?? [];
        var applications = Child(root, "Applications")?.Elements()
            .Where(e => e.Name.LocalName == "Application")
            .Select(a => new Application(
                Attr(a, "Id"), Attr(a, "Executable"), Attr(a, "EntryPoint"),
                Extensions(a, notes)))
            .ToList() ?? [];
        var capabilities = Child(root, "Capabilities")?.Elements()
            .Select(c => new Capability(
                Attr(c, "Name") ?? c.Name.LocalName,
                c.Name.LocalName switch
                {
                    "Capability" => "capability",
                    "DeviceCapability" => "device",
                    _ => c.Name.LocalName,
                },
                c.Name.NamespaceName.Contains(
                    "restrictedcapabilities", StringComparison.OrdinalIgnoreCase)))
            .ToList() ?? [];
        var psf = ReadPsf(entries, applications, notes, ct);
        return new Facts("MSIX package", Attr(identity, "Name"),
            Attr(identity, "Publisher"), Attr(identity, "Version"),
            Attr(identity, "ProcessorArchitecture"),
            properties?.Elements().FirstOrDefault(e => e.Name.LocalName == "DisplayName")?.Value,
            properties?.Elements().FirstOrDefault(e => e.Name.LocalName == "PublisherDisplayName")?.Value,
            families, applications, Extensions(root, notes), capabilities, [], psf,
            new SignatureRecord("unsigned", null, null, null, null, null, null, null),
            null, []);
    }

    private static List<Extension> Extensions(XElement owner, List<string> notes) =>
        Child(owner, "Extensions")?.Elements()
            .Where(e => e.Name.LocalName == "Extension" && Attr(e, "Category") != null)
            .Select(e =>
            {
                var targets = e.DescendantsAndSelf()
                    .SelectMany(d => TargetAttributes.Select(a => Attr(d, a)))
                    .OfType<string>().Distinct().ToList();
                if (targets.Count > MaxListed)
                    notes.Add($"{Attr(e, "Category")}: first {MaxListed} of {targets.Count} targets listed");
                return new Extension(Attr(e, "Category")!, [.. targets.Take(MaxListed)]);
            }).ToList() ?? [];

    private static Psf? ReadPsf(
        Dictionary<string, ZipArchiveEntry> entries, List<Application> applications,
        List<string> notes, CancellationToken ct)
    {
        static bool IsLauncher(string path) =>
            Path.GetFileName(path).StartsWith("PSFLauncher", StringComparison.OrdinalIgnoreCase);
        var launcher = entries.Keys.FirstOrDefault(IsLauncher)
            ?? applications.Select(a => a.Executable).FirstOrDefault(x => x != null && IsLauncher(x));
        if (launcher == null) return null;
        var configPath = FindConfig(entries, launcher, applications);
        if (configPath == null) return null;
        ct.ThrowIfCancellationRequested();
        if (Read(entries, configPath, MaxConfig, notes) is not { } bytes)
            return new Psf(launcher, configPath, [], []);
        // Entry names may be percent-escaped; script paths are not.
        var unescaped = new HashSet<string>(
            entries.Keys.Select(Uri.UnescapeDataString), StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });
            var directory = DirectoryOf(configPath);
            var apps = new List<PsfApplication>();
            if (doc.RootElement.TryGetProperty("applications", out var list)
                && list.ValueKind == JsonValueKind.Array)
            {
                var total = list.GetArrayLength();
                if (total > MaxListed)
                    notes.Add($"{configPath}: first {MaxListed} of {total} applications listed");
                foreach (var a in list.EnumerateArray().Take(MaxListed))
                {
                    var scripts = new List<PsfScript>();
                    foreach (var (phase, key) in new[] { ("start", "startScript"), ("end", "endScript") })
                        if (a.ValueKind == JsonValueKind.Object
                            && a.TryGetProperty(key, out var s)
                            && Text(s, "scriptPath") is { } path)
                        {
                            var relative = path.Replace('\\', '/');
                            var normalized = (directory + relative).TrimStart('/');
                            scripts.Add(new PsfScript(phase, path,
                                unescaped.Contains(normalized) || unescaped.Contains(relative),
                                Text(s, "scriptArguments"), Options(s)));
                        }
                    apps.Add(new PsfApplication(Text(a, "id"), Text(a, "executable"),
                        Text(a, "arguments"), Text(a, "workingDirectory"), scripts));
                }
            }
            var fixups = new List<string>();
            if (doc.RootElement.TryGetProperty("processes", out var processes)
                && processes.ValueKind == JsonValueKind.Array)
                foreach (var p in processes.EnumerateArray())
                    if (p.ValueKind == JsonValueKind.Object
                        && p.TryGetProperty("fixups", out var f)
                        && f.ValueKind == JsonValueKind.Array)
                        fixups.AddRange(f.EnumerateArray().Select(x => Text(x, "dll")).OfType<string>());
            var distinct = fixups.Distinct().ToList();
            if (distinct.Count > MaxListed)
                notes.Add($"{configPath}: first {MaxListed} of {distinct.Count} fixups listed");
            return new Psf(launcher, configPath, apps, [.. distinct.Take(MaxListed)]);
        }
        catch (JsonException e)
        {
            notes.Add($"{configPath}: {e.Message}");
            return new Psf(launcher, configPath, [], []);
        }
    }

    // Prefers the launcher's directory, then the applications' directories,
    // then the package root; an unrelated config.json is not bound.
    private static string? FindConfig(
        Dictionary<string, ZipArchiveEntry> entries, string launcher,
        List<Application> applications)
    {
        var directories = new[] { launcher }
            .Concat(applications.Select(a => a.Executable).OfType<string>())
            .Select(p => DirectoryOf(p.Replace('\\', '/')))
            .Append("").Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var directory in directories)
            if (entries.Keys.FirstOrDefault(k => k.Equals(directory + "config.json",
                    StringComparison.OrdinalIgnoreCase)) is { } found)
                return found;
        return null;
    }

    private static string DirectoryOf(string path) =>
        path.Contains('/') ? path[..(path.LastIndexOf('/') + 1)] : "";

    private static string? Text(JsonElement e, string key) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v)
            && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Object or JsonValueKind.Array)
            ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.ToString()
            : null;

    private static string? Options(JsonElement script)
    {
        var parts = new[]
            {
                "runInVirtualEnvironment", "showWindow", "waitForScriptToFinish",
                "stopOnScriptError", "timeout", "runOnce",
            }
            .Select(k => Text(script, k) is { } v ? $"{k}={v.ToLowerInvariant()}" : null)
            .OfType<string>().ToList();
        return parts.Count > 0 ? string.Join(", ", parts) : null;
    }

    private static SignatureRecord ReadSignature(
        Dictionary<string, ZipArchiveEntry> entries, string? publisher, List<string> notes)
    {
        var unreadable = new SignatureRecord("unreadable", null, null, null, null, null, null, null);
        if (!entries.ContainsKey("AppxSignature.p7x"))
            return new SignatureRecord("unsigned", null, null, null, null, null, null, null);
        if (Read(entries, "AppxSignature.p7x", 1 << 20, notes) is not { Length: > 4 } p7x
            || p7x[0] != 'P' || p7x[1] != 'K' || p7x[2] != 'C' || p7x[3] != 'X')
            return unreadable;
        try
        {
            var cms = new SignedCms();
            cms.Decode(p7x.AsSpan(4).ToArray());
            var info = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0] : null;
            var cert = info?.Certificate;
            bool valid = true;
            try { cms.CheckSignature(verifySignatureOnly: true); }
            catch (CryptographicException) { valid = false; }
            var timestamped = info?.UnsignedAttributes.Cast<CryptographicAttributeObject>()
                .Any(a => a.Oid.Value is "1.2.840.113549.1.9.6" or "1.2.840.113549.1.9.16.2.14");
            return new SignatureRecord(valid ? "signed" : "invalid",
                cert?.Subject, cert?.Issuer, cert?.Thumbprint,
                cert?.NotBefore.ToString("yyyy-MM-dd"), cert?.NotAfter.ToString("yyyy-MM-dd"),
                timestamped, cert != null && publisher != null ? SameName(publisher, cert) : null);
        }
        catch (CryptographicException)
        {
            return unreadable;
        }
    }

    private static bool? SameName(string publisher, X509Certificate2 cert)
    {
        try
        {
            var name = new X500DistinguishedName(publisher);
            return name.RawData.AsSpan().SequenceEqual(cert.SubjectName.RawData)
                || string.Equals(name.Format(false), cert.SubjectName.Format(false),
                    StringComparison.OrdinalIgnoreCase);
        }
        catch (CryptographicException) { return null; }
    }

    private BlockMapCheck? ReadBlockMap(
        Dictionary<string, ZipArchiveEntry> entries, List<string> notes, string? cut,
        CancellationToken ct)
    {
        if (Read(entries, "AppxBlockMap.xml", MaxManifest, notes) is not { } bytes) return null;
        XElement root;
        try { root = BoundedXml.Load(bytes); }
        catch (XmlException e)
        {
            notes.Add($"AppxBlockMap.xml: {e.Message}");
            return null;
        }
        var sha256 = Attr(root, "HashMethod") is not { } method
            || method.EndsWith("sha256", StringComparison.OrdinalIgnoreCase);
        var map = new Dictionary<string, (long Size, List<string> Hashes)>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var f in root.Elements().Where(e => e.Name.LocalName == "File"))
            map.TryAdd(Attr(f, "Name") ?? "", (
                long.TryParse(Attr(f, "Size"), out var size) ? size : -1,
                [.. f.Elements().Where(b => b.Name.LocalName == "Block")
                    .Select(b => Attr(b, "Hash") ?? "")]));
        var modified = new List<string>();
        var notInMap = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int files = 0, hashed = 0, unhashed = 0, unreadable = 0;
        long budget = maxHashBytes;
        foreach (var (path, entry) in entries)
        {
            if (path.EndsWith('/') || Special.Contains(path)
                || path.StartsWith("AppxMetadata/", StringComparison.OrdinalIgnoreCase)) continue;
            ct.ThrowIfCancellationRequested();
            files++;
            var key = Uri.UnescapeDataString(path).Replace('/', '\\');
            if (!map.TryGetValue(key, out var recorded)) { notInMap.Add(path); continue; }
            seen.Add(key);
            if (recorded.Size >= 0 && recorded.Size != entry.Length) { modified.Add(path); continue; }
            if (!sha256 || entry.Length > budget) { unhashed++; continue; }
            budget -= entry.Length;
            try
            {
                if (!SameBlocks(entry, recorded.Hashes)) modified.Add(path);
                hashed++;
            }
            catch (InvalidDataException) { unreadable++; modified.Add(path); }
        }
        // Entries past the scan cap were never seen, so absence is unknown.
        var missing = cut != null
            ? new List<string>()
            : map.Keys.Where(k => !seen.Contains(k)).Select(k => k.Replace('\\', '/')).ToList();
        var partial = new List<string>();
        if (cut != null) partial.Add(cut);
        if (unhashed > 0)
            partial.Add($"hashed {hashed} of {files} files; {unhashed} not hashed ("
                + (sha256 ? $"over the {maxHashBytes:N0} byte budget" : "hash method is not SHA-256")
                + "), their sizes match");
        if (unreadable > 0) partial.Add($"{unreadable} entries could not be decompressed");
        foreach (var (label, count) in new[]
            { ("modified", modified.Count), ("not in the map", notInMap.Count), ("missing from the package", missing.Count) })
            if (count > MaxListed) partial.Add($"first {MaxListed} of {count} {label} listed");
        return new BlockMapCheck(files, hashed,
            [.. modified.Take(MaxListed)], modified.Count,
            [.. notInMap.Take(MaxListed)], notInMap.Count,
            [.. missing.Take(MaxListed)], cut != null ? -1 : missing.Count,
            partial.Count > 0 ? string.Join("; ", partial) : null);
    }

    private static bool SameBlocks(ZipArchiveEntry entry, List<string> hashes)
    {
        using var stream = entry.Open();
        var buffer = new byte[BlockSize];
        int index = 0;
        while (true)
        {
            int got = stream.ReadAtLeast(buffer, BlockSize, throwOnEndOfStream: false);
            if (got == 0) break;
            if (index >= hashes.Count
                || Convert.ToBase64String(SHA256.HashData(buffer.AsSpan(0, got))) != hashes[index])
                return false;
            index++;
        }
        return index == hashes.Count;
    }

    private static List<string> Highlights(Facts f)
    {
        var who = string.Join(" ", new[] { f.Kind, f.Name, f.Version }.OfType<string>());
        var h = new List<string>
        {
            who + (f.Kind == "MSIX bundle"
                    ? $": {f.Packages.Count} package(s)"
                    : $": {f.Applications.Count} application(s), {f.Capabilities.Count} capability(ies)")
                + "; view=msix lists entry points, extensions, capabilities, scripts and the signature.",
        };
        foreach (var a in f.Applications.Take(5))
            h.Add($"Application {a.Id}: {string.Join(", ", new[] { a.Executable, a.EntryPoint }.OfType<string>())}.");
        if (f.Capabilities.Where(c => c.Restricted).Select(c => c.Name).ToList() is { Count: > 0 } restricted)
            h.Add($"Restricted capabilities: {string.Join(", ", restricted)}.");
        var notable = f.Applications.SelectMany(a => a.Extensions).Concat(f.Extensions)
            .Where(e => e.Category is "windows.fullTrustProcess" or "windows.startupTask"
                or "windows.service" or "windows.appExecutionAlias")
            .Take(5);
        foreach (var e in notable) h.Add($"Extension {e.Category}: {string.Join(", ", e.Targets)}.");
        if (f.Psf is { } psf)
        {
            var scripts = psf.Applications.SelectMany(a => a.Scripts).ToList();
            h.Add($"Package Support Framework launcher with {psf.Config}: "
                + $"{psf.Applications.Count} application(s), {scripts.Count} script(s)"
                + (psf.Fixups.Count > 0 ? $", fixups {string.Join(", ", psf.Fixups)}" : "") + ".");
            foreach (var s in scripts.Take(5))
                h.Add($"PSF {s.Phase} script {s.Path}"
                    + (s.InPackage == false ? " (not in the package)" : "")
                    + (s.Options != null ? $" ({s.Options})" : "") + ".");
        }
        var sig = f.Signature;
        h.Add(sig.Status switch
        {
            "unsigned" => "Unsigned: no AppxSignature.p7x.",
            "signed" => $"Signed by {sig.Subject}: the signature verifies; the chain and the signed digests are not evaluated"
                + (sig.Timestamped == true ? ", timestamped" : "")
                + (sig.PublisherMatches == false ? "; the manifest Publisher differs from the signer"
                    : sig.PublisherMatches == true ? "; the manifest Publisher matches" : "") + ".",
            _ => $"Signature {sig.Status}.",
        });
        if (f.BlockMap is { } map)
        {
            var missing = map.NotInPackageCount < 0 ? "missing from the package unknown" : $"{map.NotInPackageCount} missing from the package";
            if (map.ModifiedCount + map.NotInMapCount + Math.Max(map.NotInPackageCount, 0) > 0
                || map.NotInPackageCount < 0)
                h.Add($"Differs from the block map: {map.ModifiedCount} modified, {map.NotInMapCount} not in the map, {missing}.");
            if (map.Partial != null) h.Add($"Partial: {map.Partial}.");
        }
        else h.Add("No readable AppxBlockMap.xml: file contents are unchecked.");
        if (f.Kind == "MSIX bundle") h.Add("Next: unpack_container path=<bundle> extracts the packages.");
        h.AddRange(f.Notes.Where(n => f.BlockMap?.Partial?.Contains(n) != true).Select(n => $"Partial: {n}."));
        return h;
    }

    private static byte[]? Read(
        Dictionary<string, ZipArchiveEntry> entries, string name, int max, List<string> notes)
    {
        if (!entries.TryGetValue(name, out var e)) return null;
        if (e.Length > max)
        {
            notes.Add($"{name}: {e.Length:N0} bytes, over the {max:N0} byte read limit");
            return null;
        }
        try
        {
            using var s = e.Open();
            var buffer = new byte[e.Length];
            s.ReadExactly(buffer);
            return buffer;
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
        {
            notes.Add($"{name}: cannot be read");
            return null;
        }
    }

    private static XElement? Child(XElement? parent, string name) =>
        parent?.Elements().FirstOrDefault(e => e.Name.LocalName == name);

    private static string? Attr(XElement? e, string name) =>
        e?.Attributes().FirstOrDefault(a => a.Name.LocalName == name
            && a.Name.NamespaceName.Length == 0)?.Value is { Length: > 0 } v ? v : null;
}
