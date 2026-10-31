using Corvus.Core;
using Corvus.Native.Pe;

namespace Corvus.Services.Analysis;

/// <summary>A file of a folder or container: its path, a reader of its bytes, and its path on disk when it has one.</summary>
internal sealed record SideloadMember(string Path, Func<byte[]?> Read, string? DiskPath);

/// <summary>An import that an unsigned DLL beside a signed image answers from the image's own folder.</summary>
internal sealed record SideloadHit(string Image, string Dll, string Import, bool Delay, IReadOnlyList<string> Forwards);

/// <summary>Finds imports of a signed PE that an unsigned DLL in the same folder answers before the system copy does.</summary>
internal static class SideloadReview
{
    private const int MaxImages = 2000;
    private static readonly string[] ImageExtensions = [".exe", ".dll", ".ocx", ".cpl", ".scr", ".sys"];

    // The loader resolves API set names through its schema, never to a file.
    private static readonly string[] ApiSetPrefixes = ["api-ms-", "ext-ms-"];

    private sealed record Import(string Module, string First, bool Delay);

    // Only these facts are kept per image, so a large folder does not hold
    // every image in memory.
    private sealed record Loaded(IReadOnlyList<Import> Imports, bool IsDll, IReadOnlyList<string> ForwardTargets, bool Embedded, string? DiskPath);

    private static Loaded Read(byte[] bytes, string path, string? diskPath)
    {
        var pe = PeFile.FromBytes(bytes, path);
        var imports = pe.ImportModules.Concat(pe.DelayImportModules)
            .Select(m => new Import(m.Name, m.Functions.FirstOrDefault() is { } f ? f.Name ?? $"#{f.Ordinal}" : "(no functions)", m.IsDelayLoad)).ToList();
        var forwards = pe.Exports.Select(e => e.ForwardedTo).OfType<string>().ToList();
        return new Loaded(imports, pe.IsDll, forwards, Certificates.Read(bytes).Present, diskPath);
    }

    /// <summary>The hits among <paramref name="members"/> and notes naming what was not read; names in KnownDLLs are skipped.</summary>
    public static (IReadOnlyList<SideloadHit> Hits, IReadOnlyList<string> Notes) Scan(IEnumerable<SideloadMember> members, CancellationToken ct)
    {
        var notes = new List<string>();
        var known = KnownDlls();
        if (known == null) notes.Add("KnownDLLs is unknown on this host: every import matching a DLL beside its importer is reported.");
        var images = members.Where(m => ImageExtensions.Contains(System.IO.Path.GetExtension(m.Path), StringComparer.OrdinalIgnoreCase)).ToList();
        if (images.Count > MaxImages)
        {
            notes.Add($"{images.Count:N0} images: the first {MaxImages:N0} were read.");
            images.RemoveRange(MaxImages, images.Count - MaxImages);
        }
        var cache = new Dictionary<string, Loaded?>(StringComparer.OrdinalIgnoreCase);
        Loaded? Load(SideloadMember m)
        {
            if (cache.TryGetValue(m.Path, out var kept)) return kept;
            Loaded? image = null;
            try
            {
                if (m.Read() is { } bytes) image = Read(bytes, m.Path, m.DiskPath);
            }
            catch (Exception ex) when (ex is ToolError or IOException or UnauthorizedAccessException) { notes.Add($"{m.Path}: not read ({ex.Message})."); }
            return cache[m.Path] = image;
        }
        var hits = new List<SideloadHit>();
        foreach (var folder in images.GroupBy(m => Folder(m.Path), StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            // An archive may hold two names that differ only in case.
            var beside = new Dictionary<string, SideloadMember>(StringComparer.OrdinalIgnoreCase);
            foreach (var m in folder) beside.TryAdd(System.IO.Path.GetFileName(m.Path), m);
            foreach (var importer in folder)
            {
                if (Load(importer) is not { Embedded: true } signed) continue;
                foreach (var module in signed.Imports)
                {
                    var name = module.Module;
                    if (ApiSetPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                    if (known != null && known.Contains(name)) continue;
                    if (!beside.TryGetValue(name, out var target) || ReferenceEquals(target, importer)) continue;
                    if (Load(target) is not { } dll || !dll.IsDll || IsSigned(dll)) continue;
                    hits.Add(new SideloadHit(importer.Path, target.Path, $"{name}!{module.First}", module.Delay, Forwards(dll.ForwardTargets, name, beside.Keys)));
                }
            }
        }
        return (hits, notes);
    }

    /// <summary>A DLL with an embedded signature, or on disk in a Microsoft catalog (system DLLs are signed that way).</summary>
    private static bool IsSigned(Loaded dll) => dll.Embedded
        || dll.DiskPath != null && OperatingSystem.IsWindows() && CatalogSignature.Verify(dll.DiskPath, "Microsoft Corporation", out _) == null;

    /// <summary>The forwarded exports of <paramref name="dll"/> that name the system copy of its own module or a module file beside it.</summary>
    private static IReadOnlyList<string> Forwards(IReadOnlyList<string> targets, string name, IEnumerable<string> beside)
    {
        var files = beside.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var own = System.IO.Path.GetFileNameWithoutExtension(name);
        var found = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var target in targets)
        {
            int dot = target.IndexOf('.');
            if (dot <= 0) continue;
            var module = target[..dot];
            if (string.Equals(module, own, StringComparison.OrdinalIgnoreCase)) found.Add($"{module}.dll, the system copy of the same name");
            else if (files.Contains(module + ".dll")) found.Add($"{module}.dll, a renamed copy beside it");
        }
        return [.. found];
    }

    private static string Folder(string path)
    {
        var p = path.Replace('\\', '/');
        int i = p.LastIndexOf('/');
        return i >= 0 ? p[..i] : "";
    }

    // Microsoft Learn, "Dynamic-link library search order": a Windows
    // version lists its known DLLs in the KnownDLLs key read here.
    /// <summary>The names in the KnownDLLs key of this host; null off Windows or when the key cannot be read.</summary>
    private static HashSet<string>? KnownDlls()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs");
            if (key == null) return null;
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var value in key.GetValueNames())
            {
                if (value.StartsWith("DllDirectory", StringComparison.OrdinalIgnoreCase)) continue;
                if (key.GetValue(value) is string dll && dll.Length > 0) names.Add(dll);
            }
            return names.Count > 0 ? names : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    /// <summary>The files of a folder on disk, read on demand; links are not followed.</summary>
    public static IEnumerable<SideloadMember> OfFolder(string root)
    {
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var file in Directory.EnumerateFiles(root, "*", options))
        {
            var path = file;
            yield return new SideloadMember(System.IO.Path.GetRelativePath(root, file).Replace('\\', '/'), () => FileBytes(path), path);
        }
    }

    private static byte[]? FileBytes(string path) => new FileInfo(path).Length > PeLimits.MaxFileSize ? null : File.ReadAllBytes(path);

    /// <summary>The view of <paramref name="hits"/>, one review finding each; null when there are none.</summary>
    public static FileView? View(IReadOnlyList<SideloadHit> hits, IReadOnlyList<string> notes)
    {
        if (hits.Count == 0) return null;
        var findings = hits.Select(h => new Finding(FindingRules.Check("sideload/unsigned-dll", FindingLevel.Review), "sideload/unsigned-dll", "load order", Describe(h), h.Image, "sideload")).ToList();
        return new FileView(new Facts(hits, notes), [$"{hits.Count} unsigned DLL(s) beside a signed image that imports them: view=sideload."]) { Findings = findings };
    }

    /// <summary>The detail of view=sideload: each hit and the notes of the scan.</summary>
    public sealed record Facts(IReadOnlyList<SideloadHit> Hits, IReadOnlyList<string> Notes);

    /// <summary>One line naming the image, the DLL and the import, with the forwarded exports when there are any.</summary>
    internal static string Describe(SideloadHit h) =>
        $"{h.Image} {(h.Delay ? "delay-imports" : "imports")} {h.Import}; {h.Dll} beside it is unsigned"
        + (h.Forwards.Count > 0 ? $"; forwarded exports to {string.Join(", ", h.Forwards)}" : "") + ".";
}
