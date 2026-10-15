using Corvus.Core;
using Corvus.Native.Pdb;

namespace Corvus.Native.Dwarf;

/// <summary>
/// Finds the DWARF of an ELF or Mach-O image the way debuggers do, without network access: an explicit file, folder or
/// dSYM bundle; the image's own sections; beside the image (its .gnu_debuglink name, &lt;name&gt;.debug / .dbg /
/// .dwarf, .debug/ and .build-id/ folders, &lt;name&gt;.dSYM); the folders in <see cref="DirsVariable"/> (.build-id
/// trees, debuglink names, the image's folder under them, dSYM bundles); /usr/lib/debug on Linux and macOS hosts; and
/// this server's download cache. A candidate must carry the image's GNU build-id or Mach-O UUID (or, without one, match
/// the .gnu_debuglink CRC-32); a file that does not is reported, never used. <see cref="DownloadAsync"/> asks debuginfod
/// servers and runs only when the user asked for it.
/// </summary>
public static class DwarfLocator
{
    /// <summary>Folders searched for separate debug files (the platform's path list separator).</summary>
    public const string DirsVariable = "CORVUS_DEBUG_DIRS";
    /// <summary>debuginfod servers for load_pdb download=true (space-separated URLs); DEBUGINFOD_URLS when unset.</summary>
    public const string ServersVariable = "CORVUS_DEBUGINFOD_URLS";

    /// <summary>The probe outcome that marks the image's own DWARF.</summary>
    public const string Embedded = "the image's own DWARF sections";

    private static string Cache => System.IO.Path.Combine(PdbLocator.DownloadCache, "debuginfod");

    /// <summary>The configured debuginfod servers, else none (no download).</summary>
    public static List<string> Servers()
    {
        var value = Environment.GetEnvironmentVariable(ServersVariable) is { Length: > 0 } v ? v : Environment.GetEnvironmentVariable("DEBUGINFOD_URLS");
        return value?.Split((char[])[' ', '\t', '\n', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            .Select(s => s.TrimEnd('/')).Distinct().ToList() ?? [];
    }

    /// <summary>
    /// Looks for the DWARF of <paramref name="image"/> loaded from <paramref name="imagePath"/>; <paramref name="explicitPath"/>
    /// (a file, folder or dSYM bundle) is tried first. <see cref="PdbLocation.Path"/> is the image's own path when its sections hold the DWARF.
    /// </summary>
    public static PdbLocation Locate(INativeImage image, string imagePath, string? explicitPath = null)
    {
        var probes = new List<PdbProbe>();
        var id = image.BuildId;
        (string Name, uint Crc)? link = null;
        bool embedded = false;
        try
        {
            using var own = image is Elf.ElfFile or MachO.MachOFile ? DebugContainer.FromMemory(imagePath, FileBytes(image)) : null;
            if (own != null)
            {
                link = own.DebugLink;
                embedded = DwarfDebugInfo.HasDwarf(own);
            }
        }
        catch (ToolError) { }

        string dir = System.IO.Path.GetDirectoryName(imagePath) ?? "";
        string name = System.IO.Path.GetFileName(imagePath);
        var candidates = new List<string>();
        void Folder(string root, bool withImageDir)
        {
            if (id is { Length: > 2 } && image.Format == ImageFormat.Elf)
                candidates.Add(System.IO.Path.Combine(root, ".build-id", id[..2], id[2..] + ".debug"));
            if (link is { } l) candidates.Add(System.IO.Path.Combine(root, l.Name));
            candidates.Add(System.IO.Path.Combine(root, name + ".debug"));
            candidates.Add(System.IO.Path.Combine(root, name + ".dbg"));
            candidates.Add(System.IO.Path.Combine(root, name + ".dwarf"));
            candidates.AddRange(DsymFiles(System.IO.Path.Combine(root, name + ".dSYM")));
            if (withImageDir && link is { } l2 && dir.Length > 0)
            {
                // gdb's layout: <debug dir>/<the image's absolute folder>/<debuglink name>
                var relative = dir.Replace('\\', '/').TrimStart('/');
                if (relative.Length > 1 && relative[1] == ':') relative = relative[2..].TrimStart('/');
                candidates.Add(System.IO.Path.Combine(root, relative, l2.Name));
            }
        }

        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            if (explicitPath.EndsWith(".dSYM", StringComparison.OrdinalIgnoreCase) || explicitPath.EndsWith(".dSYM/", StringComparison.OrdinalIgnoreCase) ||
                Directory.Exists(System.IO.Path.Combine(explicitPath, "Contents", "Resources", "DWARF")))
                candidates.AddRange(DsymFiles(explicitPath));
            else if (Directory.Exists(explicitPath))
            {
                Folder(explicitPath, withImageDir: false);
                candidates.AddRange(DsymBundles(explicitPath));
            }
            else candidates.Add(explicitPath);
        }
        else if (embedded)
        {
            probes.Add(new PdbProbe(imagePath, Embedded));
            return new PdbLocation(imagePath, probes, []);
        }
        if (dir.Length > 0)
        {
            Folder(dir, withImageDir: false);
            if (link is { } l) candidates.Add(System.IO.Path.Combine(dir, ".debug", l.Name));
            if (id is { Length: > 2 } && image.Format == ImageFormat.Elf) candidates.Add(System.IO.Path.Combine(dir, ".debug", ".build-id", id[..2], id[2..] + ".debug"));
        }
        foreach (var root in Roots())
        {
            Folder(root, withImageDir: true);
            if (image.Format == ImageFormat.MachO) candidates.AddRange(DsymBundles(root));
        }
        if (id != null) candidates.Add(System.IO.Path.Combine(Cache, id, "debuginfo"));

        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var c in candidates)
        {
            string full;
            try { full = System.IO.Path.GetFullPath(c); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { continue; }
            if (!seen.Add(full) || string.Equals(full, System.IO.Path.GetFullPath(imagePath), StringComparison.OrdinalIgnoreCase)) continue;
            if (!File.Exists(full)) { probes.Add(new PdbProbe(full, "not found")); continue; }
            var outcome = Check(full, image, link);
            probes.Add(new PdbProbe(full, outcome ?? "match"));
            if (outcome == null) return new PdbLocation(full, probes, Servers());
        }
        if (embedded)
        {
            probes.Add(new PdbProbe(imagePath, Embedded));
            return new PdbLocation(imagePath, probes, Servers());
        }
        if (!embedded && link == null && id == null)
            probes.Add(new PdbProbe(imagePath, "the image has no build-id, UUID or .gnu_debuglink to match a debug file by"));
        return new PdbLocation(null, probes, Servers());
    }

    /// <summary>The bytes of a thin image (a universal Mach-O's selected slice), for its own sections.</summary>
    internal static ReadOnlyMemory<byte> FileBytes(INativeImage image) => image switch
    {
        Elf.ElfFile e => e.FileBytes,
        MachO.MachOFile m => m.FileBytes,
        _ => ReadOnlyMemory<byte>.Empty,
    };

    private static IEnumerable<string> Roots()
    {
        if (Environment.GetEnvironmentVariable(DirsVariable) is { Length: > 0 } dirs)
            foreach (var d in dirs.Split(System.IO.Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                yield return d;
        if (!OperatingSystem.IsWindows() && Directory.Exists("/usr/lib/debug")) yield return "/usr/lib/debug";
    }

    /// <summary>The DWARF files of a dSYM bundle (Contents/Resources/DWARF/*).</summary>
    private static IEnumerable<string> DsymFiles(string bundle)
    {
        var dwarf = System.IO.Path.Combine(bundle, "Contents", "Resources", "DWARF");
        if (!Directory.Exists(dwarf)) return [];
        try { return Directory.GetFiles(dwarf).Order(StringComparer.Ordinal).Take(16); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    private static IEnumerable<string> DsymBundles(string folder)
    {
        try { return Directory.GetDirectories(folder, "*.dSYM").Order(StringComparer.Ordinal).Take(256).SelectMany(DsymFiles); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }

    /// <summary>Null when <paramref name="path"/> holds DWARF for <paramref name="image"/>; else why not.</summary>
    public static string? Check(string path, INativeImage image, (string Name, uint Crc)? link = null)
    {
        try
        {
            using var c = DebugContainer.Open(path, image.BuildId, MachOCpu(image));
            if (c.Format != image.Format) return $"a {c.Format} file; the image is {image.Format}";
            if (!DwarfDebugInfo.HasDwarf(c)) return "no DWARF (.debug_info) in it";
            if (image.BuildId is { } want)
            {
                if (c.BuildId == want) return null;
                if (c.BuildId != null) return $"different build ({(image.Format == ImageFormat.MachO ? "UUID" : "build-id")} {c.BuildId}, image wants {want})";
            }
            if (link is { } l && System.IO.Path.GetFileName(path) == l.Name)
                return c.FileCrc32() == l.Crc ? null : $"different build (CRC-32 0x{c.FileCrc32():X8}, .gnu_debuglink wants 0x{l.Crc:X8})";
            return image.BuildId == null ? "the image has no build-id or UUID to check it against (pass it as path with allowMismatch=true)" : "it has no build-id to check";
        }
        catch (ToolError e) { return "unreadable: " + e.Message; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "unreadable: " + ex.Message; }
    }

    private static string? MachOCpu(INativeImage image) => (image as MachO.MachOFile)?.Arch switch
    {
        NativeArch.X64 => "x86_64",
        NativeArch.Arm64 => "arm64",
        NativeArch.X86 => "i386",
        NativeArch.Arm => "arm",
        _ => null,
    };

    /// <summary>
    /// Downloads the debug file of an ELF image by its build-id from a debuginfod server ({server}/buildid/{id}/debuginfo)
    /// into the download cache, checked by build-id; returns the cached path.
    /// </summary>
    public static Task<string> DownloadAsync(INativeImage image, string server, TimeSpan timeout, long maxBytes, HttpMessageHandler? handler = null,
        string? cache = null, CancellationToken ct = default)
    {
        if (image.Format != ImageFormat.Elf || image.BuildId is not { Length: >= 2 } id || !id.All(char.IsAsciiHexDigit))
            throw new ToolError(ErrorCode.Unsupported, "debuginfod finds debug files by GNU build-id; this image has none.");
        if (!Uri.TryCreate(server.TrimEnd('/') + "/", UriKind.Absolute, out var baseUri) || baseUri.Scheme is not ("https" or "http"))
            throw new ToolError(ErrorCode.InvalidArgument, $"'{server}' is not an http(s) debuginfod URL.");
        var url = new Uri(baseUri, $"buildid/{id}/debuginfo");
        return PdbLocator.FetchUrl(url, System.IO.Path.Combine(cache ?? Cache, id, "debuginfo"), "debug file", path => Check(path, image), timeout, maxBytes, handler, ct);
    }
}
