using Corvus.Core;
using Corvus.Native.MachO;
using Check = Corvus.Services.NativeImportVerifier.Check;

namespace Corvus.Services;

// /usr/lib and /System are in the shared cache and not checked; arm64e falls back to arm64, x86_64h to x86_64.
/// <summary>verify_native_imports for Mach-O: resolves each load command as dyld does, matches the slice and version, and checks bound symbols.</summary>
internal static class MachOLinkCheck
{
    private const int MaxMissingListed = 20;

    public static List<Check> Check(MachOFile image, string imagePath, CancellationToken ct)
    {
        var loaderDir = Path.GetDirectoryName(Path.GetFullPath(imagePath))!;
        var executable = MainExecutable(image, imagePath);
        var executableDir = executable != null ? Path.GetDirectoryName(executable) : null;
        var rpaths = image.Rpaths.ToList();
        if (executable != null && !string.Equals(executable, Path.GetFullPath(imagePath), StringComparison.OrdinalIgnoreCase))
            try { rpaths.AddRange(MachOFile.Open(executable).Rpaths); } catch (ToolError) { }
        var required = image.Fixups.All.OfType<MachOFixup.Bind>().Where(b => !b.Weak && b.Dylib != null)
            .GroupBy(b => b.Dylib!).ToDictionary(g => g.Key, g => g.Select(b => b.Symbol).ToHashSet(StringComparer.Ordinal));
        var rows = new List<Check>();
        foreach (var dylib in image.Dylibs)
        {
            ct.ThrowIfCancellationRequested();
            var symbols = required.GetValueOrDefault(dylib.Path) ?? [];
            Check Row(string status, string reason, string? file, string detail, string? symbol = null) =>
                new(symbol ?? $"load ({dylib.Kind.ToString().ToLowerInvariant()})", "", dylib.Path, symbol ?? "", "", true, "", status, reason, file, symbol, detail, null);
            if (IsSystem(dylib.Path))
            {
                rows.Add(Row(NativeImportVerifier.NotChecked, "system_library", null, $"in the dyld shared cache; {symbols.Count} symbol(s) bound"));
                continue;
            }
            var (file, searched) = Resolve(dylib.Path, loaderDir, executableDir, rpaths);
            if (file == null)
            {
                rows.Add(dylib.Kind == MachODylibKind.Weak
                    ? Row(NativeImportVerifier.NotChecked, "weak_library_absent", null, $"a weak load; searched {string.Join(", ", searched)}")
                    : Row(NativeImportVerifier.Unresolved, "dll_not_found", null, searched.Count > 0 ? $"searched {string.Join(", ", searched)}" : "no LC_RPATH resolves @rpath"));
                continue;
            }
            if (Open(file, image) is not { } dependency)
            {
                rows.Add(Row(NativeImportVerifier.Contradicted, "arch_mismatch", file, $"no {image.MachineName} slice"));
                continue;
            }
            var id = dependency.LoadCommands.OfType<MachODylibCommand>().FirstOrDefault(d => d.Kind == MachODylibKind.Id);
            if (id != null && id.CurrentVersion < dylib.CompatibilityVersion)
            {
                rows.Add(Row(NativeImportVerifier.Contradicted, "version_too_old", file, $"needs compatibility version {Version(dylib.CompatibilityVersion)}, the library is {Version(id.CurrentVersion)}"));
                continue;
            }
            var exported = Exported(dependency, file, executableDir, ct);
            var missing = symbols.Where(s => !exported.Contains(s)).Order(StringComparer.Ordinal).ToList();
            if (missing.Count == 0)
                rows.Add(Row(NativeImportVerifier.Verified, "resolved", file, $"{symbols.Count} symbol(s) bound, all exported"));
            else
            {
                rows.Add(Row(NativeImportVerifier.Contradicted, "missing_export", file, $"{missing.Count} of {symbols.Count} bound symbol(s) not exported"));
                foreach (var s in missing.Take(MaxMissingListed)) rows.Add(Row(NativeImportVerifier.Contradicted, "missing_export", file, "not exported", s));
            }
        }
        return rows;
    }

    private static bool IsSystem(string path) =>
        path.StartsWith("/usr/lib/", StringComparison.Ordinal) || path.StartsWith("/System/", StringComparison.Ordinal);

    /// <summary>The file a load command names, with the places tried.</summary>
    private static (string? File, List<string> Searched) Resolve(string name, string loaderDir, string? executableDir, IReadOnlyList<string> rpaths)
    {
        var searched = new List<string>();
        string? Expand(string path)
        {
            if (path.StartsWith("@loader_path", StringComparison.Ordinal)) return loaderDir + path["@loader_path".Length..];
            if (path.StartsWith("@executable_path", StringComparison.Ordinal)) return executableDir != null ? executableDir + path["@executable_path".Length..] : null;
            // An absolute path outside the system names the build machine.
            return path.StartsWith('/') ? null : path;
        }
        IEnumerable<string?> candidates = name.StartsWith("@rpath/", StringComparison.Ordinal)
            ? rpaths.Distinct().Select(r => Expand(r) is { } dir ? dir.TrimEnd('/') + name["@rpath".Length..] : null)
            : [Expand(name)];
        foreach (var candidate in candidates.OfType<string>())
        {
            var full = Path.GetFullPath(candidate.Replace('/', Path.DirectorySeparatorChar));
            searched.Add(full);
            if (File.Exists(full)) return (full, searched);
        }
        return (null, searched);
    }

    /// <summary>The executable whose folder @executable_path names: the image when it is one, else its .app's main executable.</summary>
    private static string? MainExecutable(MachOFile image, string imagePath)
    {
        var full = Path.GetFullPath(imagePath);
        // MH_EXECUTE.
        if (image.FileType == 2) return full;
        for (var dir = Path.GetDirectoryName(full); dir != null; dir = Path.GetDirectoryName(dir))
            if (dir.EndsWith(".app", StringComparison.OrdinalIgnoreCase))
            {
                var macos = Path.Combine(dir, "Contents", "MacOS");
                var folder = Directory.Exists(macos) ? macos : dir;
                return Directory.EnumerateFiles(folder).FirstOrDefault(f => !Path.HasExtension(f));
            }
        return null;
    }

    /// <summary>The dependency's slice for <paramref name="image"/>: the same one, else arm64e's arm64 or x86_64h's x86_64; null when none fits.</summary>
    private static MachOFile? Open(string file, MachOFile image)
    {
        try
        {
            var bytes = File.ReadAllBytes(file);
            var slices = MachOFat.Read(bytes);
            if (slices.Count == 0)
            {
                var thin = MachOFile.FromBytes(bytes, file);
                return thin.CpuType == image.CpuType ? thin : null;
            }
            string want = image.Slice?.Name ?? MachONames.CpuName(image.CpuType, image.CpuSubType);
            string[] order = want switch { "arm64e" => ["arm64e", "arm64"], "x86_64h" => ["x86_64h", "x86_64"], _ => [want] };
            return order.FirstOrDefault(n => slices.Any(s => s.Name == n)) is { } name ? MachOFile.FromBytes(bytes, file, name) : null;
        }
        catch (ToolError) { return null; }
    }

    /// <summary>The dependency's exported names, plus those of the libraries it re-exports (one level).</summary>
    private static HashSet<string> Exported(MachOFile dependency, string file, string? executableDir, CancellationToken ct)
    {
        var names = dependency.Exports.Select(e => e.Name).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var dir = Path.GetDirectoryName(file)!;
        foreach (var reexport in dependency.Dylibs.Where(d => d.Kind == MachODylibKind.Reexport && !IsSystem(d.Path)))
        {
            ct.ThrowIfCancellationRequested();
            if (Resolve(reexport.Path, dir, executableDir, dependency.Rpaths).File is { } inner && Open(inner, dependency) is { } library)
                names.UnionWith(library.Exports.Select(e => e.Name).OfType<string>());
        }
        return names;
    }

    private static string Version(uint v) => $"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}";
}
