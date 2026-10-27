using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>Recognizes AOT (GameAssembly.dll with global-metadata.dat) and Mono (*_Data/Managed) build layouts.</summary>
internal static class PlayerLayout
{
    private const uint MetadataMagic = 0xFAB11BAF;

    /// <summary>A hint for an AOT binary or metadata file, else null.</summary>
    public static string? FileHint(string path, byte[] bytes)
    {
        if (bytes.Length >= 4 && BitConverter.ToUInt32(bytes, 0) == MetadataMagic)
            return "AOT metadata (global-metadata.dat): load_assembly it with the native binary (GameAssembly, libil2cpp.so or UnityFramework) " +
                   "in the build folder for dummy assemblies with addresses, field offsets and string literals (get_method_addresses).";
        if (PeImage.TryParse(bytes) is { } pe && pe.Exports(bytes, 4000).Any(e => e.StartsWith("il2cpp_", StringComparison.Ordinal)))
        {
            var metadata = FindMetadata(Path.GetDirectoryName(Path.GetFullPath(path))!);
            return "AOT native code (exports il2cpp_*), no IL: load_assembly " +
                   (metadata != null ? $"its metadata ({metadata})" : "its global-metadata.dat (in <Product>_Data/il2cpp_data/Metadata)") +
                   " or the build folder for names, addresses and field offsets; encrypted metadata is read from a memory dump of it.";
        }
        return null;
    }

    /// <summary>Hints for a loaded folder whose managed code is elsewhere or not IL.</summary>
    public static List<string> FolderHints(string directory)
    {
        var hints = new List<string>();
        try
        {
            var dir = Path.GetFullPath(directory);
            foreach (var data in Directory.EnumerateDirectories(dir, "*_Data").Append(dir).Where(d => Path.GetFileName(d).EndsWith("_Data", StringComparison.OrdinalIgnoreCase)))
            {
                var managed = Path.Combine(data, "Managed");
                if (Directory.Exists(managed) && Directory.EnumerateFiles(managed, "*.dll").Any())
                    hints.Add($"Mono build: the managed assemblies are in {managed}; load_assembly that folder.");
            }
            if (File.Exists(Path.Combine(dir, "GameAssembly.dll")) || FindMetadata(dir) != null)
            {
                var metadata = FindMetadata(dir);
                hints.Add("AOT build: the code is native in GameAssembly.dll, no IL" +
                          (metadata != null ? $"; metadata in {metadata}" : "") +
                          "; load_assembly the folder or its global-metadata.dat with both files present.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return hints;
    }

    private static string? FindMetadata(string dir)
    {
        try
        {
            return Directory.EnumerateDirectories(dir, "*_Data")
                .Select(d => Path.Combine(d, "il2cpp_data", "Metadata", "global-metadata.dat"))
                .FirstOrDefault(File.Exists);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }
}
