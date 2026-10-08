namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// Recognizes Unity build layouts: IL2CPP (GameAssembly.dll plus global-metadata.dat) and Mono (*_Data/Managed).
/// </summary>
internal static class UnityLayout
{
    private const uint MetadataMagic = 0xFAB11BAF;

    /// <summary>A hint for an IL2CPP binary or metadata file, else null.</summary>
    public static string? FileHint(string path, byte[] bytes)
    {
        if (bytes.Length >= 4 && BitConverter.ToUInt32(bytes, 0) == MetadataMagic)
            return "Unity IL2CPP metadata (global-metadata.dat): type and method definitions of an IL2CPP build. Run Il2CppDumper or Cpp2IL on it " +
                   "with the build's GameAssembly.dll to produce dummy DLLs, then load_assembly that folder (get_il2cpp_info, find_method_by_address).";
        if (PeImage.TryParse(bytes) is { } pe && pe.Exports(bytes, 4000).Any(e => e.StartsWith("il2cpp_", StringComparison.Ordinal)))
        {
            var metadata = FindMetadata(Path.GetDirectoryName(Path.GetFullPath(path))!);
            return "Unity IL2CPP native code (exports il2cpp_*): the C# was compiled to native code, there is no IL here. " +
                   (metadata != null ? $"With its metadata ({metadata}), " : "With its global-metadata.dat (in <Product>_Data/il2cpp_data/Metadata), ") +
                   "Il2CppDumper or Cpp2IL produce dummy DLLs: load_assembly that folder for names, addresses and field offsets.";
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
                    hints.Add($"Unity (Mono) build: the managed assemblies are in {managed}; load_assembly that folder.");
            }
            if (File.Exists(Path.Combine(dir, "GameAssembly.dll")) || FindMetadata(dir) != null)
            {
                var metadata = FindMetadata(dir);
                hints.Add("Unity IL2CPP build: the C# code is compiled into GameAssembly.dll (native, no IL)" +
                          (metadata != null ? $", metadata in {metadata}" : "") +
                          ". Run Il2CppDumper or Cpp2IL on GameAssembly.dll + global-metadata.dat and load the DummyDll folder they write.");
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
