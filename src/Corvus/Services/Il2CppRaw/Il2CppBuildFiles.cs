using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// The files of an Il2Cpp build the built-in reader needs: the native binary, the metadata (global-metadata.dat) and,
/// for the Unity version, the player (UnityPlayer.dll) and the data folder. <see cref="Slice"/> picks the slice of a
/// universal Mach-O binary; <see cref="Package"/> is the .apk / .ipa the files were extracted from.
/// </summary>
public sealed record Il2CppBuildFiles(string Binary, string Metadata, string? UnityPlayer, string? DataDirectory, string? Slice = null)
{
    public const string MetadataFileName = "global-metadata.dat";
    public const string BinaryFileName = "GameAssembly.dll";
    private const uint MetadataMagic = 0xFAB11BAF;

    /// <summary>Il2Cpp binary names by platform: Windows, Linux, macOS, Android, iOS (Unity 2019.3 and later).</summary>
    public static readonly string[] BinaryNames = [BinaryFileName, "GameAssembly.so", "GameAssembly.dylib", "libil2cpp.so", "UnityFramework"];

    /// <summary>Android ABIs in the order a build is picked when none is asked for.</summary>
    public static readonly string[] AndroidAbis = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];

    /// <summary>windows, linux, macos, android or ios: the layout the files were found in.</summary>
    public string Platform { get; init; } = "windows";

    public string? Package { get; init; }

    /// <summary>
    /// The build files for <paramref name="path"/>, or null when the path is not an Il2Cpp build. Layouts: Windows and
    /// Linux (GameAssembly.dll / .so beside &lt;Product&gt;_Data/il2cpp_data/Metadata), macOS (.app with
    /// Contents/Frameworks/GameAssembly.dylib and Contents/Resources/Data/il2cpp_data/Metadata), an extracted Android
    /// package (lib/&lt;abi&gt;/libil2cpp.so, assets/bin/Data/Managed/Metadata), an iOS .app
    /// (Frameworks/UnityFramework.framework/UnityFramework or the main executable, Data/Managed/Metadata), or the metadata
    /// with the binary beside it. The path is the build folder, the metadata or the binary. <paramref name="slice"/> is the
    /// Android ABI (default arm64-v8a, armeabi-v7a, x86_64, x86) or the Mach-O slice. Throws NotFound when one half is
    /// there and the other is not, unless <paramref name="metadataOnly"/> takes metadata without a binary (Binary is then "").
    /// </summary>
    public static Il2CppBuildFiles? Find(string path, string? slice = null, bool metadataOnly = false)
    {
        var full = Path.GetFullPath(path);
        Candidate? found = null;
        if (Directory.Exists(full))
        {
            found = FromRoot(full, slice);
            if (found is not { Binary: not null } || found.Metadata == null)
                foreach (var dir in SafeList(() => Directory.EnumerateDirectories(full, "*.app")))
                    if (FromRoot(dir, slice) is { Binary: not null, Metadata: not null } app) { found = app; break; }
            if (found == null || (found.Binary == null && found.Metadata == null)) return null;
        }
        else if (File.Exists(full))
        {
            bool isMetadata = IsMetadataFile(full);
            if (!isMetadata && !IsBinaryName(Path.GetFileName(full))) return null;
            // The build root is the file's folder or one of its ancestors whose layout names this file.
            for (var dir = Path.GetDirectoryName(full); dir != null && found is not { Binary: not null, Metadata: not null }; dir = Path.GetDirectoryName(dir))
            {
                if (FromRoot(dir, slice, isMetadata ? null : full) is { } c && Same(isMetadata ? c.Metadata : c.Binary, full) && (found == null || (c.Binary != null && c.Metadata != null))) found = c;
                if (Depth(full) - Depth(dir) > 6) break;
            }
            found ??= isMetadata ? new Candidate(null, full, null, "windows") : new Candidate(full, null, null, "windows");
            if (isMetadata && !Same(found.Metadata, full)) found = found with { Metadata = full };
        }
        else return null;
        var (binary, metadata, data, platform) = found;
        if (metadata == null)
            throw new ToolError(ErrorCode.NotFound, $"Found {binary} but no {MetadataFileName} (looked in <Product>_Data/il2cpp_data/Metadata, assets/bin/Data/Managed/Metadata, Data/Managed/Metadata and beside it).",
                $"pass the {MetadataFileName} path, with the binary beside it or in its build folder");
        if (binary == null && metadataOnly)
            return new Il2CppBuildFiles("", metadata, null, data ?? DataDirectoryOf(metadata)) { Platform = platform };
        if (binary == null)
            throw new ToolError(ErrorCode.NotFound, $"Found {metadata} but no native binary ({string.Join(", ", BinaryNames)}) beside it or in the build folder.",
                "put the native binary (or a memory dump of it under its name) beside the metadata, or pass the build folder");
        var appDir = Path.GetDirectoryName(binary)!;
        var player = platform == "windows" ? Existing(appDir, "UnityPlayer.dll") : null;
        data ??= DataDirectoryOf(metadata) ?? SafeEnumerate(() => Directory.EnumerateDirectories(appDir, "*_Data").FirstOrDefault());
        return new Il2CppBuildFiles(binary, metadata, player, data, platform == "android" ? null : slice) { Platform = platform };
    }

    private sealed record Candidate(string? Binary, string? Metadata, string? Data, string Platform);

    /// <summary>The build files a folder holds in one of the known layouts; either half may be null.</summary>
    private static Candidate? FromRoot(string dir, string? slice, string? binaryHint = null)
    {
        // Android: lib/<abi>/libil2cpp.so with assets/bin/Data/Managed/Metadata.
        var androidData = Path.Combine(dir, "assets", "bin", "Data");
        var androidMetadata = Existing(Path.Combine(androidData, "Managed", "Metadata"), MetadataFileName);
        var abiDirs = Directory.Exists(Path.Combine(dir, "lib")) ? AbiBinaries(dir) : [];
        if (androidMetadata != null || abiDirs.Count > 0)
        {
            string? binary = null;
            if (binaryHint != null && abiDirs.Any(a => Same(a.Binary, binaryHint))) binary = Path.GetFullPath(binaryHint);
            else if (slice != null && AndroidAbi(slice) is { } abi)
                binary = abiDirs.FirstOrDefault(a => a.Abi == abi).Binary
                         ?? throw new ToolError(ErrorCode.NotFound, $"{dir} has no lib/{abi}/libil2cpp.so" + (abiDirs.Count > 0 ? $"; ABIs: {string.Join(", ", abiDirs.Select(a => a.Abi))}" : "") + ".",
                             abiDirs.Count > 0 ? $"pass slice={abiDirs[0].Abi}" : "pass the folder with lib/<abi>/libil2cpp.so");
            else binary = AndroidAbis.Select(a => abiDirs.FirstOrDefault(d => d.Abi == a).Binary).FirstOrDefault(b => b != null) ?? abiDirs.FirstOrDefault().Binary;
            return new Candidate(binary, androidMetadata, Directory.Exists(androidData) ? androidData : null, "android");
        }
        // macOS .app: Contents/Frameworks/GameAssembly.dylib, Contents/Resources/Data/il2cpp_data/Metadata.
        var contents = Path.Combine(dir, "Contents");
        var macData = Path.Combine(contents, "Resources", "Data");
        var dylib = Existing(Path.Combine(contents, "Frameworks"), "GameAssembly.dylib");
        if (dylib != null || Directory.Exists(macData))
            return new Candidate(dylib, Existing(Path.Combine(macData, "il2cpp_data", "Metadata"), MetadataFileName), Directory.Exists(macData) ? macData : null, "macos");
        // iOS .app: Frameworks/UnityFramework.framework/UnityFramework (or the main executable), Data/Managed/Metadata.
        var iosData = Path.Combine(dir, "Data");
        var iosMetadata = Existing(Path.Combine(iosData, "Managed", "Metadata"), MetadataFileName);
        var framework = Existing(Path.Combine(dir, "Frameworks", "UnityFramework.framework"), "UnityFramework");
        if (iosMetadata != null || framework != null)
        {
            var main = dir.EndsWith(".app", StringComparison.OrdinalIgnoreCase) ? Existing(dir, Path.GetFileNameWithoutExtension(dir)) : null;
            var binary = binaryHint != null && Same(main, binaryHint) ? main : framework ?? main;
            return new Candidate(binary, iosMetadata, Directory.Exists(iosData) ? iosData : null, "ios");
        }
        // Windows and Linux: GameAssembly.dll / .so with <Product>_Data/il2cpp_data/Metadata; or both files side by side.
        var beside = BinaryNames.Select(n => Existing(dir, n)).FirstOrDefault(p => p != null && (binaryHint == null || Same(p, binaryHint)));
        var metadata = MetadataIn(dir);
        if (beside == null && metadata == null) return null;
        return new Candidate(beside, metadata, null, Path.GetFileName(beside)?.ToLowerInvariant() switch
        {
            "libil2cpp.so" => "android",
            "unityframework" => "ios",
            "gameassembly.so" => "linux",
            "gameassembly.dylib" => "macos",
            _ => "windows",
        });
    }

    private static List<(string Abi, string Binary)> AbiBinaries(string dir) =>
        SafeList(() => Directory.EnumerateDirectories(Path.Combine(dir, "lib")))
            .Select(d => (Abi: Path.GetFileName(d), Binary: Existing(d, "libil2cpp.so")))
            .Where(x => x.Binary != null).Select(x => (x.Abi, x.Binary!)).ToList();

    /// <summary>The Android ABI a slice names (arm64 and armv7 spellings accepted), or null when it names none.</summary>
    public static string? AndroidAbi(string slice) => slice.Trim().ToLowerInvariant() switch
    {
        "arm64-v8a" or "arm64" or "aarch64" => "arm64-v8a",
        "armeabi-v7a" or "armv7" or "arm" => "armeabi-v7a",
        "x86_64" => "x86_64",
        "x86" or "i386" => "x86",
        _ => null,
    };

    private static bool IsBinaryName(string name) => BinaryNames.Any(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static bool Same(string? a, string? b) => a != null && b != null && string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

    private static int Depth(string path) => path.Count(c => c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar);

    /// <summary>Whether a file starts with the Il2Cpp metadata magic, or is named global-metadata.dat (encrypted metadata keeps the name).</summary>
    public static bool IsMetadataFile(string path)
    {
        if (Path.GetFileName(path).Equals(MetadataFileName, StringComparison.OrdinalIgnoreCase)) return true;
        try
        {
            using var f = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[4];
            return RandomAccess.Read(f, head, 0) == 4 && BitConverter.ToUInt32(head) == MetadataMagic;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>global-metadata.dat in a folder, its *_Data/il2cpp_data/Metadata, or il2cpp_data/Metadata.</summary>
    public static string? MetadataIn(string dir) =>
        Existing(dir, MetadataFileName)
        ?? Existing(Path.Combine(dir, "il2cpp_data", "Metadata"), MetadataFileName)
        ?? SafeEnumerate(() => Directory.EnumerateDirectories(dir, "*_Data")
            .Select(d => Existing(Path.Combine(d, "il2cpp_data", "Metadata"), MetadataFileName)).FirstOrDefault(p => p != null));

    private static string? DataDirectoryOf(string metadata)
    {
        var metaDir = Path.GetDirectoryName(metadata);
        var il2cppData = metaDir != null ? Path.GetDirectoryName(metaDir) : null;
        var data = il2cppData != null ? Path.GetDirectoryName(il2cppData) : null;
        return data != null && Path.GetFileName(il2cppData)!.Equals("il2cpp_data", StringComparison.OrdinalIgnoreCase) && Directory.Exists(data) ? data : null;
    }

    private static string? Existing(string dir, string name) => Path.Combine(dir, name) is var p && File.Exists(p) ? Path.GetFullPath(p) : null;

    private static string? SafeEnumerate(Func<string?> f)
    {
        try { return f(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static List<string> SafeList(Func<IEnumerable<string>> f)
    {
        try { return [.. f()]; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return []; }
    }
}
