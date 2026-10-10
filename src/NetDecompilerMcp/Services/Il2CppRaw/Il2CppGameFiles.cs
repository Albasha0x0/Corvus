using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The files of an Il2Cpp game the built-in reader needs: the native binary (GameAssembly.dll), the metadata
/// (global-metadata.dat) and, for the Unity version, the player (UnityPlayer.dll) and the data folder (&lt;Game&gt;_Data).
/// Found from the game folder, the metadata file, or the binary.
/// </summary>
public sealed record Il2CppGameFiles(string Binary, string Metadata, string? UnityPlayer, string? DataDirectory)
{
    public const string MetadataFileName = "global-metadata.dat";
    public const string BinaryFileName = "GameAssembly.dll";
    private const uint MetadataMagic = 0xFAB11BAF;

    /// <summary>
    /// The game files for <paramref name="path"/>, or null when the path is not an Il2Cpp game: a folder with
    /// GameAssembly.dll and &lt;Game&gt;_Data/il2cpp_data/Metadata/global-metadata.dat (or both files side by side), a
    /// global-metadata.dat (the binary beside it or in the game folder three levels up), or a GameAssembly.dll whose
    /// metadata is found the same way. Throws NotFound when one half is there and the other is not.
    /// </summary>
    public static Il2CppGameFiles? Find(string path)
    {
        var full = Path.GetFullPath(path);
        string? binary = null, metadata = null;
        if (Directory.Exists(full))
        {
            binary = Existing(full, BinaryFileName);
            metadata = MetadataIn(full);
            if (binary == null && metadata == null) return null;
        }
        else if (File.Exists(full))
        {
            if (IsMetadataFile(full)) { metadata = full; binary = BinaryFor(full); }
            else if (Path.GetFileName(full).Equals(BinaryFileName, StringComparison.OrdinalIgnoreCase)) { binary = full; metadata = MetadataIn(Path.GetDirectoryName(full)!); }
            else return null;
        }
        else return null;
        if (metadata == null)
            throw new ToolError(ErrorCode.NotFound, $"Found {binary} but no {MetadataFileName} (looked in <Game>_Data/il2cpp_data/Metadata and beside it).",
                $"pass the {MetadataFileName} path, with {BinaryFileName} beside it or in its game folder");
        if (binary == null)
            throw new ToolError(ErrorCode.NotFound, $"Found {metadata} but no {BinaryFileName} beside it or in the game folder.",
                $"put {BinaryFileName} (or a memory dump of it under that name) beside the metadata, or pass the game folder");
        var gameDir = Path.GetDirectoryName(binary)!;
        var player = Existing(gameDir, "UnityPlayer.dll");
        var data = DataDirectoryOf(metadata) ?? SafeEnumerate(() => Directory.EnumerateDirectories(gameDir, "*_Data").FirstOrDefault());
        return new Il2CppGameFiles(binary, metadata, player, data);
    }

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

    private static string? BinaryFor(string metadata)
    {
        var dir = Path.GetDirectoryName(metadata)!;
        if (Existing(dir, BinaryFileName) is { } beside) return beside;
        // <Game>/<Game>_Data/il2cpp_data/Metadata/global-metadata.dat
        var game = DataDirectoryOf(metadata) is { } data ? Path.GetDirectoryName(data) : null;
        return game != null ? Existing(game, BinaryFileName) : null;
    }

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
}
