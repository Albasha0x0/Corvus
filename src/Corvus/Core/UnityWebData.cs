using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>
/// A Unity WebGL data file (Build/&lt;name&gt;.data, also gzip or Brotli compressed): "UnityWebData1.0\0", the header size,
/// then (offset, size, name length, name) per file. Holds the serialized scenes and assets and, for Il2Cpp builds, the
/// global-metadata.dat that goes with the WebAssembly code in the .wasm beside it.
/// </summary>
public static class UnityWebData
{
    public const string Kind = "Unity WebGL data (UnityWebData)";
    private static ReadOnlySpan<byte> Magic => "UnityWebData1.0\0"u8;
    private const int MaxFiles = 100_000;

    public static bool Looks(ReadOnlySpan<byte> b) => b.StartsWith(Magic);

    /// <summary>
    /// The data file inside a compressed one: gzip by its magic, Brotli for .br / .unityweb names (Brotli has no magic).
    /// Null when the data is not a compressed UnityWebData.
    /// </summary>
    public static byte[]? Decompress(byte[] data, string name, long maxBytes)
    {
        byte[]? inner = null;
        if (Blob.StartsWith(data, [0x1F, 0x8B])) inner = Blob.TryDecompress(data, "gzip", maxBytes);
        else if (name.EndsWith(".br", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".unityweb", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                using var brotli = new BrotliStream(new MemoryStream(data, writable: false), CompressionMode.Decompress);
                inner = Blob.ReadBounded(brotli, maxBytes);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or InvalidOperationException) { }
        }
        return inner != null && Looks(inner) ? inner : null;
    }

    public static ContainerContents Open(byte[] data, string name, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct, string? compression = null)
    {
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        if (data.Length < Magic.Length + 4) throw new ToolError(ErrorCode.MalformedInput, $"{name}: truncated UnityWebData header.");
        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(Magic.Length));
        if (headerSize < Magic.Length + 4 || headerSize > data.Length)
            throw new ToolError(ErrorCode.MalformedInput, $"{name}: corrupt UnityWebData header (size {headerSize} in a {data.Length:N0}-byte file).");
        int at = Magic.Length + 4, bad = 0, refused = 0;
        long total = 0;
        string? metadata = null, unityVersion = null;
        while (at + 12 <= headerSize && entries.Count < MaxFiles)
        {
            ct.ThrowIfCancellationRequested();
            uint offset = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)), size = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at + 4)),
                length = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at + 8));
            if (length > 4096 || at + 12 + length > headerSize) { notes.Add($"Header entry at 0x{at:X} has a name past the header; the listing stops there."); break; }
            var file = Encoding.UTF8.GetString(data, at + 12, (int)length);
            at += 12 + (int)length;
            if (offset > data.Length || size > data.Length - offset)
            {
                if (bad++ < 3) notes.Add($"{file}: data (offset {offset}, size {size}) lies outside the file.");
                entries.Add(new ContainerEntry(file, size, "out of range"));
                continue;
            }
            var content = data.AsSpan((int)offset, (int)size);
            var role = Role(file, content);
            if (file.EndsWith("global-metadata.dat", StringComparison.OrdinalIgnoreCase)) metadata = $"{file} ({role})";
            unityVersion ??= UnityVersion(content);
            bool unsafeName = file.Split('/').Any(AsarArchive.IsUnsafeName);
            entries.Add(new ContainerEntry(file, size, unsafeName ? role + ", unsafe name" : role));
            if (!(allFiles || Containers.IsInteresting(file))) continue;
            if (unsafeName) { refused++; continue; }
            if (items.Count >= limits.MaxItems || (total += size) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
            items.Add(new ExtractedItem(file, content.ToArray(), $"UnityWebData entry ({role})"));
        }
        if (bad > 3) notes.Add($"{bad - 3} more entries lie outside the file.");
        if (refused > 0) notes.Add($"{refused} entr(ies) with unsafe names not extracted.");
        notes.Insert(0, $"UnityWebData{(compression != null ? $" ({compression} compressed)" : "")}: {entries.Count} file(s)" +
                        (unityVersion != null ? $", Unity {unityVersion}" : "") + (metadata != null ? $"; Il2Cpp metadata {metadata}" : "; no Il2Cpp metadata (a Mono or asset-only build)") + ".");
        if (location != null && Siblings(location) is { Count: > 0 } siblings) notes.Insert(1, "Build folder: " + string.Join("; ", siblings) + ".");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>What an entry is, from its name and first bytes.</summary>
    private static string Role(string file, ReadOnlySpan<byte> content)
    {
        if (content.Length >= 8 && BinaryPrimitives.ReadUInt32LittleEndian(content) == 0xFAB11BAF)
            return $"Il2Cpp metadata v{BinaryPrimitives.ReadInt32LittleEndian(content[4..])}";
        if (content.StartsWith("UnityFS"u8)) return "Unity asset bundle (UnityFS)";
        var name = Path.GetFileName(file);
        if (name is "data.unity3d") return "Unity data bundle";
        if (name is "globalgamemanagers" or "globalgamemanagers.assets" || name.StartsWith("level", StringComparison.Ordinal)
            || name.StartsWith("sharedassets", StringComparison.Ordinal) || name.StartsWith("resources.assets", StringComparison.Ordinal)
            || name == "unity_builtin_extra") return "Unity serialized file";
        if (name.EndsWith(".resource", StringComparison.Ordinal) || name.EndsWith(".resS", StringComparison.Ordinal)) return "Unity streamed resource";
        if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return Blob.Identify(content) == ".NET assembly" ? ".NET assembly" : "DLL";
        if (name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) return "JSON";
        return Blob.Identify(content);
    }

    private static readonly Regex VersionPattern = new(@"20[0-9]{2}\.[0-9]+\.[0-9]+[abfpx][0-9]+|[56]\.[0-9]\.[0-9]+[abfpx][0-9]+", RegexOptions.CultureInvariant);

    /// <summary>The engine version a serialized file or bundle names in its header ("2021.3.5f1").</summary>
    private static string? UnityVersion(ReadOnlySpan<byte> content)
    {
        var head = Encoding.Latin1.GetString(content[..Math.Min(content.Length, 96)]);
        var m = VersionPattern.Match(head);
        return m.Success ? m.Value : null;
    }

    /// <summary>The other files of a WebGL Build folder: the WebAssembly code, the JavaScript framework and loader.</summary>
    private static List<string> Siblings(string location)
    {
        var result = new List<string>();
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(location));
            if (dir == null) return result;
            foreach (var f in Directory.EnumerateFiles(dir).Select(Path.GetFileName).OfType<string>().Order(StringComparer.Ordinal))
            {
                var bare = Regex.Replace(f, @"\.(gz|br|unityweb)$", "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (bare.EndsWith(".wasm", StringComparison.OrdinalIgnoreCase)) result.Add($"{f} (the Il2Cpp code, WebAssembly)");
                else if (bare.EndsWith(".framework.js", StringComparison.OrdinalIgnoreCase)) result.Add($"{f} (the JavaScript framework: Emscripten runtime and imports)");
                else if (bare.EndsWith(".loader.js", StringComparison.OrdinalIgnoreCase)) result.Add($"{f} (the loader)");
                if (result.Count >= 12) break;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return result;
    }
}
