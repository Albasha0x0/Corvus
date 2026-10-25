using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// A Godot resource pack (.pck, or embedded at the end of an exported executable): "GDPC", the pack format version, the
/// engine version, then the file directory (path, offset, size, MD5 per file). Format 1 (Godot 3) has absolute offsets;
/// format 2 (Godot 4.0-4.3) adds pack flags, a file base and per-file flags; format 3 and later place the directory at an offset.
/// </summary>
public static class GodotPack
{
    public const string Kind = "Godot resource pack (PCK)";
    private const uint Magic = 0x43504447; // "GDPC"
    private const uint DirEncrypted = 1, RelativeFileBase = 2, FileEncrypted = 1, FileRemoval = 2;
    private const int MaxFiles = 1_000_000, MaxPath = 4096;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 4 && BinaryPrimitives.ReadUInt32LittleEndian(b) == Magic;

    /// <summary>Where a pack embedded in an executable starts: the file ends with the pack's size and "GDPC". Null when none is.</summary>
    public static long? Embedded(ReadOnlySpan<byte> b)
    {
        if (b.Length < 12 + 4 || BinaryPrimitives.ReadUInt32LittleEndian(b[^4..]) != Magic) return null;
        ulong size = BinaryPrimitives.ReadUInt64LittleEndian(b[^12..]);
        if (size > (ulong)(b.Length - 12)) return null;
        long start = b.Length - 12 - (long)size;
        return Looks(b[(int)start..]) ? start : null;
    }

    public static ContainerContents Open(byte[] data, long start, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        var pack = data.AsSpan((int)start);
        if (pack.Length < 20 + 64) throw new ToolError(ErrorCode.MalformedInput, $"{name}: truncated Godot pack header.");
        uint format = U32(pack, 4), major = U32(pack, 8), minor = U32(pack, 12), patch = U32(pack, 16);
        if (format is 0 or > 16) throw new ToolError(ErrorCode.MalformedInput, $"{name}: unknown Godot pack format {format}.");
        uint flags = 0;
        // Format 1 offsets are file offsets, also in a pack embedded after an executable.
        long fileBase = 0, at = 20;
        if (format >= 2)
        {
            flags = U32(pack, 20);
            ulong rawBase = U64(pack, 24);
            at = 32;
            if (format >= 3)
            {
                ulong dir = U64(pack, 32);
                if (dir > (ulong)pack.Length) throw new ToolError(ErrorCode.MalformedInput, $"{name}: the directory offset 0x{dir:X} lies past the pack.");
                at = (long)dir;
            }
            else at += 64; // reserved
            fileBase = (flags & RelativeFileBase) != 0 ? start + (long)Math.Min(rawBase, (ulong)data.Length) : (long)Math.Min(rawBase, (ulong)data.Length);
        }
        else at += 64;
        string engine = $"Godot {major}.{minor}.{patch}";
        if ((flags & DirEncrypted) != 0)
        {
            notes.Add($"Godot pack format {format}, {engine}: the directory is encrypted (the export's encryption key opens it); no files listed.");
            return new ContainerContents(Kind, items, notes) { Entries = entries };
        }
        if (at + 4 > pack.Length) throw new ToolError(ErrorCode.MalformedInput, $"{name}: truncated Godot pack directory.");
        uint count = U32(pack, (int)at);
        at += 4;
        int bad = 0, encrypted = 0, removed = 0, refused = 0;
        long total = 0;
        var roles = new Dictionary<string, int>();
        for (uint i = 0; i < count && i < MaxFiles; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (at + 4 > pack.Length) { notes.Add($"The directory ends after {i:N0} of {count:N0} files."); break; }
            uint length = U32(pack, (int)at);
            int entry = format >= 2 ? 36 : 32;
            if (length > MaxPath || at + 4 + length + entry > pack.Length) { notes.Add($"Directory entry {i:N0} runs past the pack; the listing stops there."); break; }
            var path = Encoding.UTF8.GetString(pack.Slice((int)at + 4, (int)length)).TrimEnd('\0');
            at += 4 + length;
            ulong offset = U64(pack, (int)at), size = U64(pack, (int)at + 8);
            uint fileFlags = format >= 2 ? U32(pack, (int)at + 32) : 0;
            at += entry;
            path = path.StartsWith("res://", StringComparison.Ordinal) ? path[6..] : path;
            long from = fileBase + (long)Math.Min(offset, (ulong)data.Length);
            if ((fileFlags & FileRemoval) != 0) { removed++; entries.Add(new ContainerEntry(path, 0, "removal (a patch pack deletes it)")); continue; }
            if (offset > (ulong)data.Length || from > data.Length || size > (ulong)(data.Length - from))
            {
                if (bad++ < 3) notes.Add($"{path}: data (offset {offset}, size {size}) lies outside the file.");
                entries.Add(new ContainerEntry(path, (long)Math.Min(size, long.MaxValue), "out of range"));
                continue;
            }
            var content = data.AsSpan((int)from, (int)size);
            bool isEncrypted = (fileFlags & FileEncrypted) != 0;
            var role = isEncrypted ? "encrypted" : Role(path, content);
            if (isEncrypted) encrypted++;
            roles[role] = roles.GetValueOrDefault(role) + 1;
            bool unsafeName = path.Split('/').Any(AsarArchive.IsUnsafeName);
            entries.Add(new ContainerEntry(path, (long)size, unsafeName ? role + ", unsafe name" : role));
            if (!(allFiles || Containers.IsInteresting(path))) continue;
            if (unsafeName) { refused++; continue; }
            if (items.Count >= limits.MaxItems || (total += (long)size) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
            items.Add(new ExtractedItem(path, content.ToArray(), $"Godot pack entry ({role})"));
        }
        if (bad > 3) notes.Add($"{bad - 3} more entries lie outside the file.");
        if (encrypted > 0) notes.Add($"{encrypted} file(s) are encrypted (the export's encryption key opens them).");
        if (removed > 0) notes.Add($"{removed} entr(ies) mark files a patch pack removes.");
        if (refused > 0) notes.Add($"{refused} entr(ies) with unsafe names not extracted.");
        notes.Insert(0, $"Godot pack format {format}, {engine}{(start > 0 ? $", embedded at 0x{start:X}" : "")}: {entries.Count:N0} file(s)" +
                        (roles.Count > 0 ? " (" + string.Join(", ", roles.OrderByDescending(r => r.Value).ThenBy(r => r.Key, StringComparer.Ordinal).Take(6).Select(r => $"{r.Value} {r.Key}")) + ")" : "") + ".");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>What an entry is, from its name and first bytes.</summary>
    private static string Role(string path, ReadOnlySpan<byte> content)
    {
        if (content.StartsWith("RSCC"u8)) return "compressed resource";
        if (content.StartsWith("RSRC"u8)) return "binary resource";
        if (content.StartsWith("GST2"u8) || content.StartsWith("GDST"u8)) return "texture";
        if (content.StartsWith("ECFG"u8)) return "project settings";
        if (content.StartsWith("GDSC"u8)) return "compiled GDScript";
        var name = Path.GetFileName(path);
        if (name.EndsWith(".gd", StringComparison.Ordinal)) return "GDScript";
        if (name.EndsWith(".remap", StringComparison.Ordinal) || name.EndsWith(".import", StringComparison.Ordinal)) return "import map";
        if (name.EndsWith(".tscn", StringComparison.Ordinal) || name.EndsWith(".tres", StringComparison.Ordinal)) return "text resource";
        if (name == "uid_cache.bin") return "UID cache";
        if (name.EndsWith(".cfg", StringComparison.Ordinal)) return "config";
        return Blob.Identify(content);
    }

    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
    private static ulong U64(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt64LittleEndian(b[at..]);
}
