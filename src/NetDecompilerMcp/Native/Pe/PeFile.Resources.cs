using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.Pe;

/// <summary>A resource directory key: a numeric id or a name string.</summary>
public sealed record PeResourceKey(uint Id, string? Name)
{
    public bool IsName => Name != null;
    public override string ToString() => Name ?? "#" + Id;
}

/// <summary>
/// A resource data entry. In the standard three-level tree <see cref="Type"/>, <see cref="Name"/> and
/// <see cref="Language"/> are the levels; <see cref="Path"/> holds every level when the tree is deeper or shallower.
/// </summary>
public sealed record PeResource(PeResourceKey Type, PeResourceKey? Name, uint Language, uint Rva, uint Size, uint CodePage, IReadOnlyList<PeResourceKey> Path)
{
    /// <summary>RT_* name for a numeric type, else the type key.</summary>
    public string TypeName => Type.IsName ? Type.Name! : PeFile.ResourceTypeName(Type.Id);
}

/// <summary>A string of an RT_STRING table: id = (block id - 1) * 16 + index.</summary>
public sealed record PeResourceString(uint Id, uint Language, string Text);

public sealed partial class PeFile
{
    private sealed record ResourceTable(IReadOnlyList<PeResource> Entries, PeVersionInfo? Version, string? Manifest, IReadOnlyList<PeResourceString> Strings)
    {
        public static readonly ResourceTable Empty = new([], null, null, []);
    }

    public const uint RtString = 6, RtVersion = 16, RtManifest = 24;

    public static string ResourceTypeName(uint id) => id switch
    {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        240 => "DLGINIT",
        241 => "TOOLBAR",
        _ => "#" + id,
    };

    /// <summary>Copies the data of <paramref name="resource"/>; null when it is not mapped.</summary>
    public byte[]? ReadResource(PeResource resource, int maxBytes = int.MaxValue)
    {
        int size = (int)Math.Min(resource.Size, (uint)Math.Max(0, maxBytes));
        return ReadBlock(resource.Rva, size);
    }

    /// <summary>
    /// Walks the resource tree depth-first in table order. Each directory is visited once (a second reference, from a
    /// cycle or a shared subtree, is recorded and skipped) and at most <see cref="PeLimits.MaxResourceDepth"/> deep.
    /// </summary>
    private ResourceTable ParseResources(IssueLog log)
    {
        var dir = Directory(PeDirectory.Resource);
        if (dir.Rva == 0) return ResourceTable.Empty;
        var budget = new WorkBudget(log);
        long root = dir.Rva;
        var entries = new List<PeResource>();
        var visited = new HashSet<uint>();
        var path = new List<PeResourceKey>();
        Walk(0, 0);

        PeVersionInfo? version = null;
        string? manifest = null;
        var strings = new List<PeResourceString>();
        foreach (var r in entries)
        {
            if (budget.Exhausted) break;
            if (r.Type.IsName || r.Path.Count != 3) continue;
            if (r.Type.Id == RtVersion && version == null)
            {
                var bytes = ReadResource(r, 0x10000);
                if (bytes == null) log.Add($"version resource at RVA 0x{r.Rva:X} is outside the mapped image");
                else version = PeVersionInfo.Parse(bytes, log);
            }
            else if (r.Type.Id == RtManifest && manifest == null)
            {
                if (r.Size > PeLimits.MaxManifestBytes) log.Add($"manifest of {r.Size} bytes; the first {PeLimits.MaxManifestBytes} are read");
                var bytes = ReadResource(r, PeLimits.MaxManifestBytes);
                if (bytes == null) log.Add($"manifest resource at RVA 0x{r.Rva:X} is outside the mapped image");
                else manifest = DecodeText(bytes);
            }
            else if (r.Type.Id == RtString && r.Name is { IsName: false } block)
                ReadStringBlock(r, block.Id, strings, budget, log);
        }
        return new ResourceTable(entries, version, manifest, strings);

        void Walk(uint offset, int depth)
        {
            if (!budget.Step()) return;
            if (!visited.Add(offset))
            {
                log.Add($"resource directory at offset 0x{offset:X} is referenced again (a cycle or a shared subtree); not walked again", RvaToOffsetOrNull(root + offset));
                return;
            }
            if (visited.Count > PeLimits.MaxResourceDirectories)
            {
                if (visited.Count == PeLimits.MaxResourceDirectories + 1) log.Add($"more than {PeLimits.MaxResourceDirectories} resource directories; the rest are not read");
                return;
            }
            var header = ReadBlock(root + offset, 16);
            if (header == null)
            {
                log.Add($"resource directory at offset 0x{offset:X} is outside the mapped image");
                return;
            }
            int count = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(12)) + BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(14));
            var table = ReadBlock(root + offset + 16, count * 8);
            if (table == null)
            {
                int fit = (int)Math.Min(count, FitCount(root + offset + 16, 8));
                log.Add($"resource directory at offset 0x{offset:X} declares {count} entries; {fit} are mapped");
                table = ReadBlock(root + offset + 16, fit * 8) ?? [];
                count = table.Length / 8;
            }
            for (int i = 0; i < count && !budget.Exhausted; i++)
            {
                if (entries.Count >= PeLimits.MaxResources)
                {
                    if (entries.Count == PeLimits.MaxResources) log.Add($"more than {PeLimits.MaxResources} resources; the rest are not read");
                    return;
                }
                if (!budget.Step()) return;
                uint nameField = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(i * 8));
                uint target = BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(i * 8 + 4));
                var key = (nameField & 0x80000000) != 0
                    ? new PeResourceKey(0, ResourceName(root + (nameField & 0x7FFFFFFF), budget, log))
                    : new PeResourceKey(nameField, null);
                path.Add(key);
                if ((target & 0x80000000) != 0)
                {
                    if (depth + 1 >= PeLimits.MaxResourceDepth)
                        log.Add($"resource tree deeper than {PeLimits.MaxResourceDepth} levels at {string.Join("/", path)}; not walked further");
                    else
                        Walk(target & 0x7FFFFFFF, depth + 1);
                }
                else
                    AddLeaf(target);
                path.RemoveAt(path.Count - 1);
            }
        }

        void AddLeaf(uint offset)
        {
            var d = ReadBlock(root + offset, 16);
            if (d == null)
            {
                log.Add($"resource data entry at offset 0x{offset:X} ({string.Join("/", path)}) is outside the mapped image");
                return;
            }
            uint rva = Le32(d, 0), size = Le32(d, 4), codePage = Le32(d, 8);
            if (size != 0 && !IsMapped(rva, size))
                log.Add($"resource {string.Join("/", path)} data at RVA 0x{rva:X} (0x{size:X} bytes) is not entirely mapped");
            var keys = path.ToArray();
            uint language = keys.Length >= 3 && !keys[2].IsName ? keys[2].Id : 0;
            entries.Add(new PeResource(keys[0], keys.Length >= 2 ? keys[1] : null, language, rva, size, codePage, keys));
        }
    }

    /// <summary>IMAGE_RESOURCE_DIR_STRING_U: a 16-bit length and UTF-16 characters.</summary>
    private string ResourceName(long rva, WorkBudget budget, IssueLog log)
    {
        if (!TryU16(rva, out ushort length))
        {
            log.Add($"resource name at RVA 0x{rva:X} is outside the mapped image");
            return $"<unreadable 0x{rva:X}>";
        }
        if (!budget.Chars(length)) return "";
        var chars = ReadBlock(rva + 2, length * 2);
        if (chars == null)
        {
            log.Add($"resource name at RVA 0x{rva:X} ({length} characters) runs out of the mapped image");
            return $"<unreadable 0x{rva:X}>";
        }
        return Encoding.Unicode.GetString(chars);
    }

    /// <summary>An RT_STRING block: 16 strings, each a 16-bit length and UTF-16 characters; empty ones are skipped.</summary>
    private void ReadStringBlock(PeResource r, uint blockId, List<PeResourceString> strings, WorkBudget budget, IssueLog log)
    {
        if (blockId == 0 || blockId > 4096)
        {
            log.Add($"string table block id {blockId} is outside 1-4096");
            return;
        }
        // Read string by string: the declared size is not trusted for an allocation.
        long at = r.Rva, end = (long)r.Rva + r.Size;
        for (uint i = 0; i < 16; i++)
        {
            if (!budget.Step()) return;
            if (at + 2 > end || !TryU16(at, out ushort length))
            {
                log.Add($"string table {blockId} (language {r.Language}) ends after {i} of 16 strings");
                return;
            }
            at += 2;
            int available = (int)Math.Min(length, (end - at) / 2);
            if (available < length) log.Add($"string {(blockId - 1) * 16 + i} of table {blockId} runs past the resource data; cut");
            if (available > 0)
            {
                if (strings.Count >= PeLimits.MaxStringTableEntries || !budget.Chars(available)) return;
                var chars = ReadBlock(at, available * 2);
                if (chars == null)
                {
                    log.Add($"string table {blockId} at RVA 0x{r.Rva:X} is outside the mapped image");
                    return;
                }
                strings.Add(new PeResourceString((blockId - 1) * 16 + i, r.Language, Encoding.Unicode.GetString(chars)));
            }
            at += available * 2L;
        }
    }

    /// <summary>Text with a UTF-8 or UTF-16 byte order mark, else UTF-8; trailing NULs dropped.</summary>
    private static string DecodeText(byte[] bytes)
    {
        string text;
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) text = Encoding.Unicode.GetString(bytes, 2, (bytes.Length - 2) & ~1);
        else if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF) text = Encoding.BigEndianUnicode.GetString(bytes, 2, (bytes.Length - 2) & ~1);
        else if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) text = Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
        else text = Encoding.UTF8.GetString(bytes);
        return text.TrimEnd('\0');
    }
}
