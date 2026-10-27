using System.Buffers.Binary;
using System.Text;

namespace Corvus.Native;

/// <summary>The Windows API set map (version 6) from apisetschema.dll: virtual DLL names and their host DLLs.</summary>
public sealed class ApiSetSchema
{
    private const int MaxEntries = 20_000;
    private readonly Dictionary<string, (string Default, Dictionary<string, string> ByImporter)> _entries;

    private ApiSetSchema(Dictionary<string, (string, Dictionary<string, string>)> entries) => _entries = entries;

    public int Count => _entries.Count;

    /// <summary>True for names the loader resolves through the API set map (api-* and ext-* prefixes).</summary>
    public static bool IsApiSetName(string module)
    {
        var m = module.Trim();
        return m.StartsWith("api-", StringComparison.OrdinalIgnoreCase) || m.StartsWith("ext-", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The host DLL for <paramref name="module"/> as imported by <paramref name="importer"/>; null when unmapped or hostless.</summary>
    public string? Resolve(string module, string? importer = null)
    {
        var key = Key(module);
        // Entries match on the name up to its last hyphen, so any minor version of a contract resolves.
        if (!_entries.TryGetValue(key, out var entry)) return null;
        if (importer != null && entry.ByImporter.TryGetValue(Path.GetFileName(importer), out var specific))
            return specific.Length > 0 ? specific : null;
        return entry.Default.Length > 0 ? entry.Default : null;
    }

    private static string Key(string module)
    {
        var name = module.Trim();
        if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) name = name[..^4];
        int dash = name.LastIndexOf('-');
        return (dash > 0 ? name[..dash] : name).ToLowerInvariant();
    }

    /// <summary>Reads the map from the system's apisetschema.dll; null when it is absent or not a version 6 map.</summary>
    public static ApiSetSchema? FromSystem(Func<string, INativeImage> open)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "apisetschema.dll");
        if (!File.Exists(path)) return null;
        try { return FromImage(open(path)); }
        catch (Core.ToolError) { return null; }
    }

    public static ApiSetSchema? FromImage(INativeImage image)
    {
        var section = image.Sections.FirstOrDefault(s => s.Name == ".apiset");
        if (section == null || section.MappedSize < 28) return null;
        var data = new byte[Math.Min(section.MappedSize, 16u << 20)];
        int read = image.Read(section.Rva, data);
        return Parse(data.AsSpan(0, read));
    }

    /// <summary>Parses an API_SET_NAMESPACE (version 6) blob; null when it is not one.</summary>
    public static ApiSetSchema? Parse(ReadOnlySpan<byte> map)
    {
        if (map.Length < 28 || U32(map, 0) != 6) return null;
        uint count = U32(map, 12), entryOffset = U32(map, 16);
        if (count > MaxEntries || entryOffset > map.Length || (ulong)count * 24 > (ulong)(map.Length - entryOffset)) return null;
        var entries = new Dictionary<string, (string, Dictionary<string, string>)>();
        for (uint i = 0; i < count; i++)
        {
            int e = (int)(entryOffset + i * 24);
            var name = Utf16(map, U32(map, e + 4), U32(map, e + 8));
            uint hashed = U32(map, e + 12), valueOffset = U32(map, e + 16), valueCount = U32(map, e + 20);
            if (name == null || hashed > (ulong)name.Length * 2 || valueCount > 64) continue;
            string def = "";
            var byImporter = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (uint v = 0; v < valueCount; v++)
            {
                long at = valueOffset + (long)v * 20;
                if (at + 20 > map.Length) break;
                var importer = Utf16(map, U32(map, (int)at + 4), U32(map, (int)at + 8)) ?? "";
                var host = Utf16(map, U32(map, (int)at + 12), U32(map, (int)at + 16)) ?? "";
                if (importer.Length == 0) def = host;
                else byImporter[importer] = host;
            }
            // Key on the hashed prefix: the name up to (excluding) its last hyphen.
            entries[name[..(int)(hashed / 2)].ToLowerInvariant()] = (def, byImporter);
        }
        return new ApiSetSchema(entries);
    }

    private static uint U32(ReadOnlySpan<byte> s, int offset) =>
        offset >= 0 && offset <= s.Length - 4 ? BinaryPrimitives.ReadUInt32LittleEndian(s[offset..]) : 0;

    private static string? Utf16(ReadOnlySpan<byte> s, uint offset, uint length) =>
        length == 0 ? "" : length > 1024 || (length & 1) != 0 || offset > s.Length || length > s.Length - offset ? null
            : Encoding.Unicode.GetString(s.Slice((int)offset, (int)length));
}
