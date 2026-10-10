using System.Buffers.Binary;
using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Text;
using dnlib.DotNet;

namespace NetDecompilerMcp.Core;

/// <summary>A structural problem of an assembly's metadata, with where it is.</summary>
public sealed record MetadataIssue(
    [property: Description("Short code: duplicate_stream, unknown_stream, stream_out_of_range, unknown_tables, extra_data_flag, bad_metadata_root, " +
                           "implmap_scope_out_of_range, implmap_name_out_of_range, implmap_member_out_of_range, moduleref_name_out_of_range.")] string Code,
    [property: Description("Stream, table and row (token) concerned.")] string Location,
    [property: Description("File offset of the structure, when known (hex).")] string? FileOffset,
    string Detail);

/// <summary>
/// Structural checks of the metadata root and the tables stream header straight from the file bytes, independent of
/// dnlib and System.Reflection.Metadata (which either read malformed metadata silently or refuse it without saying
/// where). Obfuscators produce these on purpose: duplicate or bogus streams, Valid bits for tables that do not exist,
/// the extra-data flag. The runtime, like dnlib, uses the last of duplicate streams.
/// </summary>
public static class MetadataSurvey
{
    private const int MaxIssues = 64;

    private static readonly HashSet<string> KnownStreams = new(StringComparer.Ordinal) { "#~", "#-", "#Strings", "#US", "#GUID", "#Blob", "#Pdb", "#JTD", "#Schema" };

    /// <summary>Tables defined by ECMA-335 (0x00-0x2C) and portable PDB (0x30-0x37).</summary>
    private const ulong KnownTables = (1UL << 0x2D) - 1 | 0xFFUL << 0x30;

    public static IReadOnlyList<MetadataIssue> Survey(byte[] image)
    {
        var issues = new List<MetadataIssue>();
        int mdStart, mdSize;
        try
        {
            var headers = new PEHeaders(new MemoryStream(image, writable: false));
            if (headers.CorHeader == null || headers.MetadataStartOffset < 0) return issues;
            mdStart = headers.MetadataStartOffset;
            mdSize = headers.MetadataSize;
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidOperationException or ArgumentException or IOException)
        {
            return issues;
        }
        if (mdStart < 0 || mdSize < 20 || mdStart > image.Length - mdSize)
        {
            issues.Add(new("bad_metadata_root", "metadata root", Hex(mdStart), $"metadata directory (size {mdSize}) lies outside the file ({image.Length} bytes)"));
            return issues;
        }
        var md = image.AsSpan(mdStart, mdSize);
        if (BinaryPrimitives.ReadUInt32LittleEndian(md) != 0x424A5342)
        {
            issues.Add(new("bad_metadata_root", "metadata root", Hex(mdStart), "no BSJB signature"));
            return issues;
        }
        int versionLength = BinaryPrimitives.ReadInt32LittleEndian(md[12..]);
        int at = 16 + versionLength;
        if (versionLength < 0 || at + 4 > md.Length)
        {
            issues.Add(new("bad_metadata_root", "metadata root", Hex(mdStart + 12), $"version string length {versionLength} runs past the metadata"));
            return issues;
        }
        int count = BinaryPrimitives.ReadUInt16LittleEndian(md[(at + 2)..]);
        at += 4;
        var streams = new List<(string Name, int Offset, int Size, int HeaderAt)>();
        for (int i = 0; i < count && issues.Count < MaxIssues; i++)
        {
            if (at + 8 > md.Length)
            {
                issues.Add(new("bad_metadata_root", $"stream header {i}", Hex(mdStart + at), $"{count} stream headers declared, the metadata ends after {i}"));
                break;
            }
            int offset = BinaryPrimitives.ReadInt32LittleEndian(md[at..]);
            int size = BinaryPrimitives.ReadInt32LittleEndian(md[(at + 4)..]);
            var rest = md[(at + 8)..];
            int nameLength = rest[..Math.Min(rest.Length, 32)].IndexOf((byte)0);
            if (nameLength < 0)
            {
                issues.Add(new("bad_metadata_root", $"stream header {i}", Hex(mdStart + at), "stream name is not terminated within 32 bytes"));
                break;
            }
            var name = Encoding.Latin1.GetString(rest[..nameLength]);
            streams.Add((name, offset, size, at));
            if ((uint)offset > (uint)mdSize || (uint)size > (uint)(mdSize - offset))
                issues.Add(new("stream_out_of_range", $"stream {Show(name)} (header {i})", Hex(mdStart + at),
                    $"offset 0x{offset:X} size 0x{size:X} runs past the metadata (0x{mdSize:X} bytes)"));
            if (!KnownStreams.Contains(name))
                issues.Add(new("unknown_stream", $"stream {Show(name)} (header {i})", Hex(mdStart + at),
                    $"not a stream the runtime reads ({size} bytes at metadata offset 0x{offset:X}); ignored"));
            at += 8 + ((nameLength + 4) & ~3);
        }
        foreach (var group in streams.Select((s, i) => (s, i)).GroupBy(x => x.s.Name).Where(g => g.Count() > 1 && KnownStreams.Contains(g.Key)))
        {
            var list = group.ToList();
            issues.Add(new("duplicate_stream", $"stream {group.Key} (headers {string.Join(", ", list.Select(x => x.i))})",
                Hex(mdStart + list[^1].s.HeaderAt),
                $"{list.Count} streams named {group.Key} (at file offsets {string.Join(", ", list.Select(x => Hex(mdStart + x.s.Offset)))}); " +
                $"the runtime and this tool use the last one, other readers may use the first"));
        }

        // The tables stream in use: the last #~ or #-.
        var tables = streams.LastOrDefault(s => s.Name is "#~" or "#-");
        if (tables.Name != null && (uint)tables.Offset <= (uint)mdSize && tables.Size >= 24 && (uint)tables.Size <= (uint)(mdSize - tables.Offset))
        {
            var t = md.Slice(tables.Offset, tables.Size);
            byte heapSizes = t[6];
            ulong valid = BinaryPrimitives.ReadUInt64LittleEndian(t[8..]);
            int fileAt = mdStart + tables.Offset;
            if ((valid & ~KnownTables) is var unknown and not 0)
                issues.Add(new("unknown_tables", $"stream {tables.Name} header, Valid mask", Hex(fileAt + 8),
                    $"Valid bits set for tables that do not exist: {string.Join(", ", Enumerable.Range(0, 64).Where(b => (unknown & (1UL << b)) != 0).Select(b => $"0x{b:X2}"))} " +
                    $"(mask 0x{valid:X16}); their row counts are skipped"));
            if ((heapSizes & 0x40) != 0)
            {
                int rows = System.Numerics.BitOperations.PopCount(valid);
                int extraAt = 24 + rows * 4;
                string value = extraAt + 4 <= t.Length ? $"0x{BinaryPrimitives.ReadUInt32LittleEndian(t[extraAt..]):X8}" : "(past the stream)";
                issues.Add(new("extra_data_flag", $"stream {tables.Name} header, HeapSizes", Hex(fileAt + 6),
                    $"HeapSizes flag 0x40 set: an extra 4-byte value {value} follows the row counts (at {Hex(fileAt + extraAt)})"));
            }
        }
        return issues;
    }

    /// <summary>
    /// ImplMap rows whose columns point outside their target (ModuleRef row, #Strings heap, MethodDef row), by ImplMap
    /// rid. dnlib reads such columns as null or empty without a trace, so P/Invoke names would silently come out wrong.
    /// </summary>
    public static Dictionary<uint, MetadataIssue> ImplMapRows(ModuleDefMD module)
    {
        var byRid = new Dictionary<uint, MetadataIssue>();
        var md = module.Metadata;
        var tables = md.TablesStream;
        var implMap = tables.ImplMapTable;
        uint stringsSize = md.StringsStream?.StreamLength ?? 0;
        uint moduleRefs = tables.ModuleRefTable.Rows;
        string streamName = tables.Name;
        for (uint rid = 1; rid <= implMap.Rows && byRid.Count < 256; rid++)
        {
            if (!tables.TryReadImplMapRow(rid, out var row)) continue;
            string location = $"{streamName} ImplMap row {rid} (token 0x{0x1C000000 | rid:X8})";
            string offset = Hex((long)implMap.StartOffset + (rid - 1) * implMap.RowSize);
            MetadataIssue? issue = null;
            if (row.ImportScope == 0 || row.ImportScope > moduleRefs)
                issue = new("implmap_scope_out_of_range", location, offset, $"ImportScope {row.ImportScope} is outside the ModuleRef table ({moduleRefs} rows)");
            else if (row.ImportName >= stringsSize)
                issue = new("implmap_name_out_of_range", location, offset, $"ImportName 0x{row.ImportName:X} is outside the #Strings heap (0x{stringsSize:X} bytes)");
            else if (tables.TryReadModuleRefRow(row.ImportScope, out var modRef) && modRef.Name >= stringsSize)
                issue = new("moduleref_name_out_of_range", $"{streamName} ModuleRef row {row.ImportScope} (token 0x{0x1A000000 | row.ImportScope:X8}), used by ImplMap row {rid}",
                    Hex((long)tables.ModuleRefTable.StartOffset + (row.ImportScope - 1) * tables.ModuleRefTable.RowSize),
                    $"Name 0x{modRef.Name:X} is outside the #Strings heap (0x{stringsSize:X} bytes)");
            else if ((row.MemberForwarded & 1) == 1 && (row.MemberForwarded >> 1 == 0 || row.MemberForwarded >> 1 > tables.MethodTable.Rows))
                issue = new("implmap_member_out_of_range", location, offset, $"MemberForwarded names MethodDef row {row.MemberForwarded >> 1}, outside the table ({tables.MethodTable.Rows} rows)");
            if (issue != null) byRid[rid] = issue;
        }
        return byRid;
    }

    internal static string Hex(long offset) => $"0x{offset:X}";

    private static string Show(string name) => name.All(c => c >= 0x20 && c < 0x7F) ? name : string.Concat(name.Select(c => c >= 0x20 && c < 0x7F ? c.ToString() : $"\\x{(int)c:X2}"));
}
