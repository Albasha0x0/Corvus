using System.Buffers.Binary;
using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.MD;

namespace Corvus.Core;

/// <summary>A structural problem of an assembly's metadata, with where it is.</summary>
public sealed record MetadataIssue(
    [property: Description("Short code: duplicate_stream, unknown_stream, stream_out_of_range, unknown_tables, extra_data_flag, bad_metadata_root, " +
                           "implmap_scope_out_of_range, implmap_name_out_of_range, implmap_member_out_of_range, moduleref_name_out_of_range, " +
                           "bad_table_index, bad_list_index, bad_coded_index, bad_heap_index, decompiler_reader.")] string Code,
    [property: Description("Stream, table and row (token) concerned.")] string Location,
    [property: Description("File offset of the structure, when known (hex).")] string? FileOffset,
    string Detail);

/// <summary>Structural checks of the metadata root and tables header from the file bytes, independent of either reader.</summary>
/// <remarks>The runtime, like dnlib, uses the last of duplicate streams.</remarks>
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

    /// <summary>ImplMap rows with out-of-range columns by rid, which dnlib reads as null without a trace.</summary>
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

    /// <summary>Every bad row found by <see cref="Rows"/> is counted; the first ones are kept.</summary>
    public sealed record RowSweep(int Count, IReadOnlyList<MetadataIssue> Issues);

    /// <summary>Columns whose null (0) value is a broken reference rather than "none".</summary>
    private static readonly HashSet<string> Required = new(StringComparer.Ordinal)
    {
        "MemberRef.Class", "CustomAttribute.Parent", "CustomAttribute.Type", "InterfaceImpl.Class", "InterfaceImpl.Interface",
        "NestedClass.NestedClass", "NestedClass.EnclosingClass", "MethodImpl.Class", "MethodImpl.MethodBody", "MethodImpl.MethodDeclaration",
        "MethodSemantics.Method", "MethodSemantics.Association", "GenericParam.Owner", "GenericParamConstraint.Owner",
        "GenericParamConstraint.Constraint", "MethodSpec.Method", "Constant.Parent", "FieldMarshal.Parent", "DeclSecurity.Parent",
        "ClassLayout.Parent", "FieldLayout.Field", "FieldRVA.Field", "EventMap.Parent", "PropertyMap.Parent",
    };

    /// <summary>Columns that start a run of rows in another table (ECMA-335 II.22): 1..count+1, never decreasing.</summary>
    private static readonly Dictionary<string, (Table Target, Table Pointer)> Lists = new(StringComparer.Ordinal)
    {
        ["TypeDef.FieldList"] = (Table.Field, Table.FieldPtr),
        ["TypeDef.MethodList"] = (Table.Method, Table.MethodPtr),
        ["Method.ParamList"] = (Table.Param, Table.ParamPtr),
        ["EventMap.EventList"] = (Table.Event, Table.EventPtr),
        ["PropertyMap.PropertyList"] = (Table.Property, Table.PropertyPtr),
    };

    /// <summary>One issue per row with an out-of-range column, with its file offset; ImplMap rows excluded. Never throws.</summary>
    /// <remarks>A row the decompiler's reader refuses but this sweep passes gets <see cref="MetadataProbe"/>'s finding.</remarks>
    public static RowSweep Rows(ModuleDefMD module, byte[] image, int max = 200)
    {
        var issues = new List<MetadataIssue>();
        int count = 0;
        var tokens = new HashSet<uint>();
        try
        {
            var md = module.Metadata;
            var t = md.TablesStream;
            uint strings = md.StringsStream?.StreamLength ?? 0;
            uint blobs = md.BlobStream?.StreamLength ?? 0;
            uint guids = (md.GuidStream?.StreamLength ?? 0) / 16;
            uint RowsOf(Table table) => t.Get(table)?.Rows ?? 0;
            foreach (var table in t.MDTables)
            {
                if (table.Rows == 0 || table.Table == Table.ImplMap) continue;
                var columns = table.Columns.Select(c => Classify(table, c)).ToList();
                var previous = new uint[columns.Count];
                for (uint rid = 1; rid <= table.Rows; rid++)
                {
                    (string Text, ColumnInfo Column, Check Check)? first = null;
                    for (int i = 0; i < columns.Count; i++)
                    {
                        var (column, check) = columns[i];
                        if (check == Check.None || !t.TryReadColumn(table, rid, column, out uint value)) continue;
                        var problem = check switch
                        {
                            Check.Strings => value >= strings && value != 0 ? $"#Strings offset 0x{value:X} is past the heap (0x{strings:X} bytes)" : null,
                            Check.Guid => value > guids ? $"#GUID index {value} is past the heap ({guids} GUIDs)" : null,
                            Check.Blob => value == 0 ? null : value >= blobs ? $"#Blob offset 0x{value:X} is past the heap (0x{blobs:X} bytes)"
                                : !md.BlobStream!.TryCreateReader(value, out _) ? $"#Blob entry at 0x{value:X} has an invalid length or runs past the heap" : null,
                            Check.Index => TableIndex(table, column, value, RowsOf),
                            Check.List => ListIndex(table, column, value, previous[i], RowsOf),
                            _ => CodedIndex(table, column, value, RowsOf),
                        };
                        previous[i] = value;
                        if (problem != null) first ??= (problem, column, check);
                    }
                    if (first is not { } bad) continue;
                    uint token = ((uint)table.Table << 24) | rid;
                    tokens.Add(token);
                    if (count++ < max)
                        issues.Add(new(bad.Check switch
                            {
                                Check.Strings or Check.Guid or Check.Blob => "bad_heap_index",
                                Check.List => "bad_list_index",
                                Check.Index => "bad_table_index",
                                _ => "bad_coded_index",
                            },
                            $"{t.Name} {table.Name} row {rid} (token 0x{token:X8}), column {bad.Column.Name}",
                            Hex((long)table.StartOffset + (rid - 1) * table.RowSize), bad.Text));
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            issues.Add(new("bad_metadata_root", "tables stream", null, $"row sweep stopped: {ex.Message}"));
            count++;
        }
        if (Probe(image) is { } probe && !tokens.Any(token => probe.Contains($"0x{token:X8}", StringComparison.Ordinal)))
        {
            issues.Add(new("decompiler_reader", probe.Split(':')[0], null, $"the decompiler's metadata reader refuses it: {probe}"));
            count++;
        }
        return new RowSweep(count, issues);
    }

    private enum Check { None, Strings, Guid, Blob, Index, List, Coded }

    private static (ColumnInfo Column, Check Check) Classify(MDTable table, ColumnInfo c)
    {
        if (Lists.ContainsKey($"{table.Name}.{c.Name}")) return (c, Check.List);
        return c.ColumnSize switch
        {
            ColumnSize.Strings => (c, Check.Strings),
            ColumnSize.GUID => (c, Check.Guid),
            ColumnSize.Blob => (c, Check.Blob),
            ColumnSize.Byte or ColumnSize.Int16 or ColumnSize.UInt16 or ColumnSize.Int32 or ColumnSize.UInt32 => (c, Check.None),
            _ when Enum.TryParse<Table>(c.ColumnSize.ToString(), out _) => (c, Check.Index),
            _ when CodedOf(c.ColumnSize) != null => (c, Check.Coded),
            _ => (c, Check.None),
        };
    }

    private static string? TableIndex(MDTable table, ColumnInfo c, uint value, Func<Table, uint> rowsOf)
    {
        var target = Enum.Parse<Table>(c.ColumnSize.ToString());
        if (value == 0) return Required.Contains($"{table.Name}.{c.Name}") ? $"null {target} reference where one is required" : null;
        uint rows = rowsOf(target);
        return value > rows ? $"{target} row {value} is past the table ({rows} rows)" : null;
    }

    private static string? ListIndex(MDTable table, ColumnInfo c, uint value, uint previous, Func<Table, uint> rowsOf)
    {
        var (target, pointer) = Lists[$"{table.Name}.{c.Name}"];
        uint rows = rowsOf(pointer) is > 0 and var p ? p : rowsOf(target);
        if (value == 0 || value > rows + 1) return $"list start {value} is outside {target} rows 1..{rows + 1}";
        return value < previous ? $"list start {value} is below the previous row's ({previous}): the runs overlap" : null;
    }

    private static string? CodedIndex(MDTable table, ColumnInfo c, uint value, Func<Table, uint> rowsOf)
    {
        var coded = CodedOf(c.ColumnSize)!;
        uint tag = value & ((1u << coded.Bits) - 1);
        uint row = value >> coded.Bits;
        // Row 0 is a null reference whatever the tag.
        if (row == 0) return Required.Contains($"{table.Name}.{c.Name}") ? $"null {c.ColumnSize} reference where one is required" : null;
        // CustomAttributeType defines only tags 2 (MethodDef) and 3 (MemberRef).
        if (tag >= coded.TableTypes.Length || (c.ColumnSize == ColumnSize.CustomAttributeType && tag is not (2 or 3)))
            return $"{c.ColumnSize} tag {tag} is not defined";
        var target = coded.TableTypes[tag];
        uint rows = rowsOf(target);
        return row > rows ? $"{c.ColumnSize} names {target} row {row}, past the table ({rows} rows)" : null;
    }

    private static CodedToken? CodedOf(ColumnSize size) => size switch
    {
        ColumnSize.TypeDefOrRef => CodedToken.TypeDefOrRef,
        ColumnSize.HasConstant => CodedToken.HasConstant,
        ColumnSize.HasCustomAttribute => CodedToken.HasCustomAttribute,
        ColumnSize.HasFieldMarshal => CodedToken.HasFieldMarshal,
        ColumnSize.HasDeclSecurity => CodedToken.HasDeclSecurity,
        ColumnSize.MemberRefParent => CodedToken.MemberRefParent,
        ColumnSize.HasSemantic => CodedToken.HasSemantic,
        ColumnSize.MethodDefOrRef => CodedToken.MethodDefOrRef,
        ColumnSize.MemberForwarded => CodedToken.MemberForwarded,
        ColumnSize.Implementation => CodedToken.Implementation,
        ColumnSize.CustomAttributeType => CodedToken.CustomAttributeType,
        ColumnSize.ResolutionScope => CodedToken.ResolutionScope,
        ColumnSize.TypeOrMethodDef => CodedToken.TypeOrMethodDef,
        ColumnSize.HasCustomDebugInformation => CodedToken.HasCustomDebugInformation,
        _ => null,
    };

    /// <summary>The decompiler reader's first unreadable row (<see cref="MetadataProbe"/>), or why it refuses the metadata.</summary>
    private static string? Probe(byte[] image)
    {
        try
        {
            using var pe = new PEReader(new MemoryStream(image, writable: false));
            return pe.HasMetadata ? MetadataProbe.Problem(System.Reflection.Metadata.PEReaderExtensions.GetMetadataReader(pe)) : null;
        }
        catch (BadImageFormatException ex) { return $"metadata: {ex.Message}"; }
        catch (InvalidOperationException ex) { return $"metadata: {ex.Message}"; }
    }

    internal static string Hex(long offset) => $"0x{offset:X}";

    private static string Show(string name) => name.All(c => c >= 0x20 && c < 0x7F) ? name : string.Concat(name.Select(c => c >= 0x20 && c < 0x7F ? c.ToString() : $"\\x{(int)c:X2}"));
}
