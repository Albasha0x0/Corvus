using System.Buffers.Binary;
using System.Numerics;
using dnlib.DotNet;

namespace Corvus.Core;

/// <summary>The row counts of a metadata tables stream checked against its size, and the module loader that checks them first.</summary>
public static class MetadataRows
{
    // The smallest row of each table (ECMA-335 II.22, portable PDB): every
    // heap, table and coded index at its 2-byte width. Unknown tables are 0.
    private static readonly byte[] MinRow =
    [
        10, 6, 14, 2, 6, 2, 14, 2, 6, 4, 6, 6, 6, 4, 6, 8,
        6, 2, 4, 2, 6, 4, 2, 6, 6, 6, 2, 2, 8, 6, 8, 4,
        22, 4, 12, 20, 6, 14, 8, 14, 12, 4, 8, 4, 4, 0, 0, 0,
        8, 4, 16, 6, 4, 4, 4, 6, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    private static readonly string[] Names =
    [
        "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr",
        "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity", "ClassLayout",
        "FieldLayout", "StandAloneSig", "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
        "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog", "ENCMap",
        "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType",
        "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint", "0x2D", "0x2E", "0x2F",
        "Document", "MethodDebugInformation", "LocalScope", "LocalVariable", "LocalConstant", "ImportScope", "StateMachineMethod", "CustomDebugInformation",
    ];

    /// <summary>Why tables stream <paramref name="stream"/> cannot hold the rows its header declares; null when it can or its header is shorter than 24 bytes.</summary>
    public static string? Check(ReadOnlySpan<byte> stream)
    {
        if (stream.Length < 24) return null;
        ulong valid = BinaryPrimitives.ReadUInt64LittleEndian(stream[8..]);
        // HeapSizes bit 0x40: a 4-byte value follows the row counts.
        long need = 24 + 4L * BitOperations.PopCount(valid) + ((stream[6] & 0x40) != 0 ? 4 : 0);
        if (need > stream.Length) return $"the tables stream header declares {BitOperations.PopCount(valid)} tables; the tables stream holds {stream.Length} bytes";
        int at = 24;
        for (int table = 0; table < 64; table++)
        {
            if ((valid & (1UL << table)) == 0) continue;
            // Only the low 24 bits count, as dnlib and Mono read them.
            uint rows = BinaryPrimitives.ReadUInt32LittleEndian(stream[at..]) & 0x00FFFFFF;
            at += 4;
            need += (long)rows * MinRow[table];
            if (need > stream.Length)
                return $"metadata table {(table < Names.Length ? Names[table] : $"0x{table:X2}")} declares {rows} rows; the tables stream holds {stream.Length} bytes";
        }
        return null;
    }

    /// <summary>
    /// Loads <paramref name="image"/> with dnlib once its tables stream passes
    /// <see cref="Check"/>; otherwise throws BadImageFormatException, as dnlib
    /// does for damaged metadata.
    /// </summary>
    // Workaround: dnlib 4.4.0 to 4.5.0 size the type list by a declared
    // TypeDef count up to 0xFFFFFF, about 60 bytes per row, before reading a
    // row; upstream report pending.
    public static ModuleDefMD Load(byte[] image, ModuleContext? context = null)
    {
        if (MetadataSurvey.TablesStream(image) is { } stream && Check(image.AsSpan(stream.Offset, stream.Length)) is { } problem)
            throw new BadImageFormatException(problem);
        return ModuleDefMD.Load(image, context);
    }
}
