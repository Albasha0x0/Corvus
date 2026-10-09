using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.Pe;

/// <summary>IMAGE_DEBUG_DIRECTORY.</summary>
public sealed record PeDebugEntry(
    uint Type,
    string TypeName,
    uint Characteristics,
    uint TimeDateStamp,
    ushort MajorVersion,
    ushort MinorVersion,
    uint SizeOfData,
    uint AddressOfRawData,
    uint PointerToRawData);

/// <summary>
/// A CodeView debug record: "RSDS" (PDB 7.0: GUID, age, path) or "NB10" (PDB 2.0: <see cref="Timestamp"/>, age, path;
/// <see cref="Guid"/> empty).
/// </summary>
public sealed record PeCodeView(string Format, Guid Guid, uint Age, string PdbPath, uint Timestamp = 0);

public sealed partial class PeFile
{
    private sealed record DebugInfo(IReadOnlyList<PeDebugEntry> Entries, PeCodeView? CodeView, uint ExDllCharacteristics)
    {
        public static readonly DebugInfo Empty = new([], null, 0);
    }

    public static string DebugTypeName(uint type) => type switch
    {
        0 => "UNKNOWN",
        1 => "COFF",
        2 => "CODEVIEW",
        3 => "FPO",
        4 => "MISC",
        5 => "EXCEPTION",
        6 => "FIXUP",
        7 => "OMAP_TO_SRC",
        8 => "OMAP_FROM_SRC",
        9 => "BORLAND",
        10 => "RESERVED10",
        11 => "CLSID",
        12 => "VC_FEATURE",
        13 => "POGO",
        14 => "ILTCG",
        15 => "MPX",
        16 => "REPRO",
        17 => "EMBEDDED_PORTABLE_PDB",
        18 => "SPGO",
        19 => "PDBCHECKSUM",
        20 => "EX_DLLCHARACTERISTICS",
        _ => type.ToString(),
    };

    private DebugInfo ParseDebug(IssueLog log)
    {
        var dir = Directory(PeDirectory.Debug);
        if (dir.Rva == 0 || dir.Size == 0) return DebugInfo.Empty;
        long count = dir.Size / 28;
        if (dir.Size % 28 != 0) log.Add($"debug directory size 0x{dir.Size:X} is not a multiple of 28");
        if (count > PeLimits.MaxDebugEntries)
        {
            log.Add($"{count} debug entries declared; the first {PeLimits.MaxDebugEntries} are read");
            count = PeLimits.MaxDebugEntries;
        }
        var entries = new List<PeDebugEntry>();
        PeCodeView? codeView = null;
        uint exDll = 0;
        for (int i = 0; i < count; i++)
        {
            long at = dir.Rva + i * 28L;
            var d = ReadBlock(at, 28);
            if (d == null)
            {
                log.Add($"debug entry at RVA 0x{at:X} is outside the mapped image", RvaToOffsetOrNull(at));
                break;
            }
            uint type = Le32(d, 12);
            var entry = new PeDebugEntry(type, DebugTypeName(type), Le32(d, 0), Le32(d, 4), Le16(d, 8), Le16(d, 10), Le32(d, 16), Le32(d, 20), Le32(d, 24));
            entries.Add(entry);
            if (type == 2 && codeView == null)
            {
                var body = DebugData(entry, 24 + PeLimits.MaxNameLength, log);
                if (body != null) codeView = ParseCodeView(body, log);
            }
            else if (type == 20)
            {
                var body = DebugData(entry, 4, log);
                if (body is { Length: >= 4 }) exDll = BinaryPrimitives.ReadUInt32LittleEndian(body);
            }
        }
        return new DebugInfo(entries, codeView, exDll);
    }

    /// <summary>Up to <paramref name="max"/> bytes of an entry's data, from its file pointer or else its RVA.</summary>
    private byte[]? DebugData(PeDebugEntry entry, int max, IssueLog log)
    {
        int size = (int)Math.Min(entry.SizeOfData, (uint)max);
        if (entry.PointerToRawData != 0)
        {
            if ((long)entry.PointerToRawData + size <= data.Length) return data.AsSpan((int)entry.PointerToRawData, size).ToArray();
            log.Add($"{entry.TypeName} debug data at file offset 0x{entry.PointerToRawData:X} (0x{entry.SizeOfData:X} bytes) extends past the end of the file", entry.PointerToRawData);
        }
        if (entry.AddressOfRawData != 0)
        {
            var block = ReadBlock(entry.AddressOfRawData, size);
            if (block != null) return block;
            log.Add($"{entry.TypeName} debug data at RVA 0x{entry.AddressOfRawData:X} is outside the mapped image");
        }
        return null;
    }

    private static PeCodeView? ParseCodeView(byte[] body, IssueLog log)
    {
        if (body.Length < 4) return null;
        uint signature = BinaryPrimitives.ReadUInt32LittleEndian(body);
        if (signature == 0x53445352 && body.Length >= 24) // "RSDS"
            return new PeCodeView("RSDS", new Guid(body.AsSpan(4, 16)), BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(20)), PdbPathAt(body, 24));
        if (signature == 0x3031424E && body.Length >= 16) // "NB10"
            return new PeCodeView("NB10", Guid.Empty, BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(12)), PdbPathAt(body, 16),
                BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8)));
        log.Add($"CodeView record with unknown signature 0x{signature:X8}");
        return null;

        static string PdbPathAt(byte[] b, int at)
        {
            var rest = b.AsSpan(at);
            int len = rest.IndexOf((byte)0);
            return Encoding.UTF8.GetString(len < 0 ? rest : rest[..len]);
        }
    }
}
