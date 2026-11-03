using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One export address table entry of a mapped image: the export and its RVA in memory and in the file.</summary>
/// <param name="EntryRva">RVA of the 4-byte entry.</param>
/// <param name="Export">Export name, or <c>#ordinal</c> for an export without a name.</param>
/// <param name="MemoryRva">RVA the entry holds in memory.</param>
/// <param name="FileRva">RVA the entry holds in the file; null when the file does not cover it.</param>
public sealed record ExportTableEntry(uint EntryRva, string Export, uint MemoryRva, uint? FileRva);

/// <summary>Finds the export address table entries a changed range of a mapped image covers.</summary>
public static class ExportTableEntries
{
    private const int MaxNameBytes = PeLimits.MaxNameLength;

    /// <summary>
    /// Lists the entries of the export address table of <paramref name="mapped"/> that overlap the range at
    /// <paramref name="rva"/> of <paramref name="length"/> bytes, with the RVA each holds in memory and in <paramref name="disk"/>.
    /// Empty when the image has no export directory or the range lies outside the table.
    /// </summary>
    public static IReadOnlyList<ExportTableEntry> Covering(byte[] mapped, PeFile disk, uint rva, int length)
    {
        List<ExportTableEntry> entries = [];
        if (!PeImportRestore.TryDirectory(mapped, out bool is64, out _, out _)) return entries;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(mapped.AsSpan(0x3C));
        int dirs = nt + 24 + (is64 ? 112 : 96);
        if (dirs + 8 > mapped.Length) return entries;
        long dir = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(dirs));
        if (dir == 0 || dir + 40 > mapped.Length) return entries;

        uint ordinalBase = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 16));
        uint functionCount = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 20));
        uint nameCount = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 24));
        long functions = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 28));
        long names = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 32));
        long ordinals = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)dir + 36));
        if (functions + 4L * functionCount > mapped.Length || names + 4L * nameCount > mapped.Length
            || ordinals + 2L * nameCount > mapped.Length) return entries;

        long first = Math.Max(0, ((long)rva - functions) / 4), last = Math.Min(functionCount - 1L, ((long)rva + length - 1 - functions) / 4);
        if ((long)rva + length <= functions) return entries;
        var onDisk = new byte[4];
        for (long i = first; i <= last; i++)
        {
            string? name = null;
            for (int n = 0; n < nameCount && name is null; n++)
                if (BinaryPrimitives.ReadUInt16LittleEndian(mapped.AsSpan((int)ordinals + 2 * n)) == i)
                    name = ReadName(mapped, BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)names + 4 * n)));
            uint entry = (uint)(functions + 4 * i);
            entries.Add(new ExportTableEntry(entry, name ?? $"#{ordinalBase + (uint)i}", BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)entry)),
                disk.Read(entry, onDisk) == 4 ? BinaryPrimitives.ReadUInt32LittleEndian(onDisk) : null));
        }
        return entries;
    }

    private static string? ReadName(byte[] image, uint rva)
    {
        if (rva >= image.Length) return null;
        var span = image.AsSpan((int)rva, (int)Math.Min(MaxNameBytes, image.Length - rva));
        int end = span.IndexOf((byte)0);
        return end < 0 ? null : Encoding.ASCII.GetString(span[..end]);
    }
}
