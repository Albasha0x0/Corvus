using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;

namespace Corvus.Native.Pe;

/// <summary>A rich header record: the tool (product id) and build that produced <see cref="Count"/> objects.</summary>
public sealed record PeRichEntry(ushort ProductId, ushort Build, uint Count)
{
    /// <summary>The raw comp id: product id in the high 16 bits, build in the low 16.</summary>
    public uint CompId => (uint)ProductId << 16 | Build;
}

/// <summary>The linker's rich header; <see cref="ChecksumValid"/> is whether its key matches the checksum.</summary>
public sealed record PeRichHeader(long Offset, long EndOffset, uint Key, bool ChecksumValid, IReadOnlyList<PeRichEntry> Entries);

/// <summary>Optional header CheckSum and the value computed over the file (the ImageHlp CheckSumMappedFile algorithm).</summary>
public sealed record PeChecksum(uint Stored, uint Computed)
{
    public bool Matches => Stored == Computed;
}

/// <summary>Bytes after the last section's raw data. <see cref="IsCertificateTableOnly"/>: they are just the Authenticode table.</summary>
public sealed record PeOverlay(long Offset, long Size, bool IsCertificateTableOnly);

public sealed partial class PeFile
{
    private const uint RichSignature = 0x68636952; // "Rich"
    private const uint DansSignature = 0x536E6144; // "DanS"

    /// <summary>Certificate table location from the security directory (a file offset), or null.</summary>
    public (long Offset, long Size)? CertificateTable
    {
        get
        {
            var dir = Directory(PeDirectory.Security);
            return dir.Rva != 0 && dir.Size != 0 ? (dir.Rva, dir.Size) : null;
        }
    }

    private PeRichHeader? ParseRichHeader(IssueLog log)
    {
        int limit = (int)Math.Min(PeHeaderOffset, data.Length);
        int rich = -1;
        for (int at = (limit - 8) & ~3; at >= 0x40; at -= 4)
            if (BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)) == RichSignature)
            {
                rich = at;
                break;
            }
        if (rich < 0) return null;
        uint key = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(rich + 4));
        int dans = -1;
        for (int at = rich - 4; at >= 0x40; at -= 4)
            if ((BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)) ^ key) == DansSignature)
            {
                dans = at;
                break;
            }
        if (dans < 0)
        {
            log.Add("rich header has a 'Rich' marker but no 'DanS' start", rich);
            return null;
        }
        for (int i = 1; i <= 3; i++)
            if (dans + i * 4 < rich && BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(dans + i * 4)) != key)
            {
                log.Add("rich header padding after 'DanS' is not zero", dans);
                break;
            }
        var entries = new List<PeRichEntry>();
        uint checksum = (uint)dans;
        for (int i = 0; i < dans; i++)
            if (i is < 0x3C or >= 0x40) checksum += BitOperations.RotateLeft(data[i], i);
        for (int at = dans + 16; at + 8 <= rich; at += 8)
        {
            if (entries.Count >= PeLimits.MaxRichEntries)
            {
                log.Add($"more than {PeLimits.MaxRichEntries} rich header records; the rest are not read");
                break;
            }
            uint compId = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at)) ^ key;
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(at + 4)) ^ key;
            entries.Add(new PeRichEntry((ushort)(compId >> 16), (ushort)compId, count));
            checksum += BitOperations.RotateLeft(compId, (int)(count & 31));
        }
        if ((rich - dans - 16) % 8 != 0) log.Add("rich header records do not fill whole 8-byte entries", dans);
        bool valid = checksum == key;
        if (!valid) log.Add($"rich header checksum 0x{checksum:X8} does not match the key 0x{key:X8} (edited or forged header)", rich + 4);
        return new PeRichHeader(dans, rich + 8, key, valid, entries);
    }

    /// <summary>The PE checksum as ImageHlp's CheckSumMappedFile computes it.</summary>
    private PeChecksum ComputeChecksum()
    {
        // Summed as 32-bit words: modulo 0xFFFF a word equals the sum of its two halves. 1 GB of words fits in 64 bits.
        ulong sum = 0;
        var words = MemoryMarshal.Cast<byte, uint>(data.AsSpan(0, data.Length & ~3));
        if (BitConverter.IsLittleEndian)
            foreach (var w in words) sum += w;
        else
            foreach (var w in words) sum += BinaryPrimitives.ReverseEndianness(w);
        for (int i = data.Length & ~3; i < data.Length; i++) sum += (ulong)data[i] << (8 * (i & 1));
        while (sum > 0xFFFF) sum = (sum & 0xFFFF) + (sum >> 16);
        long field = OptionalHeaderOffset + 64;
        ushort partial = (ushort)sum;
        foreach (ushort adjust in (ReadOnlySpan<ushort>)[U16(field), U16(field + 2)])
            partial = (ushort)(partial - (partial < adjust ? 1 : 0) - adjust);
        return new PeChecksum(Optional.CheckSum, partial + (uint)data.Length);
    }

    private PeOverlay? FindOverlay()
    {
        long end = Math.Max(Optional.SizeOfHeaders, SectionTableOffset + sections.Count * 40L);
        foreach (var s in sections)
            if (s.RawSize != 0) end = Math.Max(end, (long)s.RawOffset + s.RawSize);
        if (end >= data.Length) return null;
        bool certificateOnly = CertificateTable is var (offset, size) && offset >= end && offset - end < 8 && offset + size == data.Length;
        return new PeOverlay(end, data.Length - end, certificateOnly);
    }
}
