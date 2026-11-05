using System.Buffers.Binary;

namespace Corvus.Native.Pe;

/// <summary>Facts about where data directories sit relative to the sections.</summary>
public static class PeDirectoryFacts
{
    /// <summary>A .reloc section the base relocation directory does not point at, with its entry count.</summary>
    public sealed record OrphanReloc(string Section, uint Rva, long Entries);

    /// <summary>The first .reloc section outside the base relocation directory; null when there is none.</summary>
    public static OrphanReloc? FindOrphanReloc(PeFile pe)
    {
        var dir = pe.Directory(PeDirectory.BaseRelocation);
        foreach (var layout in pe.SectionLayouts)
        {
            var s = layout.Section;
            if (s.Name != ".reloc") continue;
            if (dir.Rva != 0 && dir.Rva >= s.Rva && dir.Rva < (ulong)s.Rva + layout.MappedSize) continue;
            long entries = CountEntries(pe.FileBytes.Span, layout.LoadedFileOffset, layout.LoadedFileSize);
            if (entries > 0) return new OrphanReloc(s.Name, s.Rva, entries);
        }
        return null;
    }

    /// <summary>Entries of the relocation blocks in a byte range, ABSOLUTE padding excluded; the walk stops at a malformed block.</summary>
    private static long CountEntries(ReadOnlySpan<byte> file, long offset, uint length)
    {
        long end = Math.Min(file.Length, offset + length), at = offset, total = 0;
        while (at + 8 <= end)
        {
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(file[(int)(at + 4)..]);
            if (size < 8 || at + size > end) break;
            for (long e = at + 8; e + 2 <= at + size; e += 2)
                if (BinaryPrimitives.ReadUInt16LittleEndian(file[(int)e..]) >> 12 != 0) total++;
            at += size;
        }
        return total;
    }

    /// <summary>The name of the section the exception directory points into when it is not .pdata; null otherwise.</summary>
    public static string? ExceptionSectionIfNotPdata(PeFile pe)
    {
        var dir = pe.Directory(PeDirectory.Exception);
        if (dir.Rva == 0 || dir.Size == 0) return null;
        var s = pe.SectionLayouts.Select(l => l.Section).FirstOrDefault(s => dir.Rva >= s.Rva && dir.Rva < (ulong)s.Rva + Math.Max(s.VirtualSize, 1));
        return s == null || s.Name == ".pdata" ? null : s.Name;
    }
}
