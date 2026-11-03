using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>A section whose memory past its raw data holds bytes the file does not.</summary>
public sealed record RuntimeSection(string Name, uint Rva, uint VirtualSize, uint RawSize, bool IsCode, long WrittenBytes, long UnknownBytes);

/// <summary>Finds sections written at run time.</summary>
public static class RuntimeSections
{
    private const int Page = 0x1000;

    /// <summary>
    /// Sections whose raw data is shorter than their virtual size and whose
    /// memory past the raw data is not all zero, in section order. Bytes in
    /// pages not captured count as unknown, never as zero; a section with only
    /// such bytes is reported with zero written bytes. Empty when none.
    /// </summary>
    public static IReadOnlyList<RuntimeSection> Find(byte[] mapped, CapturedImage captured, PeFile file)
    {
        var found = new List<RuntimeSection>();
        foreach (var s in file.Sections)
        {
            long start = (long)s.Rva + Math.Min(s.RawSize, s.MappedSize);
            long end = Math.Min((long)s.Rva + s.MappedSize, mapped.Length);
            if (s.RawSize >= s.MappedSize || start >= end) continue;
            long written = 0, unknown = 0;
            for (long p = start; p < end;)
            {
                long stop = Math.Min(end, (p / Page + 1) * Page);
                if (!captured.PageCaptured((uint)p)) unknown += stop - p;
                else
                    for (long i = p; i < stop; i++)
                        if (mapped[i] != 0) written++;
                p = stop;
            }
            if (written == 0 && unknown == 0) continue;
            found.Add(new RuntimeSection(s.Name, s.Rva, s.VirtualSize, s.RawSize, DiskCompare.IsCode(s.Characteristics), written, unknown));
        }
        return found;
    }
}
