using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Marks sections executable when their captured pages were executable in memory.</summary>
public static class PeExecutableSections
{
    private const uint Execute = 0x20000000, Code = 0x20, UninitializedData = 0x80;
    private const int Page = 0x1000;

    /// <summary>
    /// Sets execute and code on each section of the mapped <paramref name="image"/> that has a captured page in an
    /// executable region, and returns how many it changed. Sections already executable, with no executable page, or
    /// whose protection is unknown are unchanged; a malformed section table returns 0.
    /// </summary>
    public static int Mark(byte[] image, CapturedImage captured, IProcessMemory memory)
    {
        if (image.Length < 0x40) return 0;
        long coff = (long)BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C)) + 4;
        if (coff + 20 > image.Length) return 0;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)coff + 2));
        long table = coff + 20 + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)coff + 16));
        if (count > Pe.PeLimits.MaxSections || table + 40L * count > image.Length) return 0;
        int marked = 0;
        for (int i = 0; i < count; i++)
        {
            var h = image.AsSpan((int)table + 40 * i, 40);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(h[36..]);
            if ((flags & Execute) != 0) continue;
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]);
            if (size == 0) size = BinaryPrimitives.ReadUInt32LittleEndian(h[16..]);
            if (!HasExecutablePage(captured, memory, va, Math.Min((long)size, Math.Max(0, image.Length - (long)va)))) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(h[36..], (flags | Execute | Code) & ~UninitializedData);
            marked++;
        }
        return marked;
    }

    private static bool HasExecutablePage(CapturedImage captured, IProcessMemory memory, uint va, long size)
    {
        for (long p = va & ~(long)(Page - 1); p < va + size; p += Page)
        {
            if (!captured.PageCaptured((uint)p)) continue;
            if (memory.RegionAt(captured.Target.Base + (ulong)Math.Max(p, va)) is { IsExecutable: true }) return true;
        }
        return false;
    }
}
