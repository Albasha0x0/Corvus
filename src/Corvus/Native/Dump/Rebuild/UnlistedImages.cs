using System.Buffers.Binary;
using Corvus.Native.Live;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>PE images in memory that the module list does not name.</summary>
public static class UnlistedImages
{
    /// <summary>Most images returned.</summary>
    public const int MaxImages = 256;

    private const ulong Step = 0x10000;
    private const int HeaderWindow = 0x1000;

    /// <summary>The images found by their headers outside listed modules; empty when none.</summary>
    public static IReadOnlyList<RebuildTarget> Find(IProcessMemory memory, CancellationToken ct)
    {
        var found = new List<RebuildTarget>();
        var header = new byte[HeaderWindow];
        ulong skipTo = 0;
        foreach (var (start, size) in Extents(memory))
        {
            ulong end = start + size;
            if (end < start) end = ulong.MaxValue;
            for (ulong at = start; at < end; at = NextCandidate(at, start))
            {
                ct.ThrowIfCancellationRequested();
                if (at < skipTo || memory.ModuleAt(at) != null) continue;
                if (!TryHeader(memory, at, header, out uint imageSize, out string name)) continue;
                found.Add(new RebuildTarget(name, at, imageSize, ModuleOrigin.Unlisted));
                if (found.Count >= MaxImages) return found;
                skipTo = at + imageSize;
            }
        }
        return found;
    }

    private static ulong NextCandidate(ulong at, ulong start)
    {
        ulong next = (at & ~(Step - 1)) + Step;
        return next > at ? next : ulong.MaxValue;
    }

    private static IEnumerable<(ulong Start, ulong Size)> Extents(IProcessMemory memory)
    {
        switch (memory)
        {
            case MinidumpFile d:
                return d.MemoryRanges.Select(r => (r.Start, r.Size));
            case CoreFile c:
                return c.MemoryRanges.Select(r => (r.Start, r.Size));
            case RegionSetFile s:
                return s.Regions.Where(r => !r.Missing).Select(r => (r.Base, r.Size));
            case LiveProcess p:
                return p.Regions().Where(r => r.State == 0x1000 && (r.Protect & 0x101) == 0).Select(r => (r.Base, r.Size));
            default:
                return [];
        }
    }

    private static bool TryHeader(IProcessMemory memory, ulong address, byte[] header, out uint imageSize, out string name)
    {
        imageSize = 0;
        name = "";
        int got = memory.ReadMemory(address, header);
        if (got < 0x40 || header[0] != 'M' || header[1] != 'Z') return false;
        uint lfanew = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x3C));
        if (lfanew < 0x40 || lfanew > HeaderWindow - 0x100 || lfanew + 0x60 > got) return false;
        int nt = (int)lfanew;
        if (header[nt] != 'P' || header[nt + 1] != 'E' || header[nt + 2] != 0 || header[nt + 3] != 0) return false;
        ushort machine = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(nt + 4));
        if (machine is not (0x14C or 0x8664 or 0x1C0 or 0x1C4 or 0xAA64)) return false;
        ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(nt + 6));
        if (sections == 0 || sections > PeLimits.MaxSections) return false;
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(nt + 22));
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(nt + 24));
        if (magic is not (0x10B or 0x20B)) return false;
        imageSize = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(nt + 24 + 56));
        if (imageSize == 0 || imageSize > ModuleRebuild.MaxImageBytes) return false;
        if (memory.ReadableExtent(address, imageSize) < imageSize) return false;
        name = $"image-{address:x}{((characteristics & 0x2000) != 0 ? ".dll" : ".exe")}";
        return true;
    }
}
