using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump;

/// <summary>A user-mode process address space: a minidump or a running process read without changing it.</summary>
public interface IProcessMemory
{
    /// <summary>Instruction set of the process (x86 for a WoW64 process seen from its 32-bit side).</summary>
    NativeArch Arch { get; }

    bool Is64Bit { get; }

    /// <summary>Distinguishes this process image from any other in caches (dump file identity, or pid and start time).</summary>
    string Identity { get; }

    /// <summary>Loaded modules, sorted by base address.</summary>
    IReadOnlyList<DumpModule> Modules { get; }

    IReadOnlyList<DumpUnloadedModule> UnloadedModules { get; }

    /// <summary>Copies memory from <paramref name="address"/> up to the first unreadable byte; returns the count copied, never throws.</summary>
    int ReadMemory(ulong address, Span<byte> destination);

    DumpModule? ModuleAt(ulong address);

    /// <summary>The memory region (VirtualQuery view) containing <paramref name="address"/>, or null when unknown.</summary>
    DumpMemoryRegion? RegionAt(ulong address);

    /// <summary>How many bytes from <paramref name="start"/> (at most <paramref name="size"/>) may hold readable memory.</summary>
    ulong ReadableExtent(ulong start, ulong size);
}

public static class ProcessMemoryExtensions
{
    public static bool TryReadU64(this IProcessMemory memory, ulong address, out ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        value = 0;
        if (memory.ReadMemory(address, b) < 8) return false;
        value = BinaryPrimitives.ReadUInt64LittleEndian(b);
        return true;
    }

    public static bool TryReadU32(this IProcessMemory memory, ulong address, out uint value)
    {
        Span<byte> b = stackalloc byte[4];
        value = 0;
        if (memory.ReadMemory(address, b) < 4) return false;
        value = BinaryPrimitives.ReadUInt32LittleEndian(b);
        return true;
    }

    /// <summary>A pointer-sized value of the process.</summary>
    public static bool TryReadPointer(this IProcessMemory memory, ulong address, out ulong value)
    {
        if (memory.Is64Bit) return memory.TryReadU64(address, out value);
        bool ok = memory.TryReadU32(address, out uint v);
        value = v;
        return ok;
    }

    /// <summary>Binary search of a module list sorted by base; a near overlapping module below wins (malformed lists).</summary>
    public static DumpModule? ModuleAt(IReadOnlyList<DumpModule> modules, ulong address)
    {
        int lo = 0, hi = modules.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (modules[mid].Base <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        for (int i = best; i >= 0 && best - i < 4; i--)
            if (modules[i].Contains(address)) return modules[i];
        return null;
    }

    /// <summary>Binary search of a region list sorted by base.</summary>
    public static DumpMemoryRegion? RegionAt(IReadOnlyList<DumpMemoryRegion> regions, ulong address)
    {
        int lo = 0, hi = regions.Count - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >>> 1;
            if (regions[mid].Base <= address) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best >= 0 && regions[best].Contains(address) ? regions[best] : null;
    }
}
