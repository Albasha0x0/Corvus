using System.Globalization;

namespace Corvus.Native.Emulation;

/// <summary>
/// The heap behind the built-in malloc, calloc, realloc and free models:
/// first-fit over a fixed range, 16-byte blocks, an unmapped gap after each
/// block. Equal calls give equal addresses. A released block keeps its
/// capacity and is never split or merged.
/// </summary>
public sealed class EmulatorHeap(EmulatorMemory memory, ulong baseAddress, ulong size)
{
    private const ulong Unit = 16;
    private readonly Dictionary<ulong, (ulong Size, ulong Capacity)> _live = [];
    private readonly SortedDictionary<ulong, ulong> _free = [];
    private readonly HashSet<ulong> _released = [];
    private ulong _used;

    /// <summary>The number of blocks not yet released.</summary>
    public int LiveBlocks => _live.Count;

    /// <summary>
/// The requested size of the live block at <paramref name="address"/>; null
/// when no block starts there.
/// </summary>
    public ulong? SizeOf(ulong address) => _live.TryGetValue(address, out var b) ? b.Size : null;

    /// <summary>
/// A zeroed block of at least <paramref name="bytes"/> (zero gives the
/// smallest block); 0 when the range is exhausted.
/// </summary>
    public ulong Allocate(ulong bytes)
    {
        if (bytes > size) return 0;
        ulong capacity = Math.Max(Unit, (bytes + Unit - 1) / Unit * Unit);
        ulong address = 0;
        foreach (var (at, length) in _free)
            if (length >= capacity) { address = at; capacity = length; break; }
        if (address != 0) _free.Remove(address);
        else
        {
            if (_used + capacity + Unit > size) return 0;
            address = baseAddress + _used;
            _used += capacity + Unit;
        }
        _released.Remove(address);
        memory.Map(address, capacity);
        _live[address] = (bytes, capacity);
        return address;
    }

    /// <summary>
/// A zeroed block for <paramref name="count"/> elements of
/// <paramref name="each"/> bytes; 0 when the product overflows or the range
/// is exhausted.
/// </summary>
    public ulong AllocateArray(ulong count, ulong each)
    {
        ulong total = count * each;
        return each != 0 && total / each != count ? 0 : Allocate(total);
    }

    /// <summary>
/// Releases the block at <paramref name="address"/>; 0 releases nothing. The
/// fault names a repeated release or an address no block starts at.
/// </summary>
    public void Release(ulong address, out string? fault)
    {
        fault = null;
        if (address == 0) return;
        if (!_live.Remove(address, out var block))
        {
            fault = _released.Contains(address)
                ? $"free of 0x{address:x} releases a block already released"
                : $"free of 0x{address:x}, which no allocation starts at";
            return;
        }
        memory.Unmap(address, block.Capacity);
        _free[address] = block.Capacity;
        _released.Add(address);
    }

    /// <summary>
/// Resizes the block at <paramref name="address"/> keeping its bytes; 0
/// without a fault is a failed allocation (the block stays) or a release
/// (size 0).
/// </summary>
    public ulong Resize(ulong address, ulong bytes, out string? fault)
    {
        fault = null;
        if (address == 0) return Allocate(bytes);
        if (!_live.TryGetValue(address, out var block))
        {
            fault = $"realloc of 0x{address:x}, which no live allocation starts at";
            return 0;
        }
        if (bytes == 0)
        {
            Release(address, out fault);
            return 0;
        }
        if (bytes <= block.Capacity)
        {
            _live[address] = (bytes, block.Capacity);
            return address;
        }
        ulong moved = Allocate(bytes);
        if (moved == 0) return 0;
        var content = new byte[block.Size];
        memory.Read(address, content);
        memory.Write(moved, content);
        Release(address, out fault);
        return moved;
    }

    /// <summary>
/// Whether <paramref name="label"/> (a function name without its module) has
/// a model here.
/// </summary>
    public static bool Models(string? label) =>
        label is not null
        && label.ToLowerInvariant() is "malloc" or "calloc" or "realloc" or "free";

    /// <summary>
/// The model's return value for <paramref name="label"/> given its
/// arguments; the fault names a call that stops the run.
/// </summary>
    public ulong Call(string label, Func<int, ulong> argument, out string? fault)
    {
        fault = null;
        switch (label.ToLower(CultureInfo.InvariantCulture))
        {
            case "malloc": return Allocate(argument(0));
            case "calloc": return AllocateArray(argument(0), argument(1));
            case "realloc": return Resize(argument(0), argument(1), out fault);
            default:
                Release(argument(0), out fault);
                return 0;
        }
    }
}
