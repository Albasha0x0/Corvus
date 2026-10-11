namespace Corvus.Native.MachO;

/// <summary>
/// What a fixed-up pointer location holds. <see cref="Rebase"/>: a pointer into the image (<see cref="Rebase.TargetVm"/>
/// as a virtual address, PAC bits stripped). <see cref="Bind"/>: a pointer bound to <see cref="Bind.Symbol"/> of the
/// library with two-level ordinal <see cref="Bind.Ordinal"/> (0 self, -1 main executable, -2 flat lookup, -3 weak lookup).
/// </summary>
public abstract record MachOFixup(ulong Location)
{
    public sealed record Rebase(ulong Location, ulong TargetVm, bool Authenticated = false) : MachOFixup(Location);

    public sealed record Bind(ulong Location, int Ordinal, string? Dylib, string Symbol, long Addend, bool Weak, bool Lazy = false, bool Authenticated = false)
        : MachOFixup(Location);
}

/// <summary>Every fixup of an image, from walked chained-fixup chains or the dyld info opcode streams.</summary>
public sealed class MachOFixups
{
    private readonly MachOFixup[] sorted;
    private readonly ulong[] locations;

    internal MachOFixups(List<MachOFixup> fixups, IReadOnlyList<MachOFixup.Bind> weakBinds, string source, ushort? pointerFormat)
    {
        sorted = [.. fixups.OrderBy(f => f.Location)];
        locations = [.. sorted.Select(f => f.Location)];
        WeakBinds = weakBinds;
        Source = source;
        PointerFormat = pointerFormat;
    }

    public static readonly MachOFixups Empty = new([], [], "none", null);

    /// <summary>Rebases and binds sorted by location.</summary>
    public IReadOnlyList<MachOFixup> All => sorted;
    /// <summary>Weak-definition coalescing entries (dyld info weak bind stream): may be overridden at load time; not in <see cref="All"/>.</summary>
    public IReadOnlyList<MachOFixup.Bind> WeakBinds { get; }
    /// <summary>"chained fixups", "dyld info", "threaded" or "none".</summary>
    public string Source { get; }
    /// <summary>The chained pointer format of the first fixup segment, when chained.</summary>
    public ushort? PointerFormat { get; }
    public int RebaseCount => sorted.Count(f => f is MachOFixup.Rebase);
    public int BindCount => sorted.Count(f => f is MachOFixup.Bind);

    /// <summary>The fixup at <paramref name="vmaddr"/>, or null when the loader leaves that location alone.</summary>
    public MachOFixup? Resolve(ulong vmaddr)
    {
        int i = Array.BinarySearch(locations, vmaddr);
        return i >= 0 ? sorted[i] : null;
    }
}

/// <summary>Decoding of chained-fixup pointers (LC_DYLD_CHAINED_FIXUPS and threaded binds), every pointer format.</summary>
internal static class ChainedPointer
{
    /// <summary>One decoded chain element; <see cref="Next"/> counts strides to the next element (0 ends the chain).</summary>
    public readonly record struct Element(bool IsBind, ulong Target, uint Ordinal, long Addend, uint Next, bool Authenticated, bool IsPointer);

    public static bool IsKnown(ushort format) => format is >= 1 and <= 13;

    /// <summary>Bytes between elements per unit of <see cref="Element.Next"/>.</summary>
    public static int Stride(ushort format) => format switch { 1 or 9 or 12 or 13 => 8, 11 => 1, _ => 4 };

    /// <summary>Width of the pointer slot.</summary>
    public static int Width(ushort format) => format is 3 or 4 or 5 ? 4 : 8;

    public static Element Decode(ushort format, ulong raw, ulong imageBase, uint maxValidPointer)
    {
        switch (format)
        {
            case 1 or 7 or 9 or 10 or 12:
            {
                bool auth = (raw >> 63) != 0, bind = ((raw >> 62) & 1) != 0;
                uint next = (uint)((raw >> 51) & 0x7FF);
                if (bind)
                {
                    uint ordinal = (uint)(raw & (format == 12 ? 0xFFFFFFUL : 0xFFFFUL));
                    long addend = auth ? 0 : (long)(((raw >> 32) & 0x7FFFF) << 45) >> 45;
                    return new Element(true, 0, ordinal, addend, next, auth, true);
                }
                if (auth) return new Element(false, imageBase + (raw & 0xFFFFFFFF), 0, 0, next, true, true);
                ulong target = raw & 0x7FF_FFFF_FFFF, high8 = (raw >> 43) & 0xFF;
                return new Element(false, (format is 1 or 10 ? target : imageBase + target) | (high8 << 56), 0, 0, next, false, true);
            }
            case 13:
            {
                bool auth = (raw >> 63) != 0;
                ulong high8 = auth ? 0 : (raw >> 34) & 0xFF;
                return new Element(false, (imageBase + (raw & 0x3_FFFF_FFFF)) | (high8 << 56), 0, 0, (uint)((raw >> 52) & 0x7FF), auth, true);
            }
            case 2 or 6:
            {
                uint next = (uint)((raw >> 51) & 0xFFF);
                if ((raw >> 63) != 0) return new Element(true, 0, (uint)(raw & 0xFFFFFF), (long)((raw >> 24) & 0xFF), next, false, true);
                ulong target = raw & 0xF_FFFF_FFFF, high8 = (raw >> 36) & 0xFF;
                return new Element(false, (format == 2 ? target : imageBase + target) | (high8 << 56), 0, 0, next, false, true);
            }
            case 3:
            {
                uint next = (uint)((raw >> 26) & 0x1F);
                if (((raw >> 31) & 1) != 0) return new Element(true, 0, (uint)(raw & 0xFFFFF), (long)((raw >> 20) & 0x3F), next, false, true);
                ulong target = raw & 0x3FFFFFF;
                // Above max_valid_pointer the slot is a biased non-pointer value, not slid.
                if (maxValidPointer != 0 && target > maxValidPointer)
                    return new Element(false, target - ((0x04000000UL + maxValidPointer) / 2), 0, 0, next, false, false);
                return new Element(false, target, 0, 0, next, false, true);
            }
            case 4: return new Element(false, imageBase + (raw & 0x3FFFFFFF), 0, 0, (uint)((raw >> 30) & 0x3), false, true);
            case 5: return new Element(false, raw & 0x3FFFFFF, 0, 0, (uint)((raw >> 26) & 0x3F), false, true);
            case 8 or 11: return new Element(false, imageBase + (raw & 0x3FFFFFFF), 0, 0, (uint)((raw >> 51) & 0xFFF), (raw >> 63) != 0, true);
            default: return new Element(false, raw, 0, 0, 0, false, false);
        }
    }
}
