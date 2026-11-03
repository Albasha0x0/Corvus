using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Undoes or keeps the loader's relocations in a mapped image.</summary>
public static class PeRelocations
{
    private const int RelocationDirectory = 5;
    private const ushort Absolute = 0, HighLow = 3, Dir64 = 10;
    private const ushort RelocsStripped = 0x0001;

    /// <summary>The preferred base of a build: a value read from its file on disk, or unknown.</summary>
    public readonly record struct PreferredBase(bool Known, ulong Value, byte[]? File = null)
    {
        /// <summary>A preferred base read from the file of the same build; <paramref name="file"/> adds its bytes for per-site checks.</summary>
        public static PreferredBase FromFile(ulong value, byte[]? file = null) => new(true, value, file);

        /// <summary>No file of the same build was found; the header holds the loaded base.</summary>
        public static PreferredBase Unknown => new(false, 0);
    }

    /// <summary>
    /// Applies <paramref name="mode"/> to <paramref name="image"/> in place and adds one check: preferred subtracts
    /// the load delta from every fixup, loaded writes the loaded base to the optional header.
    /// A null <paramref name="preferredBase"/> reads the base from the header; an unknown one leaves the image at
    /// the loaded base and reports the check as unknown.
    /// </summary>
    public static void Apply(byte[] image, CapturedImage captured, BaseMode mode, List<RebuildCheck> checks,
        PreferredBase? preferredBase = null)
    {
        byte[]? file = null;
        if (!TryHeader(image, out int opt, out bool is64, out ulong preferred, out ushort characteristics))
        {
            checks.Add(RebuildCheck.Unknown("relocations", "the optional header is not readable"));
            return;
        }

        ulong loaded = captured.Target.Base;
        if (mode == BaseMode.Loaded)
        {
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(opt + 24), loaded);
            else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(opt + 28), (uint)loaded);
            checks.Add(RebuildCheck.Ok("relocations", "kept at the loaded base"));
            return;
        }

        if (preferredBase is { } given)
        {
            if (!given.Known)
            {
                checks.Add(RebuildCheck.Unknown("relocations",
                    "preferred base unknown: the loaded header holds the loaded base and no file of the same build was found"));
                return;
            }
            preferred = given.Value;
            file = given.File;
        }

        long delta = unchecked((long)(loaded - preferred));
        if (delta == 0)
        {
            checks.Add(RebuildCheck.Skipped("relocations", "loaded at its preferred base"));
            return;
        }

        int dirs = opt + (is64 ? 112 : 96);
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + (is64 ? 108 : 92)));
        uint rva = 0, size = 0;
        if (count > RelocationDirectory && dirs + RelocationDirectory * 8 + 8 <= image.Length)
        {
            rva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs + RelocationDirectory * 8));
            size = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(dirs + RelocationDirectory * 8 + 4));
        }
        if (rva == 0 || size == 0)
        {
            string why = (characteristics & RelocsStripped) != 0
                ? "IMAGE_FILE_RELOCS_STRIPPED is set"
                : "no relocation directory";
            checks.Add(RebuildCheck.Skipped("relocations", $"{why}; addresses kept as loaded"));
            return;
        }
        if (!captured.PageCaptured(rva))
        {
            checks.Add(RebuildCheck.Unknown("relocations", "the relocation directory page is not captured"));
            return;
        }

        // The walk stays inside the directory and the image.
        long end = Math.Min((long)rva + size, image.Length);
        int undone = 0, kept = 0, changed = 0, skipped = 0, unsupported = 0;
        ulong imageSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 56));

        // Without a file, a first pass finds an image the loader left
        // unrelocated.
        bool notRelocated = false;
        if (file == null)
        {
            int asInFile = 0, asRelocated = 0;
            Walk(image, rva, end, (site, type) =>
            {
                if (!Fits(image, captured, site, type)) return;
                ulong value = Read(image, site, type);
                if (InImage(value, preferred, imageSize)) asInFile++;
                if (InImage(Minus(value, type, delta), preferred, imageSize)) asRelocated++;
            }, out _);
            notRelocated = asRelocated == 0 && asInFile > 0;
        }

        Walk(image, rva, end, (site, type) =>
        {
            if (type != Dir64 && type != HighLow)
            {
                unsupported++;
                return;
            }
            if (!Fits(image, captured, site, type))
            {
                skipped++;
                return;
            }
            ulong value = Read(image, site, type);
            ulong undoneValue = Minus(value, type, delta);
            if (FileValue(file, (uint)site, type == Dir64 ? 8 : 4) is { } original)
            {
                // The file value is the only reference: undo only file plus
                // delta.
                if (undoneValue != original)
                {
                    if (value == original) kept++; else changed++;
                    return;
                }
            }
            else if (notRelocated)
            {
                if (InImage(value, preferred, imageSize)) kept++; else changed++;
                return;
            }
            if (type == Dir64) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan((int)site), undoneValue);
            else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)site), (uint)undoneValue);
            undone++;
        }, out bool malformed);

        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(opt + 24), preferred);
        else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(opt + 28), (uint)preferred);

        string counts = $"{undone} sites undone, {kept} kept as in the file, {changed} changed at run time";
        if (skipped == 0 && unsupported == 0 && !malformed)
        {
            if (undone == 0 && changed == 0 && kept > 0)
            {
                checks.Add(RebuildCheck.Skipped("relocations", $"the image was not relocated by the loader; {kept} sites kept as in the file"));
                return;
            }
            checks.Add(RebuildCheck.Ok("relocations", $"{counts}, delta {(delta < 0 ? "-" : "+")}0x{Math.Abs(delta):X}"));
            return;
        }
        string detail = $"{counts}, {skipped} skipped on pages not captured, {unsupported} of an unsupported type";
        if (malformed) detail += "; the table ends at a malformed block";
        checks.Add(RebuildCheck.Partial("relocations", detail));
    }

    // Calls visit for each relocation entry that is not padding; malformed
    // when the table ends inside a block.
    private static void Walk(byte[] image, long rva, long end, Action<long, ushort> visit, out bool malformed)
    {
        malformed = false;
        long at = rva;
        while (at + 8 <= end)
        {
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)at));
            uint block = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)at + 4));
            if (block < 8 || (block & 1) != 0 || at + block > end)
            {
                malformed = true;
                return;
            }
            for (long e = at + 8; e < at + block; e += 2)
            {
                ushort entry = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)e));
                ushort type = (ushort)(entry >> 12);
                if (type != Absolute) visit((long)page + (entry & 0xFFF), type);
            }
            at += block;
        }
        if (at < end && end - at < 8) malformed = true;
    }

    private static bool Fits(byte[] image, CapturedImage captured, long site, ushort type)
    {
        if (type != Dir64 && type != HighLow) return false;
        int width = type == Dir64 ? 8 : 4;
        return site + width <= image.Length && captured.PageCaptured((uint)site)
            && captured.PageCaptured((uint)(site + width - 1));
    }

    private static ulong Read(byte[] image, long site, ushort type) => type == Dir64
        ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan((int)site))
        : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)site));

    private static ulong Minus(ulong value, ushort type, long delta) =>
        type == Dir64 ? unchecked(value - (ulong)delta) : unchecked((uint)value - (uint)delta);

    private static bool InImage(ulong value, ulong preferred, ulong size) => value >= preferred && value - preferred < size;

    // The file's value at an RVA of a section's raw data; null when there is
    // no file or the site is not backed by it.
    private static ulong? FileValue(byte[]? file, uint rva, int width)
    {
        if (file == null || file.Length < 0x40) return null;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        if (nt < 0 || nt + 24 > file.Length || BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(nt)) != 0x4550) return null;
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        for (int i = 0; i < sections && table + (i + 1) * 40 <= file.Length; i++)
        {
            var s = file.AsSpan(table + i * 40);
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(s[12..]);
            uint raw = BinaryPrimitives.ReadUInt32LittleEndian(s[16..]);
            uint ptr = BinaryPrimitives.ReadUInt32LittleEndian(s[20..]);
            if (rva < va || (long)rva + width - va > raw) continue;
            long at = (long)ptr + (rva - va);
            if (at + width > file.Length) return null;
            return width == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(file.AsSpan((int)at))
                : BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan((int)at));
        }
        return null;
    }

    private static bool TryHeader(byte[] image, out int opt, out bool is64, out ulong preferred, out ushort characteristics)
    {
        opt = 0;
        is64 = false;
        preferred = 0;
        characteristics = 0;
        if (image.Length < 0x40) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        if (nt < 0 || nt + 24 + 112 > image.Length) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(nt)) != 0x4550) return false;
        characteristics = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 22));
        opt = nt + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        is64 = magic == 0x20B;
        preferred = is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(opt + 24))
            : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 28));
        return true;
    }
}
