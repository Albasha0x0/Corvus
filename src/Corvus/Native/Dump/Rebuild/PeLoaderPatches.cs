using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Restores the sites the loader rewrites after mapping from the file of the same build.</summary>
public static class PeLoaderPatches
{
    private const int LoadConfigDirectory = 10;
    private const int PatchWindow = 6;
    private const int Arm64Instruction = 4;

    // A site: its RVA, byte length, and whether it holds an absolute address of the image.
    private readonly record struct Site(uint Rva, int Length, bool Pointer);

    /// <summary>
    /// Adds the "loader patches" check and, when <paramref name="file"/> is the file of the same build, copies the bytes of every
    /// site the dynamic value relocation table or the load configuration names from it into <paramref name="image"/> (mapped layout).
    /// Without a file the sites keep their captured bytes and the check is unknown; sites that cannot be read are named, never guessed.
    /// </summary>
    public static void Restore(byte[] image, CapturedImage captured, byte[]? file, BaseMode mode, List<RebuildCheck> checks)
    {
        const string name = "loader patches";
        if (!TryHeader(image, out var h))
        {
            checks.Add(RebuildCheck.Unknown(name, "the optional header is not readable"));
            return;
        }

        var sites = new Dictionary<uint, Site>();
        var unread = new SortedSet<string>();
        string? blocked = Collect(image, captured, h, sites, unread);
        if (blocked != null)
        {
            checks.Add(RebuildCheck.Unknown(name, blocked));
            return;
        }
        if (sites.Count == 0 && unread.Count == 0)
        {
            checks.Add(RebuildCheck.Skipped(name, "no dynamic relocations"));
            return;
        }

        string notRead = unread.Count == 0 ? "" : $"; not read: {string.Join(", ", unread)}";
        if (file == null || !TryFileMap(file, out var map, out ulong fileBase))
        {
            checks.Add(RebuildCheck.Unknown(name, $"{sites.Count} loader-patched sites kept: no file of the same build{notRead}"));
            return;
        }

        // File bytes hold the preferred base. Restore after the base is set, and add the load delta to address sites only
        // when the image stays at its loaded base, so rel32 operands (position independent) are copied as they are.
        long delta = mode == BaseMode.Loaded ? unchecked((long)(captured.Target.Base - fileBase)) : 0;
        int restored = 0, missing = 0, outside = 0;
        foreach (var site in sites.Values.OrderBy(s => s.Rva))
        {
            uint last = site.Rva + (uint)site.Length - 1;
            if (!captured.PageCaptured(site.Rva) || !captured.PageCaptured(last) || last >= image.Length)
            {
                missing++;
                continue;
            }
            if (!map.TryRead(site.Rva, site.Length, out var bytes))
            {
                outside++;
                continue;
            }
            bytes.CopyTo(image.AsSpan((int)site.Rva));
            if (site.Pointer && delta != 0) Rebase(image.AsSpan((int)site.Rva, site.Length), fileBase, h.SizeOfImage, delta);
            restored++;
        }

        if (restored == sites.Count && unread.Count == 0)
        {
            checks.Add(RebuildCheck.Ok(name, $"{restored} sites restored from the file"));
            return;
        }
        string why = "";
        if (missing > 0) why += $"; {missing} on pages not captured";
        if (outside > 0) why += $"; {outside} outside the raw data of the file";
        checks.Add(RebuildCheck.Partial(name, $"{restored} of {sites.Count} sites restored from the file{why}{notRead}"));
    }

    // Reads the sites into the dictionary; returns why the tables cannot be read, or null.
    private static string? Collect(byte[] image, CapturedImage captured, Header h, Dictionary<uint, Site> sites, SortedSet<string> unread)
    {
        if (h.DirectoryCount <= LoadConfigDirectory) return null;
        uint lcRva = U32(image, h.Directories + LoadConfigDirectory * 8);
        if (lcRva == 0) return null;
        if (!Readable(image, captured, lcRva, 4)) return "the load configuration is not captured";
        uint lcSize = U32(image, (int)lcRva);
        int width = h.Is64 ? 8 : 4;

        // Function pointers the loader fills in: the load configuration holds the address of each slot.
        int[] slotFields = h.Is64 ? [0x70, 0x78, 0xD8, 0xE8, 0x118, 0x120, 0x128] : [72, 76, 132, 144, 172, 176, 180];
        foreach (int field in slotFields)
        {
            if (field + width > lcSize || !Readable(image, captured, lcRva + (uint)field, (uint)width)) continue;
            ulong va = h.Is64 ? U64(image, (int)lcRva + field) : U32(image, (int)lcRva + field);
            if (va < h.Base || va - h.Base + (uint)width > h.SizeOfImage) continue;
            uint slot = (uint)(va - h.Base);
            sites[slot] = new Site(slot, width, true);
        }

        int offsetField = h.Is64 ? 0xE0 : 136, sectionField = offsetField + 4;
        if (sectionField + 2 > lcSize) return null;
        uint tableOffset = U32(image, (int)lcRva + offsetField);
        ushort tableSection = U16(image, (int)lcRva + sectionField);
        if (tableSection == 0 && tableOffset == 0) return null;
        if (tableSection == 0 || tableSection > h.Sections)
            return $"the dynamic value relocation table names section {tableSection}, which does not exist";
        uint start = U32(image, h.SectionTable + 40 * (tableSection - 1) + 12) + tableOffset;
        if (!Readable(image, captured, start, 8)) return "the dynamic value relocation table is not captured";

        uint version = U32(image, (int)start), size = U32(image, (int)start + 4);
        if (version != 1)
        {
            unread.Add($"dynamic value relocation table version {version}");
            return null;
        }
        long end = Math.Min((long)start + 8 + size, image.Length);
        long at = start + 8;
        int header = h.Is64 ? 12 : 8;
        while (at + header <= end)
        {
            ulong symbol = h.Is64 ? U64(image, (int)at) : U32(image, (int)at);
            uint body = U32(image, (int)at + header - 4);
            long from = at + header, to = from + body;
            if (to > end)
            {
                unread.Add("a record that runs past the table");
                break;
            }
            if (!Readable(image, captured, (uint)from, body)) return "the dynamic value relocation table is not captured";
            ReadRecord(image, h.IsArm64, symbol, (int)from, (int)to, sites, unread);
            at = to;
        }
        return null;
    }

    private static void ReadRecord(byte[] image, bool arm64, ulong symbol, int from, int to, Dictionary<uint, Site> sites,
        SortedSet<string> unread)
    {
        // An ARM64 control transfer site is one 4-byte instruction.
        int window = arm64 ? Arm64Instruction : PatchWindow;
        switch (symbol)
        {
            case 3: Blocks(image, from, to, 4, sites, unread, "import control transfer", window); break;
            case 4: Blocks(image, from, to, 2, sites, unread, "indirect control transfer", window); break;
            case 5: Blocks(image, from, to, 2, sites, unread, "switchable branch", window); break;
            case 7: FunctionOverride(image, from, to, sites, unread); break;
            case 1: unread.Add("guard RF prologue"); break;
            case 2: unread.Add("guard RF epilogue"); break;
            case 6 when arm64: Arm64X(image, from, to, sites, unread); break;
            case 6: unread.Add("ARM64X"); break;
            case 8: unread.Add("ARM64 kernel import call transfer"); break;
            case 9: unread.Add("ARM64 secure import call transfer"); break;
            default: unread.Add($"symbol {symbol}"); break;
        }
    }

    // The function override record: a size, then entries of fixed fields, RVAs and base relocation blocks; the BDD info after them is not a site list.
    private static void FunctionOverride(byte[] image, int from, int to, Dictionary<uint, Site> sites, SortedSet<string> unread)
    {
        if (from + 4 > to) { unread.Add("function override"); return; }
        long at = from + 4, end = Math.Min(to, at + U32(image, from));
        while (at + 16 <= end)
        {
            uint rvaSize = U32(image, (int)at + 8), relocSize = U32(image, (int)at + 12);
            long relocs = at + 16 + rvaSize;
            if (relocs + relocSize > end) { unread.Add("function override"); return; }
            Blocks(image, (int)relocs, (int)(relocs + relocSize), 2, sites, unread, "function override", overrideEntries: true);
            at = relocs + relocSize;
        }
    }

    // ARM64X blocks: page RVA, block size, then 16-bit fixups (offset:12,
    // type:2, size:2) with their operand words.
    private static void Arm64X(byte[] image, int from, int to, Dictionary<uint, Site> sites, SortedSet<string> unread)
    {
        const int zeroFill = 0, value = 1, delta = 2;
        long at = from;
        while (at + 8 <= to)
        {
            uint page = U32(image, (int)at), block = U32(image, (int)at + 4);
            if (block < 8 || at + block > to)
            {
                unread.Add("ARM64X block that does not fit its record");
                return;
            }
            long end = at + block, e = at + 8;
            while (e + 2 <= end)
            {
                ushort fixup = U16(image, (int)e);
                e += 2;
                int type = (fixup >> 12) & 3, sizeCode = fixup >> 14;
                // A zero size code is the padding that aligns the block to 4
                // bytes.
                if (sizeCode == 0) continue;
                int length = 1 << sizeCode;
                if (type == value) e += length;
                else if (type == delta) e += 2;
                else if (type != zeroFill)
                {
                    unread.Add($"ARM64X fixup type {type}");
                    break;
                }
                uint rva = page + (uint)(fixup & 0xFFF);
                sites[rva] = new Site(rva, length, false);
            }
            at = end;
        }
    }

    // Base relocation blocks: page RVA, block size, then entries of the given width with the page offset in the low 12 bits.
    private static void Blocks(byte[] image, int from, int to, int entryWidth, Dictionary<uint, Site> sites, SortedSet<string> unread,
        string kind, int window = PatchWindow, bool overrideEntries = false)
    {
        long at = from;
        while (at + 8 <= to)
        {
            uint page = U32(image, (int)at), block = U32(image, (int)at + 4);
            if (block < 8 || at + block > to)
            {
                unread.Add($"{kind} block that does not fit its record");
                return;
            }
            for (long e = at + 8; e + entryWidth <= at + block; e += entryWidth)
            {
                uint entry = entryWidth == 4 ? U32(image, (int)e) : U16(image, (int)e);
                uint rva = page + (entry & 0xFFF);
                if (overrideEntries)
                {
                    uint type = entry >> 12;
                    if (type == 0) continue;
                    // Type 1 is the rel32 operand of a patched jump.
                    if (type != 1)
                    {
                        unread.Add($"{kind} fixup type {type}");
                        continue;
                    }
                    sites[rva] = new Site(rva, 4, false);
                }
                else
                {
                    // The patched instruction is 5 or 6 bytes; the same-build file holds the original code around it.
                    sites[rva] = new Site(rva, window, false);
                }
            }
            at += block;
        }
    }

    private static void Rebase(Span<byte> value, ulong fileBase, uint sizeOfImage, long delta)
    {
        if (value.Length == 8)
        {
            ulong v = BinaryPrimitives.ReadUInt64LittleEndian(value);
            if (v >= fileBase && v - fileBase < sizeOfImage) BinaryPrimitives.WriteUInt64LittleEndian(value, unchecked(v + (ulong)delta));
        }
        else
        {
            uint v = BinaryPrimitives.ReadUInt32LittleEndian(value);
            if (v >= (uint)fileBase && v - (uint)fileBase < sizeOfImage) BinaryPrimitives.WriteUInt32LittleEndian(value, unchecked(v + (uint)delta));
        }
    }

    private static bool Readable(byte[] image, CapturedImage captured, uint rva, uint length)
    {
        if (length == 0) return rva < image.Length;
        long last = (long)rva + length - 1;
        if (last >= image.Length) return false;
        for (long page = rva & ~0xFFFL; page <= last; page += 0x1000)
            if (!captured.PageCaptured((uint)page)) return false;
        return true;
    }

    private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
    private static ushort U16(byte[] b, int at) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));
    private static ulong U64(byte[] b, int at) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at));

    private readonly record struct Header(bool Is64, bool IsArm64, ulong Base, uint SizeOfImage, int Directories, uint DirectoryCount, int SectionTable, int Sections);

    private static bool TryHeader(byte[] image, out Header h)
    {
        h = default;
        if (image.Length < 0x40) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        if (nt < 0 || nt + 24 + 112 > image.Length || U32(image, nt) != 0x4550) return false;
        int sections = U16(image, nt + 6), opt = nt + 24, optSize = U16(image, nt + 20);
        ushort magic = U16(image, opt);
        if (magic != 0x10B && magic != 0x20B) return false;
        bool is64 = magic == 0x20B;
        int dirs = opt + (is64 ? 112 : 96);
        uint count = U32(image, opt + (is64 ? 108 : 92));
        if (dirs + 8L * Math.Min(count, 16u) > image.Length || opt + optSize + 40L * sections > image.Length) return false;
        ulong imageBase = is64 ? U64(image, opt + 24) : U32(image, opt + 28);
        h = new Header(is64, U16(image, nt + 4) is 0xAA64 or 0xA641, imageBase, U32(image, opt + 56), dirs, Math.Min(count, 16u), opt + optSize, sections);
        return true;
    }

    // The file's section map, to read bytes by RVA; false when its headers are not readable.
    private static bool TryFileMap(byte[] file, out FileMap map, out ulong fileBase)
    {
        map = default!;
        fileBase = 0;
        if (!TryHeader(file, out var h)) return false;
        var list = new List<(uint Rva, uint Size, uint Raw, uint RawSize)>();
        for (int i = 0; i < h.Sections; i++)
        {
            int at = h.SectionTable + 40 * i;
            uint vsize = U32(file, at + 8);
            list.Add((U32(file, at + 12), vsize == 0 ? U32(file, at + 16) : vsize, U32(file, at + 20), U32(file, at + 16)));
        }
        map = new FileMap(file, list);
        fileBase = h.Base;
        return true;
    }

    private sealed class FileMap(byte[] file, List<(uint Rva, uint Size, uint Raw, uint RawSize)> sections)
    {
        // The bytes at an RVA when one section holds all of them in its raw data.
        public bool TryRead(uint rva, int length, out ReadOnlySpan<byte> bytes)
        {
            foreach (var s in sections)
            {
                if (rva < s.Rva || (long)rva + length > (long)s.Rva + Math.Min(s.Size, s.RawSize)) continue;
                long at = (long)s.Raw + (rva - s.Rva);
                if (at + length > file.Length) break;
                bytes = file.AsSpan((int)at, length);
                return true;
            }
            bytes = default;
            return false;
        }
    }
}
