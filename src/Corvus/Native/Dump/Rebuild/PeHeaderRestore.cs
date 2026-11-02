using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>A rebuilt image with its headers restored, and the check naming what was restored.</summary>
public sealed record RestoredHeaders(byte[] Image, RebuildCheck Check);

/// <summary>Restores the headers a loader changes in memory from the file of the same build.</summary>
public static class PeHeaderRestore
{
    private const int ClrHeaderSize = 72, ClrDirectory = 14;
    private const ushort Pe32 = 0x10B, Pe32Plus = 0x20B;

    /// <summary>Returns the mapped <paramref name="image"/> with the optional header width and the CLR header of <paramref name="file"/> restored; the input is not changed, and an unreadable or different build is reported skipped or unknown.</summary>
    public static RestoredHeaders Restore(byte[] image, byte[]? file)
    {
        if (file == null) return Same(image, RebuildCheck.Skipped("headers", "no file of the same build"));
        if (!TryRead(image, out var memory)) return Same(image, RebuildCheck.Unknown("headers", "the rebuilt headers are not readable"));
        if (!TryRead(file, out var disk)) return Same(image, RebuildCheck.Unknown("headers", "the headers of the file are not readable"));
        if (memory.Stamp != disk.Stamp || memory.ImageSize != disk.ImageSize)
            return Same(image, RebuildCheck.Skipped("headers", "the file is not the same build"));

        var result = (byte[])image.Clone();
        var done = new List<string>();
        if (memory.Magic != disk.Magic)
        {
            int length = (int)Math.Min(Math.Min(disk.HeaderSize, (uint)file.Length), (uint)result.Length);
            if (length < disk.SectionTableEnd) return Same(image, RebuildCheck.Partial("headers", "the file headers are cut; the optional header was not restored"));
            file.AsSpan(0, length).CopyTo(result);
            done.Add($"{(disk.Magic == Pe32 ? "PE32" : "PE32+")} optional header from the file (was {(memory.Magic == Pe32 ? "PE32" : "PE32+")})");
            if (!TryRead(result, out memory)) return Same(image, RebuildCheck.Unknown("headers", "the restored headers are not readable"));
        }

        if (memory.ClrRva != 0 || disk.ClrRva != 0)
        {
            var step = RestoreClr(result, file, memory, disk);
            if (step.Failure != null) return new RestoredHeaders(result, RebuildCheck.Partial("headers", Join(done, step.Failure)));
            if (step.Done != null) done.Add(step.Done);
        }
        return done.Count == 0
            ? Same(image, RebuildCheck.Ok("headers", "match the file; nothing to restore"))
            : new RestoredHeaders(result, RebuildCheck.Ok("headers", "restored " + string.Join("; ", done)));
    }

    private readonly record struct ClrStep(string? Done, string? Failure);

    private static ClrStep RestoreClr(byte[] result, byte[] file, Header memory, Header disk)
    {
        if (disk.ClrRva == 0) return new ClrStep(null, null);
        if (!Offset(disk, disk.ClrRva, out long source) || source + ClrHeaderSize > file.Length)
            return new ClrStep(null, "the CLR header of the file is outside the file; not restored");
        if (disk.ClrRva + (long)ClrHeaderSize > result.Length)
            return new ClrStep(null, "the CLR header lies outside the rebuilt image; not restored");
        var fromFile = file.AsSpan((int)source, ClrHeaderSize);
        if (BinaryPrimitives.ReadUInt32LittleEndian(fromFile) != ClrHeaderSize)
            return new ClrStep(null, "the CLR header of the file is not valid; not restored");
        var current = result.AsSpan((int)disk.ClrRva, ClrHeaderSize);
        bool directory = memory.ClrRva != disk.ClrRva;
        bool cleared = BinaryPrimitives.ReadUInt32LittleEndian(current) != ClrHeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(current[8..]) == 0;
        if (!directory && !cleared) return new ClrStep(null, null);
        if (directory)
        {
            long entry = memory.DirectoryAt + ClrDirectory * 8;
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan((int)entry), disk.ClrRva);
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan((int)entry + 4), disk.ClrSize);
        }
        if (cleared) fromFile.CopyTo(current);
        return new ClrStep($"the CLR header at RVA 0x{disk.ClrRva:X} from the file", null);
    }

    private static string Join(List<string> done, string failure) =>
        done.Count == 0 ? failure : "restored " + string.Join("; ", done) + "; " + failure;

    private static RestoredHeaders Same(byte[] image, RebuildCheck check) => new(image, check);

    private readonly record struct Section(uint Rva, uint VirtualSize, uint RawSize, uint RawAt);

    private sealed record Header(
        ushort Magic, uint Stamp, uint ImageSize, uint HeaderSize, long SectionTableEnd,
        long DirectoryAt, uint ClrRva, uint ClrSize, IReadOnlyList<Section> Sections);

    private static bool Offset(Header h, uint rva, out long offset)
    {
        offset = rva;
        if (rva < h.HeaderSize) return true;
        foreach (var s in h.Sections)
        {
            if (rva < s.Rva || rva >= s.Rva + Math.Max(s.VirtualSize, s.RawSize)) continue;
            offset = s.RawAt + (rva - s.Rva);
            return rva - s.Rva < s.RawSize;
        }
        return false;
    }

    private static bool TryRead(byte[] bytes, out Header header)
    {
        header = default!;
        if (bytes.Length < 0x40) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        if (nt < 0 || nt + 24 + 96 > bytes.Length || BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(nt)) != 0x4550) return false;
        int count = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 6));
        int optSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(nt + 20));
        int opt = nt + 24;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(opt));
        if (magic != Pe32 && magic != Pe32Plus) return false;
        int dirs = opt + (magic == Pe32Plus ? 112 : 96);
        long table = opt + optSize, end = table + 40L * count;
        if (end > bytes.Length || dirs + (ClrDirectory + 1) * 8 > bytes.Length) return false;
        var sections = new List<Section>();
        for (int i = 0; i < count; i++)
        {
            int h = (int)table + 40 * i;
            sections.Add(new Section(
                BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 12)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 16)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(h + 20))));
        }
        int clr = dirs + ClrDirectory * 8;
        header = new Header(
            magic, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(nt + 8)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(opt + 56)),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(opt + 60)), end, dirs,
            BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(clr)), BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(clr + 4)), sections);
        return true;
    }
}
