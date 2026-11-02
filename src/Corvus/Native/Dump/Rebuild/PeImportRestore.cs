using System.Buffers.Binary;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>Restores the import address table of a mapped image.</summary>
public static class PeImportRestore
{
    private const int DescriptorSize = 20;

    /// <summary>
    /// Writes each import lookup table entry back over its address table slot in <paramref name="image"/>.
    /// Null, with a skipped check, when the image has no import directory or <paramref name="mode"/> keeps addresses.
    /// </summary>
    public static ImportSummary? Restore(byte[] image, CapturedImage captured, IProcessMemory memory, ImportMode mode, List<RebuildCheck> checks, CancellationToken ct)
    {
        if (mode == ImportMode.Keep)
        {
            checks.Add(RebuildCheck.Skipped("imports", "kept as loaded"));
            return null;
        }
        if (!TryDirectory(image, out bool is64, out uint dirRva, out uint dirSize) || dirRva == 0 || dirSize == 0)
        {
            checks.Add(RebuildCheck.Skipped("imports", "no import directory"));
            return null;
        }

        int width = is64 ? 8 : 4;
        int modules = 0, restored = 0, unresolved = 0;
        List<(uint Rva, ulong Value)> pending = [];
        string? stopped = null;
        long count = dirSize / DescriptorSize;
        for (long i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            long at = dirRva + i * DescriptorSize;
            if (at + DescriptorSize > image.Length)
            {
                stopped = "import directory runs past the image";
                break;
            }
            var d = image.AsSpan((int)at, DescriptorSize);
            uint lookup = BinaryPrimitives.ReadUInt32LittleEndian(d), first = BinaryPrimitives.ReadUInt32LittleEndian(d[16..]);
            if (lookup == 0 && first == 0 && BinaryPrimitives.ReadUInt32LittleEndian(d[12..]) == 0) break;
            modules++;
            if (first == 0 || first >= image.Length) continue;

            bool tableUsable = lookup != 0 && lookup < image.Length;
            for (long slot = 0; ; slot++)
            {
                long slotAt = first + slot * width;
                if (slotAt + width > image.Length) break;
                long lookupAt = tableUsable ? lookup + slot * width : -1;
                bool lookupRead = lookupAt >= 0 && lookupAt + width <= image.Length && captured.PageCaptured((uint)lookupAt);
                ulong entry = lookupRead ? Read(image, (int)lookupAt, width) : 0;
                // Without a readable lookup table the loaded slot itself bounds the table.
                bool end = lookupRead ? entry == 0 : Read(image, (int)slotAt, width) == 0;
                if (end) break;
                if (lookupRead && captured.PageCaptured((uint)slotAt) && captured.PageCaptured((uint)(slotAt + width - 1)))
                {
                    Write(image, (int)slotAt, width, entry);
                    restored++;
                }
                else
                {
                    unresolved++;
                    if (slotAt + width <= image.Length) pending.Add(((uint)slotAt, Read(image, (int)slotAt, width)));
                }
            }
        }

        var names = Name(pending, memory);
        unresolved -= names.Count;
        var summary = new ImportSummary(modules, restored, names.Count, unresolved, false) { Names = names };
        if (stopped == null && unresolved == 0 && names.Count == 0)
            checks.Add(RebuildCheck.Ok("imports", $"{restored} slots restored from {modules} modules"));
        else
            checks.Add(RebuildCheck.Partial("imports", $"{restored} slots restored, {names.Count} named from exports, {unresolved} unresolved in {modules} modules" + (stopped == null ? "" : $"; {stopped}")));
        return summary;
    }

    // The map is built only when a slot is left, as it reads every module's exports.
    private static IReadOnlyList<ResolvedImport> Name(List<(uint Rva, ulong Value)> pending, IProcessMemory memory)
    {
        if (pending.Count == 0 || memory == null) return [];
        var map = new ExportMap(memory);
        List<ResolvedImport> named = [];
        foreach (var (rva, value) in pending)
            if (map.NameAt(value) is { } name) named.Add(new ResolvedImport($"0x{rva:X}", name));
        return named;
    }

    private static bool TryDirectory(byte[] image, out bool is64, out uint rva, out uint size)
    {
        is64 = false;
        rva = size = 0;
        if (image.Length < 0x40) return false;
        long opt = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(0x3C)) + 24L;
        if (opt + 2 > image.Length) return false;
        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan((int)opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        is64 = magic == 0x20B;
        long dir = opt + (is64 ? 112 : 96) + 8;
        if (dir + 8 > image.Length) return false;
        rva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)dir));
        size = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan((int)dir + 4));
        return true;
    }

    private static ulong Read(byte[] image, int at, int width) =>
        width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at));

    private static void Write(byte[] image, int at, int width, ulong value)
    {
        if (width == 8) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at), value);
        else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(at), (uint)value);
    }
}
