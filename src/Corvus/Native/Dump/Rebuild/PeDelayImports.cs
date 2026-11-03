using System.Buffers.Binary;
using System.Text;
using Corvus.Native.Pe;

namespace Corvus.Native.Dump.Rebuild;

/// <summary>One delay-load import: its address table slot, and the name or ordinal from the name table.</summary>
/// <param name="Rva">The RVA of the address table slot.</param>
/// <param name="Function">The imported name; null for an ordinal import or when the name was not captured.</param>
/// <param name="Ordinal">The imported ordinal; null for a name import or when the entry was not captured.</param>
/// <param name="State"><c>unresolved</c> (slot holds an address in the image), <c>resolved</c> (outside it) or <c>unknown</c>.</param>
/// <param name="Value">The slot value; zero when its page was not captured.</param>
public sealed record DelayLoadSlot(uint Rva, string? Function, int? Ordinal, string State, ulong Value);

/// <summary>One delay-load descriptor and its slots.</summary>
/// <param name="Descriptor">The RVA of the descriptor.</param>
/// <param name="Module">The imported module name; null when it was not captured.</param>
/// <param name="State"><c>ok</c> or <c>unknown</c> when the descriptor, a table or the module name was not captured.</param>
public sealed record DelayLoadModule(uint Descriptor, string? Module, string State, IReadOnlyList<DelayLoadSlot> Slots);

/// <summary>The delay-load imports of an image.</summary>
/// <param name="Truncated">True when the slot limit stopped the listing.</param>
public sealed record DelayImportList(IReadOnlyList<DelayLoadModule> Modules, bool Truncated)
{
    /// <summary>The most slots listed.</summary>
    public int Limit => PeDelayImports.MaxSlots;
}

/// <summary>Reads the delay-load import directory of a mapped image.</summary>
public static class PeDelayImports
{
    /// <summary>The most slots listed over all descriptors.</summary>
    public const int MaxSlots = 64 * 1024;

    private const int DescriptorSize = 32;
    private const int DelayDirectory = 13;
    private const int MaxNameBytes = PeLimits.MaxNameLength;

    /// <summary>
    /// Lists each delay-load descriptor of <paramref name="mapped"/> (offset = RVA) with its slots.
    /// Empty when the image has no delay-load directory; a part on a page that was not captured is listed as unknown.
    /// </summary>
    public static DelayImportList Read(byte[] mapped, CapturedImage captured)
    {
        if (!TryHeader(mapped, out bool is64, out ulong imageBase, out uint dirRva, out uint dirSize) || dirRva == 0 || dirSize == 0)
            return new DelayImportList([], false);

        int width = is64 ? 8 : 4;
        ulong ordinalFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
        ulong imageEnd = captured.Target.Base + (ulong)mapped.Length;
        var modules = new List<DelayLoadModule>();
        int slotCount = 0;
        long count = dirSize / DescriptorSize;
        for (long i = 0; i < count; i++)
        {
            long at = dirRva + i * DescriptorSize;
            if (at + DescriptorSize > mapped.Length) break;
            uint descriptor = (uint)at;
            if (!Readable(mapped, captured, at, DescriptorSize))
            {
                modules.Add(new DelayLoadModule(descriptor, null, "unknown", []));
                continue;
            }
            var d = mapped.AsSpan((int)at, DescriptorSize);
            if (!d.ContainsAnyExcept((byte)0)) break;

            // Attributes bit 0 set: fields are RVAs; clear: virtual addresses
            // from the image base.
            bool rvaForm = (BinaryPrimitives.ReadUInt32LittleEndian(d) & 1) != 0;
            uint dllName = Field(d[4..], rvaForm, imageBase), table = Field(d[12..], rvaForm, imageBase), names = Field(d[16..], rvaForm, imageBase);
            string state = "ok";
            string? module = dllName == 0 ? null : ReadAscii(mapped, captured, dllName);
            if (module == null) state = "unknown";

            var slots = new List<DelayLoadSlot>();
            bool truncated = false;
            if (table == 0 || names == 0) state = "unknown";
            else
            {
                for (long s = 0; ; s++)
                {
                    long entryAt = names + s * width;
                    if (entryAt + width > mapped.Length) break;
                    if (!Readable(mapped, captured, entryAt, width))
                    {
                        state = "unknown";
                        slots.Add(new DelayLoadSlot((uint)Math.Min(table + s * width, uint.MaxValue), null, null, "unknown", 0));
                        break;
                    }
                    ulong entry = ReadPointer(mapped, (int)entryAt, width);
                    if (entry == 0) break;
                    if (slotCount >= MaxSlots)
                    {
                        truncated = true;
                        break;
                    }
                    slotCount++;

                    string? function = null;
                    int? ordinal = null;
                    bool named = true;
                    if ((entry & ordinalFlag) != 0) ordinal = (int)(entry & 0xFFFF);
                    else
                    {
                        ulong hintName = rvaForm ? entry : entry >= imageBase ? entry - imageBase : 0;
                        function = hintName == 0 || hintName > uint.MaxValue ? null : ReadAscii(mapped, captured, (uint)hintName + 2);
                        named = function != null;
                    }

                    long slotAt = table + s * width;
                    uint slotRva = (uint)Math.Min(slotAt, uint.MaxValue);
                    if (slotAt + width > mapped.Length || !Readable(mapped, captured, slotAt, width))
                    {
                        state = "unknown";
                        slots.Add(new DelayLoadSlot(slotRva, function, ordinal, "unknown", 0));
                        continue;
                    }
                    ulong value = ReadPointer(mapped, (int)slotAt, width);
                    string slotState = !named ? "unknown" : value >= captured.Target.Base && value < imageEnd ? "unresolved" : "resolved";
                    if (!named) state = "unknown";
                    slots.Add(new DelayLoadSlot(slotRva, function, ordinal, slotState, value));
                }
            }
            modules.Add(new DelayLoadModule(descriptor, module, state, slots));
            if (truncated) return new DelayImportList(modules, true);
        }
        return new DelayImportList(modules, false);
    }

    /// <summary>
    /// Restores the resolved delay-load slots of <paramref name="image"/> (mapped layout) from <paramref name="file"/>, the file of the
    /// same build, and adds the "delay imports" check. Without a file the slots keep their captured values and each is named from
    /// the exports of <paramref name="memory"/> in the result; slots on pages not captured or outside the file's raw data stay as captured.
    /// </summary>
    public static IReadOnlyList<ResolvedImport> Restore(byte[] image, CapturedImage captured, byte[]? file, BaseMode mode, IProcessMemory memory, List<RebuildCheck> checks)
    {
        const string name = "delay imports";
        var list = Read(image, captured);
        if (list.Modules.Count == 0 || !TryHeader(image, out bool is64, out _, out _, out _))
        {
            checks.Add(RebuildCheck.Skipped(name, "no delay-load imports"));
            return [];
        }

        int width = is64 ? 8 : 4;
        var resolved = list.Modules.SelectMany(m => m.Slots).Where(s => s.State == "resolved").ToList();
        int unreadable = list.Modules.SelectMany(m => m.Slots).Count(s => s.State == "unknown");
        string limit = (list.Truncated ? $"; listing stopped at {list.Limit} slots" : "") + (unreadable == 0 ? "" : $"; {unreadable} slots not readable");

        if (file == null || !TryFileMap(file, out var map))
        {
            if (resolved.Count == 0 && limit.Length == 0)
            {
                checks.Add(RebuildCheck.Ok(name, "0 slots restored"));
                return [];
            }
            var exports = resolved.Count == 0 ? null : ExportMap.For(memory);
            var names = resolved.Select(s => (s, Name: exports!.NameAt(s.Value))).Where(x => x.Name != null)
                .Select(x => new ResolvedImport($"0x{x.s.Rva:X}", x.Name!)).ToList();
            checks.Add(RebuildCheck.Unknown(name, $"{resolved.Count} resolved slots kept: no file of the same build{limit}"));
            return names;
        }

        // File slots hold stub addresses at the preferred base. The load delta
        // is added only when the image keeps its loaded base.
        long delta = mode == BaseMode.Loaded ? unchecked((long)(captured.Target.Base - map.Base)) : 0;
        // A preferred-base rebuild already subtracted the delta from every
        // slot, so an unresolved slot now reads as an address at the preferred
        // base.
        if (mode == BaseMode.Preferred) resolved.RemoveAll(s => s.Value >= map.Base && s.Value - map.Base < (ulong)image.Length);
        int restored = 0, outside = 0;
        foreach (var slot in resolved)
        {
            if (!map.TryRead(slot.Rva, width, out var bytes) || slot.Rva + (uint)width > image.Length)
            {
                outside++;
                continue;
            }
            ulong value = ReadPointer(bytes.ToArray(), 0, width);
            value = unchecked(value + (ulong)delta);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan((int)slot.Rva), value);
            else BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan((int)slot.Rva), (uint)value);
            restored++;
        }

        if (outside == 0 && limit.Length == 0) checks.Add(RebuildCheck.Ok(name, $"{restored} slots restored"));
        else checks.Add(RebuildCheck.Partial(name, $"{restored} slots restored" + (outside == 0 ? "" : $"; {outside} outside the raw data of the file") + limit));
        return [];
    }

    private sealed class FileMap(byte[] file, ulong imageBase, List<(uint Rva, uint Size, uint Raw, uint RawSize)> sections)
    {
        public ulong Base => imageBase;

        public bool TryRead(uint rva, int length, out ReadOnlySpan<byte> bytes) =>
            PeLoaderPatches.TryReadSection(file, sections, rva, length, out bytes);
    }

    // The file's section map, to read bytes by RVA; false when its headers are
    // not readable.
    private static bool TryFileMap(byte[] file, out FileMap map)
    {
        map = default!;
        if (!TryHeader(file, out _, out ulong imageBase, out _, out _)) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        if (table + 40L * count > file.Length) return false;
        var sections = new List<(uint Rva, uint Size, uint Raw, uint RawSize)>();
        for (int i = 0; i < count; i++)
        {
            var s = file.AsSpan(table + 40 * i, 40);
            uint rawSize = BinaryPrimitives.ReadUInt32LittleEndian(s[16..]);
            uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(s[8..]);
            sections.Add((BinaryPrimitives.ReadUInt32LittleEndian(s[12..]), virtualSize == 0 ? rawSize : virtualSize, BinaryPrimitives.ReadUInt32LittleEndian(s[20..]), rawSize));
        }
        map = new FileMap(file, imageBase, sections);
        return true;
    }

    private static uint Field(ReadOnlySpan<byte> d, bool rvaForm, ulong imageBase)
    {
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(d);
        if (rvaForm || value == 0) return value;
        return value >= imageBase && value - imageBase <= uint.MaxValue ? (uint)(value - imageBase) : 0;
    }

    private static ulong ReadPointer(byte[] image, int at, int width) =>
        width == 8 ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(at));

    private static bool Readable(byte[] image, CapturedImage captured, long at, int length)
    {
        if (at < 0 || at + length > image.Length) return false;
        for (long page = at / 0x1000; page <= (at + length - 1) / 0x1000; page++)
            if (!captured.PageCaptured((uint)(page * 0x1000))) return false;
        return true;
    }

    // Null when the string leaves the captured pages before its terminator.
    private static string? ReadAscii(byte[] image, CapturedImage captured, uint rva)
    {
        for (uint i = 0; i < MaxNameBytes; i++)
        {
            long at = rva + (long)i;
            if (at >= image.Length || !captured.PageCaptured((uint)at)) return null;
            if (image[at] == 0) return Encoding.ASCII.GetString(image, (int)rva, (int)i);
        }
        return null;
    }

    private static bool TryHeader(byte[] image, out bool is64, out ulong imageBase, out uint dirRva, out uint dirSize)
    {
        is64 = false;
        imageBase = 0;
        dirRva = dirSize = 0;
        if (image.Length < 0x200) return false;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        if (nt < 0 || nt + 24 + 112 > image.Length || BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(nt)) != 0x4550) return false;
        int opt = nt + 24;
        int magic = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(opt));
        if (magic != 0x10B && magic != 0x20B) return false;
        is64 = magic == 0x20B;
        imageBase = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(opt + 24)) : BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + 28));
        int dirs = opt + (is64 ? 112 : 96);
        uint number = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(opt + (is64 ? 108 : 92)));
        int entry = dirs + DelayDirectory * 8;
        if (number <= DelayDirectory || entry + 8 > image.Length) return false;
        dirRva = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(entry));
        dirSize = BinaryPrimitives.ReadUInt32LittleEndian(image.AsSpan(entry + 4));
        return true;
    }
}
