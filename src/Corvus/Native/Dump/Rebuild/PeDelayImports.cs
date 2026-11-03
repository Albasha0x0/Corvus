using System.Buffers.Binary;
using System.Text;

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
    private const int MaxNameBytes = 4096;

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
