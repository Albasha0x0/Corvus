using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>A delay-load import by name, or by ordinal when <paramref name="Name"/> is null.</summary>
internal sealed record DelayFunction(string? Name, ushort Ordinal = 0)
{
    /// <summary>Returns an import by name.</summary>
    public static DelayFunction Named(string name) => new(name);

    /// <summary>Returns an import by ordinal.</summary>
    public static DelayFunction ByOrdinal(ushort ordinal) => new(null, ordinal);
}

/// <summary>A module imported with delay loading, and the functions imported from it.</summary>
internal sealed record DelayImportSpec(string Module, IReadOnlyList<DelayFunction> Functions);

/// <summary>RVAs of one delay-load import: its name table entry, address table slot and in-image stub.</summary>
internal sealed record DelaySlot(string Key, uint NameEntryRva, uint SlotRva, uint StubRva);

/// <summary>RVAs of one delay-load descriptor and the tables it points at.</summary>
internal sealed record DelayDescriptor(
    string Module,
    uint DescriptorRva,
    uint DllNameRva,
    uint ModuleHandleRva,
    uint AddressTableRva,
    uint NameTableRva,
    IReadOnlyList<DelaySlot> Slots);

/// <summary>A built PE file with a delay-load import directory and the RVA of each part of it.</summary>
internal sealed record DelayImportBuilt(byte[] Bytes, uint DirectoryRva, IReadOnlyList<DelayDescriptor> Descriptors)
{
    /// <summary>Returns the slot keyed <c>module!name</c> or <c>module!#ordinal</c>; throws when absent.</summary>
    public DelaySlot Slot(string key) =>
        Descriptors.SelectMany(d => d.Slots).First(s => s.Key == key);
}

/// <summary>Builds synthetic PE files with a delay-load import directory, as a linker emits it.</summary>
internal static class DelayImportFixtures
{
    private const int DescriptorSize = 32;
    private const int StubSize = 8;
    private const int DelayDirectory = 13;
    private const uint DelaySectionFlags = 0xE0000060;

    /// <summary>
    /// Returns the image of <paramref name="spec"/> with a <c>.didat</c> section holding the delay-load imports.
    /// Descriptors use RVAs (Attributes bit 0); each address table slot holds the absolute address of its stub.
    /// </summary>
    public static DelayImportBuilt Build(PeSpec spec, IReadOnlyList<DelayImportSpec> imports)
    {
        int width = spec.Is64Bit ? 8 : 4;
        uint sectionRva = spec.SectionAlignment;
        foreach (var s in spec.Sections)
            sectionRva = Align(sectionRva + (uint)Math.Max(s.Raw.Length, 1), spec.SectionAlignment);

        var raw = new List<byte>();
        raw.AddRange(new byte[(imports.Count + 1) * DescriptorSize]);
        var descriptors = new List<DelayDescriptor>();
        var pointers = new List<PointerSite>(spec.Pointers ?? []);
        int index = 0;
        foreach (var import in imports)
        {
            uint Here() => sectionRva + (uint)raw.Count;
            void Pad(int to) { while (raw.Count % to != 0) raw.Add(0); }

            uint dllName = Here();
            raw.AddRange(Encoding.ASCII.GetBytes(import.Module));
            raw.Add(0);
            Pad(width);
            uint handle = Here();
            raw.AddRange(new byte[width]);
            uint iat = Here();
            raw.AddRange(new byte[width * (import.Functions.Count + 1)]);
            uint names = Here();
            raw.AddRange(new byte[width * (import.Functions.Count + 1)]);

            var slots = new List<DelaySlot>();
            for (int i = 0; i < import.Functions.Count; i++)
            {
                var f = import.Functions[i];
                uint entry = names + (uint)(i * width);
                if (f.Name is null)
                {
                    ulong flag = spec.Is64Bit ? 0x8000000000000000UL : 0x80000000UL;
                    WritePointer(raw, (int)(entry - sectionRva), flag | f.Ordinal, width);
                }
                else
                {
                    Pad(2);
                    WritePointer(raw, (int)(entry - sectionRva), Here(), width);
                    raw.AddRange(new byte[2]);
                    raw.AddRange(Encoding.ASCII.GetBytes(f.Name));
                    raw.Add(0);
                }
                Pad(StubSize);
                uint stub = Here();
                raw.AddRange(Enumerable.Repeat((byte)0xCC, StubSize));
                uint slot = iat + (uint)(i * width);
                pointers.Add(new PointerSite(".didat", (int)(slot - sectionRva), stub));
                string key = f.Name is null ? $"{import.Module}!#{f.Ordinal}" : $"{import.Module}!{f.Name}";
                slots.Add(new DelaySlot(key, entry, slot, stub));
            }
            Pad(4);

            int d = index * DescriptorSize;
            WriteUInt32(raw, d, 1);
            WriteUInt32(raw, d + 4, dllName);
            WriteUInt32(raw, d + 8, handle);
            WriteUInt32(raw, d + 12, iat);
            WriteUInt32(raw, d + 16, names);
            descriptors.Add(new DelayDescriptor(import.Module, sectionRva + (uint)d, dllName, handle, iat, names, slots));
            index++;
        }

        var sections = new List<SectionSpec>(spec.Sections) { new(".didat", DelaySectionFlags, [.. raw]) };
        var file = RebuildFixtures.Pe(spec with { Sections = sections, Pointers = pointers });
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int dirs = nt + 24 + (spec.Is64Bit ? 112 : 96) + DelayDirectory * 8;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs), sectionRva);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(dirs + 4), (uint)((imports.Count + 1) * DescriptorSize));
        return new DelayImportBuilt(file, sectionRva, descriptors);
    }

    /// <summary>Writes the address into the slot of a mapped image, as the delay-load helper does after a call.</summary>
    public static void WriteResolved(byte[] mapped, bool is64, DelaySlot slot, ulong address)
    {
        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(mapped.AsSpan((int)slot.SlotRva), address);
        else BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan((int)slot.SlotRva), (uint)address);
    }

    private static uint Align(uint value, uint alignment) => (value + alignment - 1) / alignment * alignment;

    private static void WriteUInt32(List<byte> raw, int at, uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        for (int i = 0; i < 4; i++) raw[at + i] = bytes[i];
    }

    private static void WritePointer(List<byte> raw, int at, ulong value, int width)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
        for (int i = 0; i < width; i++) raw[at + i] = bytes[i];
    }
}
