using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>Where the slots sit in the main image's data section.</summary>
public enum SlotPlacement
{
    /// <summary>Past the raw data of a section whose virtual size is larger.</summary>
    PastRawData,

    /// <summary>In a section with no raw data.</summary>
    NoRawData,
}

/// <summary>
/// A dump whose main image holds addresses in data the file leaves zero: the dump, the image files, the slot RVAs
/// and the <c>module!name</c> each slot should resolve to ("" when the value names no export).
/// </summary>
internal sealed record PointerTable(
    string DumpPath,
    string ImageFolder,
    string MainName,
    ulong MainBase,
    bool Is64,
    uint DataRva,
    uint DataVirtualSize,
    uint DataRawSize,
    IReadOnlyList<uint> SlotRvas,
    IReadOnlyList<string> Expected,
    IReadOnlyList<ulong> Values);

/// <summary>Builds dumps of modules that fill function pointers at run time, from synthetic images.</summary>
internal static class PointerTableFixtures
{
    /// <summary>Name of the main image in every fixture.</summary>
    public const string Main = "main.dll";

    /// <summary>Name of the image that exports the functions the slots point at.</summary>
    public const string Provider = "provider.dll";

    /// <summary>Name of the image the forwarded export resolves into.</summary>
    public const string Third = "third.dll";

    private const uint DataFlags = 0xC0000040;
    private const uint UninitializedFlags = 0xC0000080;
    private const uint PastRawStart = 0x300;
    private const uint NoRawStart = 0x100;
    private const uint PastRawSize = 0x200;
    private const uint DataSize = 0x1000;
    private const uint Page = 0x1000;

    // Provider exports in ordinal order: five by name, one by ordinal only, one
    // forwarded.
    private static readonly string[] Cycle =
    [
        "Alpha", "Beta", "Delta", "Gamma", "#6", "Fwd",
    ];

    /// <summary>
    /// Returns a dump where <paramref name="count"/> slots, then a zero entry, hold provider export addresses
    /// in cycling order (named, by ordinal, forwarded). Throws when the slots do not fit the section.
    /// </summary>
    public static PointerTable Table(TempDir dir, bool is64, SlotPlacement placement, int count,
        IReadOnlyList<uint>? omittedPages = null)
    {
        var provider = Images(is64, out var third, out var main, placement);
        var names = Enumerable.Range(0, count).Select(i => Cycle[i % Cycle.Length]).ToList();
        var values = names.Select(n => ExportAddress(provider, third, n)).ToList();
        return Write(dir, is64, placement, main, provider, third, values,
            names.Select(n => ExpectedName(n)).ToList(), count + 1, 0, omittedPages);
    }

    /// <summary>
    /// Returns a dump where one slot holds an export address between two ordinary nonzero values.
    /// </summary>
    public static PointerTable Single(TempDir dir, bool is64, SlotPlacement placement, string export = "Beta",
        IReadOnlyList<uint>? omittedPages = null)
    {
        var provider = Images(is64, out var third, out var main, placement);
        ulong before = is64 ? 0x1111111122222222UL : 0x11112222UL;
        ulong after = is64 ? 0x3333333344444444UL : 0x33334444UL;
        var values = new List<ulong> { before, ExportAddress(provider, third, export), after };
        return Write(dir, is64, placement, main, provider, third, values, [ExpectedName(export)], 3, 1,
            omittedPages);
    }

    /// <summary>
    /// Returns a dump where <paramref name="count"/> slots, then a zero entry, point into the main image itself
    /// (its three exports, cycling).
    /// </summary>
    public static PointerTable IntoSelf(TempDir dir, bool is64, SlotPlacement placement, int count,
        IReadOnlyList<uint>? omittedPages = null)
    {
        var provider = Images(is64, out var third, out var main, placement);
        ulong mainBase = main.Spec.Base;
        string[] own = ["MainA", "MainB", "MainC"];
        var names = Enumerable.Range(0, count).Select(i => own[i % own.Length]).ToList();
        var values = names.Select(n => mainBase + main.Spec.Exports!.First(e => e.Name == n).Rva).ToList();
        return Write(dir, is64, placement, main, provider, third, values,
            names.Select(n => $"{Main}!{n}").ToList(), count + 1, 0, omittedPages);
    }

    private sealed record Built(PeSpec Spec, byte[] Bytes);

    private sealed record ProviderImage(PeSpec Spec, byte[] Bytes, ulong Base, ulong ThirdBase, uint ForwardRva);

    private static ProviderImage Images(bool is64, out Built third, out Built main, SlotPlacement placement)
    {
        ulong providerBase = is64 ? 0x180000000UL : 0x10000000UL;
        ulong thirdBase = is64 ? 0x1C0000000UL : 0x20000000UL;

        var thirdSpec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, new byte[0x40])], ImageBase: thirdBase,
            Exports: [new ExportSpec("Target", 0x1020)]);
        third = new Built(thirdSpec, RebuildFixtures.Pe(thirdSpec));

        var providerSpec = new PeSpec(is64, [new SectionSpec(".text", 0x60000020, new byte[0x80])],
            ImageBase: providerBase,
            Exports:
            [
                new("Alpha", 0x1000), new("Beta", 0x1010), new("Delta", 0x1020), new("Gamma", 0x1030),
                new("Fwd", 0), new("~ord", 0x1040),
            ]);
        var providerBytes = RebuildFixtures.Pe(providerSpec);
        uint forward = PatchExports(providerBytes, "third.Target");

        var mainSpec = new PeSpec(is64,
            [
                new SectionSpec(".text", 0x60000020, new byte[0x40]),
                new SectionSpec(".data", placement == SlotPlacement.NoRawData ? UninitializedFlags : DataFlags,
                    InitialData(placement)),
            ],
            ImageBase: is64 ? 0x140000000UL : 0x00400000UL,
            Exports: [new("MainA", 0x1000), new("MainB", 0x1010), new("MainC", 0x1020)]);
        var mainBytes = RebuildFixtures.Pe(mainSpec);
        PatchRawData(mainBytes, ".data", placement == SlotPlacement.NoRawData ? 0 : PastRawSize);
        main = new Built(mainSpec, mainBytes);
        return new ProviderImage(providerSpec, providerBytes, providerBase, thirdBase, forward);
    }

    private static byte[] InitialData(SlotPlacement placement)
    {
        var data = new byte[DataSize];
        // Nonzero bytes in the raw part so the file differs from a zero-filled section.
        if (placement == SlotPlacement.PastRawData) Array.Fill(data, (byte)0x5A, 0, (int)PastRawSize);
        return data;
    }

    private static string ExpectedName(string name) => name switch
    {
        "Fwd" => $"{Third}!Target",
        "#6" => $"{Provider}!#6",
        _ => $"{Provider}!{name}",
    };

    private static ulong ExportAddress(ProviderImage provider, Built third, string name)
    {
        if (name == "Fwd") return provider.ThirdBase + third.Spec.Exports![0].Rva;
        if (name == "#6") return provider.Base + provider.Spec.Exports!.First(e => e.Name == "~ord").Rva;
        return provider.Base + provider.Spec.Exports!.First(e => e.Name == name).Rva;
    }

    private static PointerTable Write(TempDir dir, bool is64, SlotPlacement placement, Built main,
        ProviderImage provider, Built third, List<ulong> values, List<string> expected, int slots, int firstExpected,
        IReadOnlyList<uint>? omittedPages)
    {
        int width = is64 ? 8 : 4;
        uint start = placement == SlotPlacement.NoRawData ? NoRawStart : PastRawStart;
        if (start + (uint)(slots * width) > DataSize)
            throw new ArgumentException($"{slots} slots do not fit the {DataSize:X}-byte section.");

        var dataSection = Sections(main.Bytes).First(s => s.Name == ".data");
        uint dataRva = dataSection.Rva;
        var mapped = RebuildFixtures.Mapped(main.Bytes);
        var rvas = new List<uint>();
        for (int i = 0; i < values.Count; i++)
        {
            uint rva = dataRva + start + (uint)(i * width);
            rvas.Add(rva);
            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(mapped.AsSpan((int)rva), values[i]);
            else BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan((int)rva), (uint)values[i]);
        }

        var folder = Directory.CreateDirectory(dir.File($"images-{Guid.NewGuid():N}")).FullName;
        File.WriteAllBytes(Path.Combine(folder, Main), main.Bytes);
        File.WriteAllBytes(Path.Combine(folder, Provider), provider.Bytes);
        File.WriteAllBytes(Path.Combine(folder, Third), third.Bytes);

        var builder = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
        var omitted = (omittedPages ?? []).Select(r => r / Page).ToHashSet();
        Add(builder, Main, main.Bytes, main.Spec.Base, mapped, omitted);
        Add(builder, Provider, provider.Bytes, provider.Base, RebuildFixtures.Mapped(provider.Bytes), []);
        Add(builder, Third, third.Bytes, provider.ThirdBase, RebuildFixtures.Mapped(third.Bytes), []);
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        string path = dir.File($"table-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, builder.Build());

        var slotRvas = rvas.Skip(firstExpected).Take(expected.Count).ToList();
        var slotValues = values.Skip(firstExpected).Take(expected.Count).ToList();
        return new PointerTable(path, folder, Main, main.Spec.Base, is64, dataRva, dataSection.VirtualSize,
            dataSection.RawSize, slotRvas, expected, slotValues);
    }

    private static void Add(MinidumpBuilder builder, string name, byte[] file, ulong at, byte[] mapped,
        HashSet<uint> omitted)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(nt + 8));
        builder.Modules.Add(new MinidumpBuilder.Module(at, (uint)mapped.Length, stamp, name));
        int padded = (mapped.Length + (int)Page - 1) / (int)Page * (int)Page;
        var captured = new byte[padded];
        mapped.CopyTo(captured, 0);
        int run = -1;
        for (int offset = 0; offset <= padded; offset += (int)Page)
        {
            bool present = offset < padded && !omitted.Contains((uint)(offset / Page));
            if (present && run < 0) run = offset;
            if (!present && run >= 0)
            {
                builder.Memory.Add((at + (ulong)run, captured[run..offset]));
                run = -1;
            }
        }
    }

    internal sealed record SectionRow(string Name, uint Rva, uint VirtualSize, uint RawSize, uint RawAt, int Header);

    /// <summary>Returns the section table of a PE file as rows; a malformed file throws.</summary>
    internal static List<SectionRow> Sections(byte[] file)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int optional = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        var rows = new List<SectionRow>();
        for (int i = 0; i < count; i++)
        {
            int h = nt + 24 + optional + 40 * i;
            string name = Encoding.ASCII.GetString(file, h, 8).TrimEnd('\0');
            rows.Add(new SectionRow(name,
                BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 12)),
                BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 8)),
                BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 16)),
                BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 20)), h));
        }
        return rows;
    }

    // Shrinks the raw data of a section in place; zero also clears its file offset.
    private static void PatchRawData(byte[] file, string section, uint rawSize)
    {
        var row = Sections(file).First(s => s.Name == section);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(row.Header + 16), rawSize);
        if (rawSize == 0) BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(row.Header + 20), 0);
    }

    // Makes "Fwd" a forwarder and "~ord" an export by ordinal only; returns the
    // forwarder string's RVA.
    private static uint PatchExports(byte[] file, string forwarder)
    {
        var row = Sections(file).First(s => s.Name == ".edata");
        int at = (int)row.RawAt;
        int functions = (int)BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 20));
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(at + 24), (uint)(functions - 1));

        var text = Encoding.ASCII.GetBytes(forwarder + "\0");
        if (row.VirtualSize + text.Length > row.RawSize)
            throw new InvalidOperationException("The export section has no room for the forwarder text.");
        uint forwardRva = row.Rva + row.VirtualSize;
        text.CopyTo(file, at + (int)row.VirtualSize);
        // Fwd is the fourth address entry in name order.
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(at + 40 + 4 * 3), forwardRva);
        uint grown = row.VirtualSize + (uint)text.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(row.Header + 8), grown);

        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int directories = nt + 24 + (BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 24)) == 0x20B ? 112 : 96);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(directories + 4), grown);
        return forwardRva;
    }
}
