using System.Buffers.Binary;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Import slot rows and export table rows name where a stub chain ends.</summary>
public sealed class DumpSlotChainTests : FileIsolationTestBase
{
    private const uint ExportRva = 0x1020, SpareRva = 0x1010, StubGap = 0x40;

    public static TheoryData<bool> Widths => new() { true, false };

    // A dump where lib.dll exports target and spare, the spare's table entry and
    // app.exe's import slot for target both hold the first of two jump stubs
    // past the lib image, and the last stub jumps to target.
    private (string Dump, string Images) StubbedDump(bool is64)
    {
        ulong appBase = is64 ? 0x140000000UL : 0x10000000UL;
        ulong libBase = is64 ? 0x150000000UL : 0x20000000UL;
        PeSpec Spec(ulong at, IReadOnlyList<ExportSpec>? exports, IReadOnlyList<ImportSpec>? imports = null) =>
            new(is64, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())],
                ImageBase: at, Exports: exports, Imports: imports);
        var lib = RebuildFixtures.Build(Spec(libBase, [new ExportSpec("target", ExportRva), new ExportSpec("spare", SpareRva)]));
        var app = RebuildFixtures.Build(Spec(appBase, null, [new ImportSpec("lib.dll", ["target"])]));
        // The fixture leaves the import address table directory empty; the file declares the slot as one.
        int appFileNt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        int iatEntry = appFileNt + 24 + (is64 ? 112 : 96) + 12 * 8;
        uint slotRva = app.IatSlots["lib.dll!target"];
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(iatEntry), slotRva);
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(iatEntry + 4), is64 ? 8u : 4u);
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);
        var appMapped = RebuildFixtures.Mapped(app.Bytes);

        uint first = (uint)libMapped.Length + StubGap, second = first + StubGap;
        var stubs = new byte[2 * (int)StubGap];
        Jump(stubs.AsSpan(0), libBase + first, libBase + second);
        Jump(stubs.AsSpan((int)StubGap), libBase + second, libBase + ExportRva);

        int libNt = BinaryPrimitives.ReadInt32LittleEndian(lib.Bytes.AsSpan(0x3C));
        int dataDirectories = libNt + 24 + (is64 ? 112 : 96);
        uint exportDir = BinaryPrimitives.ReadUInt32LittleEndian(libMapped.AsSpan(dataDirectories));
        uint table = BinaryPrimitives.ReadUInt32LittleEndian(libMapped.AsSpan((int)exportDir + 28));
        // Exports sort by name: spare is the first entry of the address table.
        BinaryPrimitives.WriteUInt32LittleEndian(libMapped.AsSpan((int)table), first);
        int slot = (int)slotRva;
        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(appMapped.AsSpan(slot), libBase + first);
        else BinaryPrimitives.WriteUInt32LittleEndian(appMapped.AsSpan(slot), (uint)(libBase + first));

        var b = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
        int appNt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        b.Modules.Add(new MinidumpBuilder.Module(appBase, (uint)appMapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(appNt + 8)), "app.exe"));
        b.Modules.Add(new MinidumpBuilder.Module(libBase, (uint)libMapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(lib.Bytes.AsSpan(libNt + 8)), "lib.dll"));
        b.Memory.Add((appBase, appMapped));
        b.Memory.Add((libBase, libMapped));
        b.Memory.Add((libBase + first, stubs));
        var dump = _dir.File($"stubbed-{is64}.dmp");
        File.WriteAllBytes(dump, b.Build());
        var images = Directory.CreateDirectory(_dir.File($"bin-{is64}")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        File.WriteAllBytes(Path.Combine(images, "lib.dll"), lib.Bytes);
        return (dump, images);
    }

    // Writes a jump by rel32, which both machines decode.
    private static void Jump(Span<byte> into, ulong at, ulong target)
    {
        into[0] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(into[1..], (int)(target - (at + 5)));
    }

    [Theory]
    [MemberData(nameof(Widths))]
    public async Task An_import_slot_pointing_at_a_stub_names_the_final_export(bool is64)
    {
        var (dump, images) = StubbedDump(is64);
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "app.exe", imageDirectories: images);
        Assert.Contains("then lib.dll!target (2 hops)", text);
    }

    [Theory]
    [MemberData(nameof(Widths))]
    public async Task An_export_entry_pointing_at_a_stub_names_the_final_export(bool is64)
    {
        var (dump, images) = StubbedDump(is64);
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "lib.dll", imageDirectories: images);
        Assert.Contains("spare: RVA 0x1010 to 0x", text);
        Assert.Contains("then lib.dll!target (2 hops)", text);
    }
}
