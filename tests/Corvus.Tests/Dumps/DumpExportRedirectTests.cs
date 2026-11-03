using System.Buffers.Binary;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>An export address table entry rewritten to an address past its image.</summary>
public sealed class DumpExportRedirectTests : FileIsolationTestBase
{
    private const ulong AppBase = 0x140000000UL, LibBase = AppBase + 0x10000;

    // A dump where lib.dll exports beta at 0x1010 in the file and the table
    // entry holds a stub address past the image; app.exe imports beta and
    // holds the stub. The folder holds both files.
    private (string Dump, string Images) RewrittenDump()
    {
        PeSpec Spec(IReadOnlyList<ExportSpec>? exports, IReadOnlyList<ImportSpec>? imports = null) =>
            new(true, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())], Exports: exports, Imports: imports);
        var lib = RebuildFixtures.Build(Spec([new ExportSpec("beta", 0x1010)]));
        var app = RebuildFixtures.Build(Spec(null, [new ImportSpec("lib.dll", ["beta"])]));
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);
        var appMapped = RebuildFixtures.Mapped(app.Bytes);
        int libNt = BinaryPrimitives.ReadInt32LittleEndian(lib.Bytes.AsSpan(0x3C));
        uint exportDir = BinaryPrimitives.ReadUInt32LittleEndian(libMapped.AsSpan(libNt + 24 + 112));
        uint entry = BinaryPrimitives.ReadUInt32LittleEndian(libMapped.AsSpan((int)exportDir + 28));
        uint stub = (uint)libMapped.Length + 0x2C;
        BinaryPrimitives.WriteUInt32LittleEndian(libMapped.AsSpan((int)entry), stub);
        BinaryPrimitives.WriteUInt64LittleEndian(appMapped.AsSpan((int)app.IatSlots["lib.dll!beta"]), LibBase + stub);

        var b = new MinidumpBuilder();
        int appNt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)appMapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(appNt + 8)), "app.exe"));
        b.Modules.Add(new MinidumpBuilder.Module(LibBase, (uint)libMapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(lib.Bytes.AsSpan(libNt + 8)), "lib.dll"));
        b.Memory.Add((AppBase, appMapped));
        b.Memory.Add((LibBase, libMapped));
        b.Memory.Add((LibBase + stub, new byte[0x40]));
        var dump = _dir.File("rewritten.dmp");
        File.WriteAllBytes(dump, b.Build());
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        File.WriteAllBytes(Path.Combine(images, "lib.dll"), lib.Bytes);
        return (dump, images);
    }

    // Regression: an export table entry rewritten to a stub past the image
    // read as not exported.
    [Fact]
    public async Task An_export_entry_past_the_image_binds_the_importing_slot()
    {
        var (dump, images) = RewrittenDump();
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "app.exe", imageDirectories: images);

        Assert.DoesNotContain("does not export", text);
        Assert.DoesNotContain("unknown", text);
    }

    [Fact]
    public async Task A_changed_export_entry_names_the_export_and_both_targets()
    {
        var (dump, images) = RewrittenDump();
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "lib.dll", imageDirectories: images);

        Assert.Contains("beta: RVA 0x1010 to 0x", text);
        Assert.Contains("past the image", text);
    }
}
