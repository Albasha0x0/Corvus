using System.Buffers.Binary;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The ranges a module changed in memory, with names and descriptions, from one service call.</summary>
public sealed class DumpChangesTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, LibBase = AppBase + 0x10000;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(IReadOnlyList<ExportSpec>? exports = null, IReadOnlyList<ImportSpec>? imports = null)
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0x90);
        return new PeSpec(true, [new SectionSpec(".text", 0x60000020, code)], Exports: exports, Imports: imports);
    }

    private string ImageFolder(PeBuilt app)
    {
        var folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "app.exe"), app.Bytes);
        return folder;
    }

    // Regression: writes to a read-write-execute .data section were listed as
    // code changes.
    [Fact]
    public void A_write_to_a_writable_executable_section_is_a_data_row()
    {
        var app = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".data", 0xE0000040, new byte[0x40])]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        mapped[0x1010] = 1;
        var b = new MinidumpBuilder();
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C)) + 8)), "app.exe"));
        b.Memory.Add((AppBase, mapped));
        var path = _dir.File("rwx.dmp");
        File.WriteAllBytes(path, b.Build());

        var (_, rows, _, _) = new MinidumpService().Changes(path, ImageFolder(app), "app.exe", 0, 100, default);

        var row = Assert.Single(rows);
        Assert.Equal(".data", row.Section);
        Assert.Equal("data", row.Kind);
    }

    [Fact]
    public void A_patched_function_start_is_one_code_row_with_its_function_and_target()
    {
        var app = RebuildFixtures.Build(Spec([new ExportSpec("alpha", 0x1000)]));
        var lib = RebuildFixtures.Build(Spec([new ExportSpec("beta", 0x1010)]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        mapped[0x1000] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(mapped.AsSpan(0x1001), (int)(LibBase + 0x1010 - (AppBase + 0x1005)));
        var b = new MinidumpBuilder();
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C)) + 8)), "app.exe"));
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);
        b.Modules.Add(new MinidumpBuilder.Module(LibBase, (uint)libMapped.Length, 0, "lib.dll"));
        b.Memory.Add((AppBase, mapped));
        b.Memory.Add((LibBase, libMapped));
        var path = _dir.File("patched.dmp");
        File.WriteAllBytes(path, b.Build());

        var (_, rows, total, _) = new MinidumpService().Changes(path, ImageFolder(app), "app.exe", 0, 100, default);

        var row = Assert.Single(rows);
        Assert.Equal(1, total);
        Assert.Equal("code", row.Kind);
        Assert.Equal(".text", row.Section);
        Assert.Equal($"0x{AppBase + 0x1000:X}", row.Start);
        Assert.Equal(5, row.Length);
        Assert.Contains("alpha", row.Name);
        Assert.Contains("jump to", row.Description);
        Assert.Contains("beta", row.Description);
        Assert.StartsWith("e9", row.MemoryBytes);
        Assert.StartsWith("90", row.FileBytes);
    }

    [Fact]
    public void A_redirected_import_slot_is_one_import_row()
    {
        var lib = RebuildFixtures.Build(Spec([new ExportSpec("alpha", 0x1000)]));
        var app = RebuildFixtures.Build(Spec(imports: [new ImportSpec("lib.dll", ["alpha"])]));
        uint slot = app.IatSlots["lib.dll!alpha"];
        // The fixture leaves the import address table directory empty; the file
        // declares the slot as one.
        int nt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(nt + 24 + 112 + 12 * 8), slot);
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(nt + 24 + 112 + 12 * 8 + 4), 8);
        string path;
        using (var dump = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, AppBase, IatValues: new Dictionary<string, ulong> { ["lib.dll!alpha"] = 0x7FF000001000UL }),
            new Placed("lib.dll", lib, LibBase)))
            path = dump.Path;

        var (_, rows, _, _) = new MinidumpService().Changes(path, ImageFolder(app), "app.exe", 0, 100, default);

        var row = Assert.Single(rows);
        Assert.Equal("import", row.Kind);
        Assert.Equal("lib.dll!alpha", row.Name);
        Assert.Equal($"0x{AppBase + slot:X}", row.Start);
        Assert.Contains("0x7FF000001000", row.Description);
        Assert.Contains($"0x{LibBase + 0x1000:X}", row.Description);
    }

    [Fact]
    public void A_module_without_its_file_is_one_unknown_row()
    {
        var app = RebuildFixtures.Build(Spec([new ExportSpec("alpha", 0x1000)]));
        string path;
        using (var dump = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, AppBase)))
            path = dump.Path;

        var (_, rows, total, _) = new MinidumpService().Changes(path, null, null, 0, 100, default);

        var row = Assert.Single(rows);
        Assert.Equal(1, total);
        Assert.Equal("unknown", row.Kind);
        Assert.Equal("app.exe", row.Module);
        Assert.Contains("no file of the same build found", row.Description);
    }
}
