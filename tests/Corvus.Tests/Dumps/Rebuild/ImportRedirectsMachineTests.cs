using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Import slots matched by the importer's machine and checked against the file.</summary>
public sealed class ImportRedirectsMachineTests : IDisposable
{
    private const ulong HostBase = 0x100000000UL, AppBase = 0x140000000UL, Lib64 = 0x180000000UL, Lib32 = 0x20000000UL, Other32 = 0x30000000UL;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(bool is64, IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(is64,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    private IReadOnlyList<ImportRedirect> Run(PeBuilt app, bool withFile, params Placed[] others) => Run(app, withFile ? app.Bytes : null, others);

    private IReadOnlyList<ImportRedirect> Run(PeBuilt app, byte[]? fileBytes, params Placed[] others)
    {
        var host = RebuildFixtures.Build(Spec(true));
        using var dump = RebuildFixtures.Dump(_dir, [new Placed("host.exe", host, HostBase), .. others]);
        var module = dump.Modules.First(m => m.FileName == "app.exe");
        var mapped = new byte[module.Size];
        dump.ReadMemory(module.Base, mapped);
        var captured = new CapturedImage(RebuildTarget.Of(module), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        return ImportRedirects.Find(mapped, captured, new ExportMap(dump), dump, null, fileBytes is null ? null : PeFile.FromBytes(fileBytes));
    }

    [Fact]
    public void A_64_bit_importer_binds_to_the_64_bit_module_of_the_same_name()
    {
        var lib64 = RebuildFixtures.Build(Spec(true, exports: [new ExportSpec("alpha", 0x1000)]));
        var lib32 = RebuildFixtures.Build(Spec(false, exports: [new ExportSpec("alpha", 0x1002)]));
        var app = RebuildFixtures.Build(Spec(true, [new ImportSpec("lib.dll", ["alpha"])]));
        var values = new Dictionary<string, ulong> { ["lib.dll!alpha"] = Lib64 + 0x1000 };

        var rows = Run(app, false, new Placed("app.exe", app, AppBase, IatValues: values),
            new Placed("x86/lib.dll", lib32, Lib32), new Placed("x64/lib.dll", lib64, Lib64));

        Assert.Empty(rows);
    }

    [Fact]
    public void Unbound_slots_of_a_32_bit_importer_in_a_64_bit_dump_give_no_rows()
    {
        var app = RebuildFixtures.Build(Spec(false, [new ImportSpec("mscoree.dll", ["_CorExeMain", "_CorDllMain"])]));

        var placed = new Placed("app.exe", app, Lib32);

        Assert.Empty(Run(app, true, placed));
        Assert.All(Run(app, false, placed), r => Assert.Equal("unknown", r.State));
    }

    [Fact]
    public void A_32_bit_slot_pointing_into_another_module_is_a_redirect_naming_it()
    {
        var lib = RebuildFixtures.Build(Spec(false, exports: [new ExportSpec("alpha", 0x1000)]));
        var other = RebuildFixtures.Build(Spec(false));
        var app = RebuildFixtures.Build(Spec(false, [new ImportSpec("lib.dll", ["alpha"])]));
        var values = new Dictionary<string, ulong> { ["lib.dll!alpha"] = Other32 + 0x1004 };

        var row = Assert.Single(Run(app, true, new Placed("app.exe", app, 0x10000000UL, IatValues: values),
            new Placed("lib.dll", lib, Lib32), new Placed("other.dll", other, Other32)));

        Assert.Equal("redirected", row.State);
        Assert.Equal(Lib32 + 0x1000, row.Expected);
        Assert.Equal("other.dll+0x1004", row.Target);
    }

    [Fact]
    public void A_changed_address_table_slot_no_import_names_is_a_redirect_naming_its_module()
    {
        var other = RebuildFixtures.Build(Spec(false));
        byte[] pointer = BitConverter.GetBytes((uint)(Other32 + 0x1004));
        var spec = new PeSpec(false, [new SectionSpec(".text", 0x60000020, [.. pointer, 0xC3, 0xCC, 0xCC, 0xCC])]);
        var built = RebuildFixtures.Build(spec);
        // Data directory 12 (address table) covers the first four bytes of
        // .text.
        byte[] file = built.Bytes.ToArray();
        int optional = BitConverter.ToInt32(file, 0x3C) + 24;
        BitConverter.GetBytes(0x1000u).CopyTo(file, optional + 96 + 12 * 8);
        BitConverter.GetBytes(4u).CopyTo(file, optional + 96 + 12 * 8 + 4);
        // The file holds a zero where the dump holds the pointer.
        byte[] onDisk = file.ToArray();
        int at = file.AsSpan().IndexOf(pointer);
        onDisk.AsSpan(at, 4).Clear();
        var app = built with { Bytes = file };

        var row = Assert.Single(Run(app, onDisk, new Placed("app.exe", app, 0x10000000UL), new Placed("other.dll", other, Other32)));

        Assert.Equal("redirected", row.State);
        Assert.Null(row.Expected);
        Assert.Equal("other.dll+0x1004", row.Target);
    }
}
