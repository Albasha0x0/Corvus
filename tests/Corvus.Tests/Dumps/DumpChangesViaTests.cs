using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A changed import row names the API set map that resolved its contract.</summary>
public sealed class DumpChangesViaTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, LibBase = 0x180000000UL;
    private const ulong Peb = 0x7FFD0000UL, MapAt = 0x7FFE0000UL;
    private const string Contract = "api-ms-win-core-synch-l1-2-0.dll";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    // The file declares its import slot as an address table; the dump holds a
    // map that sends the contract to lib.dll and a slot pointing elsewhere.
    private (string Dump, string Images) Fixture()
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("InitOnceComplete", 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec(Contract, ["InitOnceComplete"])]));
        uint slot = app.IatSlots[Contract + "!InitOnceComplete"];
        int nt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(nt + 24 + 112 + 12 * 8), slot);
        BinaryPrimitives.WriteUInt32LittleEndian(app.Bytes.AsSpan(nt + 24 + 112 + 12 * 8 + 4), 8);
        var values = new Dictionary<string, ulong> { [Contract + "!InitOnceComplete"] = 0x7FF000001000UL };
        using var placed = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, AppBase, IatValues: values), new Placed("lib.dll", lib, LibBase));

        var builder = new MinidumpBuilder { ProcessorArchitecture = 9 };
        foreach (var module in placed.Modules)
        {
            builder.Modules.Add(new MinidumpBuilder.Module(module.Base, module.Size, module.TimeDateStamp, module.FileName));
            var bytes = new byte[module.Size];
            placed.ReadMemory(module.Base, bytes);
            builder.Memory.Add((module.Base, bytes));
        }
        builder.Threads.Add(new MinidumpBuilder.Thread(1, 0, MinidumpBuilder.ContextX64(0, 0)));
        var teb = new byte[0x1000];
        BinaryPrimitives.WriteUInt64LittleEndian(teb.AsSpan(0x60), Peb);
        builder.Memory.Add((0x7FF000002000UL, teb));
        var peb = new byte[0x1000];
        BinaryPrimitives.WriteUInt64LittleEndian(peb.AsSpan(0x68), MapAt);
        builder.Memory.Add((Peb, peb));
        builder.Memory.Add((MapAt, ImportRedirectsApiSetTests.MapBytes(Contract, "lib.dll")));
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        string path = _dir.File("via.dmp");
        File.WriteAllBytes(path, builder.Build());
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        return (path, images);
    }

    [Fact]
    public void A_contract_import_row_names_the_map_that_resolved_it()
    {
        var (dump, images) = Fixture();

        var (_, rows, _, _) = new MinidumpService().Changes(dump, images, "app.exe", 0, 100, default);

        var row = Assert.Single(rows);
        Assert.Equal("import", row.Kind);
        Assert.Equal("dump", row.Via);
        Assert.Contains("resolved through the dump API set map", row.Description);
    }
}
