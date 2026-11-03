using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import address table slots that point away from their export.</summary>
public sealed class ImportRedirectsTests : IDisposable
{
    private const ulong AppBase = 0x140000000UL, LibBase = 0x180000000UL;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    private IReadOnlyList<ImportRedirect> Run(PeBuilt app, PeBuilt lib, IReadOnlyDictionary<string, ulong>? values = null)
    {
        using var dump = RebuildFixtures.Dump(_dir, new Placed("app.exe", app, AppBase, IatValues: values), new Placed("lib.dll", lib, LibBase));
        var module = dump.Modules.First(m => m.FileName == "app.exe");
        var mapped = new byte[module.Size];
        dump.ReadMemory(module.Base, mapped);
        var captured = new CapturedImage(RebuildTarget.Of(module), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        return ImportRedirects.Find(mapped, captured, new ExportMap(dump), dump);
    }

    [Fact]
    public void A_slot_pointing_at_another_address_is_reported_with_both_addresses()
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("alpha", 0x1000), new ExportSpec("beta", 0x1001)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", ["alpha", "beta"])]));

        var rows = Run(app, lib, new Dictionary<string, ulong> { ["lib.dll!beta"] = 0x7FF000001000UL });

        var row = Assert.Single(rows);
        Assert.Equal(app.IatSlots["lib.dll!beta"], row.SlotRva);
        Assert.Equal("lib.dll!beta", row.Import);
        Assert.Equal("redirected", row.State);
        Assert.Equal(LibBase + 0x1001, row.Expected);
        Assert.Equal(0x7FF000001000UL, row.Actual);
    }

    [Fact]
    public void A_slot_holding_its_export_address_is_not_reported()
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("alpha", 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", ["alpha"])]));

        Assert.Empty(Run(app, lib));
    }

    [Fact]
    public void A_name_no_loaded_module_exports_is_reported_unknown()
    {
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec("alpha", 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", ["gamma"])]));

        var row = Assert.Single(Run(app, lib, new Dictionary<string, ulong> { ["lib.dll!gamma"] = 0x7FF000001000UL }));

        Assert.Equal("unknown", row.State);
        Assert.Null(row.Expected);
        Assert.Contains("gamma", row.Reason);
    }

    // Regression: a 270-character C++ name past the old 256-byte window read
    // as "import name was not captured".
    [Fact]
    public void A_redirected_slot_with_a_long_decorated_name_is_named()
    {
        string name = "?F@@YA" + new string('X', 300) + "@Z";
        var lib = RebuildFixtures.Build(Spec(exports: [new ExportSpec(name, 0x1000)]));
        var app = RebuildFixtures.Build(Spec([new ImportSpec("lib.dll", [name])]));

        var row = Assert.Single(Run(app, lib, new Dictionary<string, ulong> { ["lib.dll!" + name] = 0x7FF000001000UL }));

        Assert.Equal("redirected", row.State);
        Assert.Equal("lib.dll!" + name, row.Import);
    }
}
