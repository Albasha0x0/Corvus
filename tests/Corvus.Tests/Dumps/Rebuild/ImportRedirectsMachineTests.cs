using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import slots matched by the importer's machine and checked against the file.</summary>
public sealed class ImportRedirectsMachineTests : IDisposable
{
    private const ulong HostBase = 0x100000000UL, AppBase = 0x140000000UL, Lib64 = 0x180000000UL, Lib32 = 0x20000000UL;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec(bool is64, IReadOnlyList<ImportSpec>? imports = null, IReadOnlyList<ExportSpec>? exports = null) => new(is64,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC])], Imports: imports, Exports: exports);

    private IReadOnlyList<ImportRedirect> Run(params Placed[] others)
    {
        var host = RebuildFixtures.Build(Spec(true));
        using var dump = RebuildFixtures.Dump(_dir, [new Placed("host.exe", host, HostBase), .. others]);
        var module = dump.Modules.First(m => m.FileName == "app.exe");
        var mapped = new byte[module.Size];
        dump.ReadMemory(module.Base, mapped);
        var captured = new CapturedImage(RebuildTarget.Of(module), mapped, Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray(), "mapped");
        return ImportRedirects.Find(mapped, captured, new ExportMap(dump), dump);
    }

    [Fact]
    public void A_64_bit_importer_binds_to_the_64_bit_module_of_the_same_name()
    {
        var lib64 = RebuildFixtures.Build(Spec(true, exports: [new ExportSpec("alpha", 0x1000)]));
        var lib32 = RebuildFixtures.Build(Spec(false, exports: [new ExportSpec("alpha", 0x1002)]));
        var app = RebuildFixtures.Build(Spec(true, [new ImportSpec("lib.dll", ["alpha"])]));
        var values = new Dictionary<string, ulong> { ["lib.dll!alpha"] = Lib64 + 0x1000 };

        var rows = Run(new Placed("app.exe", app, AppBase, IatValues: values),
            new Placed("x86/lib.dll", lib32, Lib32), new Placed("x64/lib.dll", lib64, Lib64));

        Assert.Empty(rows);
    }
}
