using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules with symbols copies the matching PDB next to each saved module.</summary>
public sealed class SaveSymbolsTests : IDisposable
{
    private const ulong Base = 0x1_4000_0000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Dump(uint age)
    {
        var mapped = RebuildFixtures.Mapped(PdbTests.TinyImage(PdbBuilder.Sample().Guid, age, "synth.pdb"));
        var b = new MinidumpBuilder { ProcessorArchitecture = 9 };
        b.Modules.Add(new MinidumpBuilder.Module(Base, (uint)mapped.Length, 0, @"Z:\app\synth.dll"));
        b.Memory.Add((Base, mapped));
        var dump = _dir.File("synth.dmp");
        File.WriteAllBytes(dump, b.Build());
        return dump;
    }

    [Fact]
    public void symbols_local_copies_the_matching_pdb_next_to_the_module()
    {
        var symbols = Directory.CreateDirectory(_dir.File("symbols")).FullName;
        var pdb = PdbBuilder.Sample().Msf().Build();
        File.WriteAllBytes(Path.Combine(symbols, "synth.pdb"), pdb);
        var dump = Dump(3);
        var folder = _dir.File("modules");

        using var service = new MinidumpService();
        var rows = service.Modules(dump, symbols, 0, 10, folder, default,
            MinidumpService.ModuleOptions.Parse(null, null, null, null, "local")).Rows;

        var row = Assert.Single(rows);
        Assert.Equal("synth.pdb", row.Pdb);
        Assert.Equal(pdb, File.ReadAllBytes(Path.Combine(folder, "synth.pdb")));
        var check = Assert.Single(row.ImageChecks!, c => c.Name == "symbols");
        Assert.Equal("ok", check.State);
        Assert.Equal("synth.pdb", check.Detail);
    }

    [Fact]
    public async Task symbols_without_outputPath_is_refused()
    {
        var dump = Dump(3);

        using var service = new MinidumpService();
        var e = await Assert.ThrowsAsync<ToolError>(() => new MinidumpTools(service).OpenMinidump(dump, "modules", symbols: "local"));

        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("symbols", e.Message);
    }

    [Fact]
    public void A_pdb_of_another_age_is_reported_unknown_and_not_copied()
    {
        var symbols = Directory.CreateDirectory(_dir.File("symbols")).FullName;
        File.WriteAllBytes(Path.Combine(symbols, "synth.pdb"), PdbBuilder.Sample().Msf().Build());
        var dump = Dump(9);
        var folder = _dir.File("modules");

        using var service = new MinidumpService();
        var row = Assert.Single(service.Modules(dump, symbols, 0, 10, folder, default,
            MinidumpService.ModuleOptions.Parse(null, null, null, null, "local")).Rows);

        Assert.Null(row.Pdb);
        Assert.False(File.Exists(Path.Combine(folder, "synth.pdb")));
        Assert.Equal("unknown", Assert.Single(row.ImageChecks!, c => c.Name == "symbols").State);
    }
}
