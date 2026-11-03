using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=modules modules=code saves code regions with their function table entries.</summary>
public sealed class SaveCodeRegionsTests : IDisposable
{
    private const ulong Private = 0x2000_0000_0000;
    private const uint Rx = 0x20;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // One private executable region of two pages; only the first is captured.
    private string Dump(byte[]? functionTables)
    {
        var b = new MinidumpBuilder { FullMemory = true, ProcessorArchitecture = 9 };
        var code = new byte[0x1000];
        code[0] = 0x55;
        code[1] = 0xC3;
        b.Memory.Add((Private, code));
        b.Regions.Add(new MinidumpBuilder.Region(Private, 0x2000, Rx));
        if (functionTables != null)
            b.ExtraStreams.Add((FunctionTableFixtures.StreamType, functionTables));
        var path = _dir.File($"code-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    private static MinidumpService.ModuleOptions Code => MinidumpService.ModuleOptions.Default with { Module = "code" };

    [Fact]
    public void modules_code_saves_a_region_and_its_function_starts()
    {
        var stream = FunctionTableFixtures.Stream([new FunctionTableFixtures.Table(Private, Private + 0x2000, Private,
            [(0x10, 0x20, 0x100), (0x30, 0x48, 0x100), (0x5000, 0x5010, 0x100)])]);
        var dump = Dump(stream);
        var folder = _dir.File("out");

        using var service = new MinidumpService();
        var rows = service.Modules(dump, null, 0, 10, folder, default, Code).Rows;

        var row = Assert.Single(rows);
        Assert.Equal("code", row.Format);
        Assert.Equal($"0x{Private:X}", row.Base);
        Assert.Equal("0x2000", row.Size);
        Assert.Equal(50, row.ImageCaptured);
        Assert.Equal(2, row.EntryCount);
        Assert.Equal([0x55, 0xC3], File.ReadAllBytes(Path.Combine(folder, $"code-{Private:X}.bin"))[..2]);
        var lines = File.ReadAllLines(Path.Combine(folder, $"code-{Private:X}.txt"));
        Assert.Equal(["2 entries", $"0x{Private + 0x10:X} 0x{Private + 0x20:X}", $"0x{Private + 0x30:X} 0x{Private + 0x48:X}"], lines);
    }

    [Fact]
    public void A_region_without_entries_says_so()
    {
        var stream = FunctionTableFixtures.Stream([new FunctionTableFixtures.Table(0x1000, 0x2000, 0x1000, [(0x10, 0x20, 0x100)])]);
        var withStream = Dump(stream);
        var withoutStream = Dump(null);

        using var service = new MinidumpService();
        var empty = Assert.Single(service.Modules(withStream, null, 0, 10, _dir.File("a"), default, Code).Rows);
        var unknown = Assert.Single(service.Modules(withoutStream, null, 0, 10, _dir.File("b"), default, Code).Rows);

        Assert.Equal("0 entries", empty.Entries);
        Assert.Equal("0 entries", File.ReadAllLines(Path.Combine(_dir.File("a"), $"code-{Private:X}.txt"))[0]);
        Assert.Equal("unknown", unknown.Entries);
        Assert.Null(unknown.EntryCount);
        Assert.StartsWith("unknown", File.ReadAllText(Path.Combine(_dir.File("b"), $"code-{Private:X}.txt")));
    }
}
