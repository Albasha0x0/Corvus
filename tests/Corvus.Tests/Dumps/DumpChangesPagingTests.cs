using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Paging the changes of a dump reuses the rows computed by the first call.</summary>
public sealed class DumpChangesPagingTests : IDisposable
{
    private const ulong First = 0x140000000UL;
    private const int Modules = 24;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // A dump of many modules, each a copy of one image whose function start is
    // patched.
    private string ManyModules()
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0x90);
        var app = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, code)], Exports: [new ExportSpec("alpha", 0x1000)]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C)) + 8));
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        var b = new MinidumpBuilder();
        for (int i = 0; i < Modules; i++)
        {
            ulong at = First + (ulong)i * 0x10000;
            var copy = (byte[])mapped.Clone();
            copy[0x1000] = 0xCC;
            b.Modules.Add(new MinidumpBuilder.Module(at, (uint)copy.Length, stamp, $"m{i:D2}.dll"));
            b.Memory.Add((at, copy));
            File.WriteAllBytes(Path.Combine(images, $"m{i:D2}.dll"), app.Bytes);
        }
        var path = _dir.File("many.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    [Fact]
    public void Paging_the_changes_of_a_dump_computes_the_rows_once()
    {
        var path = ManyModules();
        var images = _dir.File("bin");
        using var service = new MinidumpService();

        var seen = new List<string>();
        int total = 0;
        for (int offset = 0; offset == 0 || offset < total; offset += 5)
        {
            var page = service.Changes(path, images, null, offset, 5, default);
            total = page.Total;
            seen.AddRange(page.Rows.Select(r => r.Module));
        }

        Assert.Equal(Modules, total);
        Assert.Equal(Modules, seen.Distinct().Count());
        Assert.Equal(1, service.ChangeComputations);
    }

    [Fact]
    public void A_dump_written_again_has_its_changes_computed_again()
    {
        var path = ManyModules();
        var images = _dir.File("bin");
        using var service = new MinidumpService();
        service.Changes(path, images, null, 0, 5, default);

        File.AppendAllText(path, "\0");
        service.Changes(path, images, null, 0, 5, default);

        Assert.Equal(2, service.ChangeComputations);
    }

    [Fact]
    public void A_recorded_system_path_also_names_the_wow64_system_folder()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitOperatingSystem) return;
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var wow = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
        var target = new RebuildTarget("x.dll", 0x10000, 0x1000, ModuleOrigin.Listed, Path.Combine(system, "x.dll"));

        var candidates = DiskCompare.Candidates(target, RebuildOptions.Default);

        Assert.Equal([Path.Combine(system, "x.dll"), Path.Combine(wow, "x.dll")], candidates);
    }
}
