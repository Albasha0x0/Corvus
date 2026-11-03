using System.Buffers.Binary;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes with compareWith describes export address table entries.</summary>
public sealed class DumpCompareExportTests : FileIsolationTestBase
{
    private const ulong AppBase = 0x140000000UL;

    // Two dumps of one image; the second holds new at the entry of alpha
    // when asked.
    private (string Before, string After) Dumps(bool rewrite)
    {
        var built = RebuildFixtures.Build(new PeSpec(true,
            [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())],
            Exports: [new ExportSpec("alpha", 0x1000), new ExportSpec("beta", 0x1010)]));
        int nt = BinaryPrimitives.ReadInt32LittleEndian(built.Bytes.AsSpan(0x3C));
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(built.Bytes.AsSpan(nt + 8));
        var before = RebuildFixtures.Mapped(built.Bytes);
        var after = (byte[])before.Clone();
        if (rewrite)
        {
            uint dir = BinaryPrimitives.ReadUInt32LittleEndian(after.AsSpan(nt + 24 + 112));
            uint table = BinaryPrimitives.ReadUInt32LittleEndian(after.AsSpan((int)dir + 28));
            BinaryPrimitives.WriteUInt32LittleEndian(after.AsSpan((int)table), 0x1020);
        }

        string Write(string name, byte[] mapped)
        {
            var b = new MinidumpBuilder();
            b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, stamp, "app.dll"));
            b.Memory.Add((AppBase, mapped));
            var path = _dir.File(name);
            File.WriteAllBytes(path, b.Build());
            return path;
        }

        return (Write("before.dmp", before), Write("after.dmp", after));
    }

    [Fact]
    public void A_changed_export_entry_between_two_dumps_names_the_export_and_both_targets()
    {
        var (before, after) = Dumps(true);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "app.dll", 0, 10, default, before).Rows;

        var row = Assert.Single(rows, r => r.Kind == "export");
        Assert.Equal("alpha", row.Name);
        Assert.Equal(4, row.Length);
        Assert.Contains("RVA 0x1000", row.Description);
        Assert.Contains("to 0x1020", row.Description);
    }

    [Fact]
    public void An_unchanged_export_table_adds_no_row()
    {
        var (before, after) = Dumps(false);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "app.dll", 0, 10, default, before).Rows;

        Assert.DoesNotContain(rows, r => r.Kind == "export");
    }
}
