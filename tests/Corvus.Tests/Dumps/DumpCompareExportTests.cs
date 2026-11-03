using System.Buffers.Binary;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes with compareWith describes export address table entries.</summary>
public sealed class DumpCompareExportTests : FileIsolationTestBase
{
    // Two dumps of one image; the second holds new at the entry of alpha
    // when asked, and leaves out the page of the export table when asked.
    private (string Before, string After) Dumps(bool is64, bool rewrite, bool omitTable = false)
    {
        var spec = new PeSpec(is64,
            [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())],
            Exports: [new ExportSpec("alpha", 0x1000), new ExportSpec("beta", 0x1010)]);
        ulong appBase = spec.Base;
        var built = RebuildFixtures.Build(spec);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(built.Bytes.AsSpan(0x3C));
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(built.Bytes.AsSpan(nt + 8));
        var before = RebuildFixtures.Mapped(built.Bytes);
        var after = (byte[])before.Clone();
        if (rewrite)
        {
            uint dir = BinaryPrimitives.ReadUInt32LittleEndian(after.AsSpan(nt + 24 + (is64 ? 112 : 96)));
            uint table = BinaryPrimitives.ReadUInt32LittleEndian(after.AsSpan((int)dir + 28));
            BinaryPrimitives.WriteUInt32LittleEndian(after.AsSpan((int)table), 0x1020);
        }

        string Write(string name, byte[] mapped, bool omit)
        {
            var b = new MinidumpBuilder { ProcessorArchitecture = is64 ? (ushort)9 : (ushort)0 };
            b.Modules.Add(new MinidumpBuilder.Module(appBase, (uint)mapped.Length, stamp, "app.dll"));
            int tablePage = (int)BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan(nt + 24 + (is64 ? 112 : 96))) / 0x1000 * 0x1000;
            if (omit)
            {
                b.Memory.Add((appBase, mapped[..tablePage]));
                if (tablePage + 0x1000 < mapped.Length)
                    b.Memory.Add((appBase + (ulong)tablePage + 0x1000, mapped[(tablePage + 0x1000)..]));
            }
            else b.Memory.Add((appBase, mapped));
            var path = _dir.File(name);
            File.WriteAllBytes(path, b.Build());
            return path;
        }

        return (Write("before.dmp", before, false), Write("after.dmp", after, omitTable));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_changed_export_entry_between_two_dumps_names_the_export_and_both_targets(bool is64)
    {
        var (before, after) = Dumps(is64, true);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "app.dll", 0, 10, default, before).Rows;

        var row = Assert.Single(rows, r => r.Kind == "export");
        Assert.Equal("alpha", row.Name);
        Assert.Equal(4, row.Length);
        Assert.Contains("RVA 0x1000", row.Description);
        Assert.Contains("to 0x1020", row.Description);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_unchanged_export_table_adds_no_row(bool is64)
    {
        var (before, after) = Dumps(is64, false);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "app.dll", 0, 10, default, before).Rows;

        Assert.DoesNotContain(rows, r => r.Kind == "export");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_export_table_page_missing_from_one_dump_is_not_reported_as_unchanged(bool is64)
    {
        var (before, after) = Dumps(is64, true, omitTable: true);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "app.dll", 0, 10, default, before).Rows;

        Assert.DoesNotContain(rows, r => r.Kind == "export");
        var row = Assert.Single(rows, r => r.Kind == "unknown");
        Assert.Contains("not captured", row.Description);
    }
}
