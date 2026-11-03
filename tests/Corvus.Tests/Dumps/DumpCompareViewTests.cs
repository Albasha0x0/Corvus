using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes with compareWith lists the ranges that differ between two dumps.</summary>
public sealed class DumpCompareViewTests : FileIsolationTestBase
{
    private const ulong AppBase = 0x140000000UL, LibBase = AppBase + 0x10000;

    // Two dumps of app.exe, the second with its first function start patched,
    // and lib.dll in the second only when asked.
    private (string Before, string After) Dumps(bool libInAfter)
    {
        PeSpec Spec(uint export) =>
            new(true, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())],
                Exports: [new ExportSpec("alpha", export)]);
        var app = RebuildFixtures.Build(Spec(0x1000));
        var lib = RebuildFixtures.Build(Spec(0x1010));
        uint stamp = BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C)) + 8));
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);

        string Write(string name, byte[] mapped, bool withLib)
        {
            var b = new MinidumpBuilder();
            b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, stamp, "app.exe"));
            b.Memory.Add((AppBase, mapped));
            if (withLib)
            {
                b.Modules.Add(new MinidumpBuilder.Module(LibBase, (uint)libMapped.Length, 0, "lib.dll"));
                b.Memory.Add((LibBase, libMapped));
            }
            var path = _dir.File(name);
            File.WriteAllBytes(path, b.Build());
            return path;
        }

        var before = RebuildFixtures.Mapped(app.Bytes);
        var after = (byte[])before.Clone();
        after[0x1000] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(after.AsSpan(0x1001), (int)(LibBase + 0x1010 - (AppBase + 0x1005)));
        return (Write("before.dmp", before, false), Write("after.dmp", after, libInAfter));
    }

    [Fact]
    public async Task Changes_between_two_dumps_list_the_changed_run()
    {
        var (before, after) = Dumps(false);
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(after, "changes", modules: "app.exe", compareWith: before);

        Assert.Contains($"app.exe .text 0x{AppBase + 0x1000:X} 5 code", text);
        Assert.Contains("jump to", text);
        var rows = service.Changes(after, null, "app.exe", 0, 10, default, before).Rows;
        var row = Assert.Single(rows);
        Assert.StartsWith("90", row.BeforeBytes);
        Assert.StartsWith("e9", row.AfterBytes);
    }

    [Fact]
    public async Task A_module_in_one_dump_only_is_one_unknown_row()
    {
        var (before, after) = Dumps(true);
        using var service = new MinidumpService();

        var rows = service.Changes(after, null, "lib.dll", 0, 10, default, before).Rows;

        var row = Assert.Single(rows);
        Assert.Equal("unknown", row.Kind);
        Assert.Contains("before.dmp", row.Description);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task compareWith_with_another_view_is_refused()
    {
        var (before, after) = Dumps(false);
        using var service = new MinidumpService();

        var e = await Assert.ThrowsAsync<ToolError>(() => new MinidumpTools(service).OpenMinidump(after, "modules", compareWith: before));

        Assert.Contains("compareWith", e.Message);
        Assert.Contains("view=changes", e.NextFor(null));
    }
}
