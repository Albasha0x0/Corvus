using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes labels the rows a session's saved hooks wrote.</summary>
public sealed class DumpSessionHookLabelTests : FileIsolationTestBase
{
    private const ulong AppBase = 0x140000000UL, LibBase = AppBase + 0x10000;

    // A dump of app.exe with jumps into lib.dll written at 0x1000 and 0x1020.
    private (string Dump, string Images) TwoPatchedDump()
    {
        PeSpec Spec(IReadOnlyList<ExportSpec> exports) =>
            new(true, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())], Exports: exports);
        var app = RebuildFixtures.Build(Spec([new ExportSpec("alpha", 0x1000)]));
        var lib = RebuildFixtures.Build(Spec([new ExportSpec("beta", 0x1010)]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        foreach (int at in new[] { 0x1000, 0x1020 })
        {
            mapped[at] = 0xE9;
            BinaryPrimitives.WriteInt32LittleEndian(mapped.AsSpan(at + 1), (int)(LibBase + 0x1010 - (AppBase + (ulong)at + 5)));
        }
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);
        var b = new MinidumpBuilder();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(nt + 8)), "app.exe"));
        b.Modules.Add(new MinidumpBuilder.Module(LibBase, (uint)libMapped.Length, 0, "lib.dll"));
        b.Memory.Add((AppBase, mapped));
        b.Memory.Add((LibBase, libMapped));
        var dump = _dir.File("hooked.dmp");
        File.WriteAllBytes(dump, b.Build());
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        return (dump, images);
    }

    private static async Task<string> Changes(string dump, string images)
    {
        using var service = new MinidumpService();
        return await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "app.exe", imageDirectories: images);
    }

    [Fact]
    public async Task A_sidecar_labels_the_rows_at_hook_addresses_and_leaves_the_others()
    {
        var (dump, images) = TwoPatchedDump();
        SessionHookSidecar.Write(dump, [new SessionHookMark(AppBase + 0x1000, 5, "coverage")]);

        var text = await Changes(dump, images);

        var rows = text.Split('\n').Where(l => l.Contains("app.exe .text")).ToList();
        Assert.Equal(2, rows.Count);
        Assert.Contains("session hook (coverage)", rows.Single(l => l.Contains($"0x{AppBase + 0x1000:X}")));
        Assert.DoesNotContain("session hook", rows.Single(l => l.Contains($"0x{AppBase + 0x1020:X}")));
        Assert.Contains("1 of 2 changed range(s) are session hooks", text);
    }

    [Fact]
    public async Task A_dump_without_a_sidecar_lists_its_rows_unlabelled()
    {
        var (dump, images) = TwoPatchedDump();

        var text = await Changes(dump, images);

        Assert.DoesNotContain("session hook", text);
    }

    [Fact]
    public void A_malformed_sidecar_reads_as_absent()
    {
        var (dump, _) = TwoPatchedDump();
        File.WriteAllText(SessionHookSidecar.PathFor(dump), "{ not json");

        Assert.Null(SessionHookSidecar.Read(dump));
    }

    [Fact]
    public void The_sidecar_takes_the_base_name_of_the_dump()
    {
        Assert.EndsWith("run.hooks.json", SessionHookSidecar.PathFor(Path.Combine("x", "run.dmp")));
    }
}
