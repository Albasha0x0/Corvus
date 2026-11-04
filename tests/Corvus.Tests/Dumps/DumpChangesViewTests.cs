using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native.Providers.Worker;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>open_minidump view=changes lists the ranges changed in memory, in process and in the worker.</summary>
public sealed class DumpChangesViewTests : FileIsolationTestBase
{
    private const ulong AppBase = 0x140000000UL, LibBase = AppBase + 0x10000;

    // A dump of app.exe with its first function start patched to jump into
    // lib.dll, and the folder holding app.exe.
    private (string Dump, string Images) PatchedDump()
    {
        PeSpec Spec(IReadOnlyList<ExportSpec> exports) =>
            new(true, [new SectionSpec(".text", 0x60000020, Enumerable.Repeat((byte)0x90, 0x40).ToArray())], Exports: exports);
        var app = RebuildFixtures.Build(Spec([new ExportSpec("alpha", 0x1000)]));
        var lib = RebuildFixtures.Build(Spec([new ExportSpec("beta", 0x1010)]));
        var mapped = RebuildFixtures.Mapped(app.Bytes);
        mapped[0x1000] = 0xE9;
        BinaryPrimitives.WriteInt32LittleEndian(mapped.AsSpan(0x1001), (int)(LibBase + 0x1010 - (AppBase + 0x1005)));
        var libMapped = RebuildFixtures.Mapped(lib.Bytes);
        var b = new MinidumpBuilder();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(app.Bytes.AsSpan(0x3C));
        b.Modules.Add(new MinidumpBuilder.Module(AppBase, (uint)mapped.Length, BinaryPrimitives.ReadUInt32LittleEndian(app.Bytes.AsSpan(nt + 8)), "app.exe"));
        b.Modules.Add(new MinidumpBuilder.Module(LibBase, (uint)libMapped.Length, 0, "lib.dll"));
        b.Memory.Add((AppBase, mapped));
        b.Memory.Add((LibBase, libMapped));
        var dump = _dir.File("patched.dmp");
        File.WriteAllBytes(dump, b.Build());
        var images = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(images, "app.exe"), app.Bytes);
        return (dump, images);
    }

    [Fact]
    public async Task open_minidump_view_changes_lists_the_patched_function()
    {
        var (dump, images) = PatchedDump();
        using var service = new MinidumpService();

        var text = await new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "app.exe", imageDirectories: images);

        Assert.Contains($"app.exe .text 0x{AppBase + 0x1000:X} 5 code", text);
        Assert.Contains("alpha", text);
        Assert.Contains("jump to", text);
        Assert.Contains("beta", text);
    }

    [Fact]
    public async Task The_changes_view_refuses_code_regions_and_names_the_save()
    {
        var (dump, images) = PatchedDump();
        using var service = new MinidumpService();

        var e = await Assert.ThrowsAsync<ToolError>(() => new MinidumpTools(service).OpenMinidump(dump, "changes", modules: "code", imageDirectories: images));

        Assert.Contains("code regions have none", e.Message);
        Assert.Contains("outputPath with modules=code", e.Remediation);
    }

    [Fact]
    public async Task The_changes_view_runs_the_same_in_the_isolated_worker()
    {
        if (!OperatingSystem.IsWindows()) return;
        var (dump, images) = PatchedDump();
        var args = new Dictionary<string, object?> { ["path"] = dump, ["view"] = "changes", ["modules"] = "app.exe", ["imageDirectories"] = images };
        string inProcess;
        await using (var session = await Session(true))
            inProcess = Whole(await Call(session, "open_minidump", args));
        using var pool = Pool();
        using var shared = WorkerPool.UseShared(pool);
        await using var isolated = await Session(false);

        var inWorker = Whole(await Call(isolated, "open_minidump", args));

        Assert.Contains("jump to", inProcess);
        Assert.Equal(Rows(inProcess), Rows(inWorker));
    }

    // The change rows, without the dump id that differs between the two
    // servers.
    private static string[] Rows(string text) => text.Split('\n').Where(l => l.StartsWith("app.exe ", StringComparison.Ordinal)).ToArray();
}
