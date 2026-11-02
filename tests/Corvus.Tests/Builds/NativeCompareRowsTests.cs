using Corvus.Native.Pe;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>compare_native_images rows carry both builds' name, size and block counts; the summary carries both file versions.</summary>
public class NativeCompareRowsTests(ITestOutputHelper output)
{
    private const uint Name = 0x1000, Other = 0x1040;

    // The first function grows one block between builds; the second keeps its shape.
    private static byte[] Image(bool newer, string? version, bool fixedOnly = false)
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x180000000, DllCharacteristics = 0x0160 };
        var code = Enumerable.Repeat((byte)0xCC, 0x80).ToArray();
        byte[] first = newer
            ? [0x31, 0xC0, 0x85, 0xC9, 0x74, 0x03, 0x83, 0xC0, 0x05, 0xC3]
            : [0x31, 0xC0, 0x83, 0xC0, 0x05, 0xC3];
        first.CopyTo(code, 0);
        new byte[] { 0xB8, 0x01, 0, 0, 0, 0x83, 0xC0, 0x22, 0xC3 }.CopyTo(code, 0x40);
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        if (version != null)
        {
            var rsrc = b.Add(".rsrc", rva => NativePeTests.ResourceTree(rva, [new(PeFile.RtVersion, 1, 0x409, NativePeTests.VersionResource(fixedOnly ? null : version))]));
            b.Directories[PeDirectory.Resource] = (rsrc.Rva, (uint)rsrc.Data.Length);
        }
        return b.Build();
    }

    private static async Task<(NativeDiffTools.NativeComparison Record, string Text)> Compare(string? oldVersion, string? newVersion, string view, string? renamed = null, bool fixedOnly = false)
    {
        using var h = new NativeBuildUpdateTests.Harness();
        var (o, oi) = await h.Load(Image(false, oldVersion, fixedOnly), "old.dll", [Name, Other]);
        var (n, ni) = await h.Load(Image(true, newVersion, fixedOnly), "new.dll", [Name, Other]);
        foreach (var (native, index) in new[] { (o, oi), (n, ni) })
        {
            h.Code.Annotations(native).SetMany([(Name, "Grown"), (Other, native == n && renamed != null ? renamed : "Steady")], []);
            index.SetUserName(Name, "Grown");
            index.SetUserName(Other, native == n && renamed != null ? renamed : "Steady");
        }
        var tools = new NativeDiffTools(h.Env.Workspace, h.Code);
        return await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() => tools.CompareNativeImages(o.Id, n.Id, view: view));
    }

    [Fact]
    public async Task A_changed_row_matched_by_name_carries_both_sides_name_size_and_blocks()
    {
        var (record, text) = await Compare(null, null, "changed");
        output.WriteLine(text);
        var row = Assert.Single(record.Items);
        Assert.Equal("Grown", row.OldName);
        Assert.Equal("Grown", row.NewName);
        Assert.Equal(6u, row.OldSize);
        Assert.Equal(10u, row.NewSize);
        Assert.Equal(1, row.OldBlocks);
        Assert.Equal(3, row.NewBlocks);
        Assert.Contains("size 6->10", text);
        Assert.DoesNotContain("Grown / Grown", text);
    }

    [Fact]
    public async Task An_unchanged_side_of_a_pairs_row_is_still_reported()
    {
        var (record, _) = await Compare(null, null, "pairs");
        var row = record.Items.Single(r => r.OldName == "Steady");
        Assert.Equal((row.OldSize, row.OldBlocks, row.OldCalls, row.OldName), (row.NewSize, row.NewBlocks, row.NewCalls, row.NewName));
        Assert.NotNull(row.NewSize);
    }

    [Fact]
    public async Task The_summary_shows_the_file_version_of_both_builds()
    {
        var (record, text) = await Compare("1.0.0.1", "1.0.0.2", "changed");
        Assert.Equal(("1.0.0.1", "1.0.0.2"), (record.OldVersion, record.NewVersion));
        Assert.Contains("File version: 1.0.0.1 -> 1.0.0.2.", text);
    }

    [Fact]
    public async Task Builds_without_a_version_resource_report_no_file_version()
    {
        var (record, text) = await Compare(null, null, "changed");
        Assert.Null(record.OldVersion);
        Assert.DoesNotContain("File version", text);
    }

    [Fact]
    public async Task A_pair_renamed_between_builds_shows_both_names()
    {
        var (record, text) = await Compare(null, null, "pairs", "Steady2");
        var row = record.Items.Single(r => r.OldName == "Steady");
        Assert.Equal("Steady2", row.NewName);
        Assert.Contains("Steady / Steady2", text);
    }

    [Fact]
    public async Task A_build_with_only_fixed_file_info_reports_its_version()
    {
        var (record, _) = await Compare(null, "1.0.0.2", "changed", null, fixedOnly: true);
        Assert.Equal("1.2.3.4", record.NewVersion);
    }

    [Fact]
    public async Task A_changed_webassembly_row_carries_both_names_and_sizes()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var tools = new NativeDiffTools(h.Workspace, h.Code);
        var (record, _) = await BuildToolCalls.Collected<NativeDiffTools.NativeComparison>(() =>
            tools.CompareNativeImages(WasmTextTests.DotnetNative("9.0.11"), WasmTextTests.DotnetNative("10.0.11"), view: "changed", limit: 5));
        Assert.NotEmpty(record.Items);
        Assert.All(record.Items, r => Assert.True(r.OldName != null && r.NewName != null && r.OldSize != null && r.NewSize != null));
    }
}
