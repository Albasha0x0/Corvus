using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;
using Corvus.Native.Providers.Worker;
using Corvus.Native.Providers.Worker.Yara;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>regionFilter=unbacked: executable regions with no image, runtime code heaps labelled jit, noteworthy only with a PE header or a YARA hit.</summary>
public sealed class DumpUnbackedTests : IDisposable
{
    private const ulong Image = 0x7FF6_1000_0000, WithHeader = 0x2000_0000_0000, Plain = 0x2000_0001_0000, Unread = 0x2000_0002_0000,
        Mapped = 0x2000_0003_0000, Data = 0x2000_0004_0000, Heap = 0x2000_0005_0000;
    private const uint Rx = 0x20, Rw = 0x04, MappedView = 0x40000, ImageType = 0x1000000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>A dump with one region of each kind: a PE header, plain bytes, bytes not captured, a mapped view, a data region, a runtime heap and the module's image.</summary>
    private string Dump(bool regions = true, string plainText = "code")
    {
        var b = new MinidumpBuilder { FullMemory = true };
        b.Modules.Add(new MinidumpBuilder.Module(Image, 0x3000, 0, @"Z:\nowhere\synth.dll"));
        b.Memory.Add((Image, new byte[0x3000]));
        var header = new byte[0x1000];
        SyntheticCrash.FileImage().AsSpan(0, 0x400).CopyTo(header);
        b.Memory.Add((WithHeader, header));
        var bytes = new byte[0x1000];
        System.Text.Encoding.ASCII.GetBytes(plainText).CopyTo(bytes, 0x10);
        b.Memory.Add((Plain, bytes));
        b.Memory.Add((Mapped, new byte[0x1000]));
        b.Memory.Add((Heap, new byte[0x2000]));
        if (regions)
        {
            b.Regions.Add(new MinidumpBuilder.Region(Image, 0x3000, Rx, Type: ImageType));
            b.Regions.Add(new MinidumpBuilder.Region(WithHeader, 0x1000, Rx));
            b.Regions.Add(new MinidumpBuilder.Region(Plain, 0x1000, Rx));
            b.Regions.Add(new MinidumpBuilder.Region(Unread, 0x1000, Rx));
            b.Regions.Add(new MinidumpBuilder.Region(Mapped, 0x1000, Rx, Type: MappedView));
            b.Regions.Add(new MinidumpBuilder.Region(Data, 0x1000, Rw));
            b.Regions.Add(new MinidumpBuilder.Region(Heap, 0x2000, Rx));
        }
        var path = _dir.File("regions.dmp");
        File.WriteAllBytes(path, b.Build());
        return path;
    }

    private async Task<(MinidumpService.UnbackedPage Page, MinidumpService Service)> Unbacked(string dump, IReadOnlyList<RuntimeCodeHeap>? heaps = null, string? yara = null)
    {
        var service = new MinidumpService();
        using var s = service.Open(dump, null);
        var regions = s.Dump.MemoryRegions;
        return (await service.Unbacked(s, regions, _ => null, heaps, null, yara, 0, 100, default), service);
    }

    [Fact]
    public async Task Unbacked_lists_the_executable_regions_that_no_image_backs()
    {
        var (page, _) = await Unbacked(Dump());
        Assert.Equal([WithHeader, Plain, Unread, Mapped, Heap], page.Rows.Select(r => Convert.ToUInt64(r.Base[2..], 16)));
        Assert.All(page.Rows, r => Assert.Equal("unbacked", r.Backing));
        Assert.Equal(5, page.Total);
    }

    [Fact]
    public async Task A_PE_header_at_the_start_makes_an_unbacked_region_noteworthy()
    {
        var (page, _) = await Unbacked(Dump());
        var noteworthy = Assert.Single(page.Rows, r => r.Noteworthy == true);
        Assert.Equal($"0x{WithHeader:X}", noteworthy.Base);
        Assert.Equal("pe", noteworthy.Header);
        Assert.Equal("none", page.Rows.Single(r => r.Base == $"0x{Plain:X}").Header);
        Assert.Contains(page.Notes, n => n.StartsWith("5 executable region(s) with no image: 1 noteworthy", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_region_whose_first_bytes_are_not_captured_has_an_unknown_header_and_is_not_flagged()
    {
        var (page, _) = await Unbacked(Dump());
        var row = page.Rows.Single(r => r.Base == $"0x{Unread:X}");
        Assert.Equal("unknown", row.Header);
        Assert.False(row.Noteworthy);
        Assert.Contains(page.Notes, n => n.Contains("unknown header", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_region_inside_the_runtime_code_heaps_is_labelled_jit_and_not_flagged()
    {
        var (page, _) = await Unbacked(Dump(), [new RuntimeCodeHeap(Heap - 0x1000, Heap + 0x3000, "LoaderCodeHeap")]);
        var row = page.Rows.Single(r => r.Base == $"0x{Heap:X}");
        Assert.Equal("jit", row.Backing);
        Assert.Equal("LoaderCodeHeap", row.Detail);
        Assert.Null(row.Noteworthy);
        Assert.Contains(page.Notes, n => n.Contains("1 jit", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_region_only_partly_inside_a_runtime_heap_stays_unbacked()
    {
        var (page, _) = await Unbacked(Dump(), [new RuntimeCodeHeap(Heap, Heap + 0x1000, "StubHeap")]);
        var row = page.Rows.Single(r => r.Base == $"0x{Heap:X}");
        Assert.Equal("unbacked", row.Backing);
        Assert.Equal("partly inside StubHeap", row.Detail);
    }

    [Fact]
    public async Task A_dump_without_a_region_list_reports_unbacked_regions_as_unknown()
    {
        using var service = new MinidumpService();
        var (_, page) = await service.UnbackedMemory(Dump(regions: false), 0, 10, null, new DacRequest(), default);
        Assert.Empty(page.Rows);
        Assert.Contains(page.Notes, n => n.Contains("unknown", StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_open_minidump_tool_rejects_a_filter_it_does_not_know()
    {
        using var service = new MinidumpService();
        var tools = new MinidumpTools(service);
        var path = Dump();
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.OpenMinidump(path, "memory", regionFilter: "stack"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.OpenMinidump(path, "modules", regionFilter: "unbacked"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.OpenMinidump(path, "memory", yara: "rule a { condition: true }"))).Code);
    }

    [Fact]
    public async Task The_open_minidump_tool_lists_unbacked_regions_with_their_notes()
    {
        using var service = new MinidumpService();
        var text = await new MinidumpTools(service).OpenMinidump(Dump(), "memory", regionFilter: "unbacked");
        Assert.Contains("[noteworthy unbacked, PE header]", text);
        Assert.Contains("note: 5 executable region(s) with no image: 1 noteworthy", text);
    }

    [YaraFact]
    public async Task A_YARA_hit_makes_an_unbacked_region_noteworthy()
    {
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [YaraX.LibraryVariable] = YaraTestTools.Library } },
        });
        using var shared = WorkerPool.UseShared(pool);
        var (page, _) = await Unbacked(Dump(plainText: "marker-in-memory"), yara: "rule marker { strings: $a = \"marker-in-memory\" condition: $a }");
        var hit = Assert.Single(page.Rows, r => r.Yara is { Count: > 0 });
        Assert.Equal($"0x{Plain:X}", hit.Base);
        Assert.Equal(["marker"], hit.Yara);
        Assert.True(hit.Noteworthy);
        Assert.Equal([$"0x{WithHeader:X}", $"0x{Plain:X}"], page.Rows.Where(r => r.Noteworthy == true).Select(r => r.Base).Order());
    }
}
