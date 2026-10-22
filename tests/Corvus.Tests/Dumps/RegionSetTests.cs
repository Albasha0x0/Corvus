using System.Text.Json;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Region-set dumps: a manifest of region files read through the dump tools at the regions' own addresses.</summary>
public sealed class RegionSetTests
{
    /// <summary>A region-set dump of the synthetic crash's captured ranges, one file per range, with its module.</summary>
    private static string Manifest(TempDir dir, Func<int, string>? file = null, Action<List<object>>? edit = null, int format = 1)
    {
        using var dump = MinidumpFile.Open(SyntheticCrash.Write(dir));
        var regions = new List<object>();
        int i = 0;
        foreach (var range in dump.MemoryRanges)
        {
            var bytes = new byte[range.Size];
            Assert.Equal(bytes.Length, dump.ReadMemory(range.Start, bytes));
            var name = file?.Invoke(i) ?? $"r{i}.bin";
            File.WriteAllBytes(dir.File($"r{i}.bin"), bytes);
            regions.Add(new { file = name, @base = $"0x{range.Start:X}", size = range.Size, protect = range.Start == SyntheticCrash.Stack ? "rw" : "rx" });
            i++;
        }
        edit?.Invoke(regions);
        var module = dump.Modules.Single();
        var path = dir.File("regions.json");
        File.WriteAllText(path, JsonSerializer.Serialize(new
        {
            format, arch = "x64", processId = 4242, source = "test writer", regions,
            modules = new[] { new { name = module.Path, @base = $"0x{module.Base:X}", size = module.Size } },
        }));
        return path;
    }

    [Fact]
    public void A_manifest_of_a_minidumps_ranges_reads_its_bytes_and_rebuilds_its_module()
    {
        using var dir = new TempDir();
        var set = RegionSetFile.Open(Manifest(dir));
        using var dump = MinidumpFile.Open(SyntheticCrash.Write(dir));
        Assert.Equal(dump.MemoryRanges.Count, set.Regions.Count);
        foreach (var range in dump.MemoryRanges)
        {
            byte[] expected = new byte[range.Size], actual = new byte[range.Size];
            dump.ReadMemory(range.Start, expected);
            Assert.Equal(expected.Length, set.ReadMemory(range.Start, actual));
            Assert.Equal(expected, actual);
        }
        Assert.Equal(0, set.ReadMemory(SyntheticCrash.Stack - 1, new byte[1]));
        var module = set.Modules.Single();
        Assert.Equal(dump.Modules.Single().TimeDateStamp, module.TimeDateStamp);
        var fromDump = DumpImages.FromMemory(dump, dump.Modules.Single(), out _)!;
        var fromSet = DumpImages.FromMemory(set, module, out _)!;
        byte[] a = new byte[0x2000], b = new byte[0x2000];
        Assert.Equal(fromDump.Read(0, a), fromSet.Read(0, b));
        Assert.Equal(a, b);
    }

    [Fact]
    public async Task The_dump_views_read_a_region_set_and_name_its_threads_unknown()
    {
        using var dir = new TempDir();
        var path = Manifest(dir);
        using var service = new MinidumpService();
        var summary = await service.Summarize(path, null, default);
        Assert.Equal((uint)4242, summary.Process!.ProcessId);
        Assert.Contains(summary.Notes!, n => n.Contains("from test writer") && n.Contains("3 region(s), 1 module(s)"));
        Assert.Equal("synth.dll", service.Modules(path, null, 0, 10).Rows.Single().Name);
        var stack = service.Memory(path, 0, 10).Rows.Single(r => r.Base == $"0x{SyntheticCrash.Stack:X}");
        Assert.Equal("PAGE_READWRITE", stack.Protection);
        Assert.Equal(0x1100UL, stack.Captured);
        var read = await service.ReadMemory(path, $"synth.dll+0x{SyntheticCrash.CrashRva:X}", 4, false, default);
        Assert.Equal("534883EC", read.Code);
        Assert.Equal("synth!Crash", read.Location);
        var threads = await Assert.ThrowsAsync<ToolError>(() => service.Stack(path, null, false, 10, 0, 10, null, default));
        Assert.Equal(ErrorCode.Unsupported, threads.Code);
        Assert.Contains("threads, exception and runtime state are unknown", threads.Message);
    }

    [Fact]
    public async Task A_missing_region_file_reads_as_unknown_for_its_range()
    {
        using var dir = new TempDir();
        var path = Manifest(dir, i => i == 1 ? "gone.bin" : $"r{i}.bin");
        var set = RegionSetFile.Open(path);
        var gone = set.Regions.Single(r => r.Missing);
        Assert.Contains(set.Issues, i => i.Message == $"gone.bin is missing: 0x{gone.Base:X}-0x{gone.End:X} is unknown");
        using var service = new MinidumpService();
        var read = await service.ReadMemory(path, $"0x{gone.Base:X}", 16, false, default);
        Assert.Equal(0, read.Length);
        Assert.Equal($"0x{gone.Base:X} is in gone.bin, which is missing: its bytes are unknown", read.Note);
        Assert.Null(service.Memory(path, 0, 10).Rows.Single(r => r.Base == $"0x{gone.Base:X}").Captured);
    }

    [Fact]
    public void Overlapping_regions_and_an_unknown_format_are_refused_by_name()
    {
        using var dir = new TempDir();
        var overlap = Assert.Throws<ToolError>(() => RegionSetFile.Open(Manifest(dir,
            edit: r => r.Add(new { file = "r1.bin", @base = $"0x{SyntheticCrash.Stack + 0x10:X}", size = 0x10 }))));
        Assert.Equal(ErrorCode.InvalidArgument, overlap.Code);
        Assert.Matches(@"r\d\.bin \(0x[0-9A-F]+-0x[0-9A-F]+\) and r1\.bin \(0x[0-9A-F]+-0x[0-9A-F]+\) overlap", overlap.Message);
        var format = Assert.Throws<ToolError>(() => RegionSetFile.Open(Manifest(dir, format: 2)));
        Assert.Equal(ErrorCode.Unsupported, format.Code);
        Assert.Contains("format 2; this build reads format 1", format.Message);
        var outside = Assert.Throws<ToolError>(() => RegionSetFile.Open(Manifest(dir, i => $"../r{i}.bin")));
        Assert.Contains("outside the manifest's folder", outside.Message);
    }
}
