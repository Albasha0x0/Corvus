using System.Diagnostics;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Tests;

/// <summary>Native tools stay fast and bounded on hostile layouts, and fence work on images that are unloaded or reloaded.</summary>
public class NativeToolBoundsTests
{
    private static readonly string Kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    /// <summary>An x64 image whose .text claims 2 GB of raw data past the end of the file and whose .bss is 1.5 GB of zero fill.</summary>
    private static byte[] HugeSections()
    {
        var b = new PeBuilder();
        var text = b.Add(".text", [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC], 0x60000020);
        text.RawOffset = 0x400;
        text.RawSize = 0x7FFFFE00;
        b.EntryPoint = text.Rva;
        var data = b.Add(".data", Enumerable.Repeat((byte)0x11, 64).ToArray(), 0xC0000040, virtualSize: 0x60000000);
        data.RawOffset = 0x600;
        return b.Build();
    }

    [Fact]
    public async Task ZeroFillAndRawSizesPastTheFileAreNotScanned()
    {
        using var dir = new TempDir();
        var path = dir.File("huge.dll");
        File.WriteAllBytes(path, HugeSections());
        using var h = new NativeToolHarness();
        var sw = Stopwatch.StartNew();
        var hits = await h.Native.SearchBytes(path, "00 00 00 00", limit: 3);
        Assert.Matches(@"^\d{10} hits \(showing 1-3\)", hits);
        Assert.Contains("(zero fill, not in the file)", hits);
        Assert.Contains("[More: call again with offset=3]", hits);
        var next = await h.Native.SearchBytes(path, "00 00 00 00", limit: 2, offset: 1_000_000_000);
        Assert.Contains("(showing 1000000001-1000000002)", next);
        Assert.Contains("1 function", await h.CodeTools.ListFunctions(path));
        Assert.Contains("0 classes", await h.Analysis.ListCppClasses(path));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"took {sw.Elapsed}");
    }

    [WindowsFact]
    public async Task SearchBytesPagesItsHits()
    {
        using var h = new NativeToolHarness();
        var first = await h.Native.SearchBytes(Kernel32, "00 ?? ?? 00", limit: 10_000);
        Assert.True(first.Length < 60_000, $"{first.Length} chars");
        var more = System.Text.RegularExpressions.Regex.Match(first, @"\[More: call again with offset=(\d+)\]");
        Assert.True(more.Success);
        var second = await h.Native.SearchBytes(Kernel32, "00 ?? ?? 00", limit: 10, offset: int.Parse(more.Groups[1].Value));
        Assert.Contains($"(showing {int.Parse(more.Groups[1].Value) + 1}-", second);
    }

    [WindowsFact]
    public async Task SearchBytesCountsWhatANaiveScanCounts()
    {
        using var h = new NativeToolHarness();
        var pe = NetDecompilerMcp.Native.Pe.PeFile.Open(Kernel32);
        byte?[] pattern = [0x48, 0x8B, null, 0x24];
        long naive = 0;
        foreach (var s in pe.Sections)
        {
            var data = new byte[Math.Min(s.MappedSize, pe.SizeOfImage - s.Rva)];
            int n = pe.Read(s.Rva, data);
            for (int i = 0; i + pattern.Length <= n; i++)
                if (pattern.Select((b, k) => b == null || data[i + k] == b).All(x => x)) naive++;
        }
        var text = await h.Native.SearchBytes(Kernel32, "48 8B ?? 24", limit: 1);
        Assert.StartsWith($"{naive} hits", text);
    }

    [WindowsFact]
    public async Task IndexRequestsOnAnUnloadedImageAreConflicts()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var native = h.Workspace.LoadAny(Kernel32).Native!;
        h.Workspace.UnloadNative(native);
        var e = await Assert.ThrowsAsync<ToolError>(() => h.Code.Index(native, null, default));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Empty(native.Analysis);
    }

    [WindowsFact]
    public async Task UnloadCancelsTheBuildAWaitingCallGetsAConflict()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var native = h.Workspace.LoadAny(Kernel32).Native!;
        var waiting = h.Code.Index(native, null, default);
        h.Workspace.UnloadNative(native);
        try { await waiting; } // the build may finish before the unload lands
        catch (ToolError e) { Assert.Equal(ErrorCode.Conflict, e.Code); }
        Assert.True(native.Released.IsCancellationRequested);
    }

    [WindowsFact]
    public void ConcurrentReloadsOfTheSameImageKeepOneEntry()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var stale = h.Workspace.LoadAny(Kernel32).Native!;
        var first = h.Workspace.ReloadNative(stale);
        // a second call that resolved the same entry before the first reload
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => h.Workspace.ReloadNative(stale)).Code);
        Assert.Same(first, Assert.Single(h.Workspace.Read(() => h.Workspace.Natives)));
        Assert.True(stale.Released.IsCancellationRequested);
        h.Workspace.UnloadNative(first);
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => h.Workspace.ReloadNative(first)).Code);
    }
}
