using Corvus.Core;

namespace Corvus.Tests;

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
        var hits = await h.Native.SearchBytes(path, "00 00 00 00", limit: 3);
        Assert.Matches(@"^\d{10} hits \(showing 1-3\)", hits);
        Assert.Contains("(zero fill, not in the file)", hits);
        Assert.Contains("[More: offset=3]", hits);
        var next = await h.Native.SearchBytes(path, "00 00 00 00", limit: 2, offset: 1_000_000_000);
        Assert.Contains("(showing 1000000001-1000000002)", next);

        // Inside a call the page is cut by the token budget, not by limit, and the record holds the same hits (G1).
        var call = OutputCall.Begin(new OutputCall("search_bytes", 1_000, null));
        var page = await h.Native.SearchBytes(path, "00 00 00 00", limit: 5_000);
        var record = (Corvus.Tools.NativeTools.ByteSearch)call.Record!;
        Assert.InRange(TokenEstimate.Of(page), 1, 1_000);
        Assert.InRange(record.Items!.Count, 10, 4_999);
        Assert.Equal(record.Items.Count, page.Split('\n').Count(l => l.StartsWith("  0x", StringComparison.Ordinal)));
        Assert.Contains($"[More: offset={record.Items.Count}]", page);
        Assert.True(record.Total > 1_000_000_000);
        OutputCall.Begin(null!);
        Assert.Contains("1 function", await h.CodeTools.ListFunctions(path));
        Assert.Contains("0 classes", await h.Analysis.ListCppClasses(path));

        // the scanners behind those tools read the file's bytes, not the 3.5 GB the headers claim (a byte count, not a clock)
        var counted = new ReadCountingImage(Corvus.Native.Pe.PeFile.Open(path));
        Corvus.Native.Code.NativeCodeIndex.Build(counted);
        Corvus.Native.Msvc.MsvcRtti.Analyze(counted);
        Assert.True(counted.BytesRead < 64 << 20, $"{counted.BytesRead:N0} bytes read");
    }

    /// <summary>Counts the bytes an analysis reads, zero fill included.</summary>
    private sealed class ReadCountingImage(Corvus.Native.INativeImage inner) : Corvus.Native.INativeImage
    {
        private long _read;
        public long BytesRead => Interlocked.Read(ref _read);
        public string Path => inner.Path;
        public string Sha256 => inner.Sha256;
        public Corvus.Native.NativeArch Arch => inner.Arch;
        public bool Is64Bit => inner.Is64Bit;
        public bool IsDll => inner.IsDll;
        public ulong ImageBase => inner.ImageBase;
        public uint EntryPointRva => inner.EntryPointRva;
        public uint SizeOfImage => inner.SizeOfImage;
        public IReadOnlyList<Corvus.Native.NativeSection> Sections => inner.Sections;
        public IReadOnlyList<Corvus.Native.NativeImport> Imports => inner.Imports;
        public IReadOnlyList<Corvus.Native.NativeExport> Exports => inner.Exports;
        public IReadOnlyList<Corvus.Native.RuntimeFunction> RuntimeFunctions => inner.RuntimeFunctions;
        public IReadOnlyList<uint> RelocationRvas => inner.RelocationRvas;
        public IReadOnlyList<uint> TlsCallbackRvas => inner.TlsCallbackRvas;
        public IReadOnlyList<Corvus.Native.ParseIssue> Issues => inner.Issues;
        public bool TryRvaToFileOffset(uint rva, out long fileOffset) => inner.TryRvaToFileOffset(rva, out fileOffset);
        public bool TryFileOffsetToRva(long fileOffset, out uint rva) => inner.TryFileOffsetToRva(fileOffset, out rva);
        public Corvus.Native.NativeSection? SectionAt(uint rva) => inner.SectionAt(rva);

        public int Read(uint rva, Span<byte> destination)
        {
            int n = inner.Read(rva, destination);
            Interlocked.Add(ref _read, Math.Max(0, n));
            return n;
        }
    }

    [Fact]
    public async Task Several_patterns_and_addresses_answer_in_one_call_with_an_error_per_bad_item()
    {
        using var dir = new TempDir();
        var path = dir.File("batch.dll");
        var b = new PeBuilder();
        var text = b.Add(".text", [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC], 0x60000020);
        b.EntryPoint = text.Rva;
        File.WriteAllBytes(path, b.Build());
        using var h = new NativeToolHarness();
        var hits = await h.Native.SearchBytes(path, patterns: ["48 89 E5", "?? ??", "CC CC"]);
        Assert.Contains("[1/3] 48 89 E5: 1 hit", hits);
        Assert.Contains("[2/3] ?? ??: error invalid_argument", hits);
        Assert.Contains("[3/3] CC CC: 1 hit", hits);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.Native.SearchBytes(path, "CC", patterns: ["CC"]))).Code);

        var va = $"0x{b.ImageBase + text.Rva:X}";
        var resolved = await h.Native.ResolveAddress(path, addresses: [va, "no_such_name", $"0x{b.ImageBase + text.Rva + 1:X}"]);
        Assert.StartsWith($"{va}: ", resolved);
        Assert.Contains("no_such_name: error", resolved);
        Assert.Equal(3, resolved.Split('\n').Count(l => l.StartsWith("0x", StringComparison.Ordinal) || l.StartsWith("no_such", StringComparison.Ordinal)));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.Native.ResolveAddress(path))).Code);
    }

    [Fact]
    public async Task PatternsMayStartWithWildcardsAsMakeCodePatternWritesThem()
    {
        using var dir = new TempDir();
        var path = dir.File("lead.dll");
        var b = new PeBuilder();
        var text = b.Add(".text", [0x55, 0x48, 0x89, 0xE5, 0x5D, 0xC3, 0xCC, 0xCC], 0x60000020);
        b.EntryPoint = text.Rva;
        File.WriteAllBytes(path, b.Build());
        using var h = new NativeToolHarness();
        Assert.StartsWith("1 hit (showing 1-1):\n", await h.Native.SearchBytes(path, "?? 48 89 E5 ?? C3"));
        Assert.StartsWith("0 hits", await h.Native.SearchBytes(path, "?? 48 89 E6"));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.Native.SearchBytes(path, "?? ??"))).Code);
        var diff = new Corvus.Tools.NativeDiffTools(h.Workspace, h.Code);
        var hit = Assert.Single((await diff.SearchCodePattern("?? ?? 89 E5", "lead.dll")).Hits);
        Assert.Equal((0u, $"0x{b.ImageBase + text.Rva:X}"), (hit.FunctionOffset!.Value, hit.Address));

        // ARM64 hits name their function too
        var arm = h.Workspace.LoadAny(NativeFormats.NativeFixtures.WinArm64DbgShim).Native!;
        var index = await h.Code.Index(arm, null, default);
        var f = index.Functions.First(x => x.Size >= 8);
        var head = new byte[8];
        arm.Image.Read(f.Start, head);
        var armHits = await diff.SearchCodePattern("?? ?? ?? ?? " + string.Join(" ", head.Skip(4).Select(x => x.ToString("X2"))), arm.Id);
        Assert.Empty(armHits.Notes);
        Assert.Contains(armHits.Hits, x => x.FunctionOffset == 0 && x.FunctionAddress == Corvus.Native.NativeAddress.Va(arm.Image, f.Start));
    }

    [WindowsFact]
    public async Task SearchBytesPagesItsHits()
    {
        using var h = new NativeToolHarness();
        var first = await h.Native.SearchBytes(Kernel32, "00 ?? ?? 00", limit: 10_000);
        Assert.True(first.Length < 60_000, $"{first.Length} chars");
        var more = System.Text.RegularExpressions.Regex.Match(first, @"\[More: offset=(\d+)\]");
        Assert.True(more.Success);
        var second = await h.Native.SearchBytes(Kernel32, "00 ?? ?? 00", limit: 10, offset: int.Parse(more.Groups[1].Value));
        Assert.Contains($"(showing {int.Parse(more.Groups[1].Value) + 1}-", second);
    }

    [WindowsFact]
    public async Task SearchBytesCountsWhatANaiveScanCounts()
    {
        using var h = new NativeToolHarness();
        var pe = Corvus.Native.Pe.PeFile.Open(Kernel32);
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
