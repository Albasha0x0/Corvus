using Corvus.Native.Providers;
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
    public async Task Zero_fill_and_raw_sizes_past_the_file_are_not_scanned()
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

        // The scanners behind those tools read the file's bytes, not the 3.5 GB the headers claim (a byte count, not a clock).
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
    public async Task Patterns_may_start_with_wildcards_as_make_code_pattern_writes_them()
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
        var (search, searchText) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.PatternSearch>(() => diff.SearchCodePattern("?? ?? 89 E5", ["lead.dll", "no_such.dll"]));
        var hit = Assert.Single(search.Items);
        Assert.Equal("no_such.dll", Assert.Single(search.Failed!).Image);
        Assert.Contains("1 hit (showing 1-1):", searchText);
        Assert.Equal((0u, $"0x{b.ImageBase + text.Rva:X}"), (hit.FunctionOffset!.Value, hit.Address));

        // ARM64 hits name their function too
        var arm = h.Workspace.LoadAny(NativeFormats.NativeFixtures.WinArm64DbgShim).Native!;
        var index = await h.Code.Index(arm, null, default);
        var f = index.Functions.First(x => x.Size >= 8);
        var head = new byte[8];
        arm.Image.Read(f.Start, head);
        var (armHits, _) = await BuildToolCalls.Collected<Corvus.Tools.NativeDiffTools.PatternSearch>(() =>
            diff.SearchCodePattern("?? ?? ?? ?? " + string.Join(" ", head.Skip(4).Select(x => x.ToString("X2"))), [arm.Id], limit: 5000));
        Assert.Empty(armHits.Notes);
        Assert.Contains(armHits.Items, x => x.FunctionOffset == 0 && x.FunctionAddress == Corvus.Native.NativeAddress.Va(arm.Image, f.Start));
    }

    [WindowsFact]
    public async Task Search_bytes_pages_its_hits()
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
    public async Task Search_bytes_counts_what_a_naive_scan_counts()
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
    public async Task Index_requests_on_an_unloaded_image_are_conflicts()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var native = h.Workspace.LoadAny(Kernel32).Native!;
        h.Workspace.UnloadNative(native);
        var e = await Assert.ThrowsAsync<ToolError>(() => h.Code.Index(native, null, default));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Empty(native.Analysis);
    }

    [WindowsFact]
    public async Task Unload_cancels_the_build_and_a_waiting_call_gets_a_conflict()
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
    public void Concurrent_reloads_of_the_same_image_keep_one_entry()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var stale = h.Workspace.LoadAny(Kernel32).Native!;
        var first = h.Workspace.ReloadNative(stale);
        // A second call that resolved the same entry before the first reload.
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => h.Workspace.ReloadNative(stale)).Code);
        Assert.Same(first, Assert.Single(h.Workspace.Read(() => h.Workspace.Natives)));
        Assert.True(stale.Released.IsCancellationRequested);
        h.Workspace.UnloadNative(first);
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => h.Workspace.ReloadNative(first)).Code);
    }

    [Fact]
    public async Task Bit_masks_and_nibble_wildcards_match_a_naive_scan()
    {
        // 3 MB of random code (crossing the 1 MB chunks), patterns cut from it with random per-byte masks.
        var rng = new Random(1234);
        var code = new byte[3 << 20];
        rng.NextBytes(code);
        var b = new PeBuilder();
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        using var dir = new TempDir();
        var path = dir.File("masked.dll");
        File.WriteAllBytes(path, b.Build());
        byte[] masks = [0xFF, 0xFF, 0xF0, 0x0F, 0x00, 0xE0, 0xF8, 0x81];
        var cases = new List<(string Text, byte[] Bytes, byte[] Mask)>();
        while (cases.Count < 40)
        {
            int at = rng.Next(code.Length - 8), length = rng.Next(1, 7);
            var mask = Enumerable.Range(0, length).Select(_ => masks[rng.Next(masks.Length)]).ToArray();
            if (mask.All(m => m == 0) || mask.Count(m => m != 0) == 1 && byte.PopCount(mask.First(m => m != 0)) < 4) continue; // too many hits to page
            var bytes = code.AsSpan(at, length).ToArray();
            var tokens = bytes.Select((v, i) => mask[i] switch
            {
                0xFF => $"{v:X2}",
                0x00 => "??",
                0xF0 => $"{v >> 4:X}?",
                0x0F => $"?{v & 0xF:X}",
                var m => $"{v & m:X2}&{m:X2}",
            });
            cases.Add((string.Join(" ", tokens), bytes, mask));
        }
        List<ulong> Naive(byte[] bytes, byte[] mask)
        {
            var hits = new List<ulong>();
            for (int i = 0; i + bytes.Length <= code.Length; i++)
            {
                int j = 0;
                while (j < bytes.Length && ((code[i + j] ^ bytes[j]) & mask[j]) == 0) j++;
                if (j == bytes.Length) hits.Add(b.ImageBase + text.Rva + (ulong)i);
            }
            return hits;
        }
        static ulong Va(string address) => Convert.ToUInt64(address, 16);
        using var h = new NativeToolHarness();
        var (batch, _) = await BuildToolCalls.Collected<Corvus.Tools.NativeTools.ByteSearch>(() =>
            h.Native.SearchBytes(path, patterns: cases.Select(c => c.Text).ToArray(), limit: 5000));
        for (int k = 0; k < cases.Count; k++)
        {
            var expected = Naive(cases[k].Bytes, cases[k].Mask);
            var got = batch.Patterns![k].Value!;
            Assert.True(expected.Count == got.Total, $"{cases[k].Text}: {got.Total} hits, naive {expected.Count}");
            Assert.Equal(expected.Take(5000), got.Items.Select(i => Va(i.Address)));
        }
        // mask= on a plain hex pattern means the same as the inline form.
        var (one, _) = await BuildToolCalls.Collected<Corvus.Tools.NativeTools.ByteSearch>(() =>
            h.Native.SearchBytes(path, string.Join(" ", cases[0].Bytes.Select(v => $"{v:X2}")), mask: string.Join(" ", cases[0].Mask.Select(m => $"{m:X2}")), limit: 5000));
        Assert.Equal(batch.Patterns![0].Value!.Total, one.Total);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.Native.SearchBytes(path, "48 8B", mask: "FF"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.Native.SearchBytes(path, "4G"))).Code);
    }

    private sealed class FakeMemory(params NativeMemoryRun[] runs) : INativeEngineControl
    {
        public Task<IReadOnlyList<NativeMemoryRun>> MemoryAsync(uint rva, uint length, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeMemoryRun>>([.. runs.Where(r => r.Rva < rva + length && r.Rva + r.Bytes.Length > rva)]);
        public Task<IReadOnlyList<NativeAnalyzerOption>> AnalyzersAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeReanalysis> ReanalyzeAsync(IReadOnlyList<KeyValuePair<string, string>> options, uint? start, uint? end, double seconds,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeCandidateScan> FunctionCandidatesAsync(int maxInstructions, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NativeMarkResult> SetMarksAsync(IReadOnlyList<NativeMark> marks, string stamp, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    [Fact]
    public async Task Engine_memory_hits_that_differ_from_the_file_are_marked_fixed()
    {
        var b = new PeBuilder();
        var text = b.Add(".text", [0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x48, 0x8B, 0x05, 0x10, 0x20, 0x00, 0x00, 0xC3], 0x60000020);
        b.EntryPoint = text.Rva;
        using var dir = new TempDir();
        var path = dir.File("fixed.dll");
        File.WriteAllBytes(path, b.Build());
        using var h = new NativeToolHarness();
        await h.Native.SearchBytes(path, "C3");
        var native = h.Workspace.GetNative("fixed.dll");
        // The engine holds the first load relocated (00 00 00 00 -> 10 20 00 00) and the second as in the file.
        byte[] loaded = [0x48, 0x8B, 0x05, 0x10, 0x20, 0x00, 0x00, 0xC3, 0x48, 0x8B, 0x05, 0x10, 0x20, 0x00, 0x00, 0xC3];
        var results = await Corvus.Tools.NativeTools.SearchEngine(native, new FakeMemory(new NativeMemoryRun(text.Rva, loaded)),
            [Corvus.Tools.NativeTools.Parse("48 8B 05 10 2? 00 00", false, null)], null, 100, 0, default);
        var (hits, total) = Assert.Single(results);
        Assert.Equal(2, total);
        Assert.Equal([true, false], hits.Select(x => x.Fixed == true));
    }
}
