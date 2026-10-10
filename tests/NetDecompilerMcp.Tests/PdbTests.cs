using System.Buffers.Binary;
using System.Net;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Pdb;
using NetDecompilerMcp.Native.Pe;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

/// <summary>The native PDB reader on synthetic MSF files (valid, malformed, mutated), PDB location and download, and names in the code index.</summary>
public class PdbTests
{
    private static readonly Guid SampleGuid = new("11223344-5566-7788-99aa-bbccddeeff00");

    /// <summary>
    /// A tiny x64 image: .text (entry: mov eax,1 ; ret, nop filler, mov eax,2 ; ret at +0x40 reached by nothing), .rdata
    /// with a CodeView RSDS record naming <paramref name="pdbName"/>, .data.
    /// </summary>
    internal static byte[] TinyImage(Guid guid, uint age, string pdbName = "tiny.pdb")
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new byte[0x80];
        Array.Fill(code, (byte)0x90);
        code[0] = 0xB8; code[1] = 1; code[2] = 0; code[3] = 0; code[4] = 0; code[5] = 0xC3;
        code[0x40] = 0xB8; code[0x41] = 2; code[0x42] = 0; code[0x43] = 0; code[0x44] = 0; code[0x45] = 0xC3;
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        var rdata = b.Add(".rdata", rva =>
        {
            var d = new List<byte>();
            var rsds = new List<byte>(Encoding.ASCII.GetBytes("RSDS"));
            rsds.AddRange(guid.ToByteArray());
            rsds.AddRange(BitConverter.GetBytes(age));
            rsds.AddRange(Encoding.UTF8.GetBytes(@"C:\build\out\" + pdbName));
            rsds.Add(0);
            void U32(uint v) => d.AddRange(BitConverter.GetBytes(v));
            U32(0); U32(0x12345678); U32(0); U32(2); U32((uint)rsds.Count); U32(rva + 28); U32(0);
            d.AddRange(rsds);
            return d.ToArray();
        });
        b.Directories[6] = (rdata.Rva, 28);
        b.Add(".data", new byte[0x200], 0xC0000040);
        return b.Build();
    }

    // ---- reading ----

    [Fact]
    public void ReadsIdentityModulesSectionsAndSymbols()
    {
        var pdb = PdbFile.FromBytes(PdbBuilder.Sample().Build());
        Assert.Empty(pdb.Issues);
        Assert.Equal(SampleGuid, pdb.Guid);
        Assert.Equal((3u, 3u), (pdb.InfoAge, pdb.DbiAge));
        Assert.Equal(20000404u, pdb.Version);
        Assert.Equal((ushort)0x8664, pdb.Machine);
        Assert.Equal([".text", ".data"], pdb.Sections.Select(s => s.Name));
        var m = Assert.Single(pdb.Modules);
        Assert.Equal(@"C:\src\bar.obj", m.Name);
        Assert.False(pdb.HasOmap);

        var syms = pdb.Symbols.Select(s => (s.Kind, s.Name, s.Rva, s.Size)).ToList();
        Assert.Contains((PdbSymbolKind.PublicFunction, "?Foo@Bar@@QEAAHH@Z", (uint?)0x1010, 0u), syms);
        Assert.Contains((PdbSymbolKind.PublicData, "g_value", (uint?)0x3008, 0u), syms);
        Assert.Contains((PdbSymbolKind.GlobalData, "g_value", (uint?)0x3008, 0u), syms);
        Assert.Contains((PdbSymbolKind.GlobalProc, "Bar::Foo", (uint?)0x1010, 0x20u), syms);
        Assert.Contains((PdbSymbolKind.LocalProc, "helper", (uint?)0x1040, 8u), syms);
        Assert.Equal(5, syms.Count);
        Assert.Equal(pdb.Symbols.Select(s => s.Rva).Order(), pdb.Symbols.Select(s => s.Rva));

        Assert.True(pdb.Matches(new PeCodeView("RSDS", SampleGuid, 3, "x.pdb")));
        Assert.False(pdb.Matches(new PeCodeView("RSDS", SampleGuid, 4, "x.pdb")));
        Assert.False(pdb.Matches(new PeCodeView("RSDS", Guid.NewGuid(), 3, "x.pdb")));
    }

    [Fact]
    public void NamingPrefersProceduresAndKeepsTheDecoratedName()
    {
        var names = PdbNaming.Choose(PdbFile.FromBytes(PdbBuilder.Sample().Build())).ToDictionary(n => n.Rva);
        Assert.Equal(3, names.Count);
        Assert.Equal(("Bar::Foo", "?Foo@Bar@@QEAAHH@Z", true, 0x20u), (names[0x1010].Name, names[0x1010].Decorated, names[0x1010].IsFunction, names[0x1010].Size));
        Assert.Equal(("helper", true), (names[0x1040].Name, names[0x1040].IsFunction));
        Assert.Equal(("g_value", false), (names[0x3008].Name, names[0x3008].IsFunction));
        Assert.Equal("public: int __cdecl Bar::Foo(int)", PdbNaming.Signature(names[0x1010].Decorated));
        Assert.Equal("Bar::Foo", PdbNaming.Display("?Foo@Bar@@QEAAHH@Z"));
        // an image size cuts off names beyond the image
        Assert.Equal(2, PdbNaming.Choose(PdbFile.FromBytes(PdbBuilder.Sample().Build()), sizeOfImage: 0x2000).Count);
    }

    [Fact]
    public void AddressesMapThroughOmap()
    {
        var p = new PdbBuilder
        {
            OriginalSections = [(".text", 0x1000, 0x1000), (".data", 0x5000, 0x200)],
            OmapFromSource = [(0x1000, 0x2000), (0x1030, 0), (0x1040, 0x2400), (0x5000, 0x3000)],
        };
        p.GlobalRecords.Add(PdbBuilder.Pub("moved", 1, 0x10, true));    // 0x1010 -> 0x2010
        p.GlobalRecords.Add(PdbBuilder.Pub("removed", 1, 0x30, true));  // 0x1030 -> nowhere
        p.GlobalRecords.Add(PdbBuilder.Pub("later", 1, 0x48, true));    // 0x1048 -> 0x2408
        p.GlobalRecords.Add(PdbBuilder.Pub("var", 2, 4, false));        // 0x5004 -> 0x3004
        var pdb = PdbFile.FromBytes(p.Build());
        Assert.True(pdb.HasOmap);
        var rva = pdb.Symbols.ToDictionary(s => s.Name, s => s.Rva);
        Assert.Equal(0x2010u, rva["moved"]);
        Assert.Null(rva["removed"]);
        Assert.Equal(0x2408u, rva["later"]);
        Assert.Equal(0x3004u, rva["var"]);
        Assert.Equal(pdb.Symbols.Count - 1, pdb.Symbols.TakeWhile(s => s.Rva != null).Count());
    }

    [Theory]
    [InlineData(512u)]
    [InlineData(4096u)]
    public void ManyModulesAndAMultiPageDirectory(uint blockSize)
    {
        var p = new PdbBuilder();
        for (int i = 0; i < 300; i++) p.Modules.Add(($"m{i}.obj", [PdbBuilder.Proc($"f{i}", 1, (uint)(i * 16), 16, true), PdbBuilder.End()]));
        var pdb = PdbFile.FromBytes(p.Build(blockSize));
        Assert.True(pdb.Issues.Count == 0, string.Join("; ", pdb.Issues.Select(i => i.Message)));
        Assert.Equal(300, pdb.Modules.Count);
        Assert.Equal(Enumerable.Range(0, 300).Select(i => (uint?)(0x1000 + i * 16)), pdb.Symbols.Select(s => s.Rva));
        Assert.Equal("m299.obj", pdb.Modules[^1].ObjectFile);
    }

    // ---- malformed input ----

    [Fact]
    public void HeaderProblemsAreTypedErrors()
    {
        var good = PdbBuilder.Sample().Build();
        ErrorCode Code(byte[] bytes) => Assert.Throws<ToolError>(() => PdbFile.FromBytes(bytes)).Code;

        Assert.Equal(ErrorCode.MalformedInput, Code(good[..40]));
        Assert.Equal(ErrorCode.MalformedInput, Code(new byte[4096]));
        var badBlock = (byte[])good.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(badBlock.AsSpan(32), 1000);
        Assert.Equal(ErrorCode.MalformedInput, Code(badBlock));
        var old = new byte[256];
        "Microsoft C/C++ program database 2.00\r\n\u001aJG\0\0"u8.CopyTo(old);
        Assert.Equal(ErrorCode.Unsupported, Code(old));
    }

    public static TheoryData<string> Tampers() => [.. TamperCases.Keys];

    private static readonly Dictionary<string, Action<byte[], MsfBuilder.Layout>> TamperCases = new()
    {
        ["directory size too large"] = (f, _) => BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(44), 0x7FFFFFFF),
        ["block count beyond the file"] = (f, _) => BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(40), 0x100000),
        ["block map outside the file"] = (f, _) => BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(52), 0xFFFFFF),
        ["directory page is the superblock"] = (f, l) => BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan((int)(l.MapBlock * l.BlockSize)), 0),
        ["directory pages all the same block"] = (f, l) =>
        {
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan((int)(l.DirectoryPages[0] * l.BlockSize)), 0xFFFFFFF);
        },
        ["stream sizes beyond the file"] = (f, l) =>
        {
            int dir = (int)(l.DirectoryPages[0] * l.BlockSize);
            for (int i = 1; i <= 6; i++) BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(dir + 4 * i), 0x7FFFFFF0);
        },
        ["stream page beyond the file"] = (f, l) =>
        {
            int dir = (int)(l.DirectoryPages[0] * l.BlockSize);
            int count = BinaryPrimitives.ReadInt32LittleEndian(f.AsSpan(dir));
            // first page of stream 3 (DBI): after the sizes and the pages of streams 0..2 (stream 0 and 2 are empty)
            int at = dir + 4 + count * 4 + 4 * l.StreamPages[1].Count;
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(at), 0xFFFFF0);
        },
        ["truncated symbol record"] = (f, l) =>
        {
            int recs = (int)(l.StreamPages[5][0] * l.BlockSize);
            BinaryPrimitives.WriteUInt16LittleEndian(f.AsSpan(recs), 0xFFF0);
        },
        ["zero-length symbol record"] = (f, l) =>
        {
            int recs = (int)(l.StreamPages[5][0] * l.BlockSize);
            BinaryPrimitives.WriteUInt16LittleEndian(f.AsSpan(recs), 0);
        },
        ["module symbols shorter than declared"] = (f, l) =>
        {
            int dbi = (int)(l.StreamPages[3][0] * l.BlockSize);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(dbi + 64 + 36), 0x100000);
        },
        ["module stream index out of range"] = (f, l) =>
        {
            int dbi = (int)(l.StreamPages[3][0] * l.BlockSize);
            BinaryPrimitives.WriteUInt16LittleEndian(f.AsSpan(dbi + 64 + 34), 0x7000);
        },
        ["DBI substream sizes beyond the stream"] = (f, l) =>
        {
            int dbi = (int)(l.StreamPages[3][0] * l.BlockSize);
            BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(dbi + 24), 0x7FFFFFFF);
        },
        ["negative DBI substream size"] = (f, l) =>
        {
            int dbi = (int)(l.StreamPages[3][0] * l.BlockSize);
            BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(dbi + 48), -5);
        },
        ["module name not terminated"] = (f, l) =>
        {
            int dbi = (int)(l.StreamPages[3][0] * l.BlockSize);
            int modInfo = BinaryPrimitives.ReadInt32LittleEndian(f.AsSpan(dbi + 24));
            f.AsSpan(dbi + 64 + 64, modInfo - 64).Fill((byte)'A');
        },
        ["section headers name a huge address"] = (f, l) =>
        {
            int sec = (int)(l.StreamPages[4][0] * l.BlockSize);
            BinaryPrimitives.WriteUInt32LittleEndian(f.AsSpan(sec + 12), 0xFFFFFFF0);
        },
    };

    [Theory]
    [MemberData(nameof(Tampers))]
    public void MalformedFilesReadWithIssuesAndNoException(string tamper)
    {
        var bytes = PdbBuilder.Sample().Msf().Build(TamperCases[tamper]);
        var pdb = PdbFile.FromBytes(bytes);
        if (tamper != "section headers name a huge address")
            Assert.NotEmpty(pdb.Issues);
        Assert.All(pdb.Symbols, s => Assert.True(s.Rva == null || s.Rva < 0xFFFFFFFF));
        PdbNaming.Choose(pdb);
    }

    [Fact]
    public void TruncatedFilesReadWithoutException()
    {
        var good = PdbBuilder.Sample().Build();
        for (int len = 56; len < good.Length; len += 97)
        {
            var pdb = PdbFile.FromBytes(good[..len]);
            Assert.True(pdb.Issues.Count > 0 || pdb.Symbols.Count == 5, $"length {len}");
        }
    }

    [Fact]
    public void MutatedFilesNeverThrowAfterTheSuperblock()
    {
        var good = PdbBuilder.Sample().Build();
        var rng = new Random(12345);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        int runs = 0;
        while (runs < 2000 && sw.ElapsedMilliseconds < 600)
        {
            var bytes = (byte[])good.Clone();
            int flips = 1 + rng.Next(8);
            for (int i = 0; i < flips; i++)
            {
                int at = 56 + rng.Next(bytes.Length - 56);
                bytes[at] = rng.Next(4) switch { 0 => 0xFF, 1 => 0, _ => (byte)rng.Next(256) };
            }
            var pdb = PdbFile.FromBytes(bytes);
            PdbNaming.Choose(pdb);
            runs++;
        }
        Assert.True(runs >= 200, $"only {runs} runs");
    }

    // ---- location ----

    [Fact]
    public void SymbolPathsSplitIntoStoresAndServers()
    {
        var stores = new List<string>();
        var servers = new List<string>();
        PdbLocator.ParseSymbolPath(@"srv*C:\cache*https://msdl.microsoft.com/download/symbols/;D:\plain; cache*E:\c2 ;symsrv*symsrv.dll*F:\s*http://x.example/sym;SRV*https://only.example", stores, servers);
        Assert.Equal([@"C:\cache", @"D:\plain", @"E:\c2", @"F:\s"], stores);
        Assert.Equal(["https://msdl.microsoft.com/download/symbols", "http://x.example/sym", "https://only.example"], servers);
        Assert.Equal("112233445566778899AABBCCDDEEFF003", PdbLocator.StoreKey(new PeCodeView("RSDS", SampleGuid, 3, "")));
        Assert.Equal("a.pdb", PdbLocator.PdbFileName(new PeCodeView("RSDS", SampleGuid, 3, @"C:\x/y\a.pdb")));
    }

    [Fact]
    public void LocatesBesideTheImageInStoresAndRejectsOtherBuilds()
    {
        using var dir = new TempDir();
        var imagePath = dir.File("tiny.dll");
        File.WriteAllBytes(imagePath, TinyImage(SampleGuid, 3));
        var image = PeFile.Open(imagePath);
        Assert.Equal(SampleGuid, image.CodeView!.Guid);

        // nothing anywhere
        var none = PdbLocator.Locate(image, symbolPath: "srv*" + dir.File("store") + "*https://example.invalid/sym");
        Assert.Null(none.Path);
        Assert.Contains(none.Probes, p => p.Location == imagePath[..^3] + "pdb" && p.Outcome == "not found");
        Assert.Equal(["https://example.invalid/sym"], none.Servers);

        // a symbol store from the symbol path
        var stored = Path.Combine(dir.File("store"), "tiny.pdb", "112233445566778899AABBCCDDEEFF003", "tiny.pdb");
        Directory.CreateDirectory(Path.GetDirectoryName(stored)!);
        File.WriteAllBytes(stored, PdbBuilder.Sample().Build());
        Assert.Equal(stored, PdbLocator.Locate(image, symbolPath: "srv*" + dir.File("store") + "*https://example.invalid/sym").Path);
        // the same store as an explicit directory
        Assert.Equal(stored, PdbLocator.Locate(image, dir.File("store"), symbolPath: "").Path);

        // beside the image, but another age: reported, not used; the store copy is found after it
        File.WriteAllBytes(dir.File("tiny.pdb"), PdbBuilder.Sample(age: 4).Build());
        var r = PdbLocator.Locate(image, symbolPath: "srv*" + dir.File("store") + "*https://example.invalid/sym");
        Assert.Equal(stored, r.Path);
        Assert.Contains(r.Probes, p => p.Location == dir.File("tiny.pdb") && p.Outcome.StartsWith("different age (4, image wants 3)"));
        // not a PDB at all
        File.WriteAllText(dir.File("tiny.pdb"), "junk");
        Assert.Contains(PdbLocator.Locate(image, symbolPath: "").Probes, p => p.Location == dir.File("tiny.pdb") && p.Outcome.StartsWith("unreadable"));
        // beside the image and matching
        File.WriteAllBytes(dir.File("tiny.pdb"), PdbBuilder.Sample().Build());
        Assert.Equal(dir.File("tiny.pdb"), PdbLocator.Locate(image, symbolPath: "").Path);
    }

    private sealed class FakeServer(Func<HttpRequestMessage, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(answer(request));
        }
    }

    [Fact]
    public async Task DownloadsIntoTheStoreLayoutAndVerifies()
    {
        using var dir = new TempDir();
        var cv = new PeCodeView("RSDS", SampleGuid, 3, @"C:\build\tiny.pdb");
        var good = PdbBuilder.Sample().Build();
        var server = new FakeServer(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(good) });
        var path = await PdbLocator.DownloadAsync(cv, "https://sym.example/store/", TimeSpan.FromSeconds(30), 1 << 20, server, dir.File("cache"));
        Assert.Equal(Path.Combine(dir.File("cache"), "tiny.pdb", "112233445566778899AABBCCDDEEFF003", "tiny.pdb"), path);
        Assert.Equal("https://sym.example/store/tiny.pdb/112233445566778899AABBCCDDEEFF003/tiny.pdb", server.Requests.Single().ToString());
        // cached: no second request
        await PdbLocator.DownloadAsync(cv, "https://sym.example/store", TimeSpan.FromSeconds(30), 1 << 20, server, dir.File("cache"));
        Assert.Single(server.Requests);

        var other = new PeCodeView("RSDS", SampleGuid, 9, @"C:\build\tiny.pdb");
        async Task<ErrorCode> Fails(HttpMessageHandler h, long max = 1 << 20) =>
            (await Assert.ThrowsAsync<ToolError>(() => PdbLocator.DownloadAsync(other, "https://sym.example", TimeSpan.FromSeconds(30), max, h, dir.File("cache")))).Code;
        Assert.Equal(ErrorCode.MalformedInput, await Fails(server)); // age 3 served for age 9
        Assert.Equal(ErrorCode.NotFound, await Fails(new FakeServer(_ => new HttpResponseMessage(HttpStatusCode.NotFound))));
        Assert.Equal(ErrorCode.LimitExceeded, await Fails(server, 100));
        Assert.Equal(ErrorCode.ProviderUnavailable, await Fails(new FakeServer(_ => throw new HttpRequestException("refused"))));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() =>
            PdbLocator.DownloadAsync(cv, "file:///c:/x", TimeSpan.FromSeconds(1), 1, server, dir.File("cache")))).Code);
        // nothing but the verified file is left behind
        Assert.Single(Directory.GetFiles(dir.File("cache"), "*", SearchOption.AllDirectories));
    }

    // ---- names in the code index ----

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly PdbService Pdbs;
        public readonly NativeEditService Edits;
        public readonly string ImagePath;

        public Harness()
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new NetDecompilerMcp.Native.Annotations.AnnotationStore(Dir.File("ann")));
            Pdbs = new PdbService(Code);
            Edits = new NativeEditService(Env.Workspace, Code);
            ImagePath = Dir.File("tiny.dll");
            File.WriteAllBytes(ImagePath, TinyImage(SampleGuid, 3));
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    [Fact]
    public async Task AMatchingPdbBesideTheImageIsReadDuringTheFirstIndexBuild()
    {
        using var h = new Harness();
        File.WriteAllBytes(h.Dir.File("tiny.pdb"), PdbBuilder.Sample().Build());
        var native = h.Env.Workspace.LoadAny(h.ImagePath).Native!;
        var index = await h.Code.Index(native, null, default);
        var state = PdbService.StateOf(native);
        Assert.NotNull(state);
        Assert.True(state!.Automatic && state.Verified);
        // the function nothing calls is a function start because the PDB names it
        var helper = index.FunctionByStart(0x1040);
        Assert.NotNull(helper);
        Assert.True(helper!.Sources.HasFlag(FunctionSource.Symbol));
        Assert.Equal("helper", index.NameAt(0x1040));
        Assert.Equal(("g_value", NativeNameSource.Pdb), index.Sourced.NameAt(0x3008));
        Assert.Equal(0x1040u, index.AddressOfName("helper"));
        Assert.Contains("PDB loaded", PdbTools_Status(native));
    }

    private static string PdbTools_Status(LoadedNative native) => NetDecompilerMcp.Tools.PdbTools.Status(native) ?? "";

    [Fact]
    public async Task LoadPdbAppliesNamesKeepsUserNamesAndAddsMissedFunctions()
    {
        using var h = new Harness();
        var native = h.Env.Workspace.LoadAny(h.ImagePath).Native!;
        var index = await h.Code.Index(native, null, default);
        Assert.Null(index.FunctionByStart(0x1040));
        Assert.Contains("not found locally", PdbTools_Status(native));
        h.Edits.Rename(native, index, 0x1000, "MyEntry", false);

        var elsewhere = h.Dir.File("syms");
        Directory.CreateDirectory(elsewhere);
        File.WriteAllBytes(Path.Combine(elsewhere, "tiny.pdb"), PdbBuilder.Sample().Build());
        // a PDB of another build is refused
        File.WriteAllBytes(h.Dir.File("other.pdb"), PdbBuilder.Sample(age: 7).Build());
        var refused = await h.Pdbs.Load(native, h.Dir.File("other.pdb"), false, null, false, TimeSpan.FromSeconds(5), 1 << 20, default);
        Assert.Null(refused.State);
        Assert.Contains(refused.Location.Probes, p => p.Location == h.Dir.File("other.pdb") && p.Outcome.StartsWith("different age"));

        var r = await h.Pdbs.Load(native, elsewhere, false, null, false, TimeSpan.FromSeconds(5), 1 << 20, default);
        Assert.NotNull(r.State);
        Assert.Equal(2, r.NewFunctionStarts); // Bar::Foo and helper: nothing reaches either
        Assert.True(r.Rebuilding);
        Assert.Equal("MyEntry", index.NameAt(0x1000));
        Assert.Equal("Bar::Foo", index.NameAt(0x1010));

        // the rebuilt index replaces the old one and has the PDB's function, its names and the user's name
        var deadline = DateTime.UtcNow.AddSeconds(20);
        NativeCodeIndex? rebuilt;
        while ((rebuilt = h.Code.Ready(native)) == index && DateTime.UtcNow < deadline) await Task.Delay(20);
        Assert.NotSame(index, rebuilt);
        Assert.NotNull(rebuilt!.FunctionByStart(0x1040));
        Assert.Equal("helper", rebuilt.FunctionByStart(0x1040)!.Name);
        Assert.Equal(("MyEntry", NativeNameSource.User), rebuilt.Sourced.NameAt(0x1000));
        Assert.Equal(("Bar::Foo", NativeNameSource.Pdb), rebuilt.Sourced.NameAt(0x1010));
    }

    [Fact]
    public async Task ForceUsesAMismatchingPdb()
    {
        using var h = new Harness();
        var native = h.Env.Workspace.LoadAny(h.ImagePath).Native!;
        await h.Code.Index(native, null, default);
        File.WriteAllBytes(h.Dir.File("other.pdb"), PdbBuilder.Sample(age: 7).Build());
        var r = await h.Pdbs.Load(native, h.Dir.File("other.pdb"), false, null, true, TimeSpan.FromSeconds(5), 1 << 20, default);
        Assert.False(r.State!.Verified);
        Assert.Equal(3, r.State.Names.Count);
    }
}
