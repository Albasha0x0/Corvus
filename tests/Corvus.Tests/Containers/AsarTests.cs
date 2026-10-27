using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>ASAR archives built by <see cref="AsarWriter"/>: listing, integrity at header, file and block level, unpacked entries, links, hostile headers.</summary>
public sealed class AsarTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static readonly AsarWriter.File[] AppFiles =
    [
        AsarWriter.Text("package.json", """{"name":"demo","version":"1.2.3","main":"dist/main.js"}"""),
        AsarWriter.Text("dist/main.js", "const { app } = require('electron');\n"),
        AsarWriter.Text("dist/sub/deep.txt", "deep"),
        AsarWriter.Text("native/addon.node", "unpacked add-on bytes", unpacked: true),
    ];

    private static AsarArchive Read(byte[] bytes) => AsarArchive.Read(new MemoryStream(bytes));

    private string Write(string name, byte[] bytes)
    {
        var path = _dir.File(name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    [Fact]
    public void Lists_files_directories_and_links()
    {
        var (bytes, header) = AsarWriter.Build(AppFiles, [("dist/alias.js", "dist/main.js")]);
        Assert.Equal("asar", Blob.Identify(bytes));
        var archive = Read(bytes);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(header)), archive.HeaderSha256);
        Assert.Empty(archive.Issues);
        Assert.Equal(["dist", "dist/alias.js", "dist/main.js", "dist/sub", "dist/sub/deep.txt", "native", "native/addon.node", "package.json"],
            archive.Entries.Select(e => e.Path).Order(StringComparer.Ordinal));
        var link = archive.Find("dist/alias.js")!;
        Assert.Equal(AsarEntryKind.Link, link.Kind);
        Assert.Equal("dist/main.js", archive.ResolveLink(link, out _)!.Path);
        Assert.True(archive.Find("native/addon.node")!.Unpacked);
        Assert.Equal("deep", Encoding.UTF8.GetString(archive.ReadPacked(new MemoryStream(bytes), archive.Find("dist/sub/deep.txt")!, 1 << 20)!));
    }

    [Fact]
    public void List_assemblies_shows_entries_with_integrity_and_pages()
    {
        var path = Write("app.asar", AsarWriter.Build(AppFiles).Archive);
        var listing = new UnpackService(_workspace).List(path, AnalysisLimits.Default, default, limit: 3);
        Assert.Equal(AsarContainer.Kind, listing.Container);
        Assert.Empty(listing.Assemblies);
        Assert.Equal(7, listing.FileTotal);
        Assert.Equal(3, listing.Files!.Count);
        var all = new UnpackService(_workspace).List(path, AnalysisLimits.Default, default).Files!;
        Assert.Contains(all, f => f.Path == "dist/main.js" && f.Detail == "integrity ok");
        Assert.Contains(all, f => f.Path == "native/addon.node" && f.Detail!.Contains("unpacked_missing"));
        Assert.Contains(listing.Notes, n => n.StartsWith("ASAR archive: 4 file(s) (1 unpacked), 3 director(ies)", StringComparison.Ordinal));
        Assert.Contains(listing.Notes, n => n.StartsWith("Header integrity absent", StringComparison.Ordinal));
        var filtered = new UnpackService(_workspace).List(path, AnalysisLimits.Default, default, filter: "sub/");
        Assert.Equal(["dist/sub/", "dist/sub/deep.txt"], filtered.Files!.Select(f => f.Path));
    }

    [Fact]
    public void Unpacks_every_file_with_unpacked_entries_and_link_copies()
    {
        var path = Write("app.asar", AsarWriter.Build(AppFiles, [("dist/alias.js", "dist/main.js")]).Archive);
        Directory.CreateDirectory(_dir.File("app.asar.unpacked/native"));
        File.WriteAllText(_dir.File("app.asar.unpacked/native/addon.node"), "unpacked add-on bytes");
        var output = _dir.File("out");
        var report = new UnpackService(_workspace).Unpack(path, output, load: false, AnalysisLimits.Default, default);
        Assert.Equal(AsarContainer.Kind, report.Container);
        Assert.Equal("const { app } = require('electron');\n", File.ReadAllText(Path.Combine(output, "dist", "main.js.bin")));
        Assert.Equal("const { app } = require('electron');\n", File.ReadAllText(Path.Combine(output, "dist", "alias.js.bin")));
        Assert.Equal("unpacked add-on bytes", File.ReadAllText(Path.Combine(output, "native", "addon.node")));
        Assert.Equal("deep", File.ReadAllText(Path.Combine(output, "dist", "sub", "deep.txt")));
        Assert.Contains(report.Files, f => f.Origin == "ASAR unpacked entry");
        Assert.Contains(report.Notes, n => n.StartsWith("File integrity: 4 ok", StringComparison.Ordinal));
    }

    [Fact]
    public void File_and_block_hashes_are_checked()
    {
        var big = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        var (bytes, _) = AsarWriter.Build([new("a.bin", big), AsarWriter.Text("b.txt", "bee"), new("c.txt", "sea"u8.ToArray(), Integrity: false)], blockSize: 16);
        var archive = Read(bytes);
        byte[] buffer = [];
        var stream = new MemoryStream(bytes);
        Assert.Equal("ok", archive.Verify(stream, null, archive.Find("a.bin")!, ref buffer).Status);
        Assert.Equal("no_integrity", archive.Verify(stream, null, archive.Find("c.txt")!, ref buffer).Status);

        // One byte in block 3 of a.bin.
        var damaged = (byte[])bytes.Clone();
        damaged[archive.DataStart + 3 * 16 + 5] ^= 0xFF;
        var verdict = archive.Verify(new MemoryStream(damaged), null, archive.Find("a.bin")!, ref buffer);
        Assert.Equal(("hash_mismatch", 3), (verdict.Status, verdict.FirstBadBlock));

        // Only a declared block hash is wrong: the whole-file hash still matches.
        var blockHash = Convert.ToHexStringLower(SHA256.HashData(big.AsSpan(32, 16)));
        var (edited, _) = AsarWriter.Build([new("a.bin", big)], blockSize: 16, editHeader: h => h.Replace(blockHash, new string('0', 64)));
        var e = Read(edited);
        var block = e.Verify(new MemoryStream(edited), null, e.Find("a.bin")!, ref buffer);
        Assert.Equal(("block_mismatch", 2), (block.Status, block.FirstBadBlock));
    }

    [Fact]
    public void Unpacked_addon_signed_after_packing_still_matches()
    {
        var unsigned = ElectronFixtures.Executable(null, fuses: null);
        Array.Resize(ref unsigned, (unsigned.Length + 7) & ~7);
        var (bytes, _) = AsarWriter.Build([new("addon.node", unsigned, Unpacked: true)]);
        var path = Write("app.asar", bytes);
        // What signing does: checksum and security directory set, the certificate table appended.
        var signed = unsigned.Concat(new byte[16]).ToArray();
        BitConverter.GetBytes(0x1234u).CopyTo(signed, 0x58 + 64);
        BitConverter.GetBytes((uint)unsigned.Length).CopyTo(signed, 0x58 + 112 + 32);
        BitConverter.GetBytes(16u).CopyTo(signed, 0x58 + 112 + 36);
        Directory.CreateDirectory(_dir.File("app.asar.unpacked"));
        File.WriteAllBytes(_dir.File("app.asar.unpacked/addon.node"), signed);
        var archive = Read(bytes);
        byte[] buffer = [];
        Assert.Equal("ok_signed_after_packing", archive.Verify(new MemoryStream(bytes), path, archive.Find("addon.node")!, ref buffer).Status);
        signed[0x300] ^= 1;
        File.WriteAllBytes(_dir.File("app.asar.unpacked/addon.node"), signed);
        Assert.Equal("hash_mismatch", archive.Verify(new MemoryStream(bytes), path, archive.Find("addon.node")!, ref buffer).Status);
        File.WriteAllBytes(_dir.File("app.asar.unpacked/addon.node"), [.. unsigned, 1, 2, 3]);
        Assert.Equal("size_mismatch", archive.Verify(new MemoryStream(bytes), path, archive.Find("addon.node")!, ref buffer).Status);
    }

    [Fact]
    public void Header_integrity_is_good_bad_or_absent()
    {
        var (bytes, header) = AsarWriter.Build(AppFiles);
        var sha = Convert.ToHexStringLower(SHA256.HashData(header));
        string Header(string app, string? declared) =>
            new UnpackService(_workspace).List(ElectronFixtures.App(_dir.File(app), bytes, declared), AnalysisLimits.Default, default).Notes[1];
        Assert.StartsWith("Header integrity good: matches the hash declared in App.exe resource INTEGRITY/ELECTRONASAR", Header("good", sha));
        Assert.StartsWith("Header integrity BAD", Header("bad", new string('a', 64)));
        Assert.StartsWith("Header integrity absent", Header("absent", null));
        Assert.Equal(sha, Electron.DeclaredFor(_dir.File("good/resources/app.asar"))!.Hash);
    }

    [Fact]
    public void Traversal_names_are_listed_but_never_written()
    {
        var (bytes, _) = AsarWriter.Build([AsarWriter.Text("evil1.txt", "x"), AsarWriter.Text("evil2.txt", "y"), AsarWriter.Text("ok.txt", "z")],
            editHeader: h => h.Replace("\"evil1.txt\"", "\"..\"").Replace("\"evil2.txt\"", "\"..\\\\..\\\\x.txt\""));
        var archive = Read(bytes);
        Assert.Equal(2, archive.Entries.Count(e => e.UnsafeName));
        Assert.Contains(archive.Issues, i => i.StartsWith("unsafe_name: 2", StringComparison.Ordinal));
        var output = _dir.File("out");
        var report = new UnpackService(_workspace).Unpack(Write("t.asar", bytes), output, load: false, AnalysisLimits.Default, default);
        Assert.Equal(["ok.txt"], report.Files.Select(f => Path.GetRelativePath(output, f.Path)));
        Assert.Contains(report.Notes, n => n.Contains("2 entr(ies) with unsafe names not extracted", StringComparison.Ordinal));
        Assert.False(File.Exists(_dir.File("x.txt")));
    }

    [Fact]
    public void Links_stay_inside_the_archive()
    {
        var (bytes, _) = AsarWriter.Build([AsarWriter.Text("a/f.txt", "f")],
            [("up", "../outside"), ("loop1", "loop2"), ("loop2", "loop1"), ("dir", "a"), ("gone", "a/missing")]);
        var archive = Read(bytes);
        string? Problem(string path) { archive.ResolveLink(archive.Find(path)!, out var p); return p; }
        Assert.Equal("link_escapes", Problem("up"));
        Assert.Equal("link_cycle", Problem("loop1"));
        Assert.Equal("link_to_directory", Problem("dir"));
        Assert.Equal("link_missing", Problem("gone"));
    }

    [DirectoryLinkFact]
    public void Unpacked_entries_through_a_link_are_refused()
    {
        var (bytes, _) = AsarWriter.Build([AsarWriter.Text("lib/secret.txt", "s", unpacked: true)]);
        var path = Write("app.asar", bytes);
        Directory.CreateDirectory(_dir.File("app.asar.unpacked"));
        Directory.CreateDirectory(_dir.File("elsewhere"));
        File.WriteAllText(_dir.File("elsewhere/secret.txt"), "s");
        Links.CreateDirectoryLink(_dir.File("app.asar.unpacked/lib"), _dir.File("elsewhere"));
        var archive = Read(bytes);
        Assert.Null(AsarArchive.UnpackedPath(path, archive.Find("lib/secret.txt")!, out var problem));
        Assert.Equal("unpacked_is_link", problem);
    }

    [Theory]
    [InlineData("""{"files":{"a":{"size":1,"offset":"x1"}}}""", "bad_offset")]
    [InlineData("""{"files":{"a":{"size":1,"offset":"999999"}}}""", "out_of_range")]
    [InlineData("""{"files":{"a":{"size":4,"offset":"0"},"b":{"size":4,"offset":"2"}}}""", "overlap")]
    [InlineData("""{"files":{"a":{"size":1,"offset":"0"},"a":{"files":{"b":{"size":1,"offset":"0"}}}}}""", "duplicate_key")]
    [InlineData("""{"files":{"a":{"size":1,"offset":"0"}""", "malformed_header")]
    [InlineData("""{"files":{"a":7}}""", "bad_entry")]
    public void Malformed_headers_give_issues(string json, string issue)
    {
        var (bytes, _) = AsarWriter.Build([new("pad", new byte[8], Integrity: false)], editHeader: _ => json);
        var archive = Read(bytes);
        Assert.Contains(archive.Issues, i => i.StartsWith(issue, StringComparison.Ordinal));
    }

    [Fact]
    public void Duplicate_keys_keep_the_last_occurrence()
    {
        var (bytes, _) = AsarWriter.Build([new("pad", new byte[8], Integrity: false)],
            editHeader: _ => """{"files":{"a":{"files":{"old":{"size":1,"offset":"0"}}},"a":{"files":{"new":{"size":1,"offset":"1"}}}}}""");
        Assert.Equal(["a", "a/new"], Read(bytes).Entries.Select(e => e.Path));
    }

    [Fact]
    public void Deep_nesting_stops_with_an_issue()
    {
        var json = string.Concat(Enumerable.Repeat("""{"files":{"d":""", 300)) + """{"size":0,"offset":"0"}""" + new string('}', 600) + "}";
        var (bytes, _) = AsarWriter.Build([new("pad", new byte[8], Integrity: false)], editHeader: _ => json);
        Assert.Contains(Read(bytes).Issues, i => i.StartsWith("malformed_header", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(4u, 0xFFFFFFF0u, 0xFFFFFFECu, 8u)] // lengths past the end
    [InlineData(4u, 100u, 50u, 8u)] // pickle and payload disagree
    [InlineData(4u, 24u, 20u, 64u)] // JSON longer than the payload
    public void Broken_pickle_headers_are_malformed_input(uint first, uint pickle, uint payload, uint json)
    {
        var bytes = new byte[64];
        BitConverter.GetBytes(first).CopyTo(bytes, 0);
        BitConverter.GetBytes(pickle).CopyTo(bytes, 4);
        BitConverter.GetBytes(payload).CopyTo(bytes, 8);
        BitConverter.GetBytes(json).CopyTo(bytes, 12);
        bytes[16] = (byte)'{';
        Assert.Equal(ErrorCode.MalformedInput, Assert.Throws<ToolError>(() => Read(bytes)).Code);
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void A_30_MB_archive_lists_within_a_second_and_100_MiB()
    {
        var rng = new Random(7);
        var files = Enumerable.Range(0, 3000).Select(i =>
        {
            var b = new byte[10_000];
            rng.NextBytes(b);
            return new AsarWriter.File($"node_modules/pkg{i % 300}/lib/file{i}.js", b);
        }).ToList();
        var path = Write("big.asar", AsarWriter.Build(files).Archive);
        var unpacker = new UnpackService(_workspace);
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        var cpu = ThreadCpuClock.Now();
        var listing = unpacker.List(path, AnalysisLimits.Default, default);
        var took = ThreadCpuClock.Now() - cpu;
        allocated = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Assert.Equal(3000 + 300 * 2 + 1, listing.FileTotal);
        Assert.Contains(listing.Notes, n => n.StartsWith("File integrity: 3000 ok", StringComparison.Ordinal));
        PerfBudget.Time("containers/asar-list-cpu", took, TimeSpan.FromSeconds(1), output);
        Assert.True(allocated < 100L * 1024 * 1024, $"listing allocated {allocated / 1048576.0:0.0} MiB");
    }

    [Fact]
    [FuzzEntry(typeof(AsarArchive), typeof(AsarContainer))]
    public void Header_fuzz_never_throws_unexpectedly()
    {
        var (seed, _) = AsarWriter.Build(AppFiles, [("dist/alias.js", "dist/main.js")], blockSize: 8);
        var failures = FormatFuzz.Run(seed, bytes =>
        {
            AsarArchive archive;
            try { archive = Read(bytes); }
            catch (ToolError) { return; }
            byte[] buffer = [];
            var stream = new MemoryStream(bytes);
            foreach (var e in archive.Entries)
            {
                archive.Verify(stream, null, e, ref buffer);
                if (e.Kind == AsarEntryKind.Link) archive.ResolveLink(e, out _);
                archive.ReadPacked(stream, e, 1 << 20);
            }
            AsarContainer.Open(bytes, null, allFiles: true, AnalysisLimits.Default, default);
        }, 3000);
        Assert.Empty(failures);
    }
}
