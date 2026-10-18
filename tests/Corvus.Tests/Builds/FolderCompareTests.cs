using System.Diagnostics;
using System.IO.Compression;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

public sealed class FolderCompareTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly FolderCompare _service = new();

    public void Dispose() => _dir.Dispose();

    private string Folder(string name, params (string Path, string Text)[] files)
    {
        var root = _dir.File(name);
        Directory.CreateDirectory(root);
        foreach (var (path, text) in files)
        {
            var full = Path.Combine(root, path);
            Directory.CreateDirectory(Path.GetDirectoryName(full)!);
            File.WriteAllText(full, text);
        }
        return root;
    }

    private string Zip(string name, params (string Path, string Text)[] entries)
    {
        var path = _dir.File(name);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (entry, text) in entries)
            using (var w = new StreamWriter(zip.CreateEntry(entry).Open())) w.Write(text);
        return path;
    }

    private FolderCompare.Comparison Run(string a, string b, string change = "all", bool? caseSensitive = null, int maxEntries = FolderCompare.DefaultMaxEntries,
        string? exclude = null, CancellationToken ct = default) =>
        _service.Compare(a, b, change, caseSensitive, exclude, maxEntries, 0, 2000, null, ct);

    private static FolderCompare.Entry One(FolderCompare.Comparison c, string path) =>
        Assert.Single(c.Entries, e => e.NewPath == path || e.OldPath == path);

    [Fact]
    public async Task A_missing_path_is_named()
    {
        var a = Folder("one", ("x.txt", "x"));
        var e = await Assert.ThrowsAsync<ToolError>(() => new Corvus.Tools.FolderTools(_service).CompareFolders(newPath: a));
        Assert.Equal((ErrorCode.InvalidArgument, "oldPath is missing: compare_folders takes both paths."), (e.Code, e.Message));
    }

    /// <summary>Two Electron archives compared by their headers' entries, without unpacking.</summary>
    [Fact]
    public void AsarArchivesCompareByEntry()
    {
        string Asar(string name, params (string Path, string Text)[] files)
        {
            var path = _dir.File(name);
            File.WriteAllBytes(path, AsarWriter.Build(files.Select(f => AsarWriter.Text(f.Path, f.Text))).Archive);
            return path;
        }
        var a = Asar("old.asar", ("main.js", "same"), ("preload.js", "v1"), ("gone.js", "x"));
        var b = Asar("new.asar", ("main.js", "same"), ("preload.js", "v2"), ("added.js", "y"));
        var c = Run(a, b);
        Assert.Equal("asar", c.Old.Kind);
        Assert.Equal("unchanged", One(c, "main.js").Change);
        Assert.Equal("modified", One(c, "preload.js").Change);
        Assert.Equal("added", One(c, "added.js").Change);
        Assert.Equal("removed", One(c, "gone.js").Change);
    }

    [Fact]
    public async Task AddedRemovedModifiedMovedUnchanged()
    {
        var a = Folder("a", ("same.txt", "same"), ("edit.json", "{\"v\": 1}\n"), ("gone.txt", "gone"), ("old/moved.bin", "moved content"), ("Logs/x.log", "1"));
        var b = Folder("b", ("same.txt", "same"), ("edit.json", "{\"v\": 2}\n"), ("new.txt", "new"), ("new/moved.bin", "moved content"), ("Logs/x.log", "2"));
        var c = await new Corvus.Tools.FolderTools(_service).CompareFolders(a, b, "all", exclude: ["Logs/*"], limit: 2000); // through the tool: exclude is a list of globs
        Assert.Equal("sha256", c.HashBasis);
        Assert.Equal((1, 1, 1, 1, 1), (c.Counts.Unchanged, c.Counts.Modified, c.Counts.Added, c.Counts.Removed, c.Counts.Moved));
        Assert.True(c.Old.Complete && c.New.Complete && !c.Counts.UnchangedAtLeast);
        Assert.Equal("old/moved.bin", One(c, "new/moved.bin").OldPath);
        var edit = One(c, "edit.json");
        Assert.Equal(("modified", "text"), (edit.Change, edit.Kind));
        Assert.Contains("-{\"v\": 1}", edit.Diff);
        Assert.Contains("+{\"v\": 2}", edit.Diff);
        Assert.DoesNotContain(c.Entries, e => e.NewPath == "Logs/x.log");
        Assert.DoesNotContain(Run(a, b, change: "changed").Entries, e => e.Change == "unchanged");
    }

    [Fact]
    public void AmbiguousMovesListCandidates()
    {
        var a = Folder("a", ("x/dup.bin", "twin"), ("y/dup.bin", "twin"));
        var b = Folder("b", ("z/dup.bin", "twin"));
        var c = Run(a, b);
        Assert.Equal(3, c.Counts.MovedAmbiguous);
        Assert.Equal(0, c.Counts.Moved + c.Counts.Added + c.Counts.Removed);
        var z = One(c, "z/dup.bin");
        Assert.Equal(2, z.CandidateCount);
        Assert.Equal(["x/dup.bin", "y/dup.bin"], z.Candidates!.Order());
    }

    [Fact]
    public void CaseOnlyRenames()
    {
        var a = Folder("a", ("Readme.TXT", "text"));
        var b = Folder("b", ("readme.txt", "text"));
        var insensitive = Run(a, b, caseSensitive: false);
        Assert.Equal("renamed", Assert.Single(insensitive.Entries).Change);
        var sensitive = Run(a, b, caseSensitive: true);
        Assert.Equal(("moved", "Readme.TXT", "readme.txt"), (Assert.Single(sensitive.Entries).Change, sensitive.Entries[0].OldPath, sensitive.Entries[0].NewPath));
    }

    [DirectoryLinkFact]
    public void LinksAreReportedNotFollowed()
    {
        var target = Folder("target", ("inside.txt", "x"));
        var a = Folder("a", ("f.txt", "f"));
        var b = Folder("b", ("f.txt", "f"));
        Links.CreateDirectoryLink(Path.Combine(b, "linked"), target);
        var c = Run(a, b);
        var link = One(c, "linked");
        Assert.Equal(("added", "link"), (link.Change, link.Kind));
        Assert.Equal(1, c.Counts.Links);
        Assert.DoesNotContain(c.Entries, e => e.NewPath?.Contains("inside.txt") == true);
    }

    [Fact]
    public void LockedFileIsUnreadableNeverUnchanged()
    {
        var a = Folder("a", ("locked.bin", "content"));
        var b = Folder("b", ("locked.bin", "content"));
        using var hold = new FileStream(Path.Combine(b, "locked.bin"), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        var c = Run(a, b);
        Assert.Equal("unreadable", Assert.Single(c.Entries).Change);
        Assert.Equal(0, c.Counts.Unchanged);
        Assert.Contains(c.New.Problems, p => p.Contains("could not be read"));
    }

    [Fact]
    public void LimitMakesTheSideIncompleteAndClaimsNoAdditions()
    {
        var files = Enumerable.Range(0, 6).Select(i => ($"f{i}.txt", $"v{i}")).ToArray();
        var a = Folder("a", files);
        var b = Folder("b", files);
        var c = Run(a, b, maxEntries: 3);
        Assert.False(c.Old.Complete);
        Assert.True(c.Counts.UnchangedAtLeast);
        Assert.Equal(0, c.Counts.Added + c.Counts.Removed);
        Assert.Equal(3, c.Counts.Unchanged);
        Assert.Contains(c.Notes, n => n.Contains("incomplete"));
    }

    [Fact]
    public void CancelledCallThrows()
    {
        var a = Folder("a", ("f.txt", "1"));
        var b = Folder("b", ("f.txt", "2"));
        Assert.ThrowsAny<OperationCanceledException>(() => Run(a, b, ct: new CancellationToken(true)));
    }

    [Fact]
    public void ZipVersusZipReadsNoEntry()
    {
        var a = Zip("a.nupkg", ("lib/same.bin", "same"), ("lib/changed.bin", "one"), ("old/moved.bin", "moved data"), ("gone.bin", "gone"));
        var b = Zip("b.nupkg", ("lib/same.bin", "same"), ("lib/changed.bin", "two"), ("new/moved.bin", "moved data"), ("added.bin", "added"));
        var c = Run(a, b);
        Assert.Equal(("zip", "zip", "crc32+size"), (c.Old.Kind, c.New.Kind, c.HashBasis));
        Assert.Equal((1, 1, 1, 1, 1), (c.Counts.Unchanged, c.Counts.Modified, c.Counts.Added, c.Counts.Removed, c.Counts.Moved));
        Assert.Equal((0, 0), (c.Old.EntryReads, c.New.EntryReads));
    }

    [Fact]
    public void FolderVersusZipComparesByCrc()
    {
        var a = Folder("a", ("lib/a.bin", "alpha"), ("b.txt", "beta"));
        var b = Zip("b.zip", ("lib/a.bin", "alpha"), ("b.txt", "beta!"));
        var c = Run(a, b);
        Assert.Equal("crc32+size", c.HashBasis);
        Assert.Equal((1, 1), (c.Counts.Unchanged, c.Counts.Modified));
        Assert.Contains("+beta!", One(c, "b.txt").Diff);
        Assert.DoesNotContain("\r", One(Run(Folder("crlf-a", ("w.ini", "a=1\r\nb=2\r\n")), Folder("crlf-b", ("w.ini", "a=1\r\nb=3\r\n"))), "w.ini").Diff);
        Assert.Equal(2, c.New.EntryReads); // the changed text entry only: its kind probe and its diff
    }

    [Fact]
    public void Diff_false_lists_a_changed_text_file_without_reading_it_for_a_diff()
    {
        var a = Folder("plain-a", ("b.txt", "beta"));
        var b = Folder("plain-b", ("b.txt", "beta!"));
        var c = _service.Compare(a, b, "all", null, null, FolderCompare.DefaultMaxEntries, 0, 100, null, default, diff: false);
        var entry = One(c, "b.txt");
        Assert.Equal(("modified", "text", null), (entry.Change, entry.Kind, entry.Diff));
    }

    [Fact]
    public void ChangedAssemblyGetsFactsAndNextStep()
    {
        var a = Folder("a");
        var b = Folder("b");
        File.Copy(Env.FixturePath, Path.Combine(a, "App.dll"));
        File.Copy(Env.ConsumerPath, Path.Combine(b, "App.dll"));
        var e = Assert.Single(Run(a, b).Entries);
        Assert.Equal(("modified", "dotnet"), (e.Change, e.Kind));
        Assert.NotNull(e.Old!.Mvid);
        Assert.NotEqual(e.Old.Mvid, e.New!.Mvid);
        Assert.NotNull(e.New.Timestamp);
        Assert.Contains("compare_assemblies oldAssembly=App.dll newAssembly=App.dll#2", e.NextStep);
    }

    [Fact]
    public void NativeImageGetsMachineAndNativeNextStep()
    {
        var a = Folder("a");
        var b = Folder("b");
        File.WriteAllBytes(Path.Combine(a, "n.dll"), NativePeTests.KitchenSink(is64: true));
        File.WriteAllBytes(Path.Combine(b, "n.dll"), [.. NativePeTests.KitchenSink(is64: true), 0]);
        var e = Assert.Single(Run(a, b).Entries);
        Assert.Equal(("modified", "pe"), (e.Change, e.Kind));
        Assert.Equal("AMD64", e.New!.Machine);
        Assert.Contains("compare_native_images oldImage=n.dll newImage=n.dll#2", e.NextStep);
    }

    [Fact]
    public void RepeatCallsReuseHashes()
    {
        var a = Folder("a", ("1.txt", "1"), ("2.txt", "2"));
        var b = Folder("b", ("1.txt", "1"), ("2.txt", "3"));
        var first = Run(a, b);
        Assert.Equal((2, 0), (first.Old.Hashed, first.Old.Reused));
        File.WriteAllText(Path.Combine(b, "2.txt"), "33");
        var second = Run(a, b);
        Assert.Equal((0, 2), (second.Old.Hashed, second.Old.Reused));
        Assert.Equal((1, 1), (second.New.Hashed, second.New.Reused));
        Assert.Equal(1, second.Counts.Modified);
    }

    [Fact]
    public void OverTheHashBudgetEqualSizesAreUnverified()
    {
        var a = Folder("a", ("f.bin", "aaaa"));
        var b = Folder("b", ("f.bin", "bbbb"));
        _service.MaxHashBytes = 0;
        var c = Run(a, b);
        Assert.Equal("unverified", Assert.Single(c.Entries).Change);
        Assert.Contains(c.Notes, n => n.Contains("budget"));
    }

    [Fact]
    public void ProgressEndsAtTheTotal()
    {
        var a = Folder("a", ("1.txt", "1"), ("2.txt", "2"));
        var b = Folder("b", ("1.txt", "1"), ("3.txt", "3"));
        var reports = new List<(int Done, int Total)>();
        _service.Compare(a, b, "changed", null, null, FolderCompare.DefaultMaxEntries, 0, 10, (d, t) => { lock (reports) reports.Add((d, t)); }, default);
        Assert.Equal((4, 4), reports[^1]);
    }

    [Fact]
    public void MissingPathIsNotFound()
    {
        var a = Folder("a");
        var ex = Assert.Throws<ToolError>(() => Run(a, _dir.File("missing")));
        Assert.Equal(ErrorCode.NotFound, ex.Code);
        Assert.Throws<ToolError>(() => Run(a, a, change: "bogus"));
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public void TenThousandFilePairWarmUnderTenSeconds()
    {
        var a = _dir.File("big-a");
        var b = _dir.File("big-b");
        for (int i = 0; i < 10_000; i++)
        {
            var rel = Path.Combine($"d{i % 100}", $"f{i}.bin");
            foreach (var root in new[] { a, b })
            {
                Directory.CreateDirectory(Path.Combine(root, $"d{i % 100}"));
                File.WriteAllText(Path.Combine(root, rel), root == b && i % 1000 == 0 ? $"changed {i}" : $"content {i} {new string('x', i % 300)}");
            }
        }
        var cold = Stopwatch.StartNew();
        var first = _service.Compare(a, b, "changed", null, null, FolderCompare.DefaultMaxEntries, 0, 100, null, default);
        cold.Stop();
        var warm = Stopwatch.StartNew();
        var second = _service.Compare(a, b, "changed", null, null, FolderCompare.DefaultMaxEntries, 0, 100, null, default);
        warm.Stop();
        Assert.Equal(10, first.Counts.Modified);
        Assert.Equal(first.Counts, second.Counts);
        Assert.True(warm.Elapsed < TimeSpan.FromSeconds(10), $"warm {warm.Elapsed.TotalSeconds:0.00} s (cold {cold.Elapsed.TotalSeconds:0.00} s)");
        File.AppendAllText(TestReports.File("folder-compare-speed.txt"), $"10k pair: cold {cold.Elapsed.TotalSeconds:0.00} s, warm {warm.Elapsed.TotalSeconds:0.00} s\n");
    }

    [RequiresRealDataFact(RealData.CompareOldDir, RealData.CompareNewDir)]
    [Trait("Speed", "Slow")]
    public void RealBuildPair()
    {
        var c = _service.Compare(RealData.Path(RealData.CompareOldDir), RealData.Path(RealData.CompareNewDir), "changed", null, null,
            FolderCompare.DefaultMaxEntries, 0, 200, null, default);
        Assert.True(c.Old.Complete && c.New.Complete, string.Join("; ", c.Old.Problems.Concat(c.New.Problems)));
        Assert.True(c.Counts.Modified + c.Counts.Added + c.Counts.Removed + c.Counts.Moved > 0, "two builds with no difference");
        Assert.All(c.Entries.Where(e => e.Change == "modified" && e.Kind is "dotnet" or "pe"), e => Assert.NotNull(e.NextStep));
    }
}
