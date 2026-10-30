using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Output files: atomic, no-clobber unless asked, never through links, never to a device name.</summary>
public class SafeFileTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static byte[] Bytes(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    [Fact]
    public void An_existing_file_is_refused_unless_overwrite_and_no_temp_file_is_left()
    {
        var path = _dir.File("sub/out.bin");
        Assert.Equal(Path.GetFullPath(path), SafeFile.WriteAllBytes(path, Bytes("one"), overwrite: false));
        var error = Assert.Throws<ToolError>(() => SafeFile.WriteAllBytes(path, Bytes("two"), overwrite: false));
        Assert.Equal(ErrorCode.Conflict, error.Code);
        Assert.Equal("one", File.ReadAllText(path));
        SafeFile.WriteAllText(path, "three", overwrite: true);
        Assert.Equal("three", File.ReadAllText(path));
        Assert.Equal(["out.bin"], Directory.GetFiles(_dir.File("sub")).Select(Path.GetFileName));
    }

    [Fact]
    public void Concurrent_no_clobber_writers_exactly_one_wins()
    {
        var path = _dir.File("race.txt");
        int won = 0, refused = 0;
        Parallel.For(0, 16, i =>
        {
            try { SafeFile.WriteAllText(path, $"writer {i}", overwrite: false); Interlocked.Increment(ref won); }
            catch (ToolError ex) when (ex.Code == ErrorCode.Conflict) { Interlocked.Increment(ref refused); }
        });
        Assert.Equal(1, won);
        Assert.Equal(15, refused);
        Assert.StartsWith("writer ", File.ReadAllText(path));
    }

    [Theory]
    [InlineData("CON")]
    [InlineData("nul.txt")]
    [InlineData("Aux.tar.gz")]
    [InlineData("COM0")]
    [InlineData("com9.log")]
    [InlineData("LPT¹")]
    [InlineData("COM³.bin")]
    [InlineData("CONIN$")]
    [InlineData("conout$.txt")]
    [InlineData("PRN. ")]
    [InlineData("Con .txt")]
    public void DeviceNames_AreReserved(string name)
    {
        Assert.True(SafeFile.IsReservedName(name));
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => SafeFile.WriteAllText(Path.Combine(_dir.Path, name), "x", true)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => SafeFile.WriteAllText(Path.Combine(_dir.Path, name, "f.txt"), "x", true)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => SafeFile.UnderRoot(_dir.Path, "a/" + name + "/b")).Code);
    }

    [Theory]
    [InlineData("CONSOLE")]
    [InlineData("COM10")]
    [InlineData("LPT")]
    [InlineData("nul_file")]
    [InlineData("my.con")]
    public void Similar_names_are_not_reserved(string name) => Assert.False(SafeFile.IsReservedName(name));

    [Fact]
    public void A_trailing_dot_or_space_is_refused_on_Windows()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(_dir.File("name."), "x", false));
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(_dir.File("dir /f.txt"), "x", false));
    }

    [Fact]
    public void Archive_names_with_device_segments_are_prefixed()
    {
        var relative = Blob.SafeRelativePath("lib/COM1/LPT².dll", "x");
        Assert.Equal(Path.Combine("lib", "_COM1", "_LPT².dll"), relative);
    }

    [Fact]
    public void Shell_parsed_names_are_written_with_a_bin_suffix()
    {
        foreach (var name in new[] { "a.url", "a.scf", "a.library-ms", "a.search-ms", "a.searchConnector-ms", "Desktop.ini", "a.settingcontent-ms",
                     "a.chm", "a.msc", "a.xll", "a.wsc", "a.inf", "a.appinstaller" })
            Assert.Equal(Path.Combine("dir", name + ".bin"), Blob.SafeRelativePath("dir/" + name, "x"));
        Assert.Equal("notes.txt", Blob.SafeRelativePath("notes.txt", "x"));
    }

    [Fact]
    public void An_extracted_file_is_marked_as_from_the_internet_zone_on_ntfs()
    {
        var root = Directory.CreateDirectory(_dir.File("root")).FullName;
        if (!OperatingSystem.IsWindows() || new DriveInfo(root).DriveFormat != "NTFS") return;
        var path = Blob.WriteUnique(root, "a.dll", Bytes("x"));
        Assert.Contains("ZoneId=3", File.ReadAllText(path + ":" + Blob.ZoneStream));
        // A repeat write of the same content returns the file, still marked.
        File.Delete(path + ":" + Blob.ZoneStream);
        Assert.Equal(path, Blob.WriteUnique(root, "a.dll", Bytes("x")));
        Assert.Contains("ZoneId=3", File.ReadAllText(path + ":" + Blob.ZoneStream));
    }

    // Reproduces an unpack on c4742626 where 655 members of one import
    // library took over 900 s to name.
    [Fact]
    public void Members_with_one_name_are_numbered_and_a_repeat_returns_its_file()
    {
        var root = Directory.CreateDirectory(_dir.File("root")).FullName;
        var zone = new ZoneMark(_ => { });
        var names = new UniqueNames();
        var paths = Enumerable.Range(0, 300).Select(i => Blob.WriteUnique(root, "lib/jvm.dll", Bytes($"m{i}"), zone, names)).ToList();
        Assert.Equal("jvm.dll", Path.GetFileName(paths[0]));
        Assert.Equal("jvm_300.dll", Path.GetFileName(paths[^1]));
        Assert.Equal(300, paths.Distinct().Count());
        Assert.Equal(paths[150], Blob.WriteUnique(root, "lib/jvm.dll", Bytes("m150"), zone, names));
        // Without the extraction's names, the probe finds the same files.
        Assert.Equal(paths[150], Blob.WriteUnique(root, "lib/jvm.dll", Bytes("m150")));
        Assert.Equal("jvm_301.dll", Path.GetFileName(Blob.WriteUnique(root, "lib/jvm.dll", Bytes("new"))));
    }

    [Fact]
    public void A_refused_zone_mark_is_named_once_with_the_first_reason()
    {
        if (!OperatingSystem.IsWindows()) return;
        var root = Directory.CreateDirectory(_dir.File("root")).FullName;
        int attempts = 0;
        // As a FAT volume refuses an alternate data stream.
        var zone = new ZoneMark(_ => throw new IOException($"no streams {++attempts}"));
        foreach (var name in new[] { "a.dll", "b.dll", "c.dll" }) Blob.WriteUnique(root, name, Bytes(name), zone);
        Assert.Equal(3, attempts);
        Assert.Equal("files not marked as from the internet zone: no streams 1", zone.Note);
        Assert.Equal(3, Directory.GetFiles(root).Length);
        Assert.Null(new ZoneMark(_ => { }).Note);
    }

    [Fact]
    public void Traversal_IsRefused()
    {
        foreach (var relative in new[] { "../escape.bin", "a/../../escape.bin", Path.Combine(Path.GetTempPath(), "abs.bin") })
            Assert.Throws<ToolError>(() => SafeFile.WriteUnderRoot(_dir.File("root"), relative, Bytes("x"), false));
        Assert.False(File.Exists(_dir.File("escape.bin")));
    }

    [DirectoryLinkFact]
    public void A_link_under_the_output_root_is_refused()
    {
        var root = Directory.CreateDirectory(_dir.File("root")).FullName;
        var outside = Directory.CreateDirectory(_dir.File("outside")).FullName;
        Links.CreateDirectoryLink(Path.Combine(root, "lib"), outside);

        var error = Assert.Throws<ToolError>(() => SafeFile.WriteUnderRoot(root, "lib/a.dll", Bytes("x"), overwrite: true));
        Assert.Contains("link", error.Message);
        Assert.Throws<ToolError>(() => Blob.WriteUnique(root, "lib/deeper/a.dll", Bytes("x")));
        Assert.Empty(Directory.GetFileSystemEntries(outside));
    }

    [DirectoryLinkFact]
    public void A_link_at_the_target_is_refused_even_with_overwrite()
    {
        var outside = Directory.CreateDirectory(_dir.File("outside")).FullName;
        var link = _dir.File("out.json");
        Links.CreateDirectoryLink(link, outside);
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(link, "x", overwrite: true));
        Assert.True(Directory.Exists(outside));
        Assert.Empty(Directory.GetFileSystemEntries(outside));
    }

    [DirectoryLinkFact]
    public void Unpack_into_an_earlier_output_with_a_planted_link_is_refused()
    {
        var source = _dir.File("app.zip");
        File.WriteAllBytes(source, ContainerFixtures.Zip(("lib/a.dll", Bytes("not an assembly"))));
        var root = _dir.File("unpacked");
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var unpacker = new UnpackService(workspace);
        unpacker.Unpack(source, root, load: false, AnalysisLimits.Default, default);
        Directory.Delete(Path.Combine(root, "lib"), true);
        var outside = Directory.CreateDirectory(_dir.File("outside")).FullName;
        Links.CreateDirectoryLink(Path.Combine(root, "lib"), outside);

        Assert.Throws<ToolError>(() => unpacker.Unpack(source, root, load: false, AnalysisLimits.Default, default));
        Assert.Empty(Directory.GetFileSystemEntries(outside));
    }

    [Fact]
    public void Write_unique_shares_equal_content_while_another_writer_still_holds_the_file()
    {
        var root = _dir.File("held");
        var first = Blob.WriteUnique(root, "same.bin", Bytes("content"));
        using (new FileStream(first, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            Assert.Equal(first, Blob.WriteUnique(root, "same.bin", Bytes("content")));
    }

    [Fact]
    public void Write_unique_concurrent_writers_of_different_content_keep_every_one()
    {
        var root = _dir.File("unique");
        var written = new System.Collections.Concurrent.ConcurrentBag<(string Path, string Text)>();
        Parallel.For(0, 12, i => written.Add((Blob.WriteUnique(root, "same.bin", Bytes($"content {i % 6}")), $"content {i % 6}")));
        Assert.All(written, w => Assert.Equal(w.Text, File.ReadAllText(w.Path)));
        Assert.Equal(6, written.Select(w => w.Path).Distinct().Count()); // equal content is shared, different content never overwritten
    }

    [Fact]
    public void Exports_refuse_an_existing_file_unless_overwrite()
    {
        using var env = new Env();
        var res = env.Fixture.Module.Resources.First(r => r.Name.String.EndsWith("hello.txt")).Name.String;
        var path = _dir.File("hello.txt");
        env.Resources.Get(env.Fixture, res, null, path);
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => env.Resources.Get(env.Fixture, res, null, path)).Code);
        Assert.Contains("Saved", env.Resources.Get(env.Fixture, res, null, path, overwrite: true));

        env.Edit(() => env.Edits.Rename(env.One("Shop::Describe"), "Summary"));
        var script = _dir.File("edits.json");
        env.Workspace.Read(() => env.History.Export(env.Fixture, script));
        Assert.Equal(ErrorCode.Conflict, Assert.Throws<ToolError>(() => env.Workspace.Read(() => env.History.Export(env.Fixture, script))).Code);
        env.Workspace.Read(() => env.History.Export(env.Fixture, script, overwrite: true));
    }

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void A_held_file_is_waited_for_and_a_lost_race_is_not()
    {
        int tries = 0;
        SafeFile.WhenReleased(() => { if (++tries < 3) throw new IOException("held open"); });
        Assert.Equal(3, tries);
        int calls = 0;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.Throws<IOException>(() => SafeFile.WhenReleased(() => { calls++; throw new IOException("target exists"); }, lost: () => true));
        Assert.Equal(1, calls);
        PerfBudget.Time("session/safe-file-lost-race", clock.Elapsed, TimeSpan.FromSeconds(1), output);
    }
}
