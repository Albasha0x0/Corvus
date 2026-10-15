using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>Output files: atomic, no-clobber unless asked, never through links, never to a device name.</summary>
public class SafeFileTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static byte[] Bytes(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    [Fact]
    public void ExistingFile_IsRefusedUnlessOverwrite_AndNoTempFileIsLeft()
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
    public void ConcurrentNoClobberWriters_ExactlyOneWins()
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
    public void SimilarNames_AreNotReserved(string name) => Assert.False(SafeFile.IsReservedName(name));

    [Fact]
    public void TrailingDotOrSpace_IsRefusedOnWindows()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(_dir.File("name."), "x", false));
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(_dir.File("dir /f.txt"), "x", false));
    }

    [Fact]
    public void ArchiveNames_WithDeviceSegments_ArePrefixed()
    {
        var relative = Blob.SafeRelativePath("lib/COM1/LPT².dll", "x");
        Assert.Equal(Path.Combine("lib", "_COM1", "_LPT².dll"), relative);
    }

    [Fact]
    public void Traversal_IsRefused()
    {
        foreach (var relative in new[] { "../escape.bin", "a/../../escape.bin", Path.Combine(Path.GetTempPath(), "abs.bin") })
            Assert.Throws<ToolError>(() => SafeFile.WriteUnderRoot(_dir.File("root"), relative, Bytes("x"), false));
        Assert.False(File.Exists(_dir.File("escape.bin")));
    }

    [DirectoryLinkFact]
    public void LinkUnderTheOutputRoot_IsRefused()
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
    public void LinkAtTheTarget_IsRefusedEvenWithOverwrite()
    {
        var outside = Directory.CreateDirectory(_dir.File("outside")).FullName;
        var link = _dir.File("out.json");
        Links.CreateDirectoryLink(link, outside);
        Assert.Throws<ToolError>(() => SafeFile.WriteAllText(link, "x", overwrite: true));
        Assert.True(Directory.Exists(outside));
        Assert.Empty(Directory.GetFileSystemEntries(outside));
    }

    [DirectoryLinkFact]
    public void Unpack_IntoAnEarlierOutputWithAPlantedLink_IsRefused()
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
    public void WriteUnique_SharesEqualContentWhileAnotherWriterStillHoldsTheFile()
    {
        var root = _dir.File("held");
        var first = Blob.WriteUnique(root, "same.bin", Bytes("content"));
        using (new FileStream(first, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete))
            Assert.Equal(first, Blob.WriteUnique(root, "same.bin", Bytes("content")));
    }

    [Fact]
    public void WriteUnique_ConcurrentWritersOfDifferentContent_KeepEveryOne()
    {
        var root = _dir.File("unique");
        var written = new System.Collections.Concurrent.ConcurrentBag<(string Path, string Text)>();
        Parallel.For(0, 12, i => written.Add((Blob.WriteUnique(root, "same.bin", Bytes($"content {i % 6}")), $"content {i % 6}")));
        Assert.All(written, w => Assert.Equal(w.Text, File.ReadAllText(w.Path)));
        Assert.Equal(6, written.Select(w => w.Path).Distinct().Count()); // equal content is shared, different content never overwritten
    }

    [Fact]
    public void Exports_RefuseAnExistingFile_UnlessOverwrite()
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
    public void A_held_file_is_waited_for_and_a_lost_race_is_not()
    {
        int tries = 0;
        SafeFile.WhenReleased(() => { if (++tries < 3) throw new IOException("held open"); });
        Assert.Equal(3, tries);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.Throws<IOException>(() => SafeFile.WhenReleased(() => throw new IOException("target exists"), lost: () => true));
        Assert.True(clock.ElapsedMilliseconds < 1000, $"{clock.ElapsedMilliseconds} ms");
    }
}
