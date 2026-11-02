using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Rebuilt modules written into a folder.</summary>
public sealed class ModuleWriterTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static RebuiltModule Module(string name, int size, string? refused = null) =>
        new(new RebuildTarget(name, 0x10000, (uint)size, ModuleOrigin.Listed), "pe", "mapped", refused == null ? new byte[size] : null, 100, [], Refused: refused);

    [Fact]
    public void Writing_into_a_folder_that_is_not_empty_is_refused_before_any_file()
    {
        var folder = _dir.File("out");
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "old.txt"), "x");
        var ex = Assert.Throws<ToolError>(() => ModuleWriter.WriteAll([Module("a.dll", 16)], folder));
        Assert.Equal(ErrorCode.Conflict, ex.Code);
        Assert.Equal(["old.txt"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public void A_module_past_the_total_limit_is_not_written_and_names_the_limit()
    {
        var folder = _dir.File("out");
        var result = ModuleWriter.WriteAll([Module("a.dll", 1 << 20), Module("b.dll", 1 << 20)], folder, 1L << 20, null);
        Assert.Equal("a.dll", result[0].File);
        Assert.Null(result[1].File);
        Assert.Equal("past the 1 MB total limit", result[1].Reason);
        Assert.Equal(["a.dll"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public void A_refused_module_is_listed_without_a_file()
    {
        var folder = _dir.File("out");
        var result = ModuleWriter.WriteAll([Module("a.dll", 16, refused: "headers not captured"), Module("b.dll", 16)], folder);
        Assert.Equal(new WrittenModule(null, "headers not captured"), result[0]);
        Assert.Equal("b.dll", result[1].File);
        Assert.Equal(["b.dll"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public void A_failed_write_removes_the_files_it_created()
    {
        var folder = _dir.File("out");
        var calls = 0;
        Assert.Throws<IOException>(() => ModuleWriter.WriteAll([Module("a.dll", 16), Module("b.dll", 16)], folder, long.MaxValue,
            _ => { if (++calls == 2) throw new IOException("disk full"); }));
        Assert.Empty(Directory.GetFiles(folder));
    }

    [Fact]
    [FuzzEntry(typeof(ModuleRebuild))]
    public void Mutated_dumps_never_throw_from_the_rebuild_and_write()
    {
        var seed = SyntheticCrash.Builder().Build();
        int n = 0;
        var failures = FormatFuzz.Run(seed, bytes =>
        {
            var path = _dir.File("fuzz.dmp");
            File.WriteAllBytes(path, bytes);
            try
            {
                using var memory = MinidumpFile.Open(path);
                var rebuilt = ModuleRebuild.Select(memory, "all", default)
                    .Select(t => ModuleRebuild.Rebuild(memory, t, RebuildOptions.Default, default)).ToList();
                ModuleWriter.WriteAll(rebuilt, _dir.File($"export{n++}"));
            }
            catch (ToolError) { }
        }, 250);
        Assert.Empty(failures);
    }
}
