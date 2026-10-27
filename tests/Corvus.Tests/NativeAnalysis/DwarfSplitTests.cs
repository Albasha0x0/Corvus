using System.Diagnostics;
using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Split DWARF (.dwo files, a .dwp package) reads like the same sources built unsplit (clang and llvm-dwp from CORVUS_LLVM_BIN).</summary>
[Trait("Speed", "Slow")]
public sealed class DwarfSplitTests(ITestOutputHelper output)
{
    private const string SourceA = """
        namespace geo {
        struct Point { int x, y; long tag; };
        static inline int mix(int v, long t) {
            if (t > 3) return v * 7;
            return v + (int)t;
        }
        int area(Point* p) { return mix(p->x, p->tag) * p->y; }
        }
        """;

    private const string SourceB = """
        namespace geo { struct Point; int area(Point* p); }
        struct Holder { geo::Point* p; int count; };
        enum Mode { ModeA = 1, ModeB = 7 };
        int run(Holder* h, Mode m) { return geo::area(h->p) + h->count + (int)m; }
        Holder g_holder;
        """;

    private static (PdbFile Pdb, INativeImage Image) Read(string path)
    {
        var image = NativeImageLoader.Open(path);
        using var container = DebugContainer.Open(path, image.BuildId);
        return (DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(path, image.BuildId)), image);
    }

    private static string Shape(PdbFile pdb, INativeImage image)
    {
        var model = PdbTypeModel.Of(pdb, 8);
        var symbols = pdb.Symbols.Where(s => s.Rva != null).OrderBy(s => s.Name, StringComparer.Ordinal)
            .Select(s => $"{s.Name}|{s.LinkageName}|{s.Kind}|{model.Spell(s.TypeIndex)}");
        var types = new[] { "geo::Point", "Holder", "Mode" }.Select(t => $"{t}:{model.Named(t).Count}");
        // Every byte of every function: lines and inlined frames.
        var rvas = pdb.Symbols.Where(s => s.IsFunction && s.Rva != null).SelectMany(s => Enumerable.Range(0, (int)s.Size).Select(i => s.Rva!.Value + (uint)i)).Order().ToList();
        var lines = pdb.Source!.Lookup(rvas).Select(i => i == null ? "none" : $"{Path.GetFileName(i.File)}:{i.Line}:{string.Join("<", i.Frames.Select(f => f.Function))}").Distinct();
        return string.Join("\n", [.. symbols, .. types, .. lines]);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(4)]
    public void Split_units_read_like_the_unsplit_build(int version)
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        File.WriteAllText(dir.File("a.cpp"), SourceA);
        File.WriteAllText(dir.File("b.cpp"), SourceB);
        string flags = $"{LlvmOracle.Options.Target}x86_64-linux-gnu {LlvmOracle.Options.ClangSharedObject} {LlvmOracle.Options.DebugInfo} {LlvmOracle.Options.DwarfVersion}{version}";
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, "a.cpp b.cpp", LlvmOracle.Options.Output, "plain.so"));
        foreach (var src in new[] { "a", "b" })
            Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, LlvmOracle.Options.SplitDwarf, LlvmOracle.Options.CompileOnly, $"{src}.cpp", LlvmOracle.Options.Output, $"{src}.o"));
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, "a.o b.o", LlvmOracle.Options.Output, "split.so"));
        Assert.True(File.Exists(dir.File("a.dwo")) && File.Exists(dir.File("b.dwo")));

        var (plain, plainImage) = Read(dir.File("plain.so"));
        var expected = Shape(plain, plainImage);
        Assert.Contains("geo::area|_ZN3geo4areaEPNS_5PointE", expected);
        Assert.Contains("geo::mix<geo::area", expected);

        var clock = Stopwatch.StartNew();
        var (split, splitImage) = Read(dir.File("split.so"));
        var dwoTime = clock.Elapsed;
        Assert.Empty(split.Issues);
        Assert.Equal(expected, Shape(split, splitImage));

        // The .dwo files packaged into split.so.dwp, then removed: the package answers alone.
        Assert.Null(LlvmOracle.Tool("llvm-dwp", dir.Path, LlvmOracle.Options.DwpFromExecutable, "split.so", LlvmOracle.Options.Output, "split.so.dwp"));
        File.Delete(dir.File("a.dwo"));
        File.Delete(dir.File("b.dwo"));
        clock.Restart();
        var (packaged, packagedImage) = Read(dir.File("split.so"));
        var dwpTime = clock.Elapsed;
        Assert.Empty(packaged.Issues);
        Assert.Equal(expected, Shape(packaged, packagedImage));

        File.Delete(dir.File("split.so.dwp"));
        var (missing, _) = Read(dir.File("split.so"));
        Assert.Contains(missing.Issues, i => i.Message.Contains("2 of 2 split units not found"));
        Assert.Contains(missing.Issues, i => i.Message.Contains("a.dwo") && i.Message.Contains("is not found"));
        output.WriteLine($"DWARF {version}: {split.Symbols.Count} symbols; .dwo files read in {dwoTime.TotalMilliseconds:0} ms, .dwp in {dwpTime.TotalMilliseconds:0} ms");
    }
}
