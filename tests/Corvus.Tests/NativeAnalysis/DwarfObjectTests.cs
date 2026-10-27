using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Elf;
using Corvus.Native.Pdb;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>DWARF of relocatable objects, with .rela / .rel.debug_* applied, reads like the same source linked (clang -c from CORVUS_LLVM_BIN).</summary>
[Trait("Speed", "Slow")]
public sealed class DwarfObjectTests(ITestOutputHelper output)
{
    private const string Source = """
        namespace geo {
        struct Point { int x, y; long tag; };
        struct Holder { Point* p; unsigned flags : 3; unsigned mode : 5; };
        static inline int mix(int v, long t) {
            if (t > 3) return v * 7;
            return v + (int)t;
        }
        int area(Point* p) { return mix(p->x, p->tag) * p->y; }
        int run(Holder* h) { return area(h->p) + (int)h->mode; }
        }
        geo::Holder g_holder;
        """;

    private static PdbFile Read(string path, INativeImage image)
    {
        using var container = DebugContainer.Open(path);
        return DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(path));
    }

    /// <summary>Functions, struct layouts, and the distinct lines and inlined frames over <paramref name="code"/> (addresses from the image base).</summary>
    private static string Shape(PdbFile pdb, IEnumerable<uint> code)
    {
        var model = PdbTypeModel.Of(pdb, 8);
        var functions = pdb.Symbols.Where(s => s.IsFunction).Select(s => $"{s.Name}|{s.LinkageName}|{s.Size}").Order(StringComparer.Ordinal);
        var types = new[] { "geo::Point", "geo::Holder" }.Select(t => model.Node(model.Named(t).Single())!)
            .Select(n => $"{n.Size}:{string.Join(",", n.Members.Select(m => $"{m.Name}@{m.Offset}.{m.BitPosition}/{m.BitLength}"))}");
        var lines = pdb.Source!.Lookup(code.ToList()).Where(i => i is { Frames.Count: > 0 }) // alignment padding between functions has lines but no function
            .Select(i => $"{Path.GetFileName(i!.File)}:{i.Line}:{string.Join("<", i.Frames.Select(f => f.Function))}").Distinct().Order(StringComparer.Ordinal);
        return string.Join("\n", [.. functions, .. types, .. lines]);
    }

    [Theory]
    [InlineData("x86_64-linux-gnu", 5)]
    [InlineData("x86_64-linux-gnu", 4)]
    [InlineData("aarch64-linux-gnu", 5)]
    [InlineData("i386-linux-gnu", 5)]
    [InlineData("armv7a-linux-gnueabihf", 4)]
    [InlineData("riscv64-linux-gnu", 5)]
    public void Object_files_read_like_the_linked_image(string target, int version)
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        File.WriteAllText(dir.File("geo.cpp"), Source);
        string flags = $"{LlvmOracle.Options.Target}{target} {LlvmOracle.Options.ClangSharedObject} {LlvmOracle.Options.DebugInfo} {LlvmOracle.Options.DwarfVersion}{version}";
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, LlvmOracle.Options.CompileOnly, "geo.cpp", LlvmOracle.Options.Output, "geo.o"));
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, "geo.o", LlvmOracle.Options.Output, "geo.so"));

        var linkedImage = NativeImageLoader.Open(dir.File("geo.so"));
        var linked = Read(dir.File("geo.so"), linkedImage);
        var code = linked.Symbols.Where(s => s.IsFunction && s.Rva != null).SelectMany(s => Enumerable.Range(0, (int)s.Size).Select(i => s.Rva!.Value + (uint)i));
        var expected = Shape(linked, code);
        Assert.Contains("geo::mix<geo::area", expected);

        var objectImage = (ElfFile)NativeImageLoader.Open(dir.File("geo.o"));
        var text = objectImage.Section(".text")!;
        var pdb = Read(dir.File("geo.o"), objectImage);
        Assert.Empty(pdb.Issues);
        Assert.Equal(expected, Shape(pdb, Enumerable.Range(0, (int)text.Size).Select(i => (uint)i)));
        output.WriteLine($"{target} DWARF {version}: {pdb.Symbols.Count} symbols, {expected.Split('\n').Length} facts equal");
    }
}
