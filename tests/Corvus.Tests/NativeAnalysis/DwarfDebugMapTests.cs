using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A Mach-O image without a dSYM: its debug map leads to the object files' DWARF, rebased to the image (clang from CORVUS_LLVM_BIN).</summary>
[Trait("Speed", "Slow")]
public sealed class DwarfDebugMapTests(ITestOutputHelper output)
{
    private const string SourceA = """
        struct P { int x; long y; };
        static inline int mix(int v) {
            if (v > 3) return v * 7;
            return v + 1;
        }
        int area(struct P* p) { return mix(p->x) * (int)p->y; }
        struct P g_p;
        """;

    private const string SourceB = """
        struct P;
        int area(struct P* p);
        __attribute__((noinline)) static int twice(int v) { return v * 2 + v / 3; }
        int run(struct P* p, int k) { return twice(area(p)) + k; }
        """;

    [Theory]
    [InlineData("arm64-apple-macos11")]
    [InlineData("x86_64-apple-macos11")]
    public void Debug_map_objects_give_names_types_and_lines(string target)
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        File.WriteAllText(dir.File("a.c"), SourceA);
        File.WriteAllText(dir.File("b.c"), SourceB);
        string flags = $"{LlvmOracle.Options.Target}{target} -O1 {LlvmOracle.Options.DebugInfo}";
        foreach (var src in new[] { "a", "b" })
            Assert.Null(LlvmOracle.Tool("clang", dir.Path, flags, LlvmOracle.Options.CompileOnly, $"{src}.c", LlvmOracle.Options.Output, $"{src}.o"));
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, $"{LlvmOracle.Options.Target}{target} -fuse-ld=lld -nostdlib -shared {LlvmOracle.Options.LinkMachODynamicLookup}",
            "a.o b.o", LlvmOracle.Options.Output, "lib.dylib"));

        var path = dir.File("lib.dylib");
        var image = NativeImageLoader.Open(path);
        var location = DwarfLocator.Locate(image, path);
        Assert.Equal(path, location.Path);
        Assert.Contains(location.Probes, p => p.Outcome == "debug map: 2 of 2 object files");

        PdbFile Read()
        {
            using var container = DebugContainer.FromMemory(path, DwarfLocator.FileBytes(image));
            return DwarfDebugInfo.Read(container, image, () => DebugContainer.FromMemory(path, DwarfLocator.FileBytes(image)));
        }
        var pdb = Read();
        Assert.Empty(pdb.Issues);
        uint Export(string name) => image.Exports.Single(e => e.Name == name).Rva;
        var area = pdb.Symbols.Single(s => s.Name == "area");
        Assert.Equal(Export("_area"), area.Rva);
        Assert.Equal(Export("_run"), pdb.Symbols.Single(s => s.Name == "run").Rva);
        Assert.NotNull(pdb.Symbols.Single(s => s.Name == "twice").Rva);
        Assert.Equal(image.Symbols.Single(s => s.Name == "_g_p").Rva, pdb.Symbols.Single(s => s.Name == "g_p").Rva);
        var model = PdbTypeModel.Of(pdb, 8);
        Assert.Equal([("x", 0L), ("y", 8L)], model.Node(model.Named("P").Single())!.Members.Select(m => (m.Name, m.Offset)));

        var bytes = Enumerable.Range(0, (int)area.Size).Select(i => area.Rva!.Value + (uint)i).ToList();
        var lines = pdb.Source!.Lookup(bytes).Where(i => i != null).Select(i => $"{Path.GetFileName(i!.File)}:{string.Join("<", i.Frames.Select(f => f.Function))}").Distinct().ToList();
        Assert.Contains("a.c:mix<area", lines);
        Assert.All(lines, l => Assert.StartsWith("a.c:", l));
        var run = pdb.Symbols.Single(s => s.Name == "run");
        Assert.Equal("b.c", Path.GetFileName(pdb.Source.Lookup([run.Rva!.Value])[0]!.File));
        output.WriteLine($"{target}: {pdb.Symbols.Count} symbols, {model.Records} type records, {lines.Count} line facts in area");

        File.Delete(dir.File("b.o"));
        var partial = Read();
        Assert.Contains(partial.Issues, i => i.Message.Contains("debug map: 1 of 2 object files not read"));
        Assert.Contains(partial.Symbols, s => s.Name == "area");
    }
}
