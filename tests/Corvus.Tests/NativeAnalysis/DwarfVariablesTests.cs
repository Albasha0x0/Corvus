using System.Text.RegularExpressions;
using Corvus.Native;
using Corvus.Native.Dwarf;
using Corvus.Native.Pdb;
using Corvus.Tests.NativeFormats;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Parameters and locals with their locations at an address: frame slots at -O0, ABI registers at an optimized entry, loop locals only in the loop.</summary>
[Trait("Speed", "Slow")]
public sealed class DwarfVariablesTests(ITestOutputHelper output)
{
    private const string Source = """
        struct P { int x; long y; };
        int sink(int);
        int work(struct P* p, long k) {
            int local = p->x * 3;
            for (int i = 0; i < k; i++) { int inner = sink(i + local); local += inner; }
            return local;
        }
        """;

    private static (PdbFile Pdb, PdbSymbol Work) Build(TempDir dir, string target, string flags)
    {
        File.WriteAllText(dir.File("v.c"), Source);
        Assert.Null(LlvmOracle.Tool("clang", dir.Path, $"{LlvmOracle.Options.Target}{target} {LlvmOracle.Options.ClangSharedObject} {LlvmOracle.Options.DebugInfo} {flags}",
            "v.c", LlvmOracle.Options.Output, "v.so"));
        var path = dir.File("v.so");
        var image = NativeImageLoader.Open(path);
        using var container = DebugContainer.Open(path);
        var pdb = DwarfDebugInfo.Read(container, image, () => DebugContainer.Open(path));
        return (pdb, pdb.Symbols.Single(s => s.Name == "work"));
    }

    private static Dictionary<string, DebugVariable> At(PdbFile pdb, uint rva) =>
        pdb.Source!.Lookup([rva])[0]!.Variables!.ToDictionary(v => v.Name);

    [Fact]
    public void Unoptimized_variables_are_frame_slots_in_their_scopes()
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        var (pdb, work) = Build(dir, "x86_64-linux-gnu", "-O0");
        var entry = At(pdb, work.Rva!.Value + 8);
        Assert.Equal(("P*", true), (entry["p"].Type, entry["p"].Parameter));
        Assert.Equal("long", entry["k"].Type);
        foreach (var name in new[] { "p", "k", "local" }) Assert.Matches(new Regex(@"^\[rbp-0x[0-9A-F]+\]$"), entry[name].Location);
        Assert.False(entry.ContainsKey("inner"));
        // Somewhere in the loop body the loop's locals are in scope, at their own slots.
        var all = pdb.Source!.Lookup([.. Enumerable.Range(0, (int)work.Size).Select(i => work.Rva!.Value + (uint)i)]);
        var inLoop = all.First(a => a?.Variables?.Any(v => v.Name == "inner") == true)!.Variables!;
        Assert.Equal(["p", "k", "local", "i", "inner"], inLoop.Select(v => v.Name));
        Assert.Equal(5, inLoop.Select(v => v.Location).Distinct().Count());
        output.WriteLine(string.Join("; ", inLoop.Select(v => $"{v.Name} ({v.Type}): {v.Location}")));
    }

    [Theory]
    [InlineData("x86_64-linux-gnu", 5, "rdi", "rsi")]
    [InlineData("x86_64-linux-gnu", 4, "rdi", "rsi")]
    [InlineData("aarch64-linux-gnu", 5, "x0", "x1")]
    public void Optimized_parameters_are_in_argument_registers_at_entry(string target, int version, string first, string second)
    {
        if (LlvmOracle.Bin == null) { output.WriteLine($"{LlvmOracle.Variable} is not set"); return; }
        using var dir = new TempDir();
        var (pdb, work) = Build(dir, target, $"-O2 {LlvmOracle.Options.DwarfVersion}{version}");
        var entry = At(pdb, work.Rva!.Value);
        Assert.Equal((first, second), (entry["p"].Location, entry["k"].Location));
        output.WriteLine($"{target} DWARF {version}: " + string.Join("; ", entry.Values.Select(v => $"{v.Name}: {v.Location}")));
    }
}
