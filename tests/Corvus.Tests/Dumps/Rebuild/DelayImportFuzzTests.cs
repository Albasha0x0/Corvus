using Corvus.Core;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Mutated images never make the delay-load reader throw.</summary>
public sealed class DelayImportFuzzTests
{
    [Fact]
    [FuzzEntry(typeof(PeDelayImports))]
    public void Fuzzed_delay_load_directories_never_throw_unexpectedly()
    {
        var spec = new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]);
        var built = DelayImportFixtures.Build(spec, [
            new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.ByOrdinal(7)]),
            new("two.dll", [DelayFunction.Named("Beta")]),
        ]);
        var seed = RebuildFixtures.Mapped(built.Bytes);

        var failures = FormatFuzz.Run(seed, bytes =>
        {
            var pages = Enumerable.Repeat(true, bytes.Length / 0x1000).ToArray();
            var image = new CapturedImage(new RebuildTarget("app.exe", spec.Base, (uint)bytes.Length, ModuleOrigin.Listed), bytes, pages, "mapped");
            try { PeDelayImports.Read(bytes, image); }
            catch (ToolError) { }
        }, 300);

        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
