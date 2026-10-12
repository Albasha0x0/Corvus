using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Elf;
using Corvus.Native.Itanium;
using Corvus.Services;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Itanium exception tables (.eh_frame, compact unwind, LSDA call sites) and CFI frames on four builds of one library.</summary>
public class ItaniumEhTests
{
    private static INativeImage Open(string build) => NativeImageLoader.Open(build switch
    {
        "linux-x64" => NativeFixtures.LinuxX64DbgShim,
        "osx-x64" => NativeFixtures.OsxX64DbgShim,
        "linux-arm64" => NativeFixtures.LinuxArm64DbgShim,
        _ => NativeFixtures.OsxArm64DbgShim,
    });

    [Theory]
    [InlineData("linux-x64")]
    [InlineData("osx-x64")]
    [InlineData("linux-arm64")]
    [InlineData("osx-arm64")]
    public void Lsda_call_sites_give_landing_pads_and_caught_types(string build)
    {
        var image = Open(build);
        var table = ItaniumEh.Of(image);
        // the same sources in every build: about 110 functions with handlers, all through the C++ personality
        var handlers = table.Functions.Where(f => f.Lsda != null).ToList();
        Assert.InRange(handlers.Count, 100, 130);
        Assert.All(handlers, f => Assert.Equal("__gxx_personality_v0", f.Personality));
        Assert.Equal(image.Format == ImageFormat.MachO ? "compact unwind" : "DWARF CFI", handlers[0].Source);
        var sites = handlers.SelectMany(f => f.CallSites).ToList();
        Assert.Contains(sites, c => c.Actions.SequenceEqual(["catch (Exception*)", "catch (...)"]));
        Assert.Contains(sites, c => c.Actions.SequenceEqual(["cleanup"]));
        Assert.Contains(sites, c => c.LandingPad == null);
        Assert.All(sites.Where(c => c.LandingPad != null), c => Assert.True(image.SectionAt(c.LandingPad!.Value) is { IsExecutable: true }));
        Assert.All(handlers, f => Assert.All(f.CallSites, c => Assert.True(c.Start >= f.Begin && c.End <= f.End, $"{c.Start:X} in {f.Begin:X}-{f.End:X}")));
    }

    [Theory]
    [InlineData("linux-x64")]
    [InlineData("osx-x64")]
    [InlineData("linux-arm64")]
    [InlineData("osx-arm64")]
    public void Frames_come_from_cfa_rules_or_compact_unwind(string build)
    {
        var image = Open(build);
        var start = ItaniumEh.Of(image).Functions.First(f => f.Lsda != null).Begin;
        var frame = UnwindFrames.Of(image, start)!;
        Assert.Equal(start, frame.Begin);
        switch (build)
        {
            case "linux-x64":
                Assert.Equal("DWARF CFI", frame.Format);
                Assert.Contains(frame.Saved, s => s.StartsWith("rbp at [CFA-10h]", StringComparison.Ordinal));
                Assert.StartsWith("CFA = r", frame.Notes[0]);
                break;
            case "linux-arm64":
                Assert.Equal("DWARF CFI", frame.Format);
                Assert.Contains(frame.Saved, s => s.StartsWith("lr at [CFA-", StringComparison.Ordinal));
                Assert.True(frame.Allocation > 0);
                break;
            case "osx-x64":
                Assert.Equal(("compact unwind", "rbp"), (frame.Format, frame.FramePointer));
                Assert.Contains("rbp frame", frame.Notes);
                break;
            default:
                Assert.Equal(("compact unwind", "fp"), (frame.Format, frame.FramePointer));
                Assert.Contains(frame.Saved, s => s == "x19/x20");
                break;
        }
    }

    [Fact]
    public void Arm32_exidx_and_extab_give_personalities_lsda_call_sites_and_frames()
    {
        const uint Text = ElfWriter.TextRva;
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = new byte[0x20] };
        w.Symbols.Add(new ElfWriter.Symbol("__gxx_personality_v0", Text + 0x1C | 1, 2, Type: 2));
        // pr0 in .ARM.extab: vsp += 12; pop {r4, lr}; finish
        w.Extab.Add((Text | 1, null, [0x8002A8B0]));
        // generic personality: pop {r4, lr}; then an LSDA with one call site [+4, +8) landing at +8 (cleanup)
        w.Extab.Add((Text + 0x10 | 1, Text + 0x1C, [0x00A8B0B0, 0x0401FFFF, 0x00080404]));
        w.Exidx.Add((Text + 0x18 | 1, true));
        var image = ElfFile.FromBytes(w.Build(), "lib.so");
        var table = ItaniumEh.Of(image);
        Assert.Equal(3, table.ExidxEntries);
        Assert.Empty(table.Notes);

        var compact = table.At(Text)!;
        Assert.Equal(("ARM EHABI", "__aeabi_unwind_cpp_pr0", Text + 0x10), (compact.Source, compact.Personality, compact.End));
        var frame = UnwindFrames.Of(image, Text + 2)!;
        Assert.Equal(("ARM EHABI", 12L, "r4,lr"), (frame.Format, frame.Allocation, string.Join(",", frame.Saved)));

        var generic = table.At(Text + 0x12)!;
        Assert.Equal("__gxx_personality_v0", generic.Personality);
        var site = Assert.Single(generic.CallSites);
        Assert.Equal((Text + 0x14, Text + 0x18, (uint?)(Text + 0x18)), (site.Start, site.End, site.LandingPad));
        Assert.Equal(["cleanup"], site.Actions);
        Assert.Contains("EXIDX_CANTUNWIND", table.At(Text + 0x18)!.Notes.Single());
    }

    [Fact]
    public void Arm32_library_lsdas_through_the_generic_personality()
    {
        var table = ItaniumEh.Of(NativeImageLoader.Open(NativeFixtures.LinuxArmDbgShim));
        Assert.Equal(630, table.ExidxEntries);
        var gxx = table.Functions.Where(f => f.Personality == "__gxx_personality_v0").ToList();
        Assert.Equal(107, gxx.Count(f => f.Lsda != null));
        Assert.Equal(348, gxx.Sum(f => f.CallSites.Count(c => c.LandingPad != null)));
        Assert.Contains("catch (...)", gxx.SelectMany(f => f.CallSites).SelectMany(c => c.Actions));
    }

    [Fact]
    public async Task Get_exception_info_and_the_dossier_report_the_tables()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(dir.File("ann")));
        var pager = new OutputPager(options);
        var tools = new NativeExceptionTools(workspace, code, pager);
        var path = NativeFixtures.LinuxX64Coverage;
        var summary = await tools.GetExceptionInfo(path);
        Assert.Contains("121 FDEs (.eh_frame); 21 functions with an LSDA", summary);
        Assert.Contains("Personality __gxx_personality_v0: 21 functions", summary);
        Assert.Matches(@"Caught: .*\bstd::exception \(\d+\)", summary);
        Assert.DoesNotContain("(std::exception", summary);

        var image = NativeImageLoader.Open(path);
        var fn = ItaniumEh.Of(image).Functions.First(f => f.CallSites.Any(c => c.Actions.Contains("catch (std::exception)")));
        var text = await tools.GetExceptionInfo(path, $"rva:0x{fn.Begin:X}");
        Assert.Contains("DWARF CFI", text);
        Assert.Contains(": catch (std::exception), cleanup", text);
        Assert.Contains("no landing pad (unwinds through)", text);

        var dossier = await new NativeFunctionTools(workspace, code, pager).AnalyzeNativeFunction(path, $"rva:0x{fn.Begin:X}", sections: "frame");
        Assert.Contains("unwind data (DWARF CFI", dossier);
        Assert.Contains("exception handling: __gxx_personality_v0", dossier);
    }
}
