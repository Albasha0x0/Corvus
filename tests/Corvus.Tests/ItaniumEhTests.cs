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
    public void Arm32_images_say_their_EHABI_tables_are_not_decoded()
    {
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = [0x70, 0x47] };
        w.Exidx.Add((ElfWriter.TextRva | 1, false));
        var table = ItaniumEh.Of(ElfFile.FromBytes(w.Build(), "lib.so"));
        Assert.Equal(0, table.Fdes);
        Assert.Contains(table.Notes, n => n.Contains("EHABI", StringComparison.Ordinal));
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
