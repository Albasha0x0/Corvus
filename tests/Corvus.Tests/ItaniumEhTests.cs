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

    /// <summary>pr1 (16-bit scopes) and pr2 (32-bit scopes) descriptors: cleanup, catch (...), a typed catch by reference, a no-throw region, an exception specification.</summary>
    [Fact]
    public void Arm32_pr1_and_pr2_scope_descriptors()
    {
        const uint Text = ElfWriter.TextRva, Slot = ElfWriter.DataRva, TypeInfo = ElfWriter.DataRva + 0x10;
        static uint Rel(uint target, uint at) => (target - at) & 0x7FFFFFFF;
        ElfFile Build(uint extab)
        {
            var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = new byte[0x80], Data = new byte[0x100] };
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(w.Data, TypeInfo);
            w.Symbols.Add(new ElfWriter.Symbol("_ZTI3Foo", TypeInfo, 8, Type: 1));
            w.Extab.Add((Text + 0x40 | 1, null,
            [
                0x8100B0B0,
                0x00040008, Rel(Text + 0x50, extab + 8),                     // cleanup [+4, +0xC)
                0x00040009, Rel(Text + 0x55, extab + 16), 0xFFFFFFFF,       // catch (...) [+4, +0xC), Thumb landing pad
                0x000D0004, 0x80000001, Slot - (extab + 32), Rel(Text + 0x58, extab + 36), // throw(Foo) [+0xC, +0x10)
                0,
            ]));
            uint e2 = extab + 44;
            w.Extab.Add((Text + 0x60 | 1, null,
            [
                0x8200B0B0,
                9, 4, Rel(Text + 0x70, e2 + 12) | 0x80000000, Slot - (e2 + 16), // catch (Foo&) [+4, +0xC)
                5, 8, Rel(Text + 0x74, e2 + 28), 0xFFFFFFFE,                  // no-throw [+8, +0xC)
                0,
            ]));
            return ElfFile.FromBytes(w.Build(), "lib.so");
        }
        var image = Build(Build(0).Sections.Single(s => s.Name == ".ARM.extab").Rva);
        var table = ItaniumEh.Of(image);

        var pr1 = table.At(Text + 0x40)!;
        Assert.Equal("__aeabi_unwind_cpp_pr1", pr1.Personality);
        Assert.Empty(pr1.Notes);
        Assert.Equal([
                (Text + 0x44, Text + 0x4C, (uint?)(Text + 0x50), "cleanup"),
                (Text + 0x44, Text + 0x4C, Text + 0x54, "catch (...)"),
                (Text + 0x4C, Text + 0x50, Text + 0x58, "exception specification throw(Foo)"),
            ], pr1.CallSites.Select(c => (c.Start, c.End, c.LandingPad, c.Actions.Single())));
        var pr2 = table.At(Text + 0x60)!;
        Assert.Equal("__aeabi_unwind_cpp_pr2", pr2.Personality);
        Assert.Equal([
                (Text + 0x64, Text + 0x6C, (uint?)(Text + 0x70), "catch (Foo&)"),
                (Text + 0x68, Text + 0x6C, Text + 0x74, "no-throw region (terminate)"),
            ], pr2.CallSites.Select(c => (c.Start, c.End, c.LandingPad, c.Actions.Single())));
    }

    /// <summary>A landing pad the function's flow never reaches joins that function as a chunk (not a function of its own).</summary>
    [Fact]
    public void Landing_pads_are_chunks_of_their_function()
    {
        const uint Text = ElfWriter.TextRva;
        // push {r4, lr}; nop; pop {r4, pc} | landing pad at +6: movs r0, #1; pop {r4, pc}
        var code = new byte[0x20];
        new byte[] { 0x10, 0xB5, 0x00, 0xBF, 0x10, 0xBD, 0x01, 0x20, 0x10, 0xBD }.CopyTo(code, 0);
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = code };
        w.Symbols.Add(new ElfWriter.Symbol("__gxx_personality_v0", Text + 0x1C | 1, 2, Type: 2));
        // generic personality: pop {r4, lr}; LSDA with one call site [+0, +4) landing at +6 (cleanup)
        w.Extab.Add((Text | 1, Text + 0x1C, [0x00A8B0B0, 0x0401FFFF, 0x00060400]));
        var index = Corvus.Native.Code.NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "lib.so"));
        var f = index.FunctionByStart(Text)!;
        Assert.Null(index.FunctionByStart(Text + 6));
        Assert.Same(f, index.FunctionAt(Text + 8));
        Assert.Equal([new Corvus.Native.Code.FunctionChunk(Text + 6, Corvus.Native.Msvc.MsvcEhChildKind.Unwind)], f.Chunks);
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
        Assert.Contains("Landing pads no flow reaches, attached to their functions as chunks: ", summary);
        uint pad = fn.CallSites.First(c => c.Actions.Contains("catch (std::exception)")).LandingPad!.Value;
        Assert.Contains($" is a landing pad of ", await tools.GetExceptionInfo(path, $"rva:0x{pad:X}"));

        var dossier = await new NativeFunctionTools(workspace, code, pager).AnalyzeNativeFunction(path, $"rva:0x{fn.Begin:X}", sections: "frame");
        Assert.Contains("unwind data (DWARF CFI", dossier);
        Assert.Contains("exception handling: __gxx_personality_v0", dossier);
    }
}
