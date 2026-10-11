using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Native.MachO;
using NetDecompilerMcp.Services.Analysis;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests.NativeFormats;

/// <summary>ELF and Mach-O through the load path and the image information tools.</summary>
public sealed class FormatLoadTests
{
    private static string Text(string result) => result;

    [Fact]
    public void Open_DispatchesByContent()
    {
        Assert.IsType<ElfFile>(NativeImageLoader.Open(NativeFixtures.LinuxArm64DbgShim));
        Assert.IsType<MachOFile>(NativeImageLoader.Open(NativeFixtures.OsxArm64DbgShim));
        var fat = Assert.IsType<MachOFile>(NativeImageLoader.Open(NativeFixtures.OsxFatSkia));
        Assert.Equal("arm64", fat.Slice!.Name);
        Assert.Equal("x86_64", ((MachOFile)NativeImageLoader.Open(NativeFixtures.OsxFatSkia, "x86_64")).Slice!.Name);
        Assert.Equal("x86_64", ((MachOFile)NativeImageLoader.Open(NativeFixtures.OsxFatSkia, "0")).Slice!.Name);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeImageLoader.Open(NativeFixtures.OsxFatSkia, "armv7")).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeImageLoader.Open(NativeFixtures.LinuxArm64DbgShim, "arm64")).Code);
    }

    [Fact]
    public async Task LoadAssembly_LoadsEachSliceUnderItsOwnId()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var text = await h.WorkspaceTools.LoadAssembly(NativeFixtures.OsxFatSkia);
        Assert.Contains("Loaded native image libSkiaSharp.dylib[arm64]: arm64 Mach-O MH_DYLIB (slice arm64 of x86_64, arm64)", text);
        await h.WorkspaceTools.LoadAssembly(NativeFixtures.OsxFatSkia, slice: "x86_64");
        await h.WorkspaceTools.LoadAssembly(NativeFixtures.OsxFatSkia); // already loaded
        var ids = h.Workspace.Read(() => h.Workspace.Natives.Select(n => n.Id).ToList());
        Assert.Equal(["libSkiaSharp.dylib[arm64]", "libSkiaSharp.dylib[x86_64]"], ids);
        var x64 = h.Workspace.Read(() => h.Workspace.GetNative("libSkiaSharp.dylib[x86_64]"));
        Assert.Equal(NativeArch.X64, x64.Image.Arch);
        Assert.Equal(x64.Image.Sha256, h.Workspace.ReloadNative(x64).Image.Sha256);
        var listed = await h.WorkspaceTools.ListAssemblies();
        Assert.Equal(["x86_64", "arm64"], listed.NativeImages[0].Slices);

        var elf = await h.WorkspaceTools.LoadAssembly(NativeFixtures.LinuxArm64DbgShim);
        Assert.Contains("libdbgshim.so: EM_AARCH64 ELF64 shared object", elf);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => h.WorkspaceTools.LoadAssembly(NativeFixtures.LinuxArmDbgShim, slice: "arm64"))).Code);
    }

    [Fact]
    public async Task GetPeInfo_DescribesElfAndMachO()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var collector = Mcp.StructuredOutput.Begin();
        var elf = await h.Native.GetPeInfo(NativeFixtures.LinuxArm64DbgShim);
        var t = Text(elf);
        Assert.Contains("soname libdbgshim.so", t);
        Assert.Contains("Program headers (", t);
        Assert.Contains("PT_GNU_EH_FRAME", t);
        Assert.Contains("Mitigations: on: PIE, NX stack, RELRO", t);
        Assert.Contains("Declared function starts: ", t);
        var summary = Assert.IsType<PeSummary>(collector.Value);
        Assert.Equal("ELF64", summary.Format);
        Assert.Equal("EM_AARCH64", summary.Machine);
        Assert.Contains(summary.Sections, s => s.Name == ".text" && s.Characteristics.Contains("SHF_EXECINSTR"));

        var macho = Text(await h.Native.GetPeInfo(NativeFixtures.OsxArm64DbgShim));
        Assert.Contains("arm64 Mach-O MH_DYLIB", macho);
        Assert.Contains("Fixups: chained fixups", macho);
        Assert.Contains("Code signature: ", macho);
        Assert.Contains("install name ", macho);
        Assert.Contains("__TEXT,__text", macho);

        var fat = Text(await h.Native.GetPeInfo(NativeFixtures.OsxFatSkia));
        Assert.Contains("slice arm64 at file 0x", fat);
        Assert.Contains("Fixups: dyld info", fat);
    }

    [Fact]
    public async Task ListImportsAndExports_RenderElfAndMachO()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var elf = (ElfFile)NativeImageLoader.Open(NativeFixtures.LinuxArm64DbgShim);
        var collector = Mcp.StructuredOutput.Begin();
        var imports = await h.Native.ListImports(NativeFixtures.LinuxArm64DbgShim, limit: 5000);
        var list = Assert.IsType<ImportList>(collector.Value);
        Assert.Equal(elf.Imports.Count, list.Total);
        var first = elf.Imports.First(i => i.Name != null);
        Assert.Contains($"{first.Module}!{first.Name}", Text(imports));
        var bound = await h.Native.ListImports(NativeFixtures.LinuxArm64DbgShim, bind: true, filter: first.Name);
        Assert.Contains("Bindings: resolved for PE images only (Elf image)", Text(bound));

        var exports = await h.Native.ListExports(NativeFixtures.LinuxArm64DbgShim, filter: "RegisterForRuntimeStartup");
        Assert.Matches(@"^\s*0x[0-9A-F]+\s+RegisterForRuntimeStartup", Text(exports).Split('\n').First(l => l.Contains("RegisterForRuntimeStartup")));

        var dylib = await h.Native.ListExports(NativeFixtures.OsxArm64DbgShim, filter: "RegisterForRuntimeStartup");
        Assert.Contains("_RegisterForRuntimeStartup", Text(dylib));
        var machoImports = Text(await h.Native.ListImports(NativeFixtures.OsxArm64DbgShim, module: "libSystem"));
        Assert.Contains("/usr/lib/libSystem.B.dylib!_", machoImports);
    }

    [Fact]
    public void SummarizeFile_ReportsTheNativeImage()
    {
        using var ws = new AssemblyWorkspace(new ServerOptions());
        var inspection = new InspectionService(ws);
        var fat = inspection.Summarize(null, NativeFixtures.OsxFatSkia, default);
        Assert.Equal("mach-o", fat.File.Type);
        Assert.NotNull(fat.NativeImage);
        Assert.Equal("arm64", fat.NativeImage!.Slice);
        Assert.Equal(["x86_64", "arm64"], fat.NativeImage.Slices);
        Assert.Contains(fat.Highlights, x => x.StartsWith("Universal binary: x86_64, arm64", StringComparison.Ordinal));

        var dylib = inspection.Summarize(null, NativeFixtures.OsxArm64DbgShim, default).NativeImage!;
        Assert.NotNull(dylib.Signature);
        Assert.NotNull(dylib.BuildId);
        Assert.Contains("macos", dylib.Platform);

        var so = inspection.Summarize(null, NativeFixtures.LinuxArm64DbgShim, default).NativeImage!;
        Assert.Equal("ELF64", so.Format);
        Assert.Equal(((ElfFile)NativeImageLoader.Open(NativeFixtures.LinuxArm64DbgShim)).BuildId, so.BuildId);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void SurveyFeatures_TakesElfAndMachOPaths()
    {
        using var ws = new AssemblyWorkspace(new ServerOptions());
        var inspection = new InspectionService(ws, new Services.NativeCodeService(ws, new ServerOptions()));
        foreach (var path in new[] { NativeFixtures.LinuxArm64DbgShim, NativeFixtures.OsxArm64DbgShim })
        {
            var report = inspection.SurveyFeatures(null, path, null, default);
            Assert.Equal(Path.GetFileName(path), report.Assembly);
            Assert.StartsWith("native image", report.Notes[0], StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Identify_TellsMachOFromJavaClasses()
    {
        Assert.Equal("mach-o", Blob.Identify([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 1, 0, 0, 12, 0, 0, 0, 0]));
        Assert.NotEqual("mach-o", Blob.Identify([0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 0x2A, 0x0A, 0, 0, 0, 0, 0]));
        Assert.Equal("elf", Blob.Identify(File.ReadAllBytes(NativeFixtures.LinuxArm64DbgShim)));
    }

    /// <summary>Every native tool on ELF and Mach-O images: results or typed errors (pe_only), never an unexpected exception.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task EveryNativeTool_AnswersOnElfAndMachO()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        foreach (var path in new[] { NativeFixtures.LinuxArm64DbgShim, NativeFixtures.LinuxArmDbgShim, NativeFixtures.OsxArm64DbgShim, NativeFixtures.OsxArm64AppHost })
            await h.Exercise(path);
        var failed = h.Calls.Where(c => c.Failed).ToList();
        Assert.True(failed.Count == 0, string.Join("\n", failed.Take(10)));
        Assert.Contains(h.Calls, c => c.Tool == "get_resource" || c.Tool == "list_resources");
    }
}
