using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>trace_native_feature: seeds, interior and pointer-table references, import calls, ranking, hubs, isolation, paging.</summary>
public sealed class FeatureTraceTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const ulong Base = 0x180000000;

    /// <summary>
    /// feature.dll: Controller (export) calls LoadSettings and SaveSettings. LoadSettings points into "open settings file" (+5)
    /// and calls CreateFileW; SaveSettings reads slot 1 of a pointer table [&amp;"settings saved", &amp;"open settings file"] and calls
    /// CreateFileW. Unrelated does nothing.
    /// </summary>
    private string Sample()
    {
        Dictionary<string, uint>? at = null;
        byte[] Code(Dictionary<string, uint> slots)
        {
            var a = new Assembler(64);
            var load = a.CreateLabel();
            var save = a.CreateLabel();
            var controller = a.CreateLabel();
            var unrelated = a.CreateLabel();
            Instruction CallImport() => Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slots["KERNEL32.dll!CreateFileW"]), 8));
            Instruction Lea(Register r, uint rva) => Instruction.Create(Iced.Intel.Code.Lea_r64_m, r, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
            a.Label(ref controller);
            a.sub(rsp, 0x28);
            a.call(load);
            a.call(save);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 4; i++) a.int3();
            a.Label(ref load);
            a.sub(rsp, 0x28);
            a.AddInstruction(Lea(Register.RCX, slots["s1"] + 10));
            a.AddInstruction(CallImport());
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 4; i++) a.int3();
            a.Label(ref save);
            a.sub(rsp, 0x28);
            a.AddInstruction(Lea(Register.RAX, slots["table"]));
            a.mov(rcx, __qword_ptr[rax + 8]);
            a.AddInstruction(CallImport());
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 4; i++) a.int3();
            a.Label(ref unrelated);
            a.ret();
            var stream = new MemoryStream();
            var r = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            uint Off(Label l) => (uint)(r.GetLabelRIP(l) - Base - LinkedImages.Text);
            at = new() { ["Controller"] = Off(controller), ["Unrelated"] = Off(unrelated) };
            return stream.ToArray();
        }
        static Dictionary<string, uint> Data(PeBlob blob, List<uint> relocations)
        {
            blob.Align(2);
            uint s1 = blob.Utf16("open settings file\0");
            uint s2 = blob.Utf16("settings saved\0");
            blob.Align(8);
            uint table = blob.U64(Base + s2);
            blob.U64(Base + s1);
            relocations.AddRange([table, table + 8]);
            return new() { ["s1"] = s1, ["table"] = table };
        }
        (string, string[])[] imports = [("KERNEL32.dll", ["CreateFileW"])];
        LinkedImages.Build("feature.dll", [], imports, Code, Data);
        var path = _dir.File("feature.dll");
        File.WriteAllBytes(path, LinkedImages.Build("feature.dll", [("Controller", (int)at!["Controller"]), ("Unrelated", (int)at["Unrelated"])], imports, Code, Data));
        return path;
    }

    private (AssemblyWorkspace Workspace, NativeCodeService Code, NativeFeatureTools Tools) Rig()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        return (ws, code, new NativeFeatureTools(ws, code, new OutputPager(options)));
    }

    [Fact]
    public async Task Strings_reach_functions_through_interiors_and_pointer_tables_and_hubs_join_them()
    {
        var (ws, _, tools) = Rig();
        using var _ = ws;
        var text = await tools.TraceNativeFeature(Sample(), "settings");
        NativeLinkTests.Has(text, "string  0x");
        NativeLinkTests.Has(text, "L\"open settings file\"");
        NativeLinkTests.Has(text, "uses L\"open settings file\" at +0xA");
        NativeLinkTests.Has(text, "uses the pointer table at 0x");
        NativeLinkTests.Has(text, "holding L\"settings saved\" (slot 0)");
        NativeLinkTests.Has(text, "holding L\"open settings file\" (slot 1)");
        NativeLinkTests.Has(text, "Hubs (callers reaching several of them):");
        NativeLinkTests.Has(text, "Controller  reaches 2 within 1");
        NativeLinkTests.Has(text, "analyze_native_function image=feature.dll address=0x");
    }

    [Fact]
    public async Task Imports_carry_their_call_arguments_and_rank_by_evidence()
    {
        var (ws, _, tools) = Rig();
        using var _ = ws;
        var path = Sample();
        var text = await tools.TraceNativeFeature(path, "CreateFile|settings saved", regex: true);
        NativeLinkTests.Has(text, "import  0x");
        NativeLinkTests.Has(text, "KERNEL32!CreateFileW");
        NativeLinkTests.Has(text, "call: CreateFileW(L\"settings file\"");
        // SaveSettings holds both seeds: ranked first
        var functions = text.Split("Functions (ranked")[1];
        Assert.Contains("seeds 0,1", functions.Split('\n')[1]);
        var page = await tools.TraceNativeFeature(path, "CreateFile|settings saved", regex: true, offset: 1, limit: 1);
        NativeLinkTests.Has(page, "Functions (ranked; 2-2 of 2)");
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.TraceNativeFeature(path, "x", kinds: "strings,bogus"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
    }

    [Fact]
    public async Task A_failing_seed_keeps_the_others_and_results_are_cached()
    {
        var (ws, code, _) = Rig();
        using var _ = ws;
        var native = ws.LoadAny(Sample()).Native!;
        var index = await code.Index(native, null, default);
        FeatureClass[] classes = [new("SettingsStore", 0x2000, null!), new("SettingsView", 0x2008, [])];
        var r = FeatureTrace.Run(index, "Settings", false, FeatureKinds.Classes | FeatureKinds.Strings, 50, 1, classes, default);
        var broken = Assert.Single(r.Seeds, s => s.Kind == "class" && s.Error != null);
        Assert.Equal("SettingsStore", broken.Text);
        Assert.Contains(r.Seeds, s => s.Text == "SettingsView" && s.Error == null);
        Assert.Contains(r.Seeds, s => s.Kind == "string");
        Assert.Same(r, FeatureTrace.Run(index, "Settings", false, FeatureKinds.Classes | FeatureKinds.Strings, 50, 1, classes, default));
        var capped = FeatureTrace.Run(index, "settings", false, FeatureKinds.Strings, 1, 0, [], default);
        Assert.Single(capped.Seeds);
        Assert.Equal(3, capped.TotalSeeds);
        Assert.Contains("3 matches; the first 1 were followed (maxSeeds)", capped.Notes);
    }
}
