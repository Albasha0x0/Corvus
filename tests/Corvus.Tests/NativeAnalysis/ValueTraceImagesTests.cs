using Corvus.Core;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>trace_native_values across loaded images: into a provider through an import, back to importers through an export.</summary>
public sealed class ValueTraceImagesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static readonly byte[] Frame = [0x48, 0x83, 0xEC, 0x28], Unframe = [0x48, 0x83, 0xC4, 0x28];

    /// <summary>
    /// provlib.dll: Take(x) calls KERNEL32!Sleep(x); Get() returns 7. app.dll: Main calls provlib!Take(0x1234), then
    /// KERNEL32!Sleep(provlib!Get()).
    /// </summary>
    private (NativeTraceTools Tools, AssemblyWorkspace Workspace) Rig()
    {
        var prov = _dir.File("provlib.dll");
        File.WriteAllBytes(prov, LinkedImages.Build("provlib.dll", [("Take", 0), ("Get", 16)], [("KERNEL32.dll", ["Sleep"])],
            slots => new LinkedImages.Code(slots).Raw(Frame).CallImport("KERNEL32.dll!Sleep").Raw(Unframe).Ret().Pad(16)
                .Raw(0xB8, 7, 0, 0, 0).Ret().ToArray()));
        var app = _dir.File("app.dll");
        File.WriteAllBytes(app, LinkedImages.Build("app.dll", [("Main", 0)], [("provlib.dll", ["Take", "Get"]), ("KERNEL32.dll", ["Sleep"])],
            slots => new LinkedImages.Code(slots).Raw(Frame).Raw(0xB9, 0x34, 0x12, 0, 0).CallImport("provlib.dll!Take").CallImport("provlib.dll!Get")
                .Raw(0x89, 0xC1).CallImport("KERNEL32.dll!Sleep").Raw(Unframe).Ret().ToArray()));
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        ws.LoadAny(app);
        ws.LoadAny(prov);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        return (new NativeTraceTools(ws, code, link: new NativeLinkService(ws, code)), ws);
    }

    /// <summary>trace_native_values follows a writable global into its writers unless stopAtGlobals (the default of the former followGlobals=true).</summary>
    [Fact]
    public async Task Backward_follows_globals_unless_stopAtGlobals()
    {
        // .text 0x1000: mov dword [rip -> 0x2000], 7; mov ecx, [rip -> 0x2000]; ret. .data 0x2000 (read, write).
        var b = new PeBuilder { ImageBase = 0x180000000, Characteristics = 0x2022, EntryPoint = 0x1000 };
        b.Add(".text", [0xC7, 0x05, 0xF6, 0x0F, 0, 0, 7, 0, 0, 0, 0x8B, 0x0D, 0xF0, 0x0F, 0, 0, 0xC3], 0x60000020);
        b.Add(".data", new byte[0x100], 0xC0000040);
        var path = _dir.File("global.dll");
        File.WriteAllBytes(path, b.Build());
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var tools = new NativeTraceTools(ws, new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann"))));
        NativeLinkTests.Has(await tools.TraceNativeValues(path, "0x180001010", location: "rcx"), "Values reached (1): 7");
        Assert.DoesNotContain("Values reached (1): 7", await tools.TraceNativeValues(path, "0x180001010", location: "rcx", stopAtGlobals: true));
    }

    // Main: sub rsp (4), mov ecx (5), call Take at +9, call Get at +0xF, mov ecx, eax at +0x15, call Sleep at +0x17
    [Fact]
    public async Task Forward_value_continues_into_the_provider_through_the_import()
    {
        var (tools, ws) = Rig();
        using var _ = ws;
        var text = await tools.TraceNativeValues("app.dll", "0x180001004", location: "rcx", direction: "forward");
        NativeLinkTests.Has(text, "-> argument: argument 1 of provlib!Take");
        NativeLinkTests.Has(text, "-> parameter: parameter 1 of Take");
        NativeLinkTests.Has(text, "@[provlib.dll] Take+0x");
        NativeLinkTests.Has(text, "-> sink: argument 1 dwMilliseconds of KERNEL32!Sleep");
    }

    [Fact]
    public async Task Backward_parameter_of_an_export_binds_to_the_importers_arguments()
    {
        var (tools, ws) = Rig();
        using var _ = ws;
        var text = await tools.TraceNativeValues("provlib.dll", "0x180001004", argument: "1");
        NativeLinkTests.Has(text, "Values reached (1): 0x1234");
        NativeLinkTests.Has(text, "@[app.dll] Main+0x");
    }

    /// <summary>
    /// fields.dll: Main calls Set(?, 0x77); Set(Widget *w, int v) stores v to w+0x10; Read(Widget *w) passes w+0x10 to
    /// KERNEL32!Sleep. The parameter types are the user's (set_native_type).
    /// </summary>
    private (NativeTraceTools Tools, AssemblyWorkspace Workspace) Fields()
    {
        var path = _dir.File("fields.dll");
        File.WriteAllBytes(path, LinkedImages.Build("fields.dll", [("Main", 0), ("Set", 0x20), ("Read", 0x40)], [("KERNEL32.dll", ["Sleep"])],
            slots => new LinkedImages.Code(slots).Raw(Frame).Raw(0xBA, 0x77, 0, 0, 0).Raw(0xE8, 0x12, 0, 0, 0).Raw(Unframe).Ret().Pad(0x20)
                .Raw(0x89, 0x51, 0x10).Ret().Pad(0x40)
                .Raw(Frame).Raw(0x8B, 0x49, 0x10).CallImport("KERNEL32.dll!Sleep").Raw(Unframe).Ret().ToArray()));
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var native = ws.LoadAny(path).Native!;
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        code.Annotations(native).ChangeUserTypes(l => l.WithType(LinkedImages.Text + 0x20, "void Set(struct Widget *w, int v)")
            .WithType(LinkedImages.Text + 0x40, "void __fastcall Read(Widget *w)"));
        return (new NativeTraceTools(ws, code), ws);
    }

    [Fact]
    public async Task Backward_field_load_finds_the_stores_to_that_field_of_the_type()
    {
        var (tools, ws) = Fields();
        using var _ = ws;
        var text = await tools.TraceNativeValues("fields.dll", "0x180001047", argument: "1");
        NativeLinkTests.Has(text, "Values reached (1): 0x77");
        NativeLinkTests.Has(text, "field +0x10: Widget+0x10");
        NativeLinkTests.Has(text, "@Set+0x0");
    }

    [Fact]
    public async Task Forward_field_store_reaches_the_loads_of_that_field_of_the_type()
    {
        var (tools, ws) = Fields();
        using var _ = ws;
        var text = await tools.TraceNativeValues("fields.dll", "0x180001004", location: "rdx", direction: "forward");
        NativeLinkTests.Has(text, "stored to [rcx+10h]: Widget+0x10");
        NativeLinkTests.Has(text, "read of Widget+0x10 at Read+0x4");
        NativeLinkTests.Has(text, "-> sink: argument 1 dwMilliseconds of KERNEL32!Sleep");
    }

    [Fact]
    public async Task Pdb_procedure_types_name_parameter_pointees_and_members()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var native = ws.LoadAny(PdbTypeFixture.Image(_dir)).Native!;
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        _ = new PdbService(code);
        var index = await code.Index(native, null, default);
        var host = CallAnalysis.For(index);
        var types = new NativeTraceTypes(ws, code);
        var helper = index.FunctionByStart(0x1040)!;
        Assert.Equal("Sensor", types.ParameterType(host, helper, "rcx"));
        Assert.Null(types.ParameterType(host, helper, "rdx"));
        Assert.Equal("next", types.Member(host, "Sensor", 0x38));
        Assert.Contains(types.Holders(host, "Sensor"), h => h.Function.Start == 0x1040 && h.Location == "rcx");
    }

    [Fact]
    public void Rtti_vftable_slots_hold_their_class_as_this()
    {
        var (image, vftables) = VirtualCallTests.Synthetic();
        var native = new LoadedNative("synthetic", "synthetic", image);
        var index = NativeCodeIndex.Build(image);
        var host = CallAnalysis.For(index);
        var types = new NativeTraceTypes(_ => native, _ => UserTypeLayer.Empty, "rtti");
        var holders = types.Holders(host, "Circle");
        Assert.NotEmpty(holders);
        Assert.All(holders, h => Assert.Equal("rcx", h.Location));
        Assert.Equal("Circle", types.ParameterType(host, holders[0].Function, "rcx"));
    }

    [Fact]
    public void A_field_read_through_a_vftable_slot_finds_the_store_of_an_inlined_constructor()
    {
        var (image, _) = VirtualCallTests.Synthetic();
        var native = new LoadedNative("synthetic", "synthetic", image);
        var index = NativeCodeIndex.Build(image);
        var host = CallAnalysis.For(index);
        var types = new NativeTraceTypes(_ => native, _ => UserTypeLayer.Empty, "rtti");
        var area = index.Functions.Single(f => f.Name == "Circle_area");
        var g = ValueTrace.Build(host, new TraceSeed(TraceSeedKind.Location, area.Start + 3, area, "eax", "eax after the load"), new ValueTraceOptions(TraceDirection.Backward), types: types);
        Assert.Contains(g.Values, v => v.Text == "0x31");
    }

    /// <summary>x86 inlined constructor storing the vftable as an immediate ("mov dword [ecx], offset vftable"): no register carries it.</summary>
    [Fact]
    public void A_field_read_finds_the_store_of_an_x86_constructor_writing_the_vftable_as_an_immediate()
    {
        const uint area = 0x1000, make = 0x1010, vftable = CodeTestImage.SyntheticDataRva + 0x10;
        const uint vfVa = 0x10000000 + vftable;
        var code = new byte[0x20];
        Array.Fill(code, (byte)0xCC);
        new byte[] { 0x8B, 0x41, 0x08, 0xC3 }.CopyTo(code, 0);                                     // mov eax, [ecx+8]; ret
        new byte[] { 0xC7, 0x01, 0, 0, 0, 0, 0xC7, 0x41, 0x08, 0x31, 0, 0, 0, 0xC3 }.CopyTo(code, 0x10); // mov dword [ecx], offset vftable; mov dword [ecx+8], 31h; ret
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(0x12), vfVa);
        var data = new byte[0x100];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), 0x10000000 + area);
        var image = CodeTestImage.Synthetic(Native.NativeArch.X86, code, data, relocations: [make + 2, vftable],
            exports: [new Native.NativeExport("Circle_area", 1, area, null), new Native.NativeExport("MakeCircle", 2, make, null)]);
        var index = NativeCodeIndex.Build(image);
        var host = CallAnalysis.For(index);
        var f = index.FunctionByStart(area)!;
        var g = ValueTrace.Build(host, new TraceSeed(TraceSeedKind.Location, area + 3, f, "eax", "eax after the load"), new ValueTraceOptions(TraceDirection.Backward),
            types: new VftableTypes(area, vftable));
        Assert.Contains(g.Values, v => v.Text == "0x31");
    }

    /// <summary>Class "Circle": this (ecx) of <paramref name="method"/>, constructed where <paramref name="vftable"/> is stored.</summary>
    private sealed class VftableTypes(uint method, uint vftable) : ITraceTypes
    {
        public string Key => "test";
        public string? ParameterType(ITraceHost host, NativeFunction f, string location) => f.Start == method && location == "ecx" ? "Circle" : null;
        public IReadOnlyList<(NativeFunction Function, string Location)> Holders(ITraceHost host, string type) => [];
        public string? Member(ITraceHost host, string type, long offset) => null;
        public IReadOnlyList<uint> Vftables(ITraceHost host, string type) => type == "Circle" ? [vftable] : [];
    }

    [Fact]
    public async Task Backward_import_result_comes_from_the_providers_return_values()
    {
        var (tools, ws) = Rig();
        using var _ = ws;
        var text = await tools.TraceNativeValues("app.dll", "0x180001017", argument: "1");
        NativeLinkTests.Has(text, "Values reached (1): 7");
        NativeLinkTests.Has(text, "<- call_result: result of provlib!Get");
        NativeLinkTests.Has(text, "@[provlib.dll] Get+0x");
    }

    /// <summary>The text alone carries each node's derivation and every edge of the page, for clients that show no structured output.</summary>
    [Fact]
    public async Task Text_carries_derivations_and_edges()
    {
        var (tools, ws) = Rig();
        using var _ = ws;
        var text = await tools.TraceNativeValues("app.dll", "0x180001017", argument: "1");
        Assert.DoesNotContain("structured output", text);
        NativeLinkTests.Has(text, "@Main+0xF  (argument at 0x180001017)");
        NativeLinkTests.Has(text, "Get+0x0  (return at 0x18000100F)");
        NativeLinkTests.Has(text, "= mov eax,7 @0x180001010");
    }
}
