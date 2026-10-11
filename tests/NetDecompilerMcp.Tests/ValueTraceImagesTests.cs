using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

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
}
