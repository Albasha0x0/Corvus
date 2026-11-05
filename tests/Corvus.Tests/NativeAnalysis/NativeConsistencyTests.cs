using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Native tool output agrees with itself: one radix, one direction, one frame.</summary>
public sealed class NativeConsistencyTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // 0x1000: mov rax,rsp; push rbp; lea rbp,[rax-38h]; mov dword [rbp-60h],5; mov ecx,[rbp-60h]; pop rbp; ret.
    // 0x1020: mov ecx,7; ret. 0x1030: add rax,-16; ret.
    // 0x1038: push rbp; lea rbp,[rcx+8]; pop rbp; ret.
    private (AssemblyWorkspace Ws, NativeCodeService Code, string Path) Rig()
    {
        var code = new byte[0x40];
        byte[] f1 = [0x48, 0x8B, 0xC4, 0x55, 0x48, 0x8D, 0x68, 0xC8, 0xC7, 0x45, 0xA0, 5, 0, 0, 0, 0x8B, 0x4D, 0xA0, 0x5D, 0xC3];
        byte[] f2 = [0xB9, 7, 0, 0, 0, 0xC3];
        f1.CopyTo(code, 0);
        f2.CopyTo(code, 0x20);
        byte[] f3 = [0x48, 0x83, 0xC0, 0xF0, 0xC3];
        f3.CopyTo(code, 0x30);
        byte[] f4 = [0x55, 0x48, 0x8D, 0x69, 0x08, 0x5D, 0xC3];
        f4.CopyTo(code, 0x38);
        var b = new PeBuilder { ImageBase = 0x180000000, Characteristics = 0x2022, EntryPoint = 0x1000 };
        b.Add(".text", code, 0x60000020);
        var path = _dir.File("consistency.dll");
        File.WriteAllBytes(path, b.Build());
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        return (ws, new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann"))), path);
    }

    private static OutputPager Pager() => new(new ServerOptions { BackgroundIndexing = false });

    [Fact]
    public async Task A_negative_immediate_reads_as_signed_hex()
    {
        var (ws, code, path) = Rig();
        using var _ = ws;
        var text = await new NativeCodeTools(ws, code, Pager()).InspectInstruction(path, "0x180001030");
        Assert.Contains("(-0x10)", text);
        Assert.DoesNotContain("(-16)", text);
    }

    [Fact]
    public async Task The_seed_of_a_forward_trace_is_marked_forward()
    {
        var (ws, code, path) = Rig();
        using var _ = ws;
        var trace = new NativeTraceTools(ws, code);
        var report = await NativeQuerySurfaceTests.Structured<NativeTraceTools.ValueTraceReport>(() =>
            trace.TraceNativeValues(path, "0x180001020", location: "rcx", direction: "forward"));
        Assert.Equal("forward", report.Direction);
        Assert.Equal("forward", report.Nodes.Single(n => n.Kind == "seed").Direction);
    }

    [Fact]
    public async Task A_frame_pointer_set_from_another_register_is_reported_with_its_setup()
    {
        var (ws, code, path) = Rig();
        using var _ = ws;
        var text = await new NativeFunctionTools(ws, code, Pager()).AnalyzeNativeFunction(path, "0x180001000", sections: "frame");
        Assert.DoesNotContain("no frame pointer", text);
        Assert.Contains("frame pointer rbp set by lea rbp,[rax-38h]", text);
    }

    [Fact]
    public async Task Rbp_set_from_a_register_that_is_not_the_stack_pointer_is_no_frame()
    {
        var (ws, code, path) = Rig();
        using var _ = ws;
        var text = await new NativeFunctionTools(ws, code, Pager()).AnalyzeNativeFunction(path, "0x180001038", sections: "frame");
        Assert.Contains("no frame pointer", text);
    }
}
