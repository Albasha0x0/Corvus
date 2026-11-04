using Corvus.Native.Dump;
using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Frames in generated code named by an address lookup when the runtime's own walk names none.</summary>
public sealed class GeneratedCodeFrameTests
{
    private const ulong Jit = 0x7FF8_67CE_4D18, Scanned = 0x7FF8_67CE_4CA1, Module = 0x7FF8_C0C2_D6E1;

    private static WalkFrame Native(ulong ip, bool scan) => new(ip, ip & 0xFFF, scan ? FrameMethod.Scan : FrameMethod.UnwindInfo, scan, true, null);

    private static ManagedFrame Named(ulong ip) => new(ip, 0, true, "Readers.ReadLoop(System.String, Int32, Int32)", 0x06000002, 0, null, null, null);

    // A snapshot caught a thread where the runtime's walk returned no method frame.
    [Fact]
    public void An_unwound_frame_in_generated_code_is_named_when_the_runtime_walk_named_none()
    {
        var merged = MinidumpService.Merge([Native(Module, false), Native(Jit, false), Native(Scanned, true)], []);
        MinidumpService.NameGeneratedCode(merged, ip => ip == Module, f => f.Ip == Jit ? Named(f.Ip) : null);
        Assert.Equal([null, "Readers.ReadLoop(System.String, Int32, Int32)", null], merged.Select(f => f.Managed?.Name));
    }

    [Fact]
    public void A_scanned_frame_in_generated_code_keeps_its_address_only()
    {
        var merged = MinidumpService.Merge([Native(Scanned, true)], []);
        MinidumpService.NameGeneratedCode(merged, _ => false, f => Named(f.Ip));
        Assert.Null(merged.Single().Managed);
    }

    [Fact]
    public void Frames_are_not_looked_up_once_the_runtime_walk_named_a_method()
    {
        var merged = MinidumpService.Merge([Native(Jit, false), Native(Scanned, false)], [Named(Jit)]);
        MinidumpService.NameGeneratedCode(merged, _ => false, f => throw new InvalidOperationException("looked up"));
        Assert.Equal([Jit, Scanned], merged.Select(f => f.Managed?.Ip ?? f.Native!.Ip));
    }
}
