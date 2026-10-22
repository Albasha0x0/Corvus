using Corvus.Services;

namespace Corvus.Tests;

/// <summary>How a managed frame is named when the runtime gives its method but not where the method's code starts.</summary>
public sealed class ManagedFrameNameTests
{
    [Fact]
    public void A_frame_without_a_method_start_reads_as_offset_unknown_not_as_the_entry()
    {
        var unknown = new LiveFrameName(0x7FF0_1234, "System.Private.CoreLib.dll", null, 0x1234, "Interop+Kernel32.CreateFilePrivate()", 0, null, null) { OffsetUnknown = true };
        Assert.Equal("System.Private.CoreLib.dll!Interop+Kernel32.CreateFilePrivate() (offset unknown)", unknown.Display);
        Assert.Equal("System.Private.CoreLib.dll!Interop+Kernel32.CreateFilePrivate()", (unknown with { OffsetUnknown = false }).Display);
    }
}
