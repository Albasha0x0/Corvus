using Corvus.Core;
using Corvus.Native.Diagnostics;

namespace Corvus.Tests;

/// <summary>A snapshot write the running program disturbs (it changed a list or a region during the read) is written again.</summary>
public sealed class ProcessSnapshotTests
{
    [Fact]
    public void A_write_the_program_changed_is_tried_again()
    {
        var errors = new Queue<int>([unchecked((int)0x80070018), unchecked((int)0x8007012B), 0]);
        ProcessSnapshot.Attempts(7, () => errors.Dequeue());
        Assert.Empty(errors);

        int calls = 0;
        var changed = Assert.Throws<ToolError>(() => ProcessSnapshot.Attempts(7, () => { calls++; return unchecked((int)0x8007012B); }));
        Assert.Equal(ProcessSnapshot.WriteTries, calls);
        Assert.Contains("the program changed while it was read", changed.Message);

        calls = 0;
        var other = Assert.Throws<ToolError>(() => ProcessSnapshot.Attempts(7, () => { calls++; return unchecked((int)0x80070070); }));
        Assert.Equal(1, calls);
        Assert.Equal(ErrorCode.IoError, other.Code);
        Assert.Contains("disk space", other.Remediation);
    }
}
