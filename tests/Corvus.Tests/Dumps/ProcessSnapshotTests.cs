using Corvus.Core;
using Corvus.Native.Diagnostics;
using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// Snapshot writes: one the running program disturbs (it changed a list or a region during the read) is written again; a
/// Linux core written at a stop gives the stopped thread the stop's registers and signal.
/// </summary>
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

    [Fact]
    public async Task A_core_written_at_a_stop_gives_the_stopped_thread_the_stops_registers_and_signal()
    {
        using var dir = new TempDir();
        var path = dir.File("stop.core");
        File.WriteAllBytes(path, SyntheticCore.Core(arm64: false));
        var p = SyntheticCore.Points(arm64: false);
        // thread 1002 waits elsewhere; the stop saw it at the crash point with thread 1001's stack
        var registers = new Dictionary<string, ulong> { ["rip"] = SyntheticCore.Base + p.Crash, ["rsp"] = SyntheticCore.X, ["rbp"] = SyntheticCore.X + 48, ["r12"] = 0xC12 };
        ProcessSnapshot.MarkStop(path, new ProcessSnapshot.Stop(1002, true, registers));

        using (var core = CoreFile.FromBytes(File.ReadAllBytes(path), "stop.core"))
        {
            Assert.Empty(core.Issues);
            Assert.Equal((1002u, 5), (core.FaultingThread!.Id, core.FaultingThread.Signal));
            Assert.Equal(0, core.ThreadById(1001)!.Signal);
            Assert.Equal(new ElfCoreSignal(5, 1, 0, SyntheticCore.Base + p.Crash, null), core.Signal);
        }
        using var service = new MinidumpService();
        var r = await service.Stack(path, "exception", true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(1002u, r.ThreadId);
        Assert.Equal(["crash::null()", "B", "A", "M"], r.Items.Select(f => f.Function));
    }
}
