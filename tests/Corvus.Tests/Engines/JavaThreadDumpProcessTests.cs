using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary>The process line of a stall report: each worker process with its CPU time.</summary>
public sealed class JavaThreadDumpProcessTests
{
    [Fact]
    public void Each_process_is_named_with_its_cpu_time_and_an_exited_one_as_not_read()
    {
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        // int.MaxValue is above every system's process id range, so it names no running process.
        var line = JavaThreadDump.Processes([Environment.ProcessId, int.MaxValue]);
        Assert.Matches($@"^processes: {self.ProcessName} {Environment.ProcessId}, \d+\.\d s CPU in \d+ s; {int.MaxValue} not read$", line);
    }

    [Fact]
    public void No_processes_give_no_line() => Assert.Equal("", JavaThreadDump.Processes([]));
}
