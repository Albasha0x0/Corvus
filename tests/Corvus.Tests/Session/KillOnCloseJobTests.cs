using System.Diagnostics;
using System.Globalization;

namespace Corvus.Tests;

/// <summary>The kill-on-close job a test host enters: programs it started end with it, however it ends.</summary>
public sealed class KillOnCloseJobTests
{
    [WindowsFact]
    public void A_killed_parent_takes_the_program_it_started_with_it()
    {
        var ping = Path.Combine(Environment.SystemDirectory, "PING.EXE");
        using var parent = Process.Start(new ProcessStartInfo(FakeTool.Executable, ["job-parent", ping, "-n", "120", "127.0.0.1"])
            { RedirectStandardOutput = true, UseShellExecute = false })!;
        // The program writes to the same output; the parent's line is the number.
        int pid = 0;
        while (parent.StandardOutput.ReadLine() is { } line && !int.TryParse(line, NumberStyles.None, CultureInfo.InvariantCulture, out pid)) { }
        using var program = Process.GetProcessById(pid);
        try
        {
            Assert.False(program.HasExited);
            parent.Kill();
            Assert.True(program.WaitForExit(10_000), $"process {pid} outlived its parent");
        }
        finally
        {
            if (!program.HasExited) program.Kill();
        }
    }
}
