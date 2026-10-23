using System.Diagnostics;

namespace Corvus.Tests;

public class ServerDumpTests
{
    [Fact]
    public void A_server_started_under_cmd_is_dumped_until_the_folder_holds_three()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var started = DateTime.Now;
        // Started as the SDK starts a test server; it waits for input that never comes.
        var psi = new ProcessStartInfo("cmd.exe") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in new[] { "/c", "dotnet", McpProtocolTests.ServerDll, "--no-index", "--no-watch" }) psi.ArgumentList.Add(arg);
        using var cmd = Process.Start(psi)!;
        try
        {
            IReadOnlyList<string> files = [];
            for (var watch = Stopwatch.StartNew(); files.Count == 0 && watch.Elapsed < TimeSpan.FromMinutes(1); Thread.Sleep(200))
                files = ServerDump.Write(started, dir.Path, cmd.Id);
            var file = Assert.Single(files);
            Assert.StartsWith("server-start-", Path.GetFileName(file));
            Assert.True(new FileInfo(file).Length > 0);

            foreach (var i in new[] { 1, 2 }) File.WriteAllBytes(Path.Combine(dir.Path, $"server-start-{i}.dmp"), [0]);
            Assert.Empty(ServerDump.Write(started, dir.Path, cmd.Id));
        }
        finally { cmd.Kill(entireProcessTree: true); }
    }
}
