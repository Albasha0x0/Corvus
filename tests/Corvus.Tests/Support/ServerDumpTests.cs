namespace Corvus.Tests;

public class ServerDumpTests
{
    [Fact]
    public async Task A_server_is_dumped_by_its_process_id_until_the_folder_holds_three()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        // A server that answered initialize, so its start-up is over before the dump reads it.
        await using var client = await McpProtocolTests.StartServerAsync("--no-index", "--no-watch");
        var pid = McpProtocolTests.ServerProcessId(client);
        Assert.True(pid > 0);

        var file = ServerDump.Write(pid, dir.Path, out var error);
        Assert.True(file != null, $"no dump of server {pid}: Win32 error {error}");
        Assert.StartsWith("server-start-", Path.GetFileName(file));
        Assert.True(new FileInfo(file).Length > 0);

        foreach (var i in new[] { 1, 2 }) File.WriteAllBytes(Path.Combine(dir.Path, $"server-start-{i}.dmp"), [0]);
        Assert.Null(ServerDump.Write(pid, dir.Path));
    }
}
