using Corvus.Core;
using Corvus.Setup;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// A client's tool call writes outputs only under the output roots; the
/// command line names its own.
/// </summary>
public sealed class OutputRootsTests : IDisposable
{
    private readonly TempDir _root = new(), _elsewhere = new();

    public void Dispose()
    {
        _root.Dispose();
        _elsewhere.Dispose();
    }

    [Fact]
    public void A_write_outside_the_output_roots_is_refused_naming_CORVUS_OUTPUT_DIRS()
    {
        using (OutputRoots.Enter(OutputRoots.Resolve(_root.Path, [])))
        {
            var error = Assert.Throws<ToolError>(() => SafeFile.Output(_elsewhere.File("out.bin")));
            Assert.Contains(OutputRoots.Variable, error.Remediation);
            Assert.Contains(InputFiles.FinalPathOfNew(_root.Path), error.Message);
            Assert.True(OutputGuard.IsRefusal(error));
            SafeFile.Output(_root.File("out.bin"));
        }
        SafeFile.Output(_elsewhere.File("out.bin"));
    }

    [Fact]
    public void A_client_root_at_the_home_folder_still_refuses_agent_and_SSH_folders()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        using (OutputRoots.Enter(OutputRoots.Resolve(null, [home])))
        {
            Assert.EndsWith("is in a .claude folder; outputs are not written there.",
                Assert.Throws<ToolError>(() => SafeFile.Output(Path.Combine(home, ".claude", "settings.json"))).Message);
            Assert.EndsWith("is in the SSH folder; outputs are not written there.",
                Assert.Throws<ToolError>(() => SafeFile.Output(Path.Combine(home, ".ssh", "config"))).Message);
        }
    }

    [Fact]
    public void The_default_roots_are_the_temporary_and_exports_folders_and_the_client_roots()
    {
        var roots = OutputRoots.Resolve(null, [_root.Path])!;
        Assert.Equal(3, roots.Count);
        Assert.Equal(2, OutputRoots.Resolve(_root.Path, [_elsewhere.Path])!.Count);
        Assert.Contains(InputFiles.FinalPathOfNew(Path.GetFullPath(Path.GetTempPath())), roots);
        Assert.Contains(InputFiles.FinalPathOfNew(_root.Path), roots);
        Assert.Null(OutputRoots.Resolve(" * ", [_root.Path]));
    }

    [Fact]
    public async Task A_star_restores_writes_anywhere_the_guard_allows()
    {
        var target = _elsewhere.File("work.session.json");
        await using (var server = await InProcessServer.StartAsync(options: Options(_root.Path)))
            Assert.Contains(OutputRoots.Variable, Text(await server.Client.CallToolAsync("save_session", new Dictionary<string, object?> { ["outputPath"] = target })));
        Assert.False(File.Exists(target));
        await using (var server = await InProcessServer.StartAsync(options: Options("*")))
            Assert.NotEqual(true, (await server.Client.CallToolAsync("save_session", new Dictionary<string, object?> { ["outputPath"] = target })).IsError);
        Assert.True(File.Exists(target));
    }

    [Fact]
    public async Task A_default_save_beside_a_file_outside_the_roots_goes_to_the_exports_folder()
    {
        var expected = Native.Providers.DataFolder.Combine(OutputGuard.ExportsFolder, "TestFixture.dll", "TestFixture.patched.dll");
        try
        {
            await using var server = await InProcessServer.StartAsync(options: Options(_root.Path));
            var text = Text(await server.Client.CallToolAsync("save_assembly", new Dictionary<string, object?> { ["assembly"] = "TestFixture" }));
            Assert.Contains($"Wrote {expected}", text);
            Assert.Contains("outside the output roots", text);
            Assert.True(File.Exists(expected));
            Assert.Contains(OutputRoots.Variable, Text(await server.Client.CallToolAsync("save_assembly",
                new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["outputPath"] = _elsewhere.File("saved.dll") })));
            Assert.False(File.Exists(_elsewhere.File("saved.dll")));
        }
        finally { File.Delete(expected); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ReplaceOriginal_writes_a_file_outside_the_roots_only_with_the_server_switch(bool allowed)
    {
        var copy = _elsewhere.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false, OutputDirs = _root.Path, AllowReplaceOriginal = allowed };
        options.Preload.Add(copy);
        await using var server = await InProcessServer.StartAsync(options: options);
        var result = await server.Client.CallToolAsync("save_assembly",
            new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["outputPath"] = copy, ["replaceOriginal"] = true });
        Assert.True(allowed != (result.IsError == true), Text(result));
        Assert.Equal(allowed, File.Exists(copy + ".bak"));
        var other = _elsewhere.File("other.dll");
        Assert.True((await server.Client.CallToolAsync("save_assembly",
            new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["outputPath"] = other, ["replaceOriginal"] = true })).IsError);
        Assert.False(File.Exists(other));
    }

    [Fact]
    public async Task A_command_line_save_is_not_held_to_the_output_roots()
    {
        var target = _elsewhere.File("work.session.json");
        await using var session = await ToolSession.StartAsync(Options(_root.Path), CancellationToken.None);
        Assert.NotEqual(true, (await session.Client.CallToolAsync("save_session", new Dictionary<string, object?> { ["outputPath"] = target })).IsError);
        Assert.True(File.Exists(target));
    }

    private static ServerOptions Options(string outputDirs)
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false, OutputDirs = outputDirs };
        options.Preload.Add(Env.FixturePath);
        return options;
    }

    private static string Text(CallToolResult result) => string.Join("\n", result.Content.OfType<TextContentBlock>().Select(t => t.Text));
}
