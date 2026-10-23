using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>export_project writes whole or not at all, replaces only a previous export, and answers by the client's deadline.</summary>
public sealed class ExportProjectTests
{
    [Fact]
    public async Task ACommitWaitsForAFileHeldOpenForAMoment()
    {
        using var dir = new TempDir();
        using var export = ExportDirectory.Begin(dir.File("out"), overwrite: false);
        var file = Path.Combine(export.Staging, "a.cs");
        File.WriteAllText(file, "class A {}");
        // As a virus scanner or indexer does with a new file; on Windows the folder cannot move while it is open.
        var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None);
        // A thread of its own and a minute's patience, so a busy pool or machine cannot run the release past the wait.
        var release = Task.Factory.StartNew(() => { Thread.Sleep(300); held.Dispose(); }, TaskCreationOptions.LongRunning);
        Assert.Contains("a.cs", export.Commit(patience: TimeSpan.FromMinutes(1)));
        await release;
        Assert.True(File.Exists(Path.Combine(dir.File("out"), "a.cs")));
    }

    [Fact]
    public void OverwriteReplacesOnlyAPreviousExport()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var output = dir.File("out");
        var first = env.Decompiler.ExportProject(env.Fixture, output, null, default);
        Assert.False(first.Replaced);
        Assert.True(File.Exists(Path.Combine(output, ExportDirectory.Marker)));

        var refused = Assert.Throws<ToolError>(() => env.Decompiler.ExportProject(env.Fixture, output, null, default));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        Assert.Contains("overwrite=true", refused.Remediation);

        var second = env.Decompiler.ExportProject(env.Fixture, output, null, default, overwrite: true);
        Assert.True(second.Replaced);
        Assert.Equal(first.FileCount, second.FileCount);

        File.WriteAllText(Path.Combine(output, "notes.txt"), "mine");
        var foreign = Assert.Throws<ToolError>(() => env.Decompiler.ExportProject(env.Fixture, output, null, default, overwrite: true));
        Assert.Contains("notes.txt", foreign.Message);
        Assert.True(File.Exists(Path.Combine(output, "notes.txt")));
        Assert.Single(Directory.GetDirectories(dir.Path));
    }

    [Fact]
    public void ACancelledExportLeavesNothing()
    {
        using var env = new Env();
        using var dir = new TempDir();
        using var cts = new CancellationTokenSource();
        int reports = 0;
        Assert.ThrowsAny<OperationCanceledException>(() => env.Decompiler.ExportProject(env.Fixture, dir.File("out"), (_, _, _) =>
        {
            if (++reports == 3) cts.Cancel();
        }, cts.Token));
        Assert.Empty(Directory.GetFileSystemEntries(dir.Path));
    }

    /// <summary>A client that waits 10 s (deadline 5 s): the call answers with a partial and the export finishes in the background.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task AtTheClientDeadlineTheExportAnswersAndFinishesInTheBackground()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var options = new ServerOptions { ClientTimeoutSeconds = 10 };
        var clock = new ArmedClock();
        using var services = new ServiceCollection().AddSingleton(options).AddSingleton<ResultStore>().AddSingleton<TimeProvider>(clock).BuildServiceProvider();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: options);
        var output = dir.File("out");
        // A writer holds the workspace, so the export cannot take its snapshot before the deadline.
        using var release = new ManualResetEventSlim();
        using var held = new ManualResetEventSlim();
        var writer = Task.Factory.StartNew(() => env.Workspace.Write(() => { held.Set(); release.Wait(); return 0; }), TaskCreationOptions.LongRunning);
        held.Wait();
        var calling = CallFilter.Run(new CallToolRequestParams { Name = "export_project" }, null, services,
            ct => new ValueTask<CallToolResult>(Call(ct)), default, null).AsTask();
        async Task<CallToolResult> Call(CancellationToken ct) =>
            new() { Content = [new TextContentBlock { Text = await tools.ExportProject("TestFixture", output, cancellationToken: ct) }] };
        var deadline = TimeSpan.FromSeconds(options.ClientTimeoutSeconds.Value) - Deadlines.ClientMargin;
        var answered = await clock.RunUntilAsync(calling, within: deadline);
        Assert.True(answered <= deadline, $"answered after {answered}");
        var result = await calling;
        var error = McpProtocolTests.ErrorJson(result);
        Assert.Equal("timeout", error.GetProperty("code").GetString());
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Equal(JsonValueKind.Object, error.GetProperty("partial").ValueKind);
        Assert.False(Directory.Exists(output));

        release.Set();
        await writer;
        var watch = Stopwatch.StartNew();
        while (!File.Exists(Path.Combine(output, ExportDirectory.Marker)) && watch.Elapsed < TimeSpan.FromSeconds(60)) await Task.Delay(50);
        Assert.NotEmpty(Directory.GetFiles(output, "*.cs", SearchOption.AllDirectories));
    }
}
