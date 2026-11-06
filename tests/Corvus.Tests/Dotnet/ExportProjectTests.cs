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
    public async Task A_commit_waits_for_a_file_held_open_for_a_moment()
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
    public void An_export_lists_the_build_and_shell_files_it_renamed()
    {
        using var dir = new TempDir();
        using var export = ExportDirectory.Begin(dir.File("out"), overwrite: false);
        string[] kept = ["a.cs", "build.gradle", "app/build.gradle", "x.csproj", "gradle.properties"];
        string[] renamed = ["Directory.Build.props", "src/Directory.Build.rsp", "src/App.targets", "NuGet.Config", "global.json", "init.gradle",
            "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties", "res/desktop.ini", "a.url"];
        foreach (var f in kept.Concat(renamed).Append("a.url.bin"))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.Combine(export.Staging, f))!);
            File.WriteAllText(Path.Combine(export.Staging, f), f);
        }
        var files = export.Commit();
        // The export wrote a.url.bin itself, so a.url takes the next free name.
        var expected = renamed.Select(f => f == "a.url" ? "a.url_2.bin" : f + ".bin").Order(StringComparer.Ordinal).ToList();
        Assert.Equal(expected, export.Renamed);
        Assert.Equal(kept.Concat(expected).Append("a.url.bin").Order(StringComparer.Ordinal), files);
        Assert.Equal("Directory.Build.props", File.ReadAllText(Path.Combine(dir.File("out"), "Directory.Build.props.bin")));
        Assert.False(File.Exists(Path.Combine(dir.File("out"), "Directory.Build.props")));
    }

    [Fact]
    public void Overwrite_replaces_only_a_previous_export()
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
    public void Overwrite_refuses_a_folder_whose_export_marker_lacks_this_data_folders_id()
    {
        using var dir = new TempDir();
        var output = Directory.CreateDirectory(dir.File("out")).FullName;
        File.WriteAllText(Path.Combine(output, "planted.dll"), "");
        File.WriteAllText(Path.Combine(output, ExportDirectory.Marker), "id: " + new string('0', 32) + "\nplanted.dll\n");
        var refused = Assert.Throws<ToolError>(() => ExportDirectory.Begin(output, overwrite: true));
        Assert.Contains("this data folder did not write", refused.Message, StringComparison.Ordinal);
        Assert.True(File.Exists(Path.Combine(output, "planted.dll")));
    }

    [Fact]
    public void A_cancelled_export_leaves_nothing()
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

    [Fact]
    public void Unsafe_reference_names_get_stub_names_and_stay_under_the_root()
    {
        using var dir = new TempDir();
        var options = new Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions(Microsoft.CodeAnalysis.OutputKind.DynamicallyLinkedLibrary);
        var libs = new[] { "LibA", "LibB", "LibC" }.Select(n => Roslyn.Compile(n, $"namespace {n} {{ public class Item {{ public int Value; }} }}", options)).ToArray();
        var app = Roslyn.Compile("App", "public class Uses { public int Sum(LibA.Item a, LibB.Item b, LibC.Item c) => a.Value + b.Value + c.Value; }",
            options, libs.Select(l => Microsoft.CodeAnalysis.MetadataReference.CreateFromImage(l)));
        // The references are renamed after compiling and the libraries are not written, so the export builds stubs.
        var unsafeNames = new[] { "Quote\"Name", "Close-->Comment", @"..\..\Up" };
        using (var module = dnlib.DotNet.ModuleDefMD.Load(app))
        {
            var refs = module.GetAssemblyRefs().Where(r => r.Name.String.StartsWith("Lib", StringComparison.Ordinal)).OrderBy(r => r.Name.String).ToList();
            for (int i = 0; i < refs.Count; i++) refs[i].Name = unsafeNames[i];
            Directory.CreateDirectory(dir.File("in"));
            module.Write(Path.Combine(dir.Path, "in", "App.dll"));
        }
        using var env = new Env(Path.Combine(dir.Path, "in", "App.dll"));
        var output = Path.Combine(dir.Path, "out", "export");
        var result = env.Decompiler.ExportProject(env.Fixture, output, null, default);

        var project = System.Xml.Linq.XDocument.Load(result.ProjectFile!);
        var includes = project.Descendants("Reference").Select(r => (string)r.Attribute("Include")!).ToList();
        Assert.Contains("Quote_Name", includes);
        Assert.Contains("Close__Comment", includes);
        Assert.Contains("____Up", includes);
        Assert.All(includes, i => Assert.DoesNotContain("..", i));
        Assert.All(project.Nodes().Concat(project.Descendants().SelectMany(e => e.Nodes())).OfType<System.Xml.Linq.XComment>(),
            c => Assert.DoesNotContain("--", c.Value));
        Assert.All(Directory.GetFiles(dir.Path, "*", SearchOption.AllDirectories).Where(f => !f.StartsWith(dir.File("in"), StringComparison.Ordinal)),
            f => Assert.StartsWith(output + Path.DirectorySeparatorChar, f));
        Assert.True(File.Exists(Path.Combine(output, "lib", "Quote_Name.dll")));
        Assert.Equal(3, result.Renamed.Count);
        Assert.Contains(result.Renamed, n => n.Contains("\"..\\\\..\\\\Up\" written as ____Up", StringComparison.Ordinal));
    }

    /// <summary>A client that waits 10 s (deadline 5 s): the call answers with a partial and the export finishes in the background.</summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task At_the_client_deadline_the_export_answers_and_finishes_in_the_background()
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

    [Fact]
    public async Task An_export_runs_past_ten_times_the_call_timeout()
    {
        using var env = new Env();
        using var dir = new TempDir();
        // The old limit was ten times this value,
        // so a zero timeout ended every export at once.
        env.Options.TimeoutSeconds = 0;
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        Assert.StartsWith("Exported", await tools.ExportProject("TestFixture", dir.File("out")));
        Assert.True(File.Exists(Path.Combine(dir.File("out"), ExportDirectory.Marker)));
    }

    [Fact]
    public async Task A_background_export_is_not_leftover_work_and_a_repeat_joins_it()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        using var hold = HoldWorkspace(env, out var writer);
        using var deadline = new CancellationTokenSource();
        BeginDeadlineCall();
        var first = tools.ExportProject("TestFixture", dir.File("out"), cancellationToken: deadline.Token);
        deadline.Cancel();
        var running = await Assert.ThrowsAsync<ToolError>(() => first);
        Assert.Equal(ErrorCode.Timeout, running.Code);
        Assert.Contains("repeat the same call to wait", running.Remediation);
        Assert.Equal(0, LeftoverWork.For(env.Options).Running);
        Assert.Equal(1, CallJoin.For(env.Options).Running);

        var repeat = tools.ExportProject("TestFixture", dir.File("out"));
        hold.Set();
        await writer;
        Assert.StartsWith("Exported", await repeat);
        Assert.Empty(env.Workspace.DrainNotices());
    }

    [Fact]
    public async Task A_finished_background_export_queues_a_notice_naming_the_project()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        using var hold = HoldWorkspace(env, out var writer);
        using var deadline = new CancellationTokenSource();
        BeginDeadlineCall();
        var first = tools.ExportProject("TestFixture", dir.File("out"), cancellationToken: deadline.Token);
        deadline.Cancel();
        await Assert.ThrowsAsync<ToolError>(() => first);
        hold.Set();
        await writer;
        var notice = await NextNotice(env);
        Assert.Contains("export_project of TestFixture finished", notice);
        Assert.Contains("Next: build", notice);
    }

    [Fact]
    public async Task A_failed_background_export_queues_a_notice_with_its_cause()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        using var hold = HoldWorkspace(env, out var writer);
        using var deadline = new CancellationTokenSource();
        BeginDeadlineCall();
        var first = tools.ExportProject("TestFixture", dir.File("out"), cancellationToken: deadline.Token);
        deadline.Cancel();
        await Assert.ThrowsAsync<ToolError>(() => first);
        // A foreign file appears while the export waits,
        // so it refuses the folder once it starts.
        Directory.CreateDirectory(dir.File("out"));
        File.WriteAllText(Path.Combine(dir.File("out"), "notes.txt"), "mine");
        hold.Set();
        await writer;
        var notice = await NextNotice(env);
        Assert.Contains("export_project of TestFixture failed (Out", notice);
        Assert.Contains("Next:", notice);
    }

    [Fact]
    public async Task A_cancelled_background_export_queues_a_cancelled_notice()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        using var hold = HoldWorkspace(env, out var writer);
        using var deadline = new CancellationTokenSource();
        using var client = new CancellationTokenSource();
        OutputCall.Begin(new OutputCall("export_project", 0, null) { ClientCancel = client.Token });
        var first = tools.ExportProject("TestFixture", dir.File("out"), cancellationToken: deadline.Token);
        deadline.Cancel();
        await Assert.ThrowsAsync<ToolError>(() => first);
        client.Cancel();
        hold.Set();
        await writer;
        Assert.Contains("export_project of TestFixture was cancelled", await NextNotice(env));
    }

    [Fact]
    public async Task A_joined_export_survives_the_first_caller_detaching()
    {
        using var env = new Env();
        using var dir = new TempDir();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options);
        using var hold = HoldWorkspace(env, out var writer);
        using var deadline = new CancellationTokenSource();
        BeginDeadlineCall();
        var first = tools.ExportProject("TestFixture", dir.File("out"), cancellationToken: deadline.Token);
        var second = tools.ExportProject("TestFixture", dir.File("out"));
        deadline.Cancel();
        await Assert.ThrowsAsync<ToolError>(() => first);
        // The second caller waits before the export can end.
        for (int i = 0; i < 500 && tools.WaitingOn("TestFixture", dir.File("out")) != 1; i++) await Task.Delay(20);
        Assert.Equal(1, tools.WaitingOn("TestFixture", dir.File("out")));
        hold.Set();
        await writer;
        Assert.StartsWith("Exported", await second);
        Assert.Empty(env.Workspace.DrainNotices());
    }

    [Fact]
    public async Task A_silent_idle_export_ends_as_stalled_and_names_the_raise_variable()
    {
        using var env = new Env();
        using var dir = new TempDir();
        env.Options.StallSeconds = 80;
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var tools = new Corvus.Tools.DecompileTools(env.Workspace, env.Decompiler, env.Pager, options: env.Options)
        {
            Clock = clock,
            ProcessCpu = () => TimeSpan.Zero,
        };
        using var hold = HoldWorkspace(env, out var writer);
        var call = tools.ExportProject("TestFixture", dir.File("out"));
        for (int i = 0; i < 400 && !call.IsCompleted; i++)
        {
            // FakeTimeProvider 10.10.0: disposing a timer does not wait for a
            // callback in flight, as a real timer's DisposeAsync does, so the
            // tick can reach a source the finished export disposed.
            try { clock.Advance(TimeSpan.FromSeconds(10)); }
            catch (ObjectDisposedException) { break; }
            await Task.Delay(10);
        }
        var stalled = await Assert.ThrowsAsync<ToolError>(() => call);
        Assert.StartsWith(StallRule.MessagePrefix + "export_project'", stalled.Message);
        Assert.Contains(ServerOptions.StallWindowVariable, stalled.Remediation);
        hold.Set();
        await writer;
        Assert.False(Directory.Exists(dir.File("out")));
    }

    /// <summary>Binds a call as the filter does: the deadline token ends the wait, the client token (none) ends the export.</summary>
    private static void BeginDeadlineCall() => OutputCall.Begin(new OutputCall("export_project", 0, null));

    /// <summary>A writer holds the workspace until the returned event is set, so an export cannot take its snapshot.</summary>
    private static ManualResetEventSlim HoldWorkspace(Env env, out Task writer)
    {
        var release = new ManualResetEventSlim();
        using var held = new ManualResetEventSlim();
        writer = Task.Factory.StartNew(() => env.Workspace.Write(() => { held.Set(); release.Wait(); return 0; }), TaskCreationOptions.LongRunning);
        held.Wait();
        return release;
    }

    private static async Task<string> NextNotice(Env env)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(60))
        {
            if (env.Workspace.DrainNotices().FirstOrDefault() is { } notice) return notice;
            await Task.Delay(20);
        }
        throw new TimeoutException("No notice was queued.");
    }
}
