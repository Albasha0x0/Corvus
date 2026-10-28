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
}
