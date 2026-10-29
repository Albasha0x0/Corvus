using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>Output paths are refused in the server's own folders, PATH, start files, repositories, SSH and agent configuration, after links and short names resolve.</summary>
public class OutputGuardTests(Xunit.Abstractions.ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    // Every place is a stand-in under the test folder; no real configuration
    // or start folder is touched.
    private OutputGuard.Host StandIns() => new(
        name => name switch
        {
            "PATH" => _dir.File("bin"),
            Native.Providers.DataFolder.RootVariable => _dir.File("data"),
            ConfigFile.Variable => _dir.File(Path.Combine("cfg", "corvus.json")),
            Relay.RelayBuilds.TargetVariable => _dir.File("relay"),
            _ => null,
        },
        folder => folder switch
        {
            Environment.SpecialFolder.UserProfile => _dir.File("home"),
            Environment.SpecialFolder.MyDocuments => _dir.File(Path.Combine("home", "Documents")),
            Environment.SpecialFolder.Startup => _dir.File("startup"),
            _ => "",
        },
        _dir.File("install"), _dir.File("program"));

    // A child process, as the probe is process-wide.
    [Fact]
    public void The_client_configurations_are_probed_once_across_calls()
    {
        if (ChildTest.Rerun(this, output)) return;
        int probes = 0;
        OutputGuard.ClientConfigs = () =>
        {
            Interlocked.Increment(ref probes);
            return [];
        };
        for (int i = 0; i < 20; i++) OutputGuard.Current();
        Assert.Equal(1, probes);
    }

    [Fact]
    public void A_path_search_lists_each_folder_once_and_keeps_path_order()
    {
        var listed = new List<string>();
        var folders = new Dictionary<string, string[]> { ["a"] = ["tool.CMD"], ["b"] = ["tool.exe", "other.exe"] };
        var search = new PathSearch(string.Join(Path.PathSeparator, "a", "\"missing\"", "b"), ".EXE;.CMD", d =>
        {
            listed.Add(d);
            return folders.TryGetValue(d, out var names) ? names : throw new DirectoryNotFoundException(d);
        });
        Assert.Equal(Path.Combine("a", "tool.CMD"), search.Find("tool"));
        // Linux file names are case-sensitive, so other.exe does not match .EXE there.
        Assert.Equal(OperatingSystem.IsLinux() ? null : Path.Combine("b", "other.EXE"), search.Find("other"));
        Assert.Null(search.Find("absent"));
        Assert.Equal(["a", "missing", "b"], listed);
    }

    private IReadOnlyList<OutputGuard.Place> Places(params string[] clients) =>
        OutputGuard.Final(OutputGuard.Defaults(StandIns(), [_dir.File("live")], clients));

    private string? Refusal(string relative, IReadOnlyList<OutputGuard.Place>? places = null)
    {
        try
        {
            SafeFile.Output(_dir.File(relative), places ?? Places());
            return null;
        }
        catch (ToolError e) when (OutputGuard.IsRefusal(e)) { return ((OutputGuard.Refused)e.Details!).Reason; }
    }

    [Theory]
    [InlineData("data/x.bin", "in the server's data folder")]
    [InlineData("data/exports/x.bin", null)]
    [InlineData("cfg/corvus.json", "the server's configuration file")]
    [InlineData("install/current/corvus.dll", "in the server's install folder")]
    [InlineData("bin/git.exe", "in a folder on PATH")]
    [InlineData("bin/sub/git.exe", null)]
    [InlineData("live/app.exe", "a program sessions may open (--live-allow)")]
    [InlineData("relay/Corvus.dll", "in the relay's publish folder")]
    [InlineData("home/.bashrc", "a shell start file")]
    [InlineData("home/.profile", "a shell start file")]
    [InlineData("home/.zshrc", "a shell start file")]
    [InlineData("home/.config/autostart/a.desktop", "in an autostart or shell start folder")]
    [InlineData("home/.gitconfig", "the git configuration file")]
    [InlineData("home/.ssh/authorized_keys", "in the SSH folder")]
    [InlineData("repo/.git/hooks/pre-commit", "in a repository's .git folder")]
    [InlineData("repo/.claude/settings.json", "in a .claude folder")]
    [InlineData("repo/.claude/commands/run.md", "in a .claude folder")]
    [InlineData("repo/AGENTS.md", "an agent instructions file")]
    [InlineData("repo/.cursor/rules/a.mdc", "an agent instructions file")]
    [InlineData("repo/.vscode/tasks.json", "an agent tasks file")]
    [InlineData("repo/.mcp.json", "an agent mcp file")]
    [InlineData("repo/out.dll", null)]
    public void Each_refused_place_is_named(string relative, string? reason) =>
        Assert.Equal(reason, Refusal(relative.Replace('/', Path.DirectorySeparatorChar)));

    [Fact]
    public void The_program_folder_refuses_code_and_host_configuration_but_takes_other_files()
    {
        Directory.CreateDirectory(_dir.File("program"));
        File.WriteAllText(_dir.File(Path.Combine("program", "corvus.runtimeconfig.json")), "{}");
        Assert.Equal("a program file in the server's folder", Refusal(Path.Combine("program", "corvus.runtimeconfig.json")));
        Assert.Equal("a program file in the server's folder", Refusal(Path.Combine("program", "version.dll")));
        Assert.Equal("a program file in the server's folder", Refusal(Path.Combine("program", "runtimes", "libx.so")));
        Assert.Null(Refusal(Path.Combine("program", "sample-patches.json")));
        Assert.Null(Refusal(Path.Combine("program", "samples", "saved.dll")));
    }

    [Fact]
    public void Startup_and_shell_profile_folders_are_refused_on_Windows()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Equal("in a Startup folder", Refusal(Path.Combine("startup", "run.lnk")));
        Assert.Equal("in a shell profile folder", Refusal(Path.Combine("home", "Documents", "PowerShell", "profile.ps1")));
        Assert.Equal("an agent instructions file", Refusal(Path.Combine("repo", "claude.md")));
    }

    [Fact]
    public void A_registered_client_configuration_is_refused()
    {
        var home = _dir.File("home");
        var os = OperatingSystem.IsWindows() ? HostOs.Windows : OperatingSystem.IsMacOS() ? HostOs.MacOs : HostOs.Linux;
        var clients = ClientCatalog.All(new SetupEnvironment
        {
            Os = os,
            Home = home,
            AppData = Path.Combine(home, "AppData", "Roaming"),
            LocalAppData = Path.Combine(home, "AppData", "Local"),
            XdgConfig = Path.Combine(home, ".config"),
            Variable = _ => null,
            FindTool = _ => null,
            DirectoryExists = _ => false,
        }).Select(c => c.Target.Path).ToArray();
        var places = Places(clients);
        Assert.NotEmpty(clients);
        Assert.All(clients, file => Assert.NotNull(OutputGuard.Refusal(InputFiles.FinalPathOfNew(file), places)));
        Assert.Equal("an MCP client's configuration file", Refusal(Path.Combine("home", ".claude.json"), places));
    }

    private static IReadOnlyList<OutputGuard.Place> StartupStandIn(string folder) =>
        OutputGuard.Final([new OutputGuard.Place(folder, OutputGuard.Reach.Tree, "in a Startup folder")]);

    [DirectoryLinkFact]
    public void A_new_file_under_a_junction_to_the_startup_folder_is_refused()
    {
        var startup = Directory.CreateDirectory(_dir.File("startup")).FullName;
        Links.CreateDirectoryLink(_dir.File("linked"), startup);
        Assert.Equal("in a Startup folder", Reason(() => SafeFile.Output(_dir.File(Path.Combine("linked", "run.cmd")), StartupStandIn(startup))));
        Assert.Empty(Directory.GetFileSystemEntries(startup));
    }

    [Fact]
    public void A_new_file_under_a_short_name_of_the_startup_folder_is_refused()
    {
        if (!OperatingSystem.IsWindows()) return;
        // The temporary folder's volume may create no 8.3 names; the profile's
        // volume usually does.
        using var profileTemp = new TempDir(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp",
            "corvus-test-" + Guid.NewGuid().ToString("N")));
        foreach (var root in new[] { _dir.Path, profileTemp.Path })
        {
            var startup = Directory.CreateDirectory(Path.Combine(root, "Startup Folder Stand In")).FullName;
            var buffer = new char[1024];
            uint n = GetShortPathName(startup, buffer, (uint)buffer.Length);
            var shortName = new string(buffer, 0, (int)n);
            if (n == 0 || shortName.Equals(startup, StringComparison.OrdinalIgnoreCase)) continue;
            Assert.Equal("in a Startup folder", Reason(() => SafeFile.Output(Path.Combine(shortName, "run.lnk"), StartupStandIn(startup))));
            return;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "GetShortPathNameW")]
    private static extern uint GetShortPathName(string longPath, [Out] char[] shortPath, uint size);

    [DirectoryLinkFact]
    public void A_link_at_the_final_target_is_refused()
    {
        Directory.CreateDirectory(_dir.File("target"));
        Links.CreateDirectoryLink(_dir.File("out"), _dir.File("target"));
        var error = Assert.Throws<ToolError>(() => SafeFile.Output(_dir.File("out"), Places()));
        Assert.Contains("link", error.Message);
    }

    [Fact]
    public void Each_file_under_an_output_root_is_checked()
    {
        var root = _dir.File("export");
        Assert.Equal("in a repository's .git folder", Reason(() => SafeFile.OutputUnderRoot(root, Path.Combine(".git", "config"), Places())));
        Assert.Equal("an agent instructions file", Reason(() => SafeFile.OutputUnderRoot(root, "CLAUDE.md", Places())));
        Assert.Equal(Path.Combine(root, "lib", "a.dll"), SafeFile.OutputUnderRoot(root, Path.Combine("lib", "a.dll"), Places()));
    }

    private static string Reason(Action action) => ((OutputGuard.Refused)Assert.Throws<ToolError>(action).Details!).Reason;

    [Fact]
    public void An_unpack_skips_refused_entries_and_names_them()
    {
        var source = _dir.File("app.zip");
        File.WriteAllBytes(source, ContainerFixtures.Zip(("lib/a.dll", [1]), (".git/config", [2]), ("CLAUDE.md", [3])));
        var root = _dir.File("unpacked");
        using var workspace = new AssemblyWorkspace(new ServerOptions());
        var result = new UnpackService(workspace).Unpack(source, root, load: false, AnalysisLimits.Default, default);
        Assert.True(File.Exists(Path.Combine(root, "lib", "a.dll")));
        Assert.False(Directory.Exists(Path.Combine(root, ".git")));
        Assert.False(File.Exists(Path.Combine(root, "CLAUDE.md")));
        Assert.Contains(result.Notes, n => n.StartsWith("Could not write CLAUDE.md", StringComparison.Ordinal) && n.Contains("an agent instructions file"));
    }

    [Fact]
    public void This_host_refuses_its_data_folder_outside_exports_and_its_start_files()
    {
        var places = OutputGuard.Current();
        var data = Native.Providers.DataFolder.Root;
        string? Of(string path) => OutputGuard.Refusal(InputFiles.FinalPathOfNew(Path.GetFullPath(path)), places);
        Assert.Equal("in the server's data folder", Of(Path.Combine(data, "annotations", "x.json")));
        Assert.Null(Of(Path.Combine(data, OutputGuard.ExportsFolder, "x.json")));
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Assert.Equal("in the SSH folder", Of(Path.Combine(home, ".ssh", "config")));
        Assert.Equal("the git configuration file", Of(Path.Combine(home, ".gitconfig")));
        if (OperatingSystem.IsWindows())
            Assert.Equal("in a Startup folder", Of(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "run.lnk")));
    }

    [Fact]
    public void An_output_parameter_in_a_refused_place_is_rejected_before_the_tool_runs()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var schema = System.Text.Json.JsonSerializer.SerializeToElement(Corvus.Mcp.Catalog.OfThisBuild().Tools.Single(t => (string)t["name"]! == "save_session")["inputSchema"]);
        var args = new Dictionary<string, System.Text.Json.JsonElement> { ["outputPath"] = System.Text.Json.JsonSerializer.SerializeToElement(Path.Combine(home, ".ssh", "session.json")) };
        var error = Assert.Throws<ToolError>(() => Corvus.Mcp.ArgumentCheck.Apply(schema, args, "save_session"));
        Assert.EndsWith("is in the SSH folder; outputs are not written there.", error.Message);
        Assert.False(File.Exists(Path.Combine(home, ".ssh", "session.json")));
    }
}
