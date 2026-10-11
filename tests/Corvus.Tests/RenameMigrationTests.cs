using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Services;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>What was saved or registered under the names used before the rename is carried over: data, registrations, installs, files.</summary>
public sealed class RenameMigrationTests : IDisposable
{
    private readonly SetupHome _home = new();
    public void Dispose() => _home.Dispose();

    private static JsonNode ReadJson(string path) => JsonNode.Parse(File.ReadAllText(path))!;
    private static readonly string OldExe = OperatingSystem.IsWindows() ? @"C:\Users\u\AppData\Local\NetDecompilerMcp\current\NetDecompilerMcp.exe" : "/home/u/.local/share/net-decompiler-mcp/current/NetDecompilerMcp";

    [Fact]
    public void Data_moves_entry_by_entry_and_the_program_files_stay()
    {
        var from = _home.Path("Local", "NetDecompilerMcp");
        var to = _home.Path("Local", "Corvus");
        foreach (var dir in new[] { "annotations", "analysis", "code-index", "relay", "versions", "current", ".new-1234" }) Directory.CreateDirectory(Path.Combine(from, dir));
        File.WriteAllText(Path.Combine(from, "annotations", "a.json"), "{}");
        File.WriteAllText(Path.Combine(from, "settings.txt"), "x");
        Directory.CreateDirectory(Path.Combine(to, "analysis"));
        File.WriteAllText(Path.Combine(to, "analysis", "ours"), "kept");

        var done = DataFolder.Migrate(from, to)!;
        Assert.Equal(["annotations", "code-index", "relay", "settings.txt"], done.Moved);
        Assert.Empty(done.Copied);
        Assert.Equal("{}", File.ReadAllText(Path.Combine(to, "annotations", "a.json")));
        Assert.Equal("kept", File.ReadAllText(Path.Combine(to, "analysis", "ours")));
        // An entry the new folder already has stays where it was, and so do the program files of an old install.
        Assert.True(Directory.Exists(Path.Combine(from, "analysis")));
        Assert.True(Directory.Exists(Path.Combine(from, "versions")) && Directory.Exists(Path.Combine(from, "current")) && Directory.Exists(Path.Combine(from, ".new-1234")));
        Assert.False(Directory.Exists(Path.Combine(to, "versions")));
        Assert.StartsWith($"Moved data from {from} to {to}: annotations, code-index, relay, settings.txt.", DataFolder.Describe(done));

        Assert.Null(DataFolder.Migrate(from, to));
        foreach (var dir in new[] { "analysis", "versions", "current", ".new-1234" }) Directory.Delete(Path.Combine(from, dir), recursive: true);
        Assert.Null(DataFolder.Migrate(from, to));
        Assert.False(Directory.Exists(from));
        Assert.Null(DataFolder.Migrate(from, to));
    }

    [Fact]
    public void Data_in_use_is_copied_and_the_original_kept()
    {
        if (!OperatingSystem.IsWindows()) return; // elsewhere a folder holding an open file moves
        var from = _home.Path("Local", "NetDecompilerMcp");
        var to = _home.Path("Local", "Corvus");
        Directory.CreateDirectory(Path.Combine(from, "notes"));
        File.WriteAllText(Path.Combine(from, "notes", "n.json"), "note");
        Directory.CreateDirectory(Path.Combine(from, "symbols"));
        DataFolder.Migration done;
        using (new FileStream(Path.Combine(from, "notes", "n.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
            done = DataFolder.Migrate(from, to)!;
        Assert.Equal(["symbols"], done.Moved);
        Assert.Equal(["notes"], done.Copied);
        Assert.Equal("note", File.ReadAllText(Path.Combine(to, "notes", "n.json")));
        Assert.Equal("note", File.ReadAllText(Path.Combine(from, "notes", "n.json")));
        Assert.Contains("notes copied; the originals were in use", DataFolder.Describe(done));
    }

    [Fact]
    public void The_default_migration_leaves_a_chosen_data_folder_alone()
    {
        // The tests choose their own folder (CORVUS_DATA_DIR), so the user's folders are never looked at.
        Assert.NotNull(Environment.GetEnvironmentVariable(DataFolder.RootVariable));
        var log = new StringWriter();
        Assert.Null(DataFolder.MigrateDefault(log));
        Assert.Equal("", log.ToString());
        Assert.Equal(Path.GetFullPath(Environment.GetEnvironmentVariable(DataFolder.RootVariable)!), DataFolder.Root);
    }

    [Fact]
    public void Install_renames_old_entries_keeping_args_env_and_keys()
    {
        _home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": {{JsonSerializer.Serialize(OldExe)}}, "args": ["--load", "x"], "env": { "NDM_IDA_DIR": "C:/ida", "NETDECOMP_LOAD": "a.dll", "KEEP": "1" }, "timeout": 30 }, "other": { "command": "y" } } }""", ".cursor", "mcp.json");
        _home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": "dotnet", "args": ["C:/src/NetDecompilerMcp.dll", "--load", "z"] } } }""", ".kiro", "settings", "mcp.json");
        _home.Write($$"""{ "mcp": { "net-decompiler": { "type": "local", "command": [{{JsonSerializer.Serialize(OldExe)}}, "--load", "x"], "environment": { "NDM_ENGINE": "ida" }, "enabled": true } } }""", ".config", "opencode", "opencode.json");
        _home.Write($$"""
            model = "o4"

            [mcp_servers.net-decompiler]
            command = '{{OldExe}}'
            args = ["--load", "x"]
            startup_timeout_sec = 30

            [mcp_servers.net-decompiler.env]
            NDM_IDA_DIR = "C:/ida"
            "NDM_ENGINE" = "ida"
            """.Replace("\r\n", "\n"), ".codex", "config.toml");

        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Contains("renamed from net-decompiler", output);

        var cursor = ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!;
        Assert.Null(cursor["net-decompiler"]);
        Assert.Equal("y", cursor["other"]!["command"]!.GetValue<string>());
        var entry = cursor["corvus"]!;
        Assert.Equal(SetupHome.Launch.Command, entry["command"]!.GetValue<string>());
        Assert.Equal(["--load", "x"], entry["args"]!.AsArray().Select(a => a!.GetValue<string>()));
        Assert.Equal(30, entry["timeout"]!.GetValue<int>());
        Assert.Equal(["CORVUS_IDA_DIR", "CORVUS_LOAD", "KEEP"], entry["env"]!.AsObject().Select(p => p.Key));
        Assert.Equal("C:/ida", entry["env"]!["CORVUS_IDA_DIR"]!.GetValue<string>());

        // The dotnet launch's old main assembly is not carried over.
        var kiro = ReadJson(_home.Path(".kiro", "settings", "mcp.json"))["mcpServers"]!["corvus"]!;
        Assert.Equal(["--load", "z"], kiro["args"]!.AsArray().Select(a => a!.GetValue<string>()));

        var opencode = ReadJson(_home.Path(".config", "opencode", "opencode.json"))["mcp"]!;
        Assert.Null(opencode["net-decompiler"]);
        Assert.Equal([SetupHome.Launch.Command, "--load", "x"], opencode["corvus"]!["command"]!.AsArray().Select(a => a!.GetValue<string>()));
        Assert.Equal("ida", opencode["corvus"]!["environment"]!["CORVUS_ENGINE"]!.GetValue<string>());

        var toml = File.ReadAllText(_home.Path(".codex", "config.toml"));
        Assert.DoesNotContain("net-decompiler", toml);
        Assert.DoesNotContain("NDM_", toml);
        Assert.Contains($"[mcp_servers.corvus]\ncommand = {JsonSerializer.Serialize(SetupHome.Launch.Command)}\nargs = [\"--load\", \"x\"]\nstartup_timeout_sec = 30\n", toml);
        Assert.Contains("[mcp_servers.corvus.env]\nCORVUS_IDA_DIR = \"C:/ida\"\n\"CORVUS_ENGINE\" = \"ida\"\n", toml);
        Assert.StartsWith("model = \"o4\"\n", toml);

        // Nothing is left to rename.
        (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.DoesNotContain("renamed", output);
    }

    [Fact]
    public void An_old_entry_beside_ours_is_removed_and_ours_refreshed()
    {
        _home.Write("""{ "mcpServers": { "corvus": { "command": "old", "args": ["--load", "mine"] }, "net-decompiler": { "command": "older" } } }""", ".cursor", "mcp.json");
        _home.Write("[mcp_servers.corvus]\ncommand = \"old\"\n\n[mcp_servers.net-decompiler]\ncommand = \"older\"\n", ".codex", "config.toml");
        var (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.Contains("removed the net-decompiler entry (corvus is registered)", output);
        var servers = ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!.AsObject();
        Assert.Equal(["corvus"], servers.Select(p => p.Key));
        Assert.Equal(SetupHome.Launch.Command, servers["corvus"]!["command"]!.GetValue<string>());
        Assert.Equal(["--load", "mine"], servers["corvus"]!["args"]!.AsArray().Select(a => a!.GetValue<string>()));
        var toml = File.ReadAllText(_home.Path(".codex", "config.toml"));
        Assert.DoesNotContain("net-decompiler", toml);
        Assert.Contains(JsonSerializer.Serialize(SetupHome.Launch.Command), toml);
    }

    [Fact]
    public void An_old_relay_entry_stays_a_relay_for_the_same_publish_folder()
    {
        var program = _home.Path("src", "bin", "corvus.exe");
        _home.Write("apphost", "src", "bin", "corvus.exe");
        _home.Write("server", "src", "bin", "corvus.dll");
        var publish = _home.Path("publish");
        Directory.CreateDirectory(publish);
        var oldHost = _home.Path("AppData", "Local", "NetDecompilerMcp", "relay", "host", "1.1.0-abc", "NetDecompilerMcp.exe");
        _home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": {{JsonSerializer.Serialize(oldHost)}}, "args": ["relay", "--target", {{JsonSerializer.Serialize(publish)}}, "--load", "y"] } } }""", ".cursor", "mcp.json");

        var output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check"], output, _home.Env(), new ServerLaunch(program, [])));
        var entry = ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!;
        var staged = entry["command"]!.GetValue<string>();
        Assert.StartsWith(_home.Path("AppData", "Local", "Corvus", "relay", "host"), staged);
        Assert.Equal("apphost", File.ReadAllText(staged));
        Assert.Equal(["relay", "--target", publish, "--load", "y"], entry["args"]!.AsArray().Select(a => a!.GetValue<string>()));
    }

    [Fact]
    public void An_old_relay_entry_is_kept_by_an_install_with_dev_reload_too()
    {
        var program = _home.Path("publish", "corvus.exe");
        _home.Write("apphost", "publish", "corvus.exe");
        _home.Write("server", "publish", "corvus.dll");
        var publish = _home.Path("publish");
        var other = _home.Path("other");
        Directory.CreateDirectory(other);
        var oldHost = _home.Path("AppData", "Local", "NetDecompilerMcp", "relay", "host", "1.1.0-abc", "NetDecompilerMcp.exe");
        _home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": {{JsonSerializer.Serialize(oldHost)}}, "args": ["relay", "--target", {{JsonSerializer.Serialize(other)}}] } } }""", ".cursor", "mcp.json");

        var output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--dev-reload", publish, "--dry-run"], output, _home.Env(), new ServerLaunch(program, [])));
        Assert.DoesNotContain("relay not kept", output.ToString());
        Assert.Contains("would rename from net-decompiler", output.ToString());

        output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--dev-reload", publish], output, _home.Env(), new ServerLaunch(program, [])));
        Assert.DoesNotContain("relay not kept", output.ToString());
        var entry = ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!["corvus"]!;
        Assert.StartsWith(_home.Path("AppData", "Local", "Corvus", "relay", "host"), entry["command"]!.GetValue<string>());
        Assert.Equal(["relay", "--target", other], entry["args"]!.AsArray().Select(a => a!.GetValue<string>()));
    }

    [Fact]
    public void Claude_Code_project_entries_are_renamed_too()
    {
        var program = _home.Path("src", "bin", "corvus.exe");
        _home.Write("apphost", "src", "bin", "corvus.exe");
        _home.Write("server", "src", "bin", "corvus.dll");
        var publish = _home.Path("publish");
        Directory.CreateDirectory(publish);
        var oldHost = _home.Path("AppData", "Local", "NetDecompilerMcp", "relay", "host", "1.1.0-abc", "NetDecompilerMcp.exe");
        _home.Write($$"""
            { "mcpServers": { "net-decompiler": { "command": {{JsonSerializer.Serialize(OldExe)}} } },
              "projects": {
                "D:/work/a": { "allowedTools": [], "mcpServers": { "net-decompiler": { "type": "stdio", "command": {{JsonSerializer.Serialize(oldHost)}}, "args": ["relay", "--target", {{JsonSerializer.Serialize(publish)}}, "--load", "a.dll"], "env": { "NDM_GHIDRA_DIR": "g" } } } },
                "D:/work/b": { "mcpServers": { "other": { "command": "x" } } } } }
            """, ".claude.json");

        var output = new StringWriter();
        Assert.Equal(0, SetupCli.TryRun(["install", "--no-check", "--dry-run"], output, _home.Env(), new ServerLaunch(program, [])));
        Assert.Contains("project D:/work/a: would rename from net-decompiler", output.ToString());

        output = new StringWriter();
        Assert.True(SetupCli.TryRun(["install", "--no-check"], output, _home.Env(), new ServerLaunch(program, [])) == 0, output.ToString());
        var root = ReadJson(_home.Path(".claude.json"));
        Assert.Null(root["mcpServers"]!["net-decompiler"]);
        Assert.NotNull(root["mcpServers"]!["corvus"]);
        var a = root["projects"]!["D:/work/a"]!;
        Assert.Null(a["mcpServers"]!["net-decompiler"]);
        var entry = a["mcpServers"]!["corvus"]!;
        Assert.StartsWith(_home.Path("AppData", "Local", "Corvus", "relay", "host"), entry["command"]!.GetValue<string>());
        Assert.Equal(["relay", "--target", publish, "--load", "a.dll"], entry["args"]!.AsArray().Select(x => x!.GetValue<string>()));
        Assert.Equal("g", entry["env"]!["CORVUS_GHIDRA_DIR"]!.GetValue<string>());
        Assert.NotNull(a["allowedTools"]);
        Assert.Equal(["other"], root["projects"]!["D:/work/b"]!["mcpServers"]!.AsObject().Select(p => p.Key));
    }

    [Theory]
    [InlineData(true, new string[0])]
    [InlineData(true, new[] { "install" })]
    [InlineData(true, new[] { "--load", "a.dll" })]
    [InlineData(false, new[] { "version" })]
    [InlineData(false, new[] { "status" })]
    [InlineData(false, new[] { "install", "--dry-run" })]
    public void Only_commands_that_write_move_the_data_folder(bool migrates, string[] args) =>
        Assert.Equal(migrates, DataFolder.MigratesOnStart(args));

    [Fact]
    public void A_dry_run_lists_the_renames_and_writes_nothing()
    {
        _home.Write("""{ "mcpServers": { "net-decompiler": { "command": "old" } } }""", ".cursor", "mcp.json");
        var before = _home.Snapshot();
        var (code, output) = _home.Run("install", "--no-check", "--dry-run");
        Assert.True(code == 0, output);
        Assert.Contains("would rename from net-decompiler", output);
        Assert.Equal(before, _home.Snapshot());

        (code, output) = _home.Run("install", "--dry-run", "--json");
        Assert.Equal(0, code);
        var cursor = JsonNode.Parse(output)!["clients"]!.AsArray().Single(c => c!["id"]!.GetValue<string>() == "cursor")!;
        Assert.Equal("rename", cursor["action"]!.GetValue<string>());
        Assert.Equal(before, _home.Snapshot());
    }

    [Fact]
    public void Status_reports_an_old_entry_and_uninstall_removes_both_names()
    {
        var gone = OperatingSystem.IsWindows() ? @"C:\gone\NetDecompilerMcp.exe" : "/gone/NetDecompilerMcp";
        _home.Write($$"""{ "mcpServers": { "net-decompiler": { "command": {{JsonSerializer.Serialize(gone)}} } } }""", ".lmstudio", "mcp.json");
        var (code, output) = _home.Run("status", "--client", "lm-studio");
        Assert.Equal(1, code);
        Assert.Contains("registered with a missing program", output);
        Assert.Contains("registered as net-decompiler, the name before the rename; corvus install renames it", output);
        var row = new ClientReport { Id = "x", Name = "X", ConfigPath = "x", State = Doctor.Healthy, Message = "registered (ok)" };
        Doctor.MarkLegacy(row);
        Assert.Equal(Doctor.LegacyName, row.State);
        Assert.False(Doctor.Fails(row.State));
        Assert.Equal("corvus install", row.Remediation);

        _home.Write("""{ "mcpServers": { "corvus": { "command": "a" }, "net-decompiler": { "command": "b" }, "other": { "command": "c" } } }""", ".cursor", "mcp.json");
        (code, output) = _home.Run("uninstall", "--keep-files");
        Assert.True(code == 0, output);
        Assert.Equal(["other"], ReadJson(_home.Path(".cursor", "mcp.json"))["mcpServers"]!.AsObject().Select(p => p.Key));
        Assert.DoesNotContain("net-decompiler", File.ReadAllText(_home.Path(".lmstudio", "mcp.json")));
    }

    [Fact]
    public void A_skill_written_before_the_rename_is_replaced_and_a_foreign_folder_kept()
    {
        _home.Write("{}", ".claude", "skills", "net-decompiler", ".netdecompiler-skill");
        _home.Write("old", ".claude", "skills", "net-decompiler", "SKILL.md");
        _home.Write("theirs", ".agents", "skills", "net-decompiler", "SKILL.md");
        var (code, output) = _home.Run("install", "--no-check", "--dry-run");
        Assert.True(code == 0, output);
        Assert.Contains("would replace", output);
        Assert.True(File.Exists(_home.Path(".claude", "skills", "net-decompiler", "SKILL.md")));

        (code, output) = _home.Run("install", "--no-check");
        Assert.True(code == 0, output);
        Assert.False(Directory.Exists(_home.Path(".claude", "skills", "net-decompiler")));
        Assert.Equal(Skill.Aligned, Skill.StateOf(_home.Path(".claude", "skills", "corvus")));
        Assert.Equal("theirs", File.ReadAllText(_home.Path(".agents", "skills", "net-decompiler", "SKILL.md")));
        Assert.False(Directory.Exists(_home.Path(".agents", "skills", "corvus")));
    }

    [Fact]
    public void The_old_install_layout_is_recognized_and_its_program_moved_and_removed()
    {
        var windows = _home.Env(os: HostOs.Windows);
        var linux = _home.Env(os: HostOs.Linux);
        Assert.True(LegacyInstall.IsRoot(windows, _home.Path("AppData", "Local", "NetDecompilerMcp")));
        Assert.True(LegacyInstall.IsRoot(linux, _home.Path(".local", "share", "net-decompiler-mcp")));
        Assert.True(LegacyInstall.IsRoot(_home.Env(os: HostOs.Linux, variables: new Dictionary<string, string> { ["XDG_DATA_HOME"] = _home.Path("xdg") }), _home.Path("xdg", "net-decompiler-mcp")));
        Assert.Equal(_home.Path("AppData", "Local", "Corvus"), Installation.DefaultRoot(windows));
        Assert.Equal(_home.Path(".local", "share", "Corvus"), Installation.DefaultRoot(linux));
        Assert.Equal(_home.Path("mine"), Installation.DefaultRoot(_home.Env(variables: new Dictionary<string, string> { ["CORVUS_HOME"] = _home.Path("mine") })));
        // The test process does not run from an install.
        Assert.Null(LegacyInstall.Relocate(["install"], new StringWriter(), windows));

        // The build is copied without the program's old name, once.
        var build = _home.Path("old", "versions", "1.2.0");
        _home.Write("new", "old", "versions", "1.2.0", Installation.ExeName);
        _home.Write("bridge", "old", "versions", "1.2.0", LegacyInstall.ExeName);
        _home.Write("dll", "old", "versions", "1.2.0", "clr32", "x.dll");
        var target = LegacyInstall.CopyBuild(build, _home.Path("new", "versions"), "1.2.0");
        Assert.Equal(_home.Path("new", "versions", "1.2.0"), target);
        Assert.Equal("new", File.ReadAllText(Path.Combine(target, Installation.ExeName)));
        Assert.Equal("dll", File.ReadAllText(Path.Combine(target, "clr32", "x.dll")));
        Assert.False(File.Exists(Path.Combine(target, LegacyInstall.ExeName)));
        File.WriteAllText(Path.Combine(target, Installation.ExeName), "kept");
        Assert.Equal(target, LegacyInstall.CopyBuild(build, _home.Path("new", "versions"), "1.2.0"));
        Assert.Equal("kept", File.ReadAllText(Path.Combine(target, Installation.ExeName)));

        // Removal takes the program files; data left in the folder keeps it, and an empty one goes.
        var root = _home.Path("old");
        _home.Write("x", "old", "versions", "1.1.0", "a.dll");
        Installation.PointCurrent(root, build);
        _home.Write("{}", "old", "annotations", "a.json");
        LegacyInstall.RemoveVersions(root);
        Assert.False(Directory.Exists(Path.Combine(root, "versions")));
        Assert.False(Directory.Exists(Path.Combine(root, "current")) || File.Exists(Path.Combine(root, "current")));
        Assert.True(File.Exists(Path.Combine(root, "annotations", "a.json")));
        Directory.Delete(Path.Combine(root, "annotations"), recursive: true);
        Directory.CreateDirectory(Path.Combine(root, "versions"));
        LegacyInstall.RemoveVersions(root);
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void An_update_refuses_a_release_from_before_the_rename()
    {
        Assert.Equal(new Version(1, 2, 0), Installation.FirstRelease);
        Assert.Equal("Albasha0x0/Corvus", Installation.DefaultRepository);
    }

    [Fact]
    public void The_release_also_ships_each_archive_under_the_name_an_old_update_looks_for()
    {
        var workflow = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), ".github", "workflows", "release.yml")).ReplaceLineEndings("\n");
        // What 1.1.0's update fetches: NetDecompilerMcp-<rid>.zip / .tar.gz, from which it runs NetDecompilerMcp(.exe) install.
        Assert.Contains("Compress-Archive -Path out/* -DestinationPath corvus-${{ matrix.rid }}.zip", workflow);
        Assert.Contains("Copy-Item out/corvus.exe out/NetDecompilerMcp.exe\n          Compress-Archive -Path out/* -DestinationPath NetDecompilerMcp-${{ matrix.rid }}.zip", workflow);
        Assert.Contains("cp -p out/corvus out/NetDecompilerMcp\n          tar -czf NetDecompilerMcp-${{ matrix.rid }}.tar.gz -C out .", workflow);
        Assert.Contains("sha256sum corvus-* NetDecompilerMcp-* > SHA256SUMS", workflow);
        Assert.Contains("            corvus-*\n            NetDecompilerMcp-*\n            SHA256SUMS", workflow);
        var release = File.ReadAllText(Path.Combine(DocsTests.RepoRoot(), "release.ps1"));
        Assert.Contains("foreach ($name in 'corvus', 'NetDecompilerMcp')", release);
    }

    [Fact]
    public void Notes_saved_before_the_rename_are_read_and_rewritten_in_the_current_format()
    {
        using var dir = new TempDir();
        var notes = new NotesService(new AnnotationStore(dir.File("annotations")));
        var anchor = new NoteAnchor(NoteAnchor.Native, new string('a', 64), Rva: 0x1000);
        notes.Record("first", null, null, anchor, null, null, null);
        var file = Assert.Single(Directory.GetFiles(notes.Root, "*.json")); // Unix keeps the .lock file beside it
        File.WriteAllText(file, File.ReadAllText(file).Replace(NotesService.Format, "net-decompiler-notes/1"));

        var again = new NotesService(new AnnotationStore(dir.File("annotations")));
        Assert.Equal("first", Assert.Single(again.All()).Text);
        again.Record("second", null, null, anchor, null, null, null);
        Assert.Contains($"\"{NotesService.Format}\"", File.ReadAllText(file));
        Assert.Equal(["first", "second"], new NotesService(new AnnotationStore(dir.File("annotations"))).All().Select(n => n.Text).Order());
    }

    [Fact]
    public void Session_files_edit_scripts_and_patch_sets_from_before_the_rename_are_read()
    {
        using var dir = new TempDir();
        var session = dir.File("old.session.json");
        File.WriteAllText(session, SessionService.Serialize(new SessionService.Document("net-decompiler-session/1", DateTime.UtcNow, "1.1.0", [], [], [], [], null)));
        Assert.Equal("1.1.0", SessionService.Read(session).ServerVersion);
        File.WriteAllText(session, SessionService.Serialize(new SessionService.Document("other/1", DateTime.UtcNow, "1.1.0", [], [], [], [], null)));
        Assert.Throws<Corvus.Core.ToolError>(() => SessionService.Read(session));

        var script = dir.File("old.edits.json");
        File.WriteAllText(script, """{ "format": "net-decompiler-edits/1", "assembly": "A", "created": "2026-01-01T00:00:00Z", "edits": [] }""");
        Assert.Equal("A", EditHistoryService.ReadScript(script).Assembly);

        var patch = """{ "kind": "netdecompilermcp.native_patches", "patches": [ { "rva": "1000", "original": "90", "replacement": "C3" } ] }""";
        Assert.Equal(0x1000u, Assert.Single(Corvus.Native.Patching.PatchMigration.FromJson(patch)).Rva);
        Assert.Single(Corvus.Native.Patching.PatchMigration.FromJson(patch.Replace("netdecompilermcp.native_patches", Corvus.Native.Patching.PatchExport.JsonKind)));
    }

    [Fact]
    public void A_name_layer_saved_before_the_rename_is_read()
    {
        var sha = new string('b', 64);
        var layer = new Corvus.Native.Code.NativeNameLayers.Layer(Corvus.Native.Code.NativeNameSource.Pdb, new Dictionary<uint, string> { [0x1000] = "Main" }, new Dictionary<uint, string>(), "test.pdb");
        using var saved = new MemoryStream();
        SavedNameLayer.Write(saved, sha, "x.dll", layer);
        // The same layer with the old magic: BinaryWriter strings are length-prefixed.
        var raw = Decompress(saved.ToArray());
        Assert.Equal("name-layer", Encoding.UTF8.GetString(raw, 1, raw[0]));
        byte[] legacy = [9, .. "ndm-names"u8, .. raw.AsSpan(1 + raw[0])];
        Assert.NotNull(SavedNameLayer.Read(new MemoryStream(Compress(legacy)), sha));
        Assert.NotNull(SavedNameLayer.Read(new MemoryStream(saved.ToArray()), sha));
        byte[] other = [9, .. "foo-names"u8, .. raw.AsSpan(1 + raw[0])];
        Assert.Null(SavedNameLayer.Read(new MemoryStream(Compress(other)), sha));

        static byte[] Decompress(byte[] data)
        {
            using var gz = new GZipStream(new MemoryStream(data), CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            return output.ToArray();
        }
        static byte[] Compress(byte[] data)
        {
            using var output = new MemoryStream();
            using (var gz = new GZipStream(output, CompressionMode.Compress)) gz.Write(data);
            return output.ToArray();
        }
    }

    [Fact]
    public void A_code_index_saved_before_the_rename_is_read()
    {
        if (!OperatingSystem.IsWindows()) return;
        var path = Path.Combine(Environment.SystemDirectory, "version.dll");
        if (!File.Exists(path)) return;
        using var dir = new TempDir();
        var cache = new Corvus.Native.Code.CodeIndexCache(new Corvus.Native.Code.CodeIndexCacheOptions(dir.File("cache"), 1L << 30, TimeSpan.FromDays(1), TimeSpan.Zero));
        var image = Corvus.Native.Pe.PeFile.Open(path);
        Assert.True(cache.Save(Corvus.Native.Code.NativeCodeIndex.Build(image), null));
        var file = Assert.Single(Directory.GetFiles(dir.File("cache")));
        var bytes = File.ReadAllBytes(file);
        Assert.Equal("CODEIDX1", Encoding.ASCII.GetString(bytes, 0, 8));
        "NDMCIDX1"u8.CopyTo(bytes);
        File.WriteAllBytes(file, bytes);
        Assert.NotNull(cache.TryLoad(Corvus.Native.Pe.PeFile.Open(path), null));
        "OTHERIDX"u8.CopyTo(bytes);
        File.WriteAllBytes(file, bytes);
        Assert.Null(cache.TryLoad(Corvus.Native.Pe.PeFile.Open(path), null));
    }

    [Fact]
    public void A_Ghidra_project_and_extensions_from_before_the_rename_are_taken_over()
    {
        using var dir = new TempDir();
        var project = dir.File("p-key");
        Directory.CreateDirectory(Path.Combine(project, "ndm.rep", "idata"));
        File.WriteAllText(Path.Combine(project, "ndm.rep", "project.prp"), "prp");
        File.WriteAllText(Path.Combine(project, "ndm.gpr"), "");
        Assert.True(GhidraSession.HasProject(project));
        GhidraSession.RenameLegacyProject(project);
        Assert.True(File.Exists(Path.Combine(project, GhidraSession.ProjectName + ".gpr")));
        Assert.Equal("prp", File.ReadAllText(Path.Combine(project, GhidraSession.ProjectName + ".rep", "project.prp")));
        Assert.False(File.Exists(Path.Combine(project, "ndm.gpr")) || Directory.Exists(Path.Combine(project, "ndm.rep")));
        Assert.True(GhidraSession.HasProject(project));

        // An open (locked) old project is left for a later start.
        var locked = dir.File("p-locked");
        Directory.CreateDirectory(Path.Combine(locked, "ndm.rep"));
        File.WriteAllText(Path.Combine(locked, "ndm.gpr"), "");
        File.WriteAllText(Path.Combine(locked, "ndm.lock"), "");
        GhidraSession.RenameLegacyProject(locked);
        Assert.True(File.Exists(Path.Combine(locked, "ndm.gpr")));

        // An extension installed before the rename and no longer configured is removed; one never ours is kept.
        var extensions = dir.File("Extensions");
        File.WriteAllText(Path.Combine(Directory.CreateDirectory(Path.Combine(extensions, "OldExt")).FullName, ".ndm-extension"), "hash");
        File.WriteAllText(Path.Combine(Directory.CreateDirectory(Path.Combine(extensions, "Theirs")).FullName, "x"), "x");
        GhidraExtensions.Install([], extensions);
        Assert.False(Directory.Exists(Path.Combine(extensions, "OldExt")));
        Assert.True(Directory.Exists(Path.Combine(extensions, "Theirs")));
    }
}
