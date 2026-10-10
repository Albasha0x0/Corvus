using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Setup;

/// <summary>Command-line setup: install, uninstall, status, config, update, version, help.</summary>
internal static class SetupCli
{
    private static readonly string[] Commands = ["install", "uninstall", "status", "doctor", "config", "update", "version", "--version", "-v", "help", "--help", "-h", "/?"];

    /// <summary>Runs a setup command and returns its exit code, or null when the arguments start the server.</summary>
    public static int? TryRun(string[] args, TextWriter? output = null, SetupEnvironment? env = null, ServerLaunch? launch = null)
    {
        if (args.Length == 0 || !Commands.Contains(args[0], StringComparer.OrdinalIgnoreCase)) return null;
        output ??= Console.Out;
        env ??= SetupEnvironment.Current();
        launch ??= Installation.Launch();
        var rest = args.Skip(1).ToArray();
        var flags = rest.Where(a => a.StartsWith('-')).Select(a => a.ToLowerInvariant()).ToHashSet();
        var names = rest.Where(a => !a.StartsWith('-')).ToArray();
        switch (args[0].ToLowerInvariant())
        {
            case "install": return Install(output, env, launch, names, check: !flags.Contains("--no-check"));
            case "uninstall": return Uninstall(output, env, names, keepFiles: flags.Contains("--keep-files") || names.Length > 0, purgeData: flags.Contains("--purge-data"));
            case "status" or "doctor": return Status(output, env, launch);
            case "config": return Config(output, env, launch, names);
            case "update": return Installation.Update(output);
            case "version" or "--version" or "-v": output.WriteLine(Installation.Version); return 0;
            default: output.WriteLine(Help); return 0;
        }
    }

    private const string Help = """
        NetDecompilerMcp: .NET decompiler MCP server. Without a command it serves MCP over stdio.

        Commands:
          install [client...]   Register the server with every installed MCP client (or only the named ones),
                                then start it once to check it works. --no-check skips the check.
          uninstall [client...] Remove the registration from every client (or the named ones). With no names it
                                also deletes an installed copy's program files; --keep-files keeps them. Your data
                                (annotations, caches, symbols) is kept; --purge-data deletes it as well.
          status | doctor       Show which clients have it registered, check the server starts and that its tool catalog (digest) matches this build.
          config [client]       Print the configuration to add by hand (for clients not listed).
          update                Install the latest release (installed copies only).
          version               Print the version.

        Clients: claude-code, claude-desktop, cursor, windsurf, vscode, vscode-insiders, vscodium, cline, roo-code,
                 kilo-code, visual-studio, codex, gemini-cli, qwen-code, copilot-cli, opencode, crush, zed, lm-studio,
                 amazon-q, kiro, antigravity
        """;

    private static IReadOnlyList<McpClient>? Select(TextWriter output, SetupEnvironment env, string[] names, bool presentOnly)
    {
        var all = ClientCatalog.All(env);
        if (names.Length == 0) return presentOnly ? all.Where(c => c.Present).ToList() : all;
        var chosen = new List<McpClient>();
        foreach (var name in names)
        {
            var match = all.FirstOrDefault(c => c.Matches(name));
            if (match == null)
            {
                output.WriteLine($"Unknown client '{name}'. Known: {string.Join(", ", all.Select(c => c.Id))}");
                return null;
            }
            if (!chosen.Contains(match)) chosen.Add(match);
        }
        return chosen;
    }

    private static string Short(SetupEnvironment env, string path) =>
        path.StartsWith(env.Home, StringComparison.OrdinalIgnoreCase) ? "~" + path[env.Home.Length..] : path;

    private static int Install(TextWriter output, SetupEnvironment env, ServerLaunch launch, string[] names, bool check)
    {
        var clients = Select(output, env, names, presentOnly: true);
        if (clients == null) return 2;
        output.WriteLine($"NetDecompilerMcp {Installation.Version}: {string.Join(" ", [launch.Command, .. launch.Args])}");
        if (check)
        {
            var test = SelfTest.Run(launch, TimeSpan.FromSeconds(60));
            output.WriteLine(test.Ok ? $"Server check: OK ({test.Detail})" : $"Server check FAILED: {test.Detail}");
            if (!test.Ok) return 1;
        }
        if (clients.Count == 0)
        {
            output.WriteLine("No supported MCP client found. Install one, then run: NetDecompilerMcp install");
            output.WriteLine("For any other client, add the output of: NetDecompilerMcp config");
            return 0;
        }
        int failed = 0, changed = 0;
        foreach (var client in clients)
        {
            ConfigChange result;
            try { result = client.Target.Install(ClientCatalog.ServerName, launch); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { result = new ConfigChange(false, $"left unchanged: {ex.Message}"); }
            bool ok = result.Changed || result.Message == "already registered";
            if (!ok) failed++;
            if (result.Changed) changed++;
            output.WriteLine($"  {(ok ? "ok " : "!! ")} {client.Name,-20} {result.Message,-20} {Short(env, client.Target.Path)}");
        }
        if (changed > 0) output.WriteLine("Restart the clients above (or reload their MCP servers) to load it.");
        return failed == 0 ? 0 : 1;
    }

    private static int Uninstall(TextWriter output, SetupEnvironment env, string[] names, bool keepFiles, bool purgeData)
    {
        if (purgeData && keepFiles)
        {
            output.WriteLine("--purge-data deletes the program files too; it cannot be combined with --keep-files or client names.");
            return 2;
        }
        var clients = Select(output, env, names, presentOnly: false);
        if (clients == null) return 2;
        foreach (var client in clients)
        {
            if (client.Target.Registered(ClientCatalog.ServerName) == null) continue;
            var result = client.Target.Uninstall(ClientCatalog.ServerName);
            output.WriteLine($"  {client.Name,-20} {result.Message,-20} {Short(env, client.Target.Path)}");
        }
        if (keepFiles) return 0;
        var dataRoot = Installation.DataRoot(env);
        if (Installation.Root() is { } root) Installation.RemoveFiles(root, dataRoot ?? root, purgeData, output);
        else if (purgeData && dataRoot != null) Installation.PurgeData(dataRoot, output);
        return 0;
    }

    private static int Status(TextWriter output, SetupEnvironment env, ServerLaunch launch)
    {
        output.WriteLine($"NetDecompilerMcp {Installation.Version}");
        output.WriteLine($"Server command: {string.Join(" ", [launch.Command, .. launch.Args])}");
        foreach (var client in ClientCatalog.All(env))
        {
            var registered = client.Target.Registered(ClientCatalog.ServerName);
            if (!client.Present && registered == null) continue;
            string state = registered switch
            {
                null => "not registered (run: NetDecompilerMcp install)",
                _ when registered.Equals(launch.Command, StringComparison.OrdinalIgnoreCase) => "registered",
                _ when registered.Length > 0 && !File.Exists(registered) => $"registered with a missing program: {registered} (run: NetDecompilerMcp install)",
                _ => $"registered with another copy: {registered}",
            };
            output.WriteLine($"  {client.Name,-20} {state}");
        }
        var test = SelfTest.Run(launch, TimeSpan.FromSeconds(60));
        output.WriteLine(test.Ok ? $"Server check: OK ({test.Detail})" : $"Server check FAILED: {test.Detail}");
        if (!test.Ok || test.ToolList == null) return 1;
        // The catalog digest server_status reports, of the registered server (from its tools/list and prompts/list) and of this build.
        var (tools, prompts) = NetDecompilerMcp.Mcp.Catalog.OfThisBuild();
        var expected = NetDecompilerMcp.Mcp.Catalog.Digest(tools, prompts);
        var installed = NetDecompilerMcp.Mcp.Catalog.Digest(test.ToolList, test.PromptList ?? []);
        if (expected == installed)
        {
            output.WriteLine($"Tool catalog: matches this build ({tools.Count} tools); digest {expected}");
            return 0;
        }
        var differences = new List<string>();
        void Compare(string kind, SortedDictionary<string, string> build, SortedDictionary<string, string> server)
        {
            var missing = build.Keys.Except(server.Keys).ToList();
            var extra = server.Keys.Except(build.Keys).ToList();
            var changed = build.Keys.Intersect(server.Keys).Where(k => build[k] != server[k]).ToList();
            if (missing.Count > 0) differences.Add($"missing {kind} {string.Join(", ", missing)}");
            if (extra.Count > 0) differences.Add($"extra {kind} {string.Join(", ", extra)}");
            if (changed.Count > 0) differences.Add($"changed {kind} {string.Join(", ", changed.Take(20))}{(changed.Count > 20 ? $" and {changed.Count - 20} more" : "")}");
        }
        Compare("tools", NetDecompilerMcp.Mcp.Catalog.ToolHashes(tools), NetDecompilerMcp.Mcp.Catalog.ToolHashes(test.ToolList));
        Compare("prompts", NetDecompilerMcp.Mcp.Catalog.PromptHashes(prompts), NetDecompilerMcp.Mcp.Catalog.PromptHashes(test.PromptList ?? []));
        output.WriteLine($"Tool catalog differs from this build (the registered server is another version; run: NetDecompilerMcp install): " +
                         $"digest {installed}, this build {expected}; {string.Join("; ", differences)}");
        return 1;
    }

    private static int Config(TextWriter output, SetupEnvironment env, ServerLaunch launch, string[] names)
    {
        var options = new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        if (names.Length == 0)
        {
            var args = new JsonArray([.. launch.Args.Select(a => (JsonNode)JsonValue.Create(a)!)]);
            var json = new JsonObject { ["mcpServers"] = new JsonObject { [ClientCatalog.ServerName] = new JsonObject { ["command"] = launch.Command, ["args"] = args } } };
            output.WriteLine(json.ToJsonString(options));
            return 0;
        }
        var clients = Select(output, env, names, presentOnly: false);
        if (clients == null) return 2;
        foreach (var client in clients)
        {
            output.WriteLine($"{client.Name}: {client.Target.Path}");
            if (client.Target is JsonTarget json)
            {
                var root = new JsonObject();
                var node = root;
                foreach (var key in json.Container) { var next = new JsonObject(); node[key] = next; node = next; }
                node[ClientCatalog.ServerName] = json.Entry(launch);
                output.WriteLine(root.ToJsonString(options));
            }
            else
            {
                output.WriteLine($"[mcp_servers.{ClientCatalog.ServerName}]");
                output.WriteLine($"command = {JsonSerializer.Serialize(launch.Command)}");
                output.WriteLine($"args = [{string.Join(", ", launch.Args.Select(a => JsonSerializer.Serialize(a)))}]");
            }
        }
        return 0;
    }
}
