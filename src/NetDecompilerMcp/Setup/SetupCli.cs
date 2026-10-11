using System.Text.Json;
using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Setup;

/// <summary>Command-line setup: install, uninstall, status, config, update, version, help.</summary>
internal static class SetupCli
{
    private static readonly string[] Commands = ["install", "uninstall", "status", "doctor", "config", "update", "version", "--version", "-v", "help", "--help", "-h", "/?"];

    /// <summary>Flags each command accepts; anything else is a usage error, so a mistyped --dry-run never writes.</summary>
    private static readonly Dictionary<string, string[]> Accepted = new()
    {
        ["install"] = ["--no-check", "--check", "--dry-run", "--json", "--yes", "-y", "--all-detected", "--strict", "--client", "--refresh-only", "--command", "--dev-reload"],
        ["uninstall"] = ["--keep-files", "--purge-data", "--dry-run", "--json", "--client"],
        ["status"] = ["--json", "--client", "--engine", "--target", "--deep"],
        ["config"] = ["--client", "--dev-reload"],
        ["update"] = ["--version", "--dry-run"],
    };

    /// <summary>Runs a setup command and returns its exit code, or null when the arguments start the server.</summary>
    public static int? TryRun(string[] args, TextWriter? output = null, SetupEnvironment? env = null, ServerLaunch? launch = null)
    {
        if (args.Length == 0 || !Commands.Contains(args[0], StringComparer.OrdinalIgnoreCase)) return null;
        output ??= Console.Out;
        env ??= SetupEnvironment.Current();
        launch ??= Installation.Launch();
        var command = args[0].ToLowerInvariant() is "doctor" ? "status" : args[0].ToLowerInvariant();
        SetupArgs parsed;
        try { parsed = SetupArgs.Parse(args.Skip(1), Accepted.GetValueOrDefault(command, [])); }
        catch (ArgumentException ex)
        {
            output.WriteLine($"{ex.Message} Run: NetDecompilerMcp help");
            return 2;
        }
        switch (command)
        {
            case "install": return Install(output, env, launch, parsed);
            case "uninstall": return Uninstall(output, env, parsed);
            case "status": return Status(output, env, launch, parsed);
            case "config":
                if (DevReload(output, env, launch, parsed, dryRun: false) is not { } configured) return 2;
                return Config(output, env, configured, parsed.Clients);
            case "update" when parsed.Clients.Count > 0:
                output.WriteLine("update takes no client names; it refreshes every existing registration.");
                return 2;
            case "update": return Installation.Update(output, parsed.Value("--version"), parsed.Has("--dry-run"));
            case "version" or "--version" or "-v": output.WriteLine(Installation.Version); return 0;
            default: output.WriteLine(HelpText(env)); return 0;
        }
    }

    private const string Help = """
        NetDecompilerMcp: .NET decompiler MCP server. Without a command it serves MCP over stdio.

        Commands:
          install [client...]   Register the server with MCP clients, then start it once to check it works.
                                Existing registrations are refreshed. Detected clients without one are listed in a
                                plan and added after one confirmation (Enter = yes); without a terminal they are
                                added only with --yes (or NDM_YES=1) or --all-detected.
                                --client X      only these clients (repeatable or comma-separated), detected or not
                                --dry-run       print the plan and write nothing (--check also runs the server check)
                                --json          print the plan and result as JSON (needs --yes to add new clients)
                                --strict        write nothing when any client's file cannot be read
                                --no-check      skip the server check
                                --command PATH  register this program instead of the running one
                                --dev-reload DIR  local development: register the relay, which runs the server
                                                published in DIR (./publish.ps1) and switches to each new publish
          uninstall [client...] Remove the registration from every client (or the named ones). With no names it
                                also deletes an installed copy's program files; --keep-files keeps them. Your data
                                (annotations, caches, symbols) is kept; --purge-data deletes it as well.
                                --dry-run and --json as for install.
          status | doctor       Read-only check. Starts each client's registered command with that entry's own args
                                and env, checks this build's server and tool catalog (digest), and the engines.
                                --client X      only these clients (fails only for them)
                                --engine E      only ida, python, ghidra or all (--deep also starts IDA's worker)
                                --target PATH   what the file is and which engines read it
                                --json          the report as JSON
          config [client]       Print the configuration to add by hand (for clients not listed).
                                --dev-reload DIR  the relay's configuration (see install)
          update                Install the latest release (installed copies only) and refresh existing registrations;
                                it never adds clients.
                                --version X     install release X instead, also an older one (rollback)
                                --dry-run       show the release, asset and checksum manifest it would use
          version               Print the version.

        Exit codes: 0 success (a dry run always), 1 a check or a registration failed, 2 usage error.
        """;

    /// <summary>The help text with the client ids of this system's catalog.</summary>
    private static string HelpText(SetupEnvironment env)
    {
        var lines = new List<string>();
        var line = "Clients: ";
        foreach (var id in ClientCatalog.All(env).Select(c => c.Id))
        {
            if (line.Length + id.Length > 110) { lines.Add(line.TrimEnd()); line = "         "; }
            line += id + ", ";
        }
        lines.Add(line.TrimEnd(' ', ','));
        return Help + Environment.NewLine + Environment.NewLine + string.Join(Environment.NewLine, lines);
    }

    /// <summary>The named clients, or null after reporting an unknown name.</summary>
    private static List<McpClient>? Named(TextWriter output, IReadOnlyList<McpClient> all, IEnumerable<string> names)
    {
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

    /// <summary>
    /// With --dev-reload DIR: the relay, started from a staged copy of <paramref name="launch"/>'s program (a publish then never
    /// replaces the running relay), watching DIR. Without it: <paramref name="launch"/>. Null after reporting a usage error.
    /// </summary>
    private static ServerLaunch? DevReload(TextWriter output, SetupEnvironment env, ServerLaunch launch, SetupArgs a, bool dryRun)
    {
        if (a.Value("--dev-reload") is not { } target) return launch;
        target = Path.GetFullPath(target);
        if (!Directory.Exists(target))
        {
            output.WriteLine($"--dev-reload: {target} does not exist; publish first (./publish.ps1).");
            return null;
        }
        var state = env.Variable("NDM_RELAY_DIR") is { Length: > 0 } dir ? dir : Installation.DataRoot(env) is { } root ? Path.Combine(root, "relay") : null;
        if (state == null)
        {
            output.WriteLine("--dev-reload: no per-user data folder; set NDM_RELAY_DIR.");
            return null;
        }
        bool dotnet = launch.Args.Count > 0 && Path.GetFileName(launch.Args[0]).Equals("NetDecompilerMcp.dll", StringComparison.OrdinalIgnoreCase);
        var program = dotnet ? launch.Args[0] : launch.Command;
        string staged;
        try { staged = NetDecompilerMcp.Relay.RelayBuilds.StageHost(program, state, dryRun); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            output.WriteLine($"--dev-reload: cannot copy {program} to {state}: {ex.Message}");
            return null;
        }
        string[] relay = [NetDecompilerMcp.Relay.RelayCli.Command, "--target", target];
        return dotnet ? new ServerLaunch(launch.Command, [staged, .. relay]) : new ServerLaunch(staged, relay);
    }

    private static LaunchReport Describe(ServerLaunch launch) => new(launch.Command, launch.Args);

    private static int Install(TextWriter output, SetupEnvironment env, ServerLaunch launch, SetupArgs a)
    {
        bool json = a.Has("--json"), dryRun = a.Has("--dry-run"), refreshOnly = a.Has("--refresh-only");
        bool yes = a.Has("--yes") || a.Has("-y") || env.Variable("NDM_YES") is "1" or "true";
        bool check = dryRun ? a.Has("--check") : !a.Has("--no-check");
        // The install scripts plan with a staged copy, for the program they are about to put in place.
        if (a.Value("--command") is { } command) launch = new ServerLaunch(Path.GetFullPath(command), []);
        if (DevReload(output, env, launch, a, dryRun) is not { } relayed) return 2;
        launch = relayed;
        var text = json ? TextWriter.Null : output;
        var all = ClientCatalog.All(env);
        if (Named(output, all, a.Clients) is not { } named) return 2;
        var report = new SetupReport { Command = refreshOnly ? "update" : "install", Launch = Describe(launch), DryRun = dryRun };
        int Finish(int code)
        {
            if (json) output.WriteLine(report.ToJson());
            return code;
        }

        text.WriteLine($"NetDecompilerMcp {Installation.Version}: {string.Join(" ", [launch.Command, .. launch.Args])}");
        if (check)
        {
            report.Server = ServerReport.From(SelfTest.Run(launch, TimeSpan.FromSeconds(60)));
            text.WriteLine(report.Server.Ok ? $"Server check: OK ({report.Server.Detail})" : $"Server check FAILED: {report.Server.Detail}");
            if (!report.Server.Ok)
            {
                report.Healthy = false;
                return Finish(1);
            }
        }

        // Named clients replace detection: only they are touched.
        var candidates = named.Count > 0 ? named : all;
        report.Clients.AddRange(SetupPlan.Build(candidates, launch, named, refreshOnly));
        var rows = SetupPlan.Shown(report.Clients).ToList();
        if (rows.Count == 0)
        {
            text.WriteLine("No supported MCP client found. Install one, then run: NetDecompilerMcp install");
            text.WriteLine("For any other client, add the output of: NetDecompilerMcp config");
            return Finish(0);
        }
        var pending = rows.Where(r => r.NeedsConsent).ToList();
        if (pending.Count > 0 && (yes || a.Has("--all-detected"))) SetupPlan.Decide(pending, add: true);
        bool blocked = rows.Any(r => r.Action == SetupAction.Blocked);

        if (dryRun || (a.Has("--strict") && blocked))
        {
            SetupPlan.Write(text, env, rows);
            if (dryRun)
            {
                if (pending.Any(r => r.NeedsConsent)) text.WriteLine("New clients are added after confirmation, or with --yes / --all-detected.");
                text.WriteLine("Dry run: nothing was written.");
                return Finish(0);
            }
            text.WriteLine("Nothing was written (--strict): fix or remove the blocked files, or run without --strict.");
            report.Healthy = false;
            return Finish(1);
        }

        if (pending.Any(r => r.NeedsConsent))
        {
            if (env.Interactive && !json)
            {
                SetupPlan.Write(text, env, rows);
                SetupPlan.Decide(pending, env.Confirm($"Register with {(pending.Count == 1 ? "this new client" : $"these {pending.Count} new clients")}?"));
            }
            else
            {
                SetupPlan.Decide(pending, add: false);
                report.Notes.Add($"Not registered with detected clients {string.Join(", ", pending.Select(p => p.Id))}; to add them run: NetDecompilerMcp install --all-detected");
            }
        }

        int failed = 0, changed = 0;
        foreach (var row in rows)
        {
            if (row.Action is SetupAction.Add or SetupAction.Refresh)
            {
                ConfigChange result;
                try { result = row.Client!.Target.Install(ClientCatalog.ServerName, launch); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { result = new ConfigChange(false, $"left unchanged: {ex.Message}"); }
                if (result.Changed) changed++;
                else if (result.Message != "already registered") { failed++; row.Action = SetupAction.Blocked; }
                row.Message = result.Message;
                if (row.Disabled) row.Message += "; disabled: kept disabled";
            }
            else if (row.Action == SetupAction.Blocked) failed++;
            var mark = row.Action == SetupAction.Blocked ? "!! " : row.Action == SetupAction.Skip ? "-- " : "ok ";
            text.WriteLine($"  {mark} {row.Name,-20} {row.Message,-20} {SetupPlan.Short(env, row.ConfigPath)}");
        }
        foreach (var note in report.Notes) text.WriteLine(note);
        if (changed > 0) text.WriteLine("Restart the clients above (or reload their MCP servers) to load it.");
        report.Applied = changed > 0;
        report.Healthy = failed == 0;
        return Finish(failed == 0 ? 0 : 1);
    }

    private static int Uninstall(TextWriter output, SetupEnvironment env, SetupArgs a)
    {
        bool json = a.Has("--json"), dryRun = a.Has("--dry-run"), purgeData = a.Has("--purge-data");
        bool keepFiles = a.Has("--keep-files") || a.Clients.Count > 0;
        if (purgeData && keepFiles)
        {
            output.WriteLine("--purge-data deletes the program files too; it cannot be combined with --keep-files or client names.");
            return 2;
        }
        var all = ClientCatalog.All(env);
        if (Named(output, all, a.Clients) is not { } named) return 2;
        var text = json ? TextWriter.Null : output;
        var report = new SetupReport { Command = "uninstall", Launch = Describe(Installation.Launch()), DryRun = dryRun };
        foreach (var client in named.Count > 0 ? named : all)
        {
            if (client.Target.Current(ClientCatalog.ServerName) is not { } current) continue;
            var row = new ClientReport
            {
                Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = client.Target.Path, Registered = current,
                Action = SetupAction.Remove, Client = client,
            };
            report.Clients.Add(row);
            if (dryRun)
            {
                text.WriteLine($"  remove    {client.Name,-20} {SetupPlan.Short(env, client.Target.Path)}");
                continue;
            }
            var result = client.Target.Uninstall(ClientCatalog.ServerName);
            row.Message = result.Message;
            report.Applied |= result.Changed;
            text.WriteLine($"  {client.Name,-20} {result.Message,-20} {SetupPlan.Short(env, client.Target.Path)}");
        }

        var dataRoot = Installation.DataRoot(env);
        Installation.Removal? removal = null;
        if (!keepFiles && Installation.Root() is { } root) removal = Installation.PlanRemoval(root, dataRoot ?? root, purgeData);
        else if (purgeData && dataRoot != null) removal = new Installation.Removal([(dataRoot, false)], null, dataRoot, []);
        if (removal != null) report.Removal = new RemovalReport([.. removal.Delete.Select(d => d.Path)], removal.DataRoot, removal.Kept);
        if (dryRun)
        {
            foreach (var path in report.Removal?.Delete ?? []) text.WriteLine($"  delete    {path}");
            if (report.Removal is { Kept.Count: > 0 } kept) text.WriteLine($"  keep      {kept.DataRoot} ({string.Join(", ", kept.Kept)})");
            text.WriteLine("Dry run: nothing was changed.");
        }
        else if (!keepFiles && Installation.Root() is { } installed) Installation.RemoveFiles(installed, dataRoot ?? installed, purgeData, text);
        else if (purgeData && dataRoot != null) Installation.PurgeData(dataRoot, text);
        if (json) output.WriteLine(report.ToJson());
        return 0;
    }

    /// <summary>
    /// Read-only. Without a scope: detected clients, this build's server and the engines; it fails only for a broken
    /// registration or server. With --client, --engine or --target only those are checked and only they can fail.
    /// </summary>
    private static int Status(TextWriter output, SetupEnvironment env, ServerLaunch launch, SetupArgs a)
    {
        bool json = a.Has("--json"), deep = a.Has("--deep");
        var all = ClientCatalog.All(env);
        if (Named(output, all, a.Clients) is not { } named) return 2;
        var engines = a.Values("--engine").SelectMany(v => v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(e => e.ToLowerInvariant()).Distinct().ToList();
        if (engines.FirstOrDefault(e => e != "all" && !Doctor.Engines.Contains(e)) is { } unknown)
        {
            output.WriteLine($"Unknown engine '{unknown}'. Known: {string.Join(", ", Doctor.Engines)}, all");
            return 2;
        }
        if (engines.Contains("all")) engines = [.. Doctor.Engines];
        var target = a.Value("--target");
        bool audit = named.Count == 0 && engines.Count == 0 && target == null;
        var text = json ? TextWriter.Null : output;
        var report = new SetupReport { Command = "status", Launch = Describe(launch) };
        bool failed = false;
        text.WriteLine($"NetDecompilerMcp {Installation.Version}");
        text.WriteLine($"Server command: {string.Join(" ", [launch.Command, .. launch.Args])}");

        var tests = new Dictionary<string, ServerReport>();
        if (audit || named.Count > 0)
        {
            foreach (var client in named.Count > 0 ? named : all)
            {
                var current = client.Target.Current(ClientCatalog.ServerName);
                if (named.Count == 0 && !client.Present && current == null && !File.Exists(client.Target.Path)) continue;
                var row = new ClientReport
                {
                    Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = client.Target.Path, Registered = current,
                    Action = null, Client = client,
                };
                Doctor.Check(row, env, launch, tests);
                if (named.Count == 0 && row.State == Doctor.NotRegistered && !client.Present) continue;
                report.Clients.Add(row);
                text.WriteLine($"  {client.Name,-20} {row.Message}");
                if (Doctor.Fails(row.State) || (named.Count > 0 && row.State == Doctor.NotRegistered)) failed = true;
            }
        }

        if (audit)
        {
            var server = report.Server = Doctor.Test(launch, new Dictionary<string, string>(), tests);
            text.WriteLine(server.Ok ? $"Server check: OK ({server.Detail})" : $"Server check FAILED: {server.Detail}");
            if (server.Ok) text.WriteLine(server.CatalogLine());
            failed |= !server.Ok || server.MatchesThisBuild != true;
        }

        foreach (var name in audit ? Doctor.Engines : [.. engines])
        {
            var check = Doctor.Engine(env, name, deep);
            report.Engines.Add(check);
            text.WriteLine($"Engine {name}: {(check.Ok ? "available" : "not available")} ({check.Detail}){(check.Remediation is { } fix ? " - " + fix : "")}");
            if (!audit && !check.Ok) failed = true;
        }

        if (target != null)
        {
            var check = report.Target = Doctor.Target(env, target);
            text.WriteLine($"Target {check.Name}: {check.Detail}{(check.Remediation is { } fix ? " - " + fix : "")}");
            failed |= !check.Ok;
        }

        report.Healthy = !failed;
        if (json) output.WriteLine(report.ToJson());
        return failed ? 1 : 0;
    }

    private static int Config(TextWriter output, SetupEnvironment env, ServerLaunch launch, IReadOnlyList<string> names)
    {
        var options = new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        if (names.Count == 0)
        {
            var args = new JsonArray([.. launch.Args.Select(a => (JsonNode)JsonValue.Create(a)!)]);
            var json = new JsonObject { ["mcpServers"] = new JsonObject { [ClientCatalog.ServerName] = new JsonObject { ["command"] = launch.Command, ["args"] = args } } };
            output.WriteLine(json.ToJsonString(options));
            return 0;
        }
        if (Named(output, ClientCatalog.All(env), names) is not { } clients) return 2;
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

/// <summary>Parsed setup arguments: flags, option values (--name value or --name=value) and positional client names.</summary>
internal sealed class SetupArgs
{
    private static readonly string[] ValueOptions = ["--client", "--engine", "--target", "--version", "--command", "--dev-reload"];
    private readonly HashSet<string> _flags = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Positional names and --client values (comma-separated lists split).</summary>
    public List<string> Clients { get; } = [];

    public bool Has(string flag) => _flags.Contains(flag);
    public IReadOnlyList<string> Values(string option) => _values.TryGetValue(option, out var v) ? v : [];
    public string? Value(string option) => Values(option) is { Count: > 0 } v ? v[^1] : null;

    public static SetupArgs Parse(IEnumerable<string> args, IReadOnlyCollection<string> accepted)
    {
        var parsed = new SetupArgs();
        var list = args.ToList();
        for (int i = 0; i < list.Count; i++)
        {
            var arg = list[i];
            if (!arg.StartsWith('-'))
            {
                parsed.Clients.Add(arg);
                continue;
            }
            var (name, inline) = arg.IndexOf('=') is > 0 and var eq ? (arg[..eq], arg[(eq + 1)..]) : (arg, null);
            if (!accepted.Contains(name, StringComparer.OrdinalIgnoreCase)) throw new ArgumentException($"Unknown option {name}.");
            if (!ValueOptions.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                if (inline != null) throw new ArgumentException($"{name} takes no value.");
                parsed._flags.Add(name);
                continue;
            }
            var value = inline ?? (i + 1 < list.Count ? list[++i] : throw new ArgumentException($"{name} needs a value."));
            if (!parsed._values.TryGetValue(name, out var values)) parsed._values[name] = values = [];
            values.Add(value);
            if (name.Equals("--client", StringComparison.OrdinalIgnoreCase))
                parsed.Clients.AddRange(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }
        return parsed;
    }
}
