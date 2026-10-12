using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>Command-line setup: install, uninstall, status, config, update, version, help.</summary>
internal static class SetupCli
{
    private static readonly string[] Commands = ["install", "uninstall", "status", "doctor", "config", "update", "version", "--version", "-v", "help", "--help", "-h", "/?"];

    /// <summary>Flags each command accepts; anything else is a usage error, so a mistyped --dry-run never writes.</summary>
    private static readonly Dictionary<string, string[]> Accepted = new()
    {
        ["install"] = ["--no-check", "--check", "--dry-run", "--json", "--yes", "-y", "--all-detected", "--strict", "--client", "--refresh-only", "--command", "--dev-reload", "--skill", "--enable"],
        ["uninstall"] = ["--keep-files", "--purge-data", "--dry-run", "--json", "--client"],
        ["status"] = ["--json", "--client", "--engine", "--target", "--deep"],
        ["config"] = ["--client", "--dev-reload"],
        ["update"] = ["--version", "--dry-run"],
    };

    public static bool IsCommand(string arg) => Commands.Contains(arg, StringComparer.OrdinalIgnoreCase);

    /// <summary>The command words (no flag spellings).</summary>
    public static IEnumerable<string> Words => Commands.Where(c => char.IsLetter(c[0]));

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
            output.WriteLine($"{ex.Message} Run: corvus help");
            return 2;
        }
        // A copy started from the install layout used before the rename moves itself first.
        if (command is "install" or "update" && !parsed.Has("--dry-run") && LegacyInstall.Relocate(args, output, env) is { } moved) return moved;
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
        Corvus: .NET and native decompiler MCP server. Without a command it serves MCP over stdio.

        Commands:
          install [client...]   Register the server with MCP clients, then start it once to check it works.
                                Existing registrations are refreshed. Detected clients without one are listed in a
                                plan and added after one confirmation (Enter = yes); without a terminal they are
                                added only with --yes (or CORVUS_YES=1) or --all-detected.
                                --client X      only these clients (repeatable or comma-separated), detected or not
                                --dry-run       print the plan and write nothing (--check also runs the server check)
                                --json          print the plan and result as JSON (needs --yes to add new clients)
                                --strict        write nothing when any client's file cannot be read
                                --no-check      skip the server check
                                --command PATH  register this program instead of the running one
                                --dev-reload DIR  local development: register the relay, which runs the server
                                                published in DIR (./publish.ps1) and switches to each new publish
                                --skill         also write the agent skill for clients that read skills; skills
                                                written earlier are kept current by every install and update
                                --enable        turn on an entry the client has turned off (its switch, disable
                                                lists, Claude Code's per-project list); otherwise it is kept off
          uninstall [client...] Remove the registration from every client (or the named ones). With no names it
                                also deletes an installed copy's program files; --keep-files keeps them. Your data
                                (annotations, caches, symbols) is kept; --purge-data deletes it as well.
                                Skill folders written by install --skill are removed.
                                --dry-run and --json as for install.
          status | doctor       Read-only check. Starts each client's registered command with that entry's own args
                                and env, checks this build's server and tool catalog (digest), the engines, and
                                installed skills (aligned with this build, or stale).
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

        Tools from the terminal (each call runs the server in this process; docs/cli.md):
          <tool> [name=value ...]  Call a tool, e.g. corvus decompile_member --load app.dll member=Ns.T::M
          call <tool> ...       The same. Values: name=value (typed by the parameter), name:=<json>, name=@file,
                                name=@- (stdin); or --args '<json object>' (also --json '{...}'), --args-file F|-.
                                --load PATH preloads (repeatable); any server option applies (see the README).
                                --json          print {tool, isError, text, structured, error}
                                --structured    print only the structured content
          tools [filter]        List the tools by toolset (--json for a table).
          describe <name>       A tool's or prompt's description, parameters and an example (help <name> too).
          batch <file|->        Run steps ({"tool": ..., "args": {...}} as a JSON array or JSON Lines) in one session,
                                so ids and in-memory edits carry over. --stop-on-error, --json (one line per step).
          prompts               List the prompts; prompt <name> [name=value ...] prints one, ready to pipe.
          resources             List resources and templates; read <uri> prints one.
          completion <shell>    A completion script for bash, zsh or pwsh.
        Tool exit codes: 0 success, 1 tool error, 2 usage or invalid_argument, 3 engine missing or unsupported,
        124 timeout, 130 cancelled (Ctrl+C).
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
        var (relayed, error) = RelayLaunch(env, launch, target, dryRun);
        if (error != null) output.WriteLine($"--dev-reload: {error}");
        return relayed;
    }

    /// <summary>The relay for <paramref name="target"/>, run from a staged copy of <paramref name="launch"/>'s program; else why not.</summary>
    private static (ServerLaunch? Launch, string? Error) RelayLaunch(SetupEnvironment env, ServerLaunch launch, string target, bool dryRun)
    {
        var state = env.Variable("CORVUS_RELAY_DIR") is { Length: > 0 } dir ? dir : Installation.DataRoot(env) is { } root ? Path.Combine(root, "relay") : null;
        if (state == null) return (null, "no per-user data folder; set CORVUS_RELAY_DIR.");
        bool dotnet = launch.Args.Count > 0 && Corvus.Relay.RelayBuilds.IsProgramDll(launch.Args[0]);
        var program = dotnet ? launch.Args[0] : launch.Command;
        string staged;
        try { staged = Corvus.Relay.RelayBuilds.StageHost(program, state, dryRun); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (null, $"cannot copy {program} to {state}: {ex.Message}"); }
        string[] relay = [Corvus.Relay.RelayCli.Command, "--target", target];
        return (dotnet ? new ServerLaunch(launch.Command, [staged, .. relay]) : new ServerLaunch(staged, relay), null);
    }

    /// <summary>
    /// Migration only: moves each entry under the name used before the rename to ours, run by this program with the
    /// entry's arguments and env (a relay entry stays a relay, staged from this program, for the same publish folder).
    /// Returns the clients' rows; they are done and left out of the plan.
    /// </summary>
    private static List<ClientReport> RenameLegacy(TextWriter text, SetupEnvironment env, IEnumerable<McpClient> clients, ServerLaunch launch, bool dryRun)
    {
        var rows = new List<ClientReport>();
        foreach (var client in clients)
        foreach (var (project, target) in ClientCatalog.LegacyTargets(client))
        {
            if (target.Current(ClientCatalog.LegacyServerName) is not { } old) continue;
            var row = new ClientReport
            {
                Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = target.Path, Registered = old,
                Action = SetupAction.Rename, Client = client, Message = project == null ? "" : $"project {project}: ",
            };
            rows.Add(row);
            var entryLaunch = launch;
            if (Corvus.Relay.RelayCli.TargetOf(old.Args) is { } relayTarget)
            {
                var (relayed, error) = RelayLaunch(env, launch, relayTarget, dryRun);
                if (relayed != null) entryLaunch = relayed;
                else row.Message += $"relay not kept ({error}); ";
            }
            if (dryRun) row.Message += $"would rename from {ClientCatalog.LegacyServerName}";
            else
            {
                ConfigChange result;
                try { result = target.Rename(ClientCatalog.LegacyServerName, ClientCatalog.ServerName, ClientCatalog.LaunchFor(client, entryLaunch)); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { result = new ConfigChange(false, $"left unchanged: {ex.Message}"); }
                row.Message += result.Message;
                if (!result.Changed) row.Action = SetupAction.Blocked;
            }
            var mark = dryRun ? SetupAction.Rename : row.Action == SetupAction.Blocked ? " !! " : " ok ";
            text.WriteLine($"  {mark,-10} {row.Name,-20} {SetupPlan.Short(env, row.ConfigPath)}  {row.Message}");
        }
        return rows;
    }

    private static LaunchReport Describe(ServerLaunch launch) => new(launch.Command, launch.Args);

    private static int Install(TextWriter output, SetupEnvironment env, ServerLaunch launch, SetupArgs a)
    {
        bool json = a.Has("--json"), dryRun = a.Has("--dry-run"), refreshOnly = a.Has("--refresh-only");
        bool yes = a.Has("--yes") || a.Has("-y") || env.Variable("CORVUS_YES") is "1" or "true";
        bool check = dryRun ? a.Has("--check") : !a.Has("--no-check");
        // The install scripts plan with a staged copy, for the program they are about to put in place.
        if (a.Value("--command") is { } command) launch = new ServerLaunch(Path.GetFullPath(command), []);
        // Old entries are re-staged from the program itself: their relays keep their own target folders.
        var program = launch;
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

        text.WriteLine($"Corvus {Installation.Version}: {string.Join(" ", [launch.Command, .. launch.Args])}");
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
        // Entries under the old name are renamed after the plan; one without ours becomes ours, so it is not planned.
        var legacy = candidates.Where(c => ClientCatalog.LegacyTargets(c).Any()).ToList();
        report.Clients.AddRange(SetupPlan.Build([.. candidates.Where(c => c.Target.Current(ClientCatalog.LegacyServerName) == null || c.Target.Current(ClientCatalog.ServerName) != null)],
            launch, named, refreshOnly));
        var rows = SetupPlan.Shown(report.Clients).ToList();
        if (rows.Count == 0 && legacy.Count == 0)
        {
            text.WriteLine("No supported MCP client found. Install one, then run: corvus install");
            text.WriteLine("For any other client, add the output of: corvus config");
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
                var renames = RenameLegacy(text, env, legacy, program, dryRun: true);
                report.Clients.AddRange(renames);
                Skills(text, env, report, [.. rows, .. renames], a.Has("--skill"), dryRun: true);
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
                report.Notes.Add($"Not registered with detected clients {string.Join(", ", pending.Select(p => p.Id))}; to add them run: corvus install --all-detected");
            }
        }

        int failed = 0, changed = 0;
        foreach (var row in rows)
        {
            if (row.Action is SetupAction.Add or SetupAction.Refresh)
            {
                ConfigChange result;
                try { result = row.Client!.Target.Install(ClientCatalog.ServerName, ClientCatalog.LaunchFor(row.Client, launch)); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { result = new ConfigChange(false, $"left unchanged: {ex.Message}"); }
                if (result.Changed) changed++;
                else if (result.Message != "already registered") { failed++; row.Action = SetupAction.Blocked; }
                row.Message = result.Message;
            }
            else if (row.Action == SetupAction.Blocked) failed++;
            if (row.Action is SetupAction.Add or SetupAction.Refresh or SetupAction.Unchanged && row.Client is { } client
                && client.Target.DisabledInProjects(ClientCatalog.ServerName) is var projects && (row.Disabled || projects.Count > 0))
            {
                if (!a.Has("--enable"))
                    row.Message += row.Disabled ? "; disabled: kept disabled (--enable turns it on)" : $"; off in projects {string.Join(", ", projects)} (--enable turns it on)";
                else
                {
                    ConfigChange enabled;
                    try { enabled = client.Target.Enable(ClientCatalog.ServerName); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { enabled = new ConfigChange(false, $"left unchanged: {ex.Message}"); }
                    if (enabled.Changed) changed++;
                    else failed++;
                    row.Message += "; " + (enabled.Changed ? "enabled" : $"not enabled: {enabled.Message}");
                }
            }
            var mark = row.Action == SetupAction.Blocked ? "!! " : row.Action == SetupAction.Skip ? "-- " : "ok ";
            text.WriteLine($"  {mark} {row.Name,-20} {row.Message,-20} {SetupPlan.Short(env, row.ConfigPath)}");
        }
        var renamed = RenameLegacy(text, env, legacy, program, dryRun: false);
        report.Clients.AddRange(renamed);
        failed += renamed.Count(r => r.Action == SetupAction.Blocked);
        changed += renamed.Count(r => r.Action == SetupAction.Rename);
        Skills(text, env, report, [.. rows, .. renamed], a.Has("--skill"), dryRun: false);
        foreach (var note in report.Notes) text.WriteLine(note);
        if (changed > 0) text.WriteLine("Restart the clients above (or reload their MCP servers) to load it.");
        // An installed copy takes over from an install made before the rename, whose registrations were renamed above.
        if (Installation.Root() is { } installed && LegacyInstall.Remove(env, installed) is { } old) text.WriteLine($"Removed the old program files from {old}.");
        report.Applied = changed > 0;
        report.Healthy = failed == 0;
        return Finish(failed == 0 ? 0 : 1);
    }

    /// <summary>
    /// Skill folders of the registered clients: folders this program wrote are kept current; --skill also writes new ones.
    /// A folder of the same name that we did not write is never touched.
    /// </summary>
    private static void Skills(TextWriter text, SetupEnvironment env, SetupReport report, IEnumerable<ClientReport> rows, bool add, bool dryRun)
    {
        var clients = rows.Where(r => r.Action is SetupAction.Add or SetupAction.Refresh or SetupAction.Unchanged or SetupAction.Rename).Select(r => r.Id).ToList();
        var folders = Skill.FoldersOf(env, clients);
        if (add && folders.Count == 0)
            report.Notes.Add($"--skill: none of these clients reads skills ({string.Join(", ", Skill.Targets(env).Select(t => t.Client).Distinct())} do).");
        foreach (var (folder, served) in folders)
        {
            var state = Skill.StateOf(folder);
            if (!add && state != Skill.Stale) continue;
            string message;
            if (dryRun) message = state switch { Skill.Aligned => "already current", Skill.Stale => "would update", Skill.Foreign => $"left unchanged: no {Skill.Marker}", _ => "would write" };
            else
            {
                try
                {
                    var result = Skill.Write(folder);
                    message = result.Message;
                    report.Applied |= result.Changed;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { message = $"left unchanged: {ex.Message}"; }
            }
            report.Skills.Add(new SkillReport(folder, served, state, message));
            text.WriteLine($"  skill      {string.Join(", ", served),-20} {SetupPlan.Short(env, folder)}  {message}");
        }

        // Migration only: a skill written before the rename is written under the current name and the old folder removed.
        foreach (var (legacy, current) in Skill.LegacyFolders(env))
        {
            string message;
            if (dryRun) message = $"would replace {SetupPlan.Short(env, legacy)}";
            else
            {
                try
                {
                    var written = Skill.Write(current);
                    if (Skill.StateOf(current) == Skill.Aligned) Skill.Remove(legacy);
                    message = Skill.StateOf(current) == Skill.Aligned ? $"replaces {SetupPlan.Short(env, legacy)}" : written.Message;
                    report.Applied = true;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { message = $"left unchanged: {ex.Message}"; }
            }
            report.Skills.Add(new SkillReport(current, [], Skill.Stale, message));
            text.WriteLine($"  skill      {"",-20} {SetupPlan.Short(env, current)}  {message}");
        }
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
        // Entries under the name used before the rename go too.
        string[] names = [ClientCatalog.ServerName, ClientCatalog.LegacyServerName];
        foreach (var client in named.Count > 0 ? named : all)
        {
            foreach (var name in names)
            {
                if (client.Target.Current(name) is not { } current) continue;
                var row = new ClientReport
                {
                    Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = client.Target.Path, Registered = current,
                    Action = SetupAction.Remove, Client = client,
                };
                report.Clients.Add(row);
                var label = name == ClientCatalog.ServerName ? client.Name : $"{client.Name} ({name})";
                if (dryRun)
                {
                    text.WriteLine($"  remove    {label,-20} {SetupPlan.Short(env, client.Target.Path)}");
                    continue;
                }
                var result = client.Target.Uninstall(name);
                row.Message = result.Message;
                report.Applied |= result.Changed;
                text.WriteLine($"  {label,-20} {result.Message,-20} {SetupPlan.Short(env, client.Target.Path)}");
            }
        }

        // A shared skill folder stays while a client not named here still has the server registered.
        List<string> stillRegistered = named.Count == 0 ? []
            : [.. all.Where(c => !named.Contains(c) && names.Any(n => c.Target.Current(n) != null)).Select(c => c.Id)];
        foreach (var (folder, served) in Skill.FoldersOf(env, (named.Count > 0 ? named : all).Select(c => c.Id))
                     .SelectMany(f => new[] { f, (Skill.LegacyOf(f.Folder), f.Clients) }))
        {
            var state = Skill.StateOf(folder);
            if (state is Skill.Missing or Skill.Foreign) continue;
            var sharedWith = Skill.FoldersOf(env, stillRegistered).Where(f => f.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase)).SelectMany(f => f.Clients).ToList();
            string message;
            if (sharedWith.Count > 0) message = $"kept: also read by {string.Join(", ", sharedWith)}";
            else if (dryRun) message = "would remove";
            else
            {
                try
                {
                    var result = Skill.Remove(folder);
                    message = result.Message;
                    report.Applied |= result.Changed;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { message = $"left unchanged: {ex.Message}"; }
            }
            report.Skills.Add(new SkillReport(folder, served, state, message));
            text.WriteLine($"  skill      {SetupPlan.Short(env, folder)}  {message}");
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
        text.WriteLine($"Corvus {Installation.Version}");
        text.WriteLine($"Server command: {string.Join(" ", [launch.Command, .. launch.Args])}");
        var kind = report.InstallKind;
        text.WriteLine($"Installed as: {kind}{(Installation.UpdateCommand(kind) is { } update ? $" (update: {update})" : "")}");

        var tests = new Dictionary<string, ServerReport>();
        if (audit || named.Count > 0)
        {
            foreach (var client in named.Count > 0 ? named : all)
            {
                // An entry under the name used before the rename is checked as the registration until install renames it.
                var legacy = client.Target.Current(ClientCatalog.ServerName) == null ? client.Target.Current(ClientCatalog.LegacyServerName) : null;
                var current = client.Target.Current(ClientCatalog.ServerName) ?? legacy;
                if (named.Count == 0 && !client.Present && current == null && !File.Exists(client.Target.Path)) continue;
                var row = new ClientReport
                {
                    Id = client.Id, Name = client.Name, Detected = client.Present, ConfigPath = client.Target.Path, Registered = current,
                    Action = null, Client = client,
                };
                Doctor.Check(row, env, launch, tests);
                if (legacy != null) Doctor.MarkLegacy(row);
                if (named.Count == 0 && row.State == Doctor.NotRegistered && !client.Present) continue;
                report.Clients.Add(row);
                text.WriteLine($"  {client.Name,-20} {row.Message}");
                if (Doctor.Fails(row.State) || (named.Count > 0 && row.State == Doctor.NotRegistered)) failed = true;
            }
        }

        if (audit || named.Count > 0)
        {
            var readers = named.Count > 0 ? named : all.Where(c => c.Present || c.Target.Current(ClientCatalog.ServerName) != null);
            foreach (var (folder, served) in Skill.FoldersOf(env, readers.Select(c => c.Id)))
            {
                var state = Skill.StateOf(folder);
                report.Skills.Add(new SkillReport(folder, served, state, null));
                if (state == Skill.Missing) continue;
                var note = state switch
                {
                    Skill.Stale => " - written by another build; run: corvus install --skill",
                    Skill.Foreign => $" - not written by Corvus (no {Skill.Marker})",
                    _ => "",
                };
                text.WriteLine($"Skill {SetupPlan.Short(env, folder)}: {state}{note}");
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
                node[ClientCatalog.ServerName] = json.Entry(ClientCatalog.LaunchFor(client, launch));
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
