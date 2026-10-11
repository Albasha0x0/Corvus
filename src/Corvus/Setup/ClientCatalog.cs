using System.Text.Json.Nodes;

namespace Corvus.Setup;

/// <summary>An MCP client, where it keeps its user-level server list, and whether it is installed.</summary>
internal sealed record McpClient(string Id, string Name, string[] Aliases, ConfigTarget Target, bool Present)
{
    public bool Matches(string query) =>
        Id.Equals(query, StringComparison.OrdinalIgnoreCase) || Name.Equals(query, StringComparison.OrdinalIgnoreCase)
        || Aliases.Any(a => a.Equals(query, StringComparison.OrdinalIgnoreCase));
}

/// <summary>User-level configuration locations and entry formats of supported MCP clients.</summary>
internal static class ClientCatalog
{
    public const string ServerName = "corvus";

    // Migration only: the registration name before the rename; install renames such entries, uninstall removes them.
    public const string LegacyServerName = "net-decompiler";

    /// <summary>A legacy entry's environment key under its current name: NDM_X became CORVUS_X, NETDECOMP_LOAD CORVUS_LOAD.</summary>
    public static string MigratedEnvKey(string key) =>
        key.StartsWith("NDM_", StringComparison.Ordinal) ? "CORVUS_" + key[4..] : key == "NETDECOMP_LOAD" ? "CORVUS_LOAD" : key;

    /// <summary>
    /// Migration only: the lists of <paramref name="client"/> holding an entry under the old name: its own, and for Claude
    /// Code each project's (local scope, edited in the file: the CLI keys a project by its working folder's spelling).
    /// </summary>
    public static IEnumerable<(string? Project, ConfigTarget Target)> LegacyTargets(McpClient client)
    {
        if (client.Target.Current(LegacyServerName) != null) yield return (null, client.Target);
        if (client.Id != "claude-code") yield break;
        JsonObject? projects;
        try
        {
            projects = File.Exists(client.Target.Path)
                ? JsonNode.Parse(File.ReadAllText(client.Target.Path), documentOptions: new() { CommentHandling = System.Text.Json.JsonCommentHandling.Skip, AllowTrailingCommas = true })?["projects"] as JsonObject
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException) { projects = null; }
        foreach (var (project, value) in projects ?? [])
            if (value?["mcpServers"]?[LegacyServerName] is JsonObject)
                yield return (project, new JsonTarget(client.Target.Path, ["projects", project, "mcpServers"], ClaudeCode));
    }

    private static JsonArray Strings(IEnumerable<string> items) => new([.. items.Select(i => (JsonNode)JsonValue.Create(i)!)]);

    private static JsonObject Plain(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args) };
    private static JsonObject Stdio(ServerLaunch l) => new() { ["type"] = "stdio", ["command"] = l.Command, ["args"] = Strings(l.Args) };
    private static JsonObject WithEnv(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject() };
    private static JsonObject ClaudeCode(ServerLaunch l) => new() { ["type"] = "stdio", ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject() };
    private static JsonObject Cline(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["disabled"] = false, ["autoApprove"] = new JsonArray() };
    private static JsonObject Roo(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["disabled"] = false, ["alwaysAllow"] = new JsonArray() };
    private static JsonObject Copilot(ServerLaunch l) => new() { ["type"] = "local", ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject(), ["tools"] = Strings(["*"]) };
    private static JsonObject CommandCode(ServerLaunch l) => new() { ["transport"] = "stdio", ["enabled"] = true, ["command"] = l.Command, ["args"] = Strings(l.Args) };
    private static JsonObject OpenCode(ServerLaunch l) => new() { ["type"] = "local", ["command"] = Strings([l.Command, .. l.Args]), ["enabled"] = true };

    private static readonly string[] Servers = ["mcpServers"];

    public static IReadOnlyList<McpClient> All(SetupEnvironment env)
    {
        var list = new List<McpClient>();
        bool Dir(string path) => env.DirectoryExists(path);
        void Add(string id, string name, string[] aliases, ConfigTarget target, bool present) => list.Add(new McpClient(id, name, aliases, target, present));
        JsonTarget Json(string path, Func<ServerLaunch, JsonObject> entry, string? container = null, Func<JsonObject, string, bool?>? listed = null) =>
            new(path, container == null ? Servers : [container], entry, listed);

        // CLAUDE_CONFIG_DIR holds both .claude.json and what is otherwise ~/.claude.
        var claudeDir = env.Set("CLAUDE_CONFIG_DIR");
        var claudeJson = Path.Combine(claudeDir ?? env.Home, ".claude.json");
        var claudeTarget = env.FindTool("claude") is { } claudeCli
            ? (ConfigTarget)new ClaudeCliTarget(claudeCli, Json(claudeJson, ClaudeCode))
            : Json(claudeJson, ClaudeCode);
        Add("claude-code", "Claude Code", ["claude"], claudeTarget,
            File.Exists(claudeJson) || Dir(claudeDir ?? env.InHome(".claude")) || env.HasTool("claude"));

        // Linux: $XDG_CONFIG_HOME/Claude.
        var desktop = env.AppSupport("Claude");
        Add("claude-desktop", "Claude Desktop", ["claude-app"], Json(Path.Combine(desktop, "claude_desktop_config.json"), Plain), Dir(desktop));

        Add("cursor", "Cursor", [], Json(env.InHome(".cursor", "mcp.json"), Plain), Dir(env.InHome(".cursor")) || env.HasTool("cursor-agent"));
        Add("windsurf", "Windsurf", ["codeium"], Json(env.InHome(".codeium", "windsurf", "mcp_config.json"), Plain), Dir(env.InHome(".codeium", "windsurf")));

        foreach (var (id, name, folder) in new[] { ("vscode", "VS Code", "Code"), ("vscode-insiders", "VS Code Insiders", "Code - Insiders"), ("vscodium", "VSCodium", "VSCodium") })
        {
            var user = Path.Combine(env.AppSupport(folder), "User");
            Add(id, name, [], Json(Path.Combine(user, "mcp.json"), Stdio, "servers"), Dir(user));
        }

        // VS Code extensions keep their own server lists.
        var storage = Path.Combine(env.AppSupport("Code"), "User", "globalStorage");
        foreach (var (id, name, extension, file, entry) in new (string, string, string, string, Func<ServerLaunch, JsonObject>)[]
                 {
                     ("cline", "Cline", "saoudrizwan.claude-dev", "cline_mcp_settings.json", Cline),
                     ("roo-code", "Roo Code", "rooveterinaryinc.roo-cline", "mcp_settings.json", Roo),
                     ("kilo-code", "Kilo Code", "kilocode.kilo-code", "mcp_settings.json", Roo),
                 })
            Add(id, name, [id.Replace("-", "")], Json(Path.Combine(storage, extension, "settings", file), entry), Dir(Path.Combine(storage, extension)));

        if (env.Os == HostOs.Windows)
        {
            var vs = Path.Combine(env.Variable("ProgramFiles") ?? @"C:\Program Files", "Microsoft Visual Studio");
            Add("visual-studio", "Visual Studio", ["vs"], Json(env.InHome(".mcp.json"), Stdio, "servers"), Dir(vs));
        }

        var codexHome = env.Variable("CODEX_HOME") is { Length: > 0 } ch ? ch : env.InHome(".codex");
        Add("codex", "Codex", ["openai-codex"], new CodexTomlTarget(Path.Combine(codexHome, "config.toml")), Dir(codexHome) || env.HasTool("codex"));

        // GEMINI_CLI_HOME replaces the home folder; QWEN_HOME and COPILOT_HOME replace the client's own folder.
        var gemini = Path.Combine(env.Set("GEMINI_CLI_HOME") ?? env.Home, ".gemini", "settings.json");
        Add("gemini-cli", "Gemini CLI", ["gemini"], Json(gemini, Plain), File.Exists(gemini) || env.HasTool("gemini"));
        var qwen = env.Set("QWEN_HOME") is { } qwenHome ? env.ExpandPath(qwenHome) : env.InHome(".qwen");
        Add("qwen-code", "Qwen Code", ["qwen"], Json(Path.Combine(qwen, "settings.json"), Plain), Dir(qwen) || env.HasTool("qwen"));
        var copilot = env.Set("COPILOT_HOME") ?? env.InHome(".copilot");
        Add("copilot-cli", "GitHub Copilot CLI", ["copilot"], Json(Path.Combine(copilot, "mcp-config.json"), Copilot), Dir(copilot) || env.HasTool("copilot"));

        var (opencodeDir, opencodeFile) = OpenCodeFile(env);
        Add("opencode", "OpenCode", [], Json(opencodeFile, OpenCode, "mcp"), Dir(opencodeDir) || File.Exists(opencodeFile) || env.HasTool("opencode"));

        // An explicit XDG_CONFIG_HOME wins on every system, then %LOCALAPPDATA%\crush on Windows, then ~/.config.
        var crush = env.Set("XDG_CONFIG_HOME") is { } xdg ? Path.Combine(xdg, "crush")
            : env.Os == HostOs.Windows && Dir(Path.Combine(env.LocalAppData, "crush")) ? Path.Combine(env.LocalAppData, "crush")
            : env.InHome(".config", "crush");
        Add("crush", "Crush", [], Json(Path.Combine(crush, "crush.json"), Stdio, "mcp"), Dir(crush) || env.HasTool("crush"));

        // XDG on Linux only; macOS always uses ~/.config/zed.
        var zed = env.Os switch
        {
            HostOs.Windows => Path.Combine(env.AppData, "Zed"),
            HostOs.Linux => Path.Combine(env.XdgConfig, "zed"),
            _ => env.InHome(".config", "zed"),
        };
        Add("zed", "Zed", [], Json(Path.Combine(zed, "settings.json"), WithEnv, "context_servers"), Dir(zed));

        Add("lm-studio", "LM Studio", ["lmstudio"], Json(env.InHome(".lmstudio", "mcp.json"), Plain), Dir(env.InHome(".lmstudio")));
        Add("amazon-q", "Amazon Q", ["amazonq", "q"], Json(env.InHome(".aws", "amazonq", "mcp.json"), Plain), Dir(env.InHome(".aws", "amazonq")));
        Add("kiro", "Kiro", [], Json(env.InHome(".kiro", "settings", "mcp.json"), Plain), Dir(env.InHome(".kiro")));

        var shared = env.InHome(".gemini", "config");
        var antigravity = Dir(shared) ? shared : env.InHome(".gemini", "antigravity");
        Add("antigravity", "Antigravity", [], Json(Path.Combine(antigravity, "mcp_config.json"), Plain), Dir(shared) || Dir(env.InHome(".gemini", "antigravity")));

        var devin = env.Os == HostOs.Windows ? Path.Combine(env.AppData, "devin") : Path.Combine(env.XdgConfig, "devin");
        Add("devin", "Devin", [], Json(Path.Combine(devin, "mcp_config.json"), Plain), Dir(devin));
        Add("command-code", "Command Code", ["commandcode"], Json(env.InHome(".commandcode", "mcp.json"), CommandCode), Dir(env.InHome(".commandcode")));
        var grok = env.Set("GROK_HOME") ?? env.InHome(".grok");
        Add("grok-build", "Grok Build", ["grok"], new CodexTomlTarget(Path.Combine(grok, "config.toml")), Dir(grok) || env.HasTool("grok"));

        var (ompRoot, ompAgent, ompError) = OmpAgentDir(env);
        Add("omp", "OMP", [], ompError != null
                ? new InvalidTarget(Path.Combine(ompRoot, "mcp.json"), ompError)
                : Json(Path.Combine(ompAgent, "mcp.json"), Stdio, listed: (root, name) =>
                    JsonTarget.Lists(root, "disabledServers", name) ? true : JsonTarget.Lists(root, "enabledServers", name) ? false : null),
            Dir(ompRoot) || env.HasTool("omp"));

        var pi = env.Set("PI_CODING_AGENT_DIR") is { } piDir ? env.ExpandPath(piDir) : env.InHome(".pi", "agent");
        Add("pi", "Pi", [], Json(Path.Combine(pi, "mcp.json"), Stdio), Dir(pi) || Dir(env.InHome(".pi")));

        return list;
    }

    private static readonly System.Text.RegularExpressions.Regex OmpProfile = new("^[a-z0-9][a-z0-9._-]{0,63}$");
    private static readonly System.Text.RegularExpressions.Regex ReservedDevice = new("^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\\..*)?$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>
    /// OMP's root (PI_CONFIG_DIR joined to the home folder, default .omp) and agent folder: profiles/&lt;p&gt;/agent for
    /// OMP_PROFILE (or PI_PROFILE), else PI_CODING_AGENT_DIR, else agent; an invalid profile name is an error.
    /// </summary>
    private static (string Root, string Agent, string? Error) OmpAgentDir(SetupEnvironment env)
    {
        var root = Path.Join(env.Home, env.Set("PI_CONFIG_DIR") ?? ".omp");
        var profile = (env.Variable("OMP_PROFILE") ?? env.Variable("PI_PROFILE"))?.Trim();
        if (profile is { Length: > 0 } && profile != "default")
        {
            if (!OmpProfile.IsMatch(profile) || profile.EndsWith('.') || ReservedDevice.IsMatch(profile))
                return (root, root, $"invalid OMP profile \"{profile}\": names match ^[a-z0-9][a-z0-9._-]{{0,63}}$, do not end with \".\" and are not device names; fix OMP_PROFILE or PI_PROFILE");
            return (root, Path.Combine(root, "profiles", profile, "agent"), null);
        }
        return (root, env.Set("PI_CODING_AGENT_DIR") is { } dir ? Path.GetFullPath(dir) : Path.Combine(root, "agent"), null);
    }

    /// <summary>
    /// OpenCode's folder and the file it loads last (so ours wins): OPENCODE_CONFIG_DIR, else the OPENCODE_CONFIG file,
    /// else $XDG_CONFIG_HOME/opencode; in a folder opencode.jsonc is loaded after opencode.json.
    /// </summary>
    private static (string Dir, string File) OpenCodeFile(SetupEnvironment env)
    {
        if (env.Set("OPENCODE_CONFIG_DIR") is null && env.Set("OPENCODE_CONFIG") is { } file)
        {
            var full = Path.GetFullPath(file);
            return (Path.GetDirectoryName(full)!, full);
        }
        var dir = env.Set("OPENCODE_CONFIG_DIR") is { } custom ? Path.GetFullPath(custom) : Path.Combine(env.XdgConfig, "opencode");
        var jsonc = Path.Combine(dir, "opencode.jsonc");
        return (dir, System.IO.File.Exists(jsonc) ? jsonc : Path.Combine(dir, "opencode.json"));
    }
}
