using System.Text.Json.Nodes;

namespace NetDecompilerMcp.Setup;

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
    public const string ServerName = "net-decompiler";

    private static JsonArray Strings(IEnumerable<string> items) => new([.. items.Select(i => (JsonNode)JsonValue.Create(i)!)]);

    private static JsonObject Plain(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args) };
    private static JsonObject Stdio(ServerLaunch l) => new() { ["type"] = "stdio", ["command"] = l.Command, ["args"] = Strings(l.Args) };
    private static JsonObject WithEnv(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject() };
    private static JsonObject ClaudeCode(ServerLaunch l) => new() { ["type"] = "stdio", ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject() };
    private static JsonObject Cline(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["disabled"] = false, ["autoApprove"] = new JsonArray() };
    private static JsonObject Roo(ServerLaunch l) => new() { ["command"] = l.Command, ["args"] = Strings(l.Args), ["disabled"] = false, ["alwaysAllow"] = new JsonArray() };
    private static JsonObject Copilot(ServerLaunch l) => new() { ["type"] = "local", ["command"] = l.Command, ["args"] = Strings(l.Args), ["env"] = new JsonObject(), ["tools"] = Strings(["*"]) };
    private static JsonObject OpenCode(ServerLaunch l) => new() { ["type"] = "local", ["command"] = Strings([l.Command, .. l.Args]), ["enabled"] = true };

    private static readonly string[] Servers = ["mcpServers"];

    public static IReadOnlyList<McpClient> All(SetupEnvironment env)
    {
        var list = new List<McpClient>();
        bool Dir(string path) => env.DirectoryExists(path);
        void Add(string id, string name, string[] aliases, ConfigTarget target, bool present) => list.Add(new McpClient(id, name, aliases, target, present));
        JsonTarget Json(string path, Func<ServerLaunch, JsonObject> entry, params string[] container) =>
            new(path, container.Length == 0 ? Servers : container, entry);

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

        return list;
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
