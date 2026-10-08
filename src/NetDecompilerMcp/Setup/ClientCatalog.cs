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

        var claudeJson = env.InHome(".claude.json");
        Add("claude-code", "Claude Code", ["claude"], Json(claudeJson, ClaudeCode),
            File.Exists(claudeJson) || Dir(env.InHome(".claude")) || env.HasTool("claude"));

        if (env.Os != HostOs.Linux)
        {
            var dir = env.AppSupport("Claude");
            Add("claude-desktop", "Claude Desktop", ["claude-app"], Json(Path.Combine(dir, "claude_desktop_config.json"), Plain), Dir(dir));
        }

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

        Add("gemini-cli", "Gemini CLI", ["gemini"], Json(env.InHome(".gemini", "settings.json"), Plain),
            File.Exists(env.InHome(".gemini", "settings.json")) || env.HasTool("gemini"));
        Add("qwen-code", "Qwen Code", ["qwen"], Json(env.InHome(".qwen", "settings.json"), Plain), Dir(env.InHome(".qwen")) || env.HasTool("qwen"));
        Add("copilot-cli", "GitHub Copilot CLI", ["copilot"], Json(env.InHome(".copilot", "mcp-config.json"), Copilot), Dir(env.InHome(".copilot")) || env.HasTool("copilot"));

        var opencode = env.InHome(".config", "opencode");
        var opencodeFile = File.Exists(Path.Combine(opencode, "opencode.jsonc")) ? "opencode.jsonc" : "opencode.json";
        Add("opencode", "OpenCode", [], Json(Path.Combine(opencode, opencodeFile), OpenCode, "mcp"), Dir(opencode) || env.HasTool("opencode"));

        var crush = env.Os == HostOs.Windows && Dir(Path.Combine(env.LocalAppData, "crush")) ? Path.Combine(env.LocalAppData, "crush") : env.InHome(".config", "crush");
        Add("crush", "Crush", [], Json(Path.Combine(crush, "crush.json"), Stdio, "mcp"), Dir(crush) || env.HasTool("crush"));

        var zed = env.Os == HostOs.Windows ? Path.Combine(env.AppData, "Zed") : env.InHome(".config", "zed");
        Add("zed", "Zed", [], Json(Path.Combine(zed, "settings.json"), WithEnv, "context_servers"), Dir(zed));

        Add("lm-studio", "LM Studio", ["lmstudio"], Json(env.InHome(".lmstudio", "mcp.json"), Plain), Dir(env.InHome(".lmstudio")));
        Add("amazon-q", "Amazon Q", ["amazonq", "q"], Json(env.InHome(".aws", "amazonq", "mcp.json"), Plain), Dir(env.InHome(".aws", "amazonq")));
        Add("kiro", "Kiro", [], Json(env.InHome(".kiro", "settings", "mcp.json"), Plain), Dir(env.InHome(".kiro")));

        var shared = env.InHome(".gemini", "config");
        var antigravity = Dir(shared) ? shared : env.InHome(".gemini", "antigravity");
        Add("antigravity", "Antigravity", [], Json(Path.Combine(antigravity, "mcp_config.json"), Plain), Dir(shared) || Dir(env.InHome(".gemini", "antigravity")));

        return list;
    }
}
