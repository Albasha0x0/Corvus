namespace Corvus.Core;

/// <summary>
/// What one MCP client keeps of a tool result and how long it waits: <see cref="MaxTokens"/> and <see cref="MaxChars"/>
/// cap a result, <see cref="DeadlineSeconds"/> is the client's own per-call limit (null: none), <see cref="DefaultProfile"/>
/// the tool profile it gets without --toolsets (lean for clients that cap the tool count). <see cref="ClientNames"/> are
/// token sequences matched against the handshake's clientInfo.name.
/// </summary>
public sealed record ClientProfile(string Id, string Name, IReadOnlyList<string> ClientNames, int MaxTokens, int? MaxChars, int? DeadlineSeconds, string DefaultProfile);

/// <summary>
/// The limits a server applies for its client, explicit settings already folded in. <see cref="Source"/> says where the
/// profile came from (--client, CORVUS_CLIENT, clientInfo, default); <see cref="MaxTokensSource"/> and
/// <see cref="DeadlineSource"/> name the setting that decided those values (an option or variable, else the profile).
/// <see cref="Toolsets"/> is the explicit --toolsets value, else the profile's default.
/// </summary>
public sealed record ClientLimits(ClientProfile Profile, int MaxTokens, int? MaxChars, int? DeadlineSeconds, string Toolsets,
    string Source, string MaxTokensSource, string DeadlineSource);

/// <summary>Per-client output ceilings, deadlines and default tool profiles (STANDARDS S1.4, S9.1; DECISIONS D4, D6).</summary>
public static class ClientProfiles
{
    public const string ClientOption = "--client";
    public const string ClientVariable = "CORVUS_CLIENT";
    public const string MaxOutputTokensVariable = "CORVUS_MAX_OUTPUT_TOKENS";
    public const string ClientTimeoutOption = "--client-timeout";
    public const string ClientTimeoutVariable = "CORVUS_CLIENT_TIMEOUT";

    public const string Full = "full", Lean = "lean";

    /// <summary>Under Claude Code's 10k warning and Codex's 10k middle cut.</summary>
    public const int DefaultMaxTokens = 9_500;

    public static ClientProfile Unknown { get; } = new("unknown", "Unknown client", [], DefaultMaxTokens, null, null, Full);

    private static ClientProfile Plain(string id, string name, params string[] names) => new(id, name, names, DefaultMaxTokens, null, null, Full);
    private static ClientProfile Capped(string id, string name, params string[] names) => new(id, name, names, DefaultMaxTokens, null, null, Lean);

    /// <summary>
    /// One row per client id of the setup catalog. Detection tries rows in this order, so a name that contains another
    /// client's (cursor-vscode, Visual Studio Code - Insiders) is listed first.
    /// </summary>
    public static IReadOnlyList<ClientProfile> All { get; } =
    [
        Plain("cursor", "Cursor", "cursor"),
        Plain("windsurf", "Windsurf", "windsurf", "codeium"),
        // Claude Code keeps 25k tokens; the char cap equals the anthropic/maxResultSizeChars every tool declares.
        new("claude-code", "Claude Code", ["claude-code"], 24_000, 100_000, null, Full),
        // Claude Desktop runs connectors: about 150k chars per result, 240 s per call.
        new("claude-desktop", "Claude Desktop", ["claude-ai", "claude-desktop"], 24_000, 140_000, 240, Full),
        Capped("vscode-insiders", "VS Code Insiders", "visual-studio-code-insiders", "vscode-insiders", "code-insiders"),
        Capped("vscodium", "VSCodium", "vscodium"),
        Capped("vscode", "VS Code", "visual-studio-code", "vscode"),
        Capped("visual-studio", "Visual Studio", "visual-studio"),
        Plain("cline", "Cline", "cline"),
        Plain("roo-code", "Roo Code", "roo-code", "roo-cline", "roocode"),
        Plain("kilo-code", "Kilo Code", "kilo-code", "kilocode", "kilo"),
        new("codex", "Codex", ["codex"], DefaultMaxTokens, null, 60, Full),
        new("gemini-cli", "Gemini CLI", ["gemini-cli", "gemini"], DefaultMaxTokens, 38_000, 600, Full),
        Plain("qwen-code", "Qwen Code", "qwen-code", "qwen"),
        Capped("copilot-cli", "GitHub Copilot CLI", "copilot-cli", "github-copilot", "copilot"),
        Plain("opencode", "OpenCode", "opencode"),
        Plain("crush", "Crush", "crush"),
        Plain("zed", "Zed", "zed"),
        Plain("lm-studio", "LM Studio", "lm-studio", "lmstudio"),
        Plain("amazon-q", "Amazon Q", "amazon-q", "amazonq", "q-cli"),
        Plain("kiro", "Kiro", "kiro"),
        Plain("antigravity", "Antigravity", "antigravity"),
        Plain("devin", "Devin", "devin"),
        Plain("command-code", "Command Code", "command-code", "commandcode"),
        Plain("grok-build", "Grok Build", "grok-build", "grok"),
        Plain("omp", "OMP", "omp"),
        Plain("pi", "Pi", "pi", "pi-coding-agent"),
        Plain("kimi-code", "Kimi Code", "kimi-code", "kimi"),
        Plain("qoder", "Qoder", "qoder", "qodercli"),
        Plain("factory-droid", "Factory Droid", "factory-droid", "droid"),
        Plain("trae", "Trae", "trae"),
        Plain("codebuddy", "CodeBuddy", "codebuddy"),
        Plain("hermes", "Hermes", "hermes"),
        Plain("deepseek-harness", "DeepSeek Harness", "deepseek-harness", "dsh"),
    ];

    /// <summary>The profile of a client id (or the unknown row's id); null for anything else.</summary>
    public static ClientProfile? Find(string? id)
    {
        var key = id?.Trim();
        if (string.IsNullOrEmpty(key)) return null;
        if (key.Equals(Unknown.Id, StringComparison.OrdinalIgnoreCase)) return Unknown;
        return All.FirstOrDefault(p => p.Id.Equals(key, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The profile whose name tokens appear in a clientInfo.name; null when none does.</summary>
    public static ClientProfile? Detect(string? clientInfoName)
    {
        if (string.IsNullOrWhiteSpace(clientInfoName)) return null;
        var tokens = Tokens(clientInfoName);
        return All.FirstOrDefault(p => p.ClientNames.Any(n => Contains(tokens, Tokens(n))));
    }

    private static string[] Tokens(string text) =>
        text.ToLowerInvariant().Split((char[])[' ', '-', '_', '.', '/', '(', ')', ':'], StringSplitOptions.RemoveEmptyEntries);

    private static bool Contains(string[] haystack, string[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return true;
        return false;
    }

    /// <summary>
    /// The limits for a call: the profile from --client / CORVUS_CLIENT, else from clientInfo.name, else unknown; then
    /// CORVUS_MAX_OUTPUT_TOKENS, --client-timeout / CORVUS_CLIENT_TIMEOUT and --toolsets replace the profile's values.
    /// </summary>
    public static ClientLimits Resolve(ServerOptions options, string? clientInfoName)
    {
        ClientProfile profile;
        string source;
        if (options.Client is { } id && Find(id) is { } named)
            (profile, source) = (named, options.ClientSource ?? ClientOption);
        else if (Detect(clientInfoName) is { } detected)
            (profile, source) = (detected, "clientInfo");
        else
            (profile, source) = (Unknown, "default");
        var (tokens, tokensFrom) = options.MaxOutputTokens is { } t ? (t, MaxOutputTokensVariable) : (profile.MaxTokens, profile.Id);
        var (deadline, deadlineFrom) = options.ClientTimeoutSeconds is { } s ? ((int?)s, options.ClientTimeoutSource ?? ClientTimeoutOption) : (profile.DeadlineSeconds, profile.Id);
        return new ClientLimits(profile, tokens, profile.MaxChars, deadline, options.ToolsetsText ?? profile.DefaultProfile, source, tokensFrom, deadlineFrom);
    }
}
