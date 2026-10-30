namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Codex config.toml keys that redirect requests, turn confirmation or the sandbox off, pass variables to commands or add MCP servers.</summary>
    private static void CodexSettings(string toml, string path, AgentReview review, CancellationToken ct)
    {
        var root = TomlTree.Parse(toml, out var skipped);
        if (skipped > 0) review.Notes.Add($"{path}: {skipped} line(s) not valid TOML, skipped; agent configuration partial");
        CodexPolicy(root, "", path, review, userLevel: false);
        // Codex ignores profiles and model_providers in a project config, so they count only from a user-level file and rank review.
        foreach (var (profile, table) in root["profiles"]?.Props ?? [])
            CodexPolicy(table, $"profiles.{Clip(profile, 40)}.", path, review, userLevel: true);
        foreach (var (id, provider) in root["model_providers"]?.Props ?? [])
            if (provider["base_url"] is { Text: { Length: > 0 } url } at && !IsLoopbackUrl(url))
                review.Findings.Add(new PackageFinding("package/agent-env-endpoint", "review", "agent configuration",
                    $"model_providers.{Clip(id, 40)}.base_url sends the agent's requests elsewhere from a user-level config: {Clip(url, 200)}", path, at.Line));
        foreach (var (name, server) in root["mcp_servers"]?.Props ?? [])
            McpServer(name, server, path, review, ct);
    }

    // OpenAI Codex configuration reference (config.toml): approval_policy, sandbox_mode, default_permissions and shell_environment_policy.
    private static void CodexPolicy(JsonTree table, string prefix, string path, AgentReview review, bool userLevel)
    {
        string where = userLevel ? " from a user-level config" : "";
        if (table["approval_policy"] is { Text: "never" } approval)
            review.Findings.Add(new PackageFinding("package/agent-confirmation-off", userLevel ? "review" : "noteworthy", "agent configuration",
                $"{prefix}approval_policy never runs every command without confirmation{where}", path, approval.Line));
        if (table["sandbox_mode"] is { Text: "danger-full-access" } sandbox)
            review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                $"{prefix}sandbox_mode danger-full-access runs commands with no sandbox{where}", path, sandbox.Line));
        if (table["default_permissions"] is { Text: ":danger-full-access" } permissions)
            review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                $"{prefix}default_permissions :danger-full-access runs commands with no sandbox{where}", path, permissions.Line));
        // ignore_default_excludes is true by default, so credential-named variables pass unless a file turns it off.
        if (table["shell_environment_policy"] is { } policy) SettingsEnv(policy["set"], $"{prefix}shell_environment_policy.set", path, review);
    }
}
