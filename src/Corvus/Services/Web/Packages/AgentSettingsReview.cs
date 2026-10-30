using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    // Claude Code settings reference (environment variables): variables that send requests or trust elsewhere.
    private static readonly HashSet<string> EndpointEnv = new(StringComparer.OrdinalIgnoreCase)
    {
        "ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_FOUNDRY_BASE_URL",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NODE_EXTRA_CA_CERTS",
    };

    // Node.js CLI documentation (NODE_OPTIONS), ld.so(8) and dyld(1): variables that load code into a process.
    private static readonly HashSet<string> LoaderEnv = new(StringComparer.OrdinalIgnoreCase)
    {
        "NODE_OPTIONS", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "BASH_ENV",
    };

    // Claude Code settings reference: keys whose value is a command the agent runs.
    private static readonly string[] HelperKeys = ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"];

    // Programs that run other code: a permission for one lets a session run anything.
    private static readonly HashSet<string> CodeRunners = new(StringComparer.OrdinalIgnoreCase)
    {
        "curl", "wget", "sh", "bash", "zsh", "pwsh", "powershell", "python", "python3", "node", "eval", "ssh", "sudo", "npx",
    };

    [GeneratedRegex(@"^[~/\\]|^[A-Za-z]:|(?:^|[/\\])\.\.(?:[/\\]|$)", RegexOptions.NonBacktracking)]
    private static partial Regex OutsideFolder();

    /// <summary>Claude Code settings keys that redirect requests, load code, run helpers, widen permissions or add plugins.</summary>
    private static void AgentSettings(JsonTree settings, string path, AgentReview review, CancellationToken ct)
    {
        foreach (var (name, value) in settings["env"]?.Props ?? [])
        {
            var text = value.Text ?? "";
            if (LoaderEnv.Contains(name) && text.Length > 0)
                review.Findings.Add(new PackageFinding("package/agent-env-loader", "noteworthy", "agent configuration",
                    $"settings env {name} loads code into the agent's processes: {Clip(text, 200)}", path, value.Line));
            else if (EndpointEnv.Contains(name) && text.Length > 0 && !IsLoopbackUrl(text))
                review.Findings.Add(new PackageFinding("package/agent-env-endpoint", "noteworthy", "agent configuration",
                    $"settings env {name} sends the agent's requests or trust elsewhere: {Clip(text, 200)}", path, value.Line));
            else if (name.Equals("NODE_TLS_REJECT_UNAUTHORIZED", StringComparison.OrdinalIgnoreCase) && text == "0")
                review.Findings.Add(new PackageFinding("package/agent-env-endpoint", "noteworthy", "agent configuration",
                    "settings env NODE_TLS_REJECT_UNAUTHORIZED turns certificate checks off", path, value.Line));
        }
        foreach (var key in HelperKeys)
            if (settings[key] is { Text: { Length: > 0 } command } helper) HelperCommand(key, command, helper.Line, path, review, ct);
        if (settings["statusLine"]?["command"] is { Text: { Length: > 0 } status } line) HelperCommand("statusLine", status, line.Line, path, review, ct);
        Permissions(settings["permissions"], path, review);
        foreach (var (plugin, on) in settings["enabledPlugins"]?.Props ?? [])
            if (on.Kind == JsonTokenType.True)
                review.Findings.Add(new PackageFinding("package/agent-plugin", "review", "agent configuration", $"enabledPlugins turns on plugin {Clip(plugin, 120)}", path, on.Line));
        foreach (var (market, entry) in settings["extraKnownMarketplaces"]?.Props ?? [])
            review.Findings.Add(new PackageFinding("package/agent-marketplace", "review", "agent configuration",
                $"extraKnownMarketplaces adds marketplace {Clip(market, 80)} from {Clip(PluginSource(entry["source"]) ?? "(no source)", 160)}", path, entry.Line));
    }

    private static void HelperCommand(string key, string command, int line, string path, AgentReview review, CancellationToken ct)
    {
        review.Entries.Add(new AgentEntry("helper command", key, Clip(command), path, line));
        review.Findings.Add(new PackageFinding("package/agent-helper-command", "review", "agent configuration", $"settings {key} runs: {Clip(command, 200)}", path, line));
        ScanCommand(command, $"settings {key}", path, line, review, ct);
    }

    private static void Permissions(JsonTree? permissions, string path, AgentReview review)
    {
        if (permissions == null) return;
        foreach (var rule in permissions["allow"]?.Items ?? [])
            if (rule.Text is { } text && WidePermission(text))
                review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                    $"permissions.allow approves {Clip(text, 120)} without asking", path, rule.Line));
        if (permissions["defaultMode"] is { Text: "bypassPermissions" } mode)
            review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                "permissions.defaultMode bypassPermissions skips every permission prompt", path, mode.Line));
        foreach (var dir in permissions["additionalDirectories"]?.Items ?? [])
            if (dir.Text is { } text && OutsideFolder().IsMatch(text))
                review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                    $"permissions.additionalDirectories gives access to {Clip(text, 120)}, outside the folder", path, dir.Line));
    }

    /// <summary>Whether a permission rule approves a whole shell tool, every command, or a program that runs other code.</summary>
    private static bool WidePermission(string rule)
    {
        var open = rule.IndexOf('(');
        if ((open < 0 ? rule : rule[..open]) is not ("Bash" or "PowerShell")) return false;
        if (open < 0) return true;
        var inner = rule[(open + 1)..].TrimEnd(')').Trim();
        return inner is "" or "*" or ":*" || CodeRunners.Contains(inner.Split(' ', ':', '*')[0]);
    }

    // A proxy value without a scheme ("localhost:8080") is read as http.
    private static bool IsLoopbackUrl(string url) =>
        Uri.TryCreate(url.Contains("://", StringComparison.Ordinal) ? url : "http://" + url, UriKind.Absolute, out var uri)
        && (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));

    private static string? PluginSource(JsonTree? source) => source?.Text ?? source?["repo"]?.Text ?? source?["url"]?.Text ?? source?["path"]?.Text;

    // VS Code settings: chat.tools.autoApprove skips the confirmation before an agent tool runs.
    private static void EditorAutoApprove(JsonTree settings, string path, AgentReview review)
    {
        foreach (var key in new[] { "chat.tools.autoApprove", "chat.tools.global.autoApprove" })
            if (settings[key] is { Kind: JsonTokenType.True } on)
                review.Findings.Add(new PackageFinding("package/agent-auto-approve", "review", "agent configuration", $"{key} runs every agent tool without confirmation", path, on.Line));
        foreach (var (command, value) in settings["chat.tools.terminal.autoApprove"]?.Props ?? [])
            if (value.Kind == JsonTokenType.True && CodeRunners.Contains(command.Trim('/', '^', '$', ' ').Split(' ')[0]))
                review.Findings.Add(new PackageFinding("package/agent-auto-approve", "review", "agent configuration",
                    $"chat.tools.terminal.autoApprove runs {Clip(command, 80)} without confirmation", path, value.Line));
    }

    // A plugin from outside the repository; a relative path is the repository's own.
    private static void PluginMarketplace(JsonTree root, string path, AgentReview review)
    {
        foreach (var plugin in root["plugins"]?.Items ?? [])
        {
            if (PluginSource(plugin["source"]) is not { } from || from.StartsWith("./", StringComparison.Ordinal) || from.StartsWith("../", StringComparison.Ordinal)) continue;
            review.Findings.Add(new PackageFinding("package/agent-plugin", "review", "agent configuration",
                $"marketplace lists plugin {Clip(plugin["name"]?.Text ?? "(unnamed)", 80)} from {Clip(from, 160)}", path, plugin.Line));
        }
    }

    private static void PluginManifest(JsonTree root, string path, AgentReview review, CancellationToken ct)
    {
        review.Entries.Add(new AgentEntry("plugin", Clip(root["name"]?.Text ?? "(unnamed)", 80)!, null, path, root.Line));
        Hooks(root, path, review, ct);
        McpServers(root, path, review, ct);
    }
}
