namespace Corvus.Services.Web.Packages;

public static partial class PackageReview
{
    /// <summary>Cursor CLI permissions.allow tokens that approve code-running shell commands, writes outside the folder or every MCP tool.</summary>
    private static void CursorCliSettings(JsonTree settings, string path, AgentReview review)
    {
        if (settings["permissions"] is not { } permissions) return;
        foreach (var rule in permissions["allow"]?.Items ?? [])
            if (rule.Text is { } token && WideCursorPermission(token))
                review.Findings.Add(new PackageFinding("package/agent-permission-widening", "review", "agent configuration",
                    $"permissions.allow approves {Clip(token, 120)} without asking", path, rule.Line));
        if (permissions["deny"] is { Items.Count: > 0 } deny)
            review.Notes.Add($"{path}: permissions.deny lists {deny.Items.Count} rule(s)");
    }

    // Tokens are Shell(command), Write(glob) and Mcp(server:tool).
    private static bool WideCursorPermission(string token)
    {
        var open = token.IndexOf('(');
        if (open < 0 || !token.EndsWith(')')) return false;
        var inner = token[(open + 1)..^1].Trim();
        switch (token[..open])
        {
            case "Shell":
                return inner is "" or "*" or ":*" || CodeRunners.Contains(inner.Split(' ', ':', '*')[0]);
            case "Write":
                return inner is "**" or "**/*" or "*" || OutsideFolder().IsMatch(inner);
            case "Mcp":
                return inner is "*:*" or "*";
            default:
                return false;
        }
    }
}
