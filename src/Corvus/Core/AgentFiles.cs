namespace Corvus.Core;

// Kept apart from PackageReview so summarize_file does not build its regex tables.
/// <summary>Names agent configuration files by path; no file is read.</summary>
internal static class AgentFiles
{
    private static readonly string[] InstructionNames =
        ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules"];

    /// <summary>Folders whose files configure an agent or editor; a path inside one is rooted at the folder's parent.</summary>
    internal static readonly string[] Folders = [".claude", ".cursor", ".vscode", ".github", ".windsurf", ".clinerules", ".codex", ".gemini", ".roo", ".kiro", ".amazonq", ".claude-plugin", "hooks"];

    /// <summary>The agent configuration kind of a '/'-separated path, or null when it is none; <paramref name="ignoreCase"/> for a case-insensitive file system.</summary>
    internal static string? Kind(string path, bool ignoreCase = false)
    {
        var c = ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var slashed = "/" + path;
        var name = path[(path.LastIndexOf('/') + 1)..];
        var dir = slashed[..slashed.LastIndexOf('/')];
        dir = dir[(dir.LastIndexOf('/') + 1)..];
        bool Is(string a, string b) => a.Equals(b, c);
        if (InstructionNames.Any(n => Is(n, name)) || slashed.Contains("/.cursor/rules/", c) || slashed.Contains("/.windsurf/rules/", c)
            || slashed.Contains("/.clinerules/", c) || slashed.EndsWith("/.github/copilot-instructions.md", c)
            || slashed.Contains("/.github/instructions/", c) && name.EndsWith(".instructions.md", c)
            || PromptFile(slashed, name, c))
            return "instructions";
        if (Is(dir, ".claude") && (Is(name, "settings.json") || Is(name, "settings.local.json"))) return "settings";
        if (Is(name, ".mcp.json") || (Is(dir, ".cursor") || Is(dir, ".vscode") || Is(dir, ".roo") || Is(dir, ".amazonq")) && Is(name, "mcp.json")
            || Is(dir, "settings") && slashed.EndsWith("/.kiro/settings/mcp.json", c) || Is(dir, ".gemini") && Is(name, "settings.json")) return "mcp";
        if (Is(dir, ".claude-plugin") && Is(name, "plugin.json")) return "plugin manifest";
        if (Is(dir, ".claude-plugin") && Is(name, "marketplace.json")) return "plugin marketplace";
        if (Is(dir, "hooks") && Is(name, "hooks.json")) return "plugin hooks";
        if (Is(dir, "workflows") && slashed.Contains("/.github/workflows/", c) && (name.EndsWith(".yml", c) || name.EndsWith(".yaml", c))) return "workflow";
        if (Is(dir, ".vscode") && Is(name, "tasks.json")) return "tasks";
        if (Is(dir, ".vscode") && Is(name, "settings.json")) return "editor settings";
        return null;
    }

    // Commands, subagents, skills and prompts that an agent loads as instructions: Claude Code, Copilot, Cursor, Codex and Gemini CLI.
    private static bool PromptFile(string slashed, string name, StringComparison c) =>
        (slashed.Contains("/.claude/commands/", c) || slashed.Contains("/.claude/agents/", c) || slashed.Contains("/.cursor/commands/", c)
            || slashed.Contains("/.codex/prompts/", c)) && name.EndsWith(".md", c)
        || (slashed.Contains("/.claude/skills/", c) || slashed.Contains("/.codex/skills/", c)) && name.Equals("SKILL.md", c)
        || slashed.Contains("/.github/prompts/", c) && name.EndsWith(".prompt.md", c)
        || slashed.Contains("/.github/agents/", c) && name.EndsWith(".agent.md", c)
        || slashed.Contains("/.github/chatmodes/", c) && name.EndsWith(".chatmode.md", c)
        || slashed.Contains("/.gemini/commands/", c) && name.EndsWith(".toml", c);
}
