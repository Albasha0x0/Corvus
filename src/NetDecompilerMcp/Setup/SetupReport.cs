using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace NetDecompilerMcp.Setup;

/// <summary>The --json record of install, uninstall, update and status: one shape for all of them.</summary>
internal sealed class SetupReport
{
    public required string Command { get; init; }
    public string Version { get; init; } = Installation.Version;
    public string? Executable { get; init; } = Environment.ProcessPath;
    public required LaunchReport Launch { get; init; }
    public bool DryRun { get; init; }
    /// <summary>Whether any configuration file was written.</summary>
    public bool Applied { get; set; }
    public ServerReport? Server { get; set; }
    public List<ClientReport> Clients { get; } = [];
    public List<CheckReport> Engines { get; } = [];
    public CheckReport? Target { get; set; }
    /// <summary>Program files uninstall deletes and data it keeps.</summary>
    public RemovalReport? Removal { get; set; }
    /// <summary>Follow-up commands, such as the one that adds clients a non-interactive install left out.</summary>
    public List<string> Notes { get; } = [];
    public bool Healthy { get; set; } = true;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Options);
}

internal sealed record LaunchReport(string Command, IReadOnlyList<string> Args);

/// <summary>One client: where its file is, what is registered, and what the command did or would do.</summary>
internal sealed class ClientReport
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public bool Detected { get; init; }
    public required string ConfigPath { get; init; }
    /// <summary>A <see cref="SetupAction"/> value.</summary>
    public string Action { get; set; } = SetupAction.Skip;
    /// <summary>A detected client without a registration: added only with --yes, --all-detected or a confirmation.</summary>
    public bool NeedsConsent { get; set; }
    /// <summary>A status classification (status only): healthy, not_registered, other_copy, missing_program, disabled, ...</summary>
    public string? State { get; set; }
    public RegisteredEntry? Registered { get; init; }
    public bool Disabled => Registered?.Disabled == true;
    public string? BackupPath { get; set; }
    public bool? PreservesComments { get; set; }
    public JsonNode? Before { get; set; }
    public JsonNode? After { get; set; }
    public string? Message { get; set; }
    public string? Remediation { get; set; }
    /// <summary>The self-test of this client's own command, args and env (status only).</summary>
    public ServerReport? Server { get; set; }
    [JsonIgnore] public McpClient? Client { get; init; }
}

/// <summary>A server start and handshake, and how its catalog compares with this build's.</summary>
internal sealed record ServerReport(bool Ok, string Detail, double Seconds, string? Version, int? Tools, string? Digest, bool? MatchesThisBuild, IReadOnlyList<string> Differences)
{
    public static ServerReport From(SelfTest.Result test)
    {
        if (!test.Ok || test.ToolList == null) return new ServerReport(false, test.Detail, test.Seconds, test.Version, null, null, null, []);
        var (tools, prompts) = NetDecompilerMcp.Mcp.Catalog.OfThisBuild();
        var expected = NetDecompilerMcp.Mcp.Catalog.Digest(tools, prompts);
        var installed = NetDecompilerMcp.Mcp.Catalog.Digest(test.ToolList, test.PromptList ?? []);
        var differences = new List<string>();
        void Compare(string kind, SortedDictionary<string, string> build, SortedDictionary<string, string> server)
        {
            var missing = build.Keys.Except(server.Keys).ToList();
            var extra = server.Keys.Except(build.Keys).ToList();
            var changed = build.Keys.Intersect(server.Keys).Where(k => build[k] != server[k]).ToList();
            if (missing.Count > 0) differences.Add($"missing {kind} {string.Join(", ", missing)}");
            if (extra.Count > 0) differences.Add($"extra {kind} {string.Join(", ", extra)}");
            if (changed.Count > 0) differences.Add($"changed {kind} {string.Join(", ", changed.Take(20))}{(changed.Count > 20 ? $" and {changed.Count - 20} more" : "")}");
        }
        if (expected != installed)
        {
            Compare("tools", NetDecompilerMcp.Mcp.Catalog.ToolHashes(tools), NetDecompilerMcp.Mcp.Catalog.ToolHashes(test.ToolList));
            Compare("prompts", NetDecompilerMcp.Mcp.Catalog.PromptHashes(prompts), NetDecompilerMcp.Mcp.Catalog.PromptHashes(test.PromptList ?? []));
        }
        return new ServerReport(true, test.Detail, test.Seconds, test.Version, test.ToolList.Count, installed, expected == installed, differences);
    }

    /// <summary>The catalog line of the text output.</summary>
    public string CatalogLine()
    {
        if (MatchesThisBuild == true) return $"Tool catalog: matches this build ({Tools} tools); digest {Digest}";
        var (tools, prompts) = NetDecompilerMcp.Mcp.Catalog.OfThisBuild();
        return "Tool catalog differs from this build (the registered server is another version; run: NetDecompilerMcp install): " +
               $"digest {Digest}, this build {NetDecompilerMcp.Mcp.Catalog.Digest(tools, prompts)}; {string.Join("; ", Differences)}";
    }
}

/// <summary>One readiness check: an engine, a target file or a client.</summary>
internal sealed record CheckReport(string Name, bool Ok, string Classification, string Detail, string? Remediation);

internal sealed record RemovalReport(IReadOnlyList<string> Delete, string DataRoot, IReadOnlyList<string> Kept);
