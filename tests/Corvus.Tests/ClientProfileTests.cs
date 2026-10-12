using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Client profiles: detection from clientInfo.name, selection order and explicit overrides.</summary>
public sealed class ClientProfileTests
{
    [Theory]
    [InlineData("claude-code", "claude-code")]
    [InlineData("claude-ai", "claude-desktop")]
    [InlineData("codex-mcp-client", "codex")]
    [InlineData("codex_cli_rs", "codex")]
    [InlineData("gemini-cli-mcp-client", "gemini-cli")]
    [InlineData("Visual Studio Code", "vscode")]
    [InlineData("Visual Studio Code - Insiders", "vscode-insiders")]
    [InlineData("VSCodium", "vscodium")]
    [InlineData("Microsoft Visual Studio", "visual-studio")]
    [InlineData("cursor-vscode", "cursor")]
    [InlineData("windsurf-client", "windsurf")]
    [InlineData("Cline", "cline")]
    [InlineData("Roo Code", "roo-code")]
    [InlineData("Kilo Code", "kilo-code")]
    [InlineData("qwen-code-mcp-client", "qwen-code")]
    [InlineData("github-copilot-cli", "copilot-cli")]
    [InlineData("opencode", "opencode")]
    [InlineData("crush", "crush")]
    [InlineData("Zed", "zed")]
    [InlineData("lm-studio", "lm-studio")]
    [InlineData("Amazon Q", "amazon-q")]
    [InlineData("kiro", "kiro")]
    [InlineData("antigravity-client", "antigravity")]
    [InlineData("devin", "devin")]
    [InlineData("command-code", "command-code")]
    [InlineData("grok-build", "grok-build")]
    [InlineData("omp", "omp")]
    [InlineData("pi-coding-agent", "pi")]
    public void KnownClientNames_AreDetected(string clientInfoName, string id) =>
        Assert.Equal(id, ClientProfiles.Detect(clientInfoName)?.Id);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("corvus-cli")]
    [InlineData("my-own-agent")]
    [InlineData("pipeline")] // a token, not a substring: "pi" does not match
    public void OtherNames_AreUnknown(string? clientInfoName)
    {
        Assert.Null(ClientProfiles.Detect(clientInfoName));
        Assert.Same(ClientProfiles.Unknown, ClientProfiles.Resolve(new ServerOptions(), clientInfoName).Profile);
    }

    [Fact]
    public void EverySetupClient_HasAProfile()
    {
        using var home = new SetupHome();
        var ids = Corvus.Setup.ClientCatalog.All(home.Env(os: Corvus.Setup.HostOs.Windows)).Select(c => c.Id).Order(StringComparer.Ordinal);
        Assert.Equal(ids, ClientProfiles.All.Select(p => p.Id).Order(StringComparer.Ordinal));
        Assert.Equal(27, ClientProfiles.All.Count);
    }

    [Fact]
    public void ProfileValues_FollowTheStandard()
    {
        static ClientLimits Of(string id) => ClientProfiles.Resolve(new ServerOptions { Client = id }, null);
        Assert.Equal(Corvus.Mcp.ToolEffects.MaxResultSizeChars, Of("claude-code").MaxChars);
        Assert.Equal((24_000, 100_000, (int?)null, "full"), (Of("claude-code").MaxTokens, Of("claude-code").MaxChars!.Value, Of("claude-code").DeadlineSeconds, Of("claude-code").Toolsets));
        Assert.Equal((9_500, (int?)null, (int?)60), (Of("codex").MaxTokens, Of("codex").MaxChars, Of("codex").DeadlineSeconds));
        Assert.Equal((9_500, (int?)38_000, (int?)600), (Of("gemini-cli").MaxTokens, Of("gemini-cli").MaxChars, Of("gemini-cli").DeadlineSeconds));
        Assert.Equal((24_000, (int?)140_000, (int?)240), (Of("claude-desktop").MaxTokens, Of("claude-desktop").MaxChars, Of("claude-desktop").DeadlineSeconds));
        Assert.Equal((9_500, (int?)null), (Of("unknown").MaxTokens, Of("unknown").DeadlineSeconds));
        foreach (var id in new[] { "vscode", "vscode-insiders", "vscodium", "visual-studio", "copilot-cli" }) Assert.Equal("lean", Of(id).Toolsets);
        Assert.All(ClientProfiles.All.Where(p => p.DefaultProfile == "lean"), p => Assert.Contains(p.Id, new[] { "vscode", "vscode-insiders", "vscodium", "visual-studio", "copilot-cli" }));
    }

    [Fact]
    public void SelectionOrder_ClientOption_ThenExplicitLimits_ThenHandshake()
    {
        // --client beats the handshake name.
        var installed = ClientProfiles.Resolve(ServerOptions.Parse(["--client", "codex"]), "claude-code");
        Assert.Equal(("codex", "--client", 60), (installed.Profile.Id, installed.Source, installed.DeadlineSeconds!.Value));
        // The handshake decides when nothing was given.
        var detected = ClientProfiles.Resolve(new ServerOptions(), "gemini-cli-mcp-client");
        Assert.Equal(("gemini-cli", "clientInfo", 600), (detected.Profile.Id, detected.Source, detected.DeadlineSeconds!.Value));
        // Explicit limits and --toolsets replace the profile's values.
        var options = ServerOptions.Parse(["--client", "codex", "--client-timeout", "300", "--toolsets", "core"]);
        options.MaxOutputTokens = 20_000;
        var raised = ClientProfiles.Resolve(options, null);
        Assert.Equal((300, "--client-timeout", 20_000, "CORVUS_MAX_OUTPUT_TOKENS", "core"),
            (raised.DeadlineSeconds!.Value, raised.DeadlineSource, raised.MaxTokens, raised.MaxTokensSource, raised.Toolsets));
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--client", "no-such-client"]));
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--client-timeout", "0"]));
    }

    [Fact]
    public void LeanToolsets_SelectTheLeanList()
    {
        var lean = ServerOptions.Parse(["--toolsets", "lean"]);
        Assert.Equal(ClientProfiles.LeanTools, lean.ToolAllowList);
        Assert.Equal(40, ClientProfiles.LeanTools.Count);
        Assert.Equal("lean", ClientProfiles.Resolve(lean, "claude-code").Toolsets);
    }
}
