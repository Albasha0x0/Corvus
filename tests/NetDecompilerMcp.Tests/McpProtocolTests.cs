using System.Collections.Concurrent;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Starts the real server over stdio and drives it with the MCP client, the way Claude Code does:
/// every tool, resources, resource templates, prompts, completion, progress, structured output, errors, cancellation, concurrency.
/// </summary>
public class McpProtocolTests : IAsyncLifetime
{
    private McpClient _client = null!;
    private readonly TempDir _dir = new();

    public async Task InitializeAsync() => _client = await StartServerAsync("--load", Env.FixturePath, "--load", Env.ConsumerPath);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    internal static async Task<McpClient> StartServerAsync(params string[] args)
    {
        var serverDll = typeof(NetDecompilerMcp.Core.AssemblyWorkspace).Assembly.Location;
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "net-decompiler",
            Command = "dotnet",
            Arguments = [serverDll, .. args],
        });
        return await McpClient.CreateAsync(transport);
    }

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));

    private async Task<string> Call(string tool, Dictionary<string, object?> args, bool expectError = false)
    {
        var result = await _client.CallToolAsync(tool, args);
        var text = Text(result);
        Assert.True(expectError == (result.IsError == true), $"{tool} IsError={result.IsError}: {text}");
        return text;
    }

    /// <summary>One successful call per tool. Adding a tool without adding it here fails EveryToolIsCovered.</summary>
    private Dictionary<string, (Dictionary<string, object?> Args, string Expect)> ToolCases() => new()
    {
        ["load_assembly"] = (new() { ["path"] = Env.ConsumerPath }, "TestFixture.Consumer"),
        ["list_assemblies"] = (new(), "TestFixture"),
        ["reload_assembly"] = (new() { ["assembly"] = "TestFixture.Consumer" }, "Reloaded"),
        ["add_search_directory"] = (new() { ["directory"] = Path.GetDirectoryName(Env.FixturePath) }, "Search directories"),
        ["get_assembly_info"] = (new() { ["assembly"] = "TestFixture" }, "Sections:"),
        ["list_namespaces"] = (new() { ["assembly"] = "TestFixture" }, "Fixture.Game"),
        ["list_types"] = (new() { ["namespace"] = "Fixture.Game", ["kind"] = "class" }, "Fixture.Game.Shop"),
        ["get_type_info"] = (new() { ["type"] = "Player" }, "TakeDamage"),
        ["get_type_hierarchy"] = (new() { ["type"] = "Entity" }, "Minion"),
        ["get_attributes"] = (new() { ["symbol"] = "NativeThing::First" }, "RVA = \"0x1000\""),
        ["resolve_symbol"] = (new() { ["symbol"] = "Player::TakeDamage" }, "2 matches"),
        ["decompile_type"] = (new() { ["type"] = "Shop" }, "public class Shop"),
        ["decompile_member"] = (new() { ["member"] = "Player::CheckLicense" }, "Secret.Validate(\"LICENSE-KEY-123\")"),
        ["get_il"] = (new() { ["symbol"] = "Player::CheckLicense" }, "ldstr"),
        ["decompile_assembly_attributes"] = (new() { ["assembly"] = "TestFixture" }, "TargetFramework"),
        ["export_project"] = (new() { ["assembly"] = "TestFixture.Consumer", ["outputDirectory"] = _dir.File("export") }, "Exported"),
        ["search_symbols"] = (new() { ["query"] = "Take*", ["kind"] = "method" }, "TakeDamage"),
        ["search_strings"] = (new() { ["query"] = "LICENSE" }, "CheckLicense"),
        ["search_constants"] = (new() { ["value"] = "0x3E8" }, "Boss::Score"),
        ["search_il"] = (new() { ["pattern"] = "ldstr *LICENSE*; call *Validate*" }, "CheckLicense"),
        ["find_references"] = (new() { ["symbol"] = "Player::TakeDamage(int)" }, "Consumer.Arena::Hit"),
        ["find_callees"] = (new() { ["method"] = "Player::TakeDamage(int, string)", ["distinct"] = true }, "Log"),
        ["find_overrides"] = (new() { ["method"] = "Entity::Score" }, "Boss::Score"),
        ["list_resources"] = (new() { ["assembly"] = "TestFixture" }, "hello.txt"),
        ["get_resource"] = (new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt" }, "Hello from"),
        ["summarize_file"] = (new() { ["assembly"] = "TestFixture" }, "none (loaded assembly)"),
        ["survey_features"] = (new() { ["assembly"] = "TestFixture" }, "\"methodsScanned\""),
        ["extract_strings"] = (new() { ["assembly"] = "TestFixture", ["types"] = "url,domain" }, "\"assembly\":\"TestFixture\""),
        ["extract_embedded"] = (new() { ["assembly"] = "TestFixture" }, "\"contents\""),
        ["search_container"] = (new() { ["path"] = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"), ["query"] = "LZ4Codec", ["kind"] = "type" }, "K4os.Compression.LZ4.LZ4Codec"),
        ["unpack_container"] = (new() { ["path"] = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"), ["outputDirectory"] = _dir.File("unpack"), ["load"] = false }, "NuGet package"),
        ["get_il2cpp_info"] = (new() { ["symbol"] = "NativeThing" }, "RVA=0x1100"),
        ["find_method_by_address"] = (new() { ["address"] = "1004" }, "NativeThing::First"),
        ["rename_symbol"] = (new() { ["symbol"] = "Player", ["newName"] = "Hero", ["dryRun"] = true }, "Dry run"),
        ["rename_namespace"] = (new() { ["assembly"] = "TestFixture", ["oldNamespace"] = "Fixture.Game", ["newNamespace"] = "G", ["dryRun"] = true }, "Dry run"),
        ["stub_method"] = (new() { ["method"] = "Secret::Validate", ["value"] = "true" }, "stub"),
        ["patch_method_csharp"] = (new() { ["method"] = "Shop::PriceOf(string, int)", ["code"] = "return quantity;" }, "Decompiled result"),
        ["patch_method_il"] = (new() { ["method"] = "Player::Score", ["il"] = "ldc.i4.7\nret" }, "New body"),
        ["add_members_csharp"] = (new() { ["type"] = "Shop", ["code"] = "public int Twice(int x) { return x * 2; }" }, "Twice"),
        ["add_types_csharp"] = (new() { ["assembly"] = "TestFixture", ["code"] = "namespace Mods { public static class M { public static int One() => 1; } }" }, "Mods.M"),
        ["list_edits"] = (new() { ["assembly"] = "TestFixture" }, "#5"),
        ["diff_edits"] = (new() { ["assembly"] = "TestFixture" }, "+public int Twice(int x)"),
        ["export_edits"] = (new() { ["assembly"] = "TestFixture", ["path"] = _dir.File("edits.json") }, "Exported 5 edit(s)"),
        ["undo_edit"] = (new() { ["assembly"] = "TestFixture" }, "Undid #5"),
        ["revert_edits"] = (new() { ["assembly"] = "TestFixture" }, "4 edit(s) discarded"),
        ["apply_edits"] = (new() { ["path"] = _dir.File("edits.json") }, "5 applied"),
        ["compare_assemblies"] = (new() { ["oldAssembly"] = "TestFixture", ["newAssembly"] = "TestFixture.Consumer" }, "Comparing TestFixture"),
        ["find_counterpart"] = (new() { ["symbol"] = "Shop", ["oldAssembly"] = "TestFixture", ["newAssembly"] = "TestFixture.Consumer" }, "not found"),
        ["get_call_tree"] = (new() { ["method"] = "Secret::Validate", ["direction"] = "callers" }, "Player::CheckLicense"),
        ["find_call_paths"] = (new() { ["to"] = "Player::TakeDamage(int)", ["from"] = "Consumer.Arena::Hit" }, "1 path"),
        ["export_il2cpp_symbols"] = (new() { ["outputDirectory"] = _dir.File("il2cpp"), ["assembly"] = "TestFixture" }, "Exported 2 functions"),
        ["generate_cpp_binding"] = (new() { ["type"] = "Player" }, "FindClass(api, \"TestFixture\", \"Fixture.Game\", \"Player\")"),
        ["save_assembly"] = (new() { ["assembly"] = "TestFixture", ["outputPath"] = _dir.File("saved.dll") }, "Wrote"),
        ["unload_assembly"] = (new() { ["assembly"] = "TestFixture.Consumer" }, "Unloaded"),
    };

    [Fact]
    public async Task EveryToolIsCoveredAndAnnotated()
    {
        var tools = await _client.ListToolsAsync();
        Assert.Equal(ToolCases().Keys.Order(), tools.Select(t => t.Name).Order());
        foreach (var tool in tools)
        {
            Assert.False(string.IsNullOrWhiteSpace(tool.Description), tool.Name);
            Assert.False(string.IsNullOrWhiteSpace(tool.ProtocolTool.Title), tool.Name);
            Assert.NotNull(tool.ProtocolTool.Annotations);
            Assert.False(tool.ProtocolTool.Annotations!.OpenWorldHint);
        }
        Assert.True(tools.Single(t => t.Name == "decompile_type").ProtocolTool.Annotations!.ReadOnlyHint);
        Assert.True(tools.Single(t => t.Name == "save_assembly").ProtocolTool.Annotations!.DestructiveHint);
    }

    [Fact]
    public async Task EveryToolSucceedsWithValidInput()
    {
        foreach (var (tool, (args, expect)) in ToolCases()) // ordered: unload last
        {
            var text = await Call(tool, args);
            Assert.True(text.Contains(expect, StringComparison.Ordinal), $"{tool}: expected '{expect}' in:\n{text}");
        }
        // The edits made above are visible and saved.
        Assert.Contains("return 7;", await Call("decompile_member", new() { ["member"] = "Player::Score" }));
        Assert.True(File.Exists(_dir.File("saved.dll")));
    }

    [Fact]
    public async Task ServerAdvertisesCapabilitiesAndInstructions()
    {
        Assert.Equal("net-decompiler", _client.ServerInfo.Name);
        Assert.Contains("load_assembly", _client.ServerInstructions);
        Assert.NotNull(_client.ServerCapabilities.Tools);
        Assert.NotNull(_client.ServerCapabilities.Resources);
        Assert.NotNull(_client.ServerCapabilities.Prompts);
        Assert.NotNull(_client.ServerCapabilities.Completions);
    }

    [Fact]
    public async Task StructuredOutput()
    {
        var result = await _client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
        Assert.NotNull(result.StructuredContent);
        var json = result.StructuredContent!.ToString();
        Assert.Contains("\"Assemblies\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("TestFixture.Consumer", json);
    }

    [Fact]
    public async Task ResourcesAndTemplates()
    {
        var resources = await _client.ListResourcesAsync();
        Assert.Contains(resources, r => r.Uri == "netdecomp://assemblies");
        var templates = await _client.ListResourceTemplatesAsync();
        Assert.Equal(3, templates.Count);

        async Task<string> Read(string uri) =>
            string.Join("", (await _client.ReadResourceAsync(uri)).Contents.OfType<TextResourceContents>().Select(c => c.Text));

        Assert.Contains("TestFixture.Consumer", await Read("netdecomp://assemblies"));
        Assert.Contains("public class Player", await Read("netdecomp://assembly/TestFixture/type/Fixture.Game.Player"));
        Assert.Contains("class Inventory", await Read("netdecomp://assembly/TestFixture/type/Fixture.Game.Player%2BInventory"));
        Assert.Contains("ldstr", await Read("netdecomp://assembly/TestFixture/il/Player::CheckLicense"));
        Assert.Contains("Sections:", await Read("netdecomp://assembly/TestFixture/info"));
        await Assert.ThrowsAnyAsync<McpException>(() => Read("netdecomp://assembly/TestFixture/type/Nope.Missing"));
    }

    [Fact]
    public async Task Prompts()
    {
        var prompts = await _client.ListPromptsAsync();
        Assert.Equal(["analyze_assembly", "explain_type", "find_feature", "map_native_address", "plan_patch"], prompts.Select(p => p.Name).Order());
        var result = await _client.GetPromptAsync("find_feature", new Dictionary<string, object?> { ["feature"] = "license check", ["assembly"] = "TestFixture" });
        var text = string.Join("\n", result.Messages.Select(m => (m.Content as TextContentBlock)?.Text));
        Assert.Contains("license check", text);
        Assert.Contains("search_strings", text);
    }

    [Fact]
    public async Task Completions()
    {
        var assemblies = await _client.CompleteAsync(new PromptReference { Name = "explain_type" }, "assembly", "TestF");
        Assert.Contains("TestFixture", assemblies.Completion.Values);
        Assert.Contains("TestFixture.Consumer", assemblies.Completion.Values);

        var types = await _client.CompleteAsync(new ResourceTemplateReference { Uri = "netdecomp://assembly/{assembly}/type/{type}" }, "type", "Fixture.Game.Pl");
        Assert.Contains("Fixture.Game.Player", types.Completion.Values);

        var shortName = await _client.CompleteAsync(new PromptReference { Name = "explain_type" }, "type", "Sho");
        Assert.Contains("Fixture.Game.Shop", shortName.Completion.Values);

        var paths = await _client.CompleteAsync(new PromptReference { Name = "analyze_assembly" }, "path", Path.GetDirectoryName(Env.FixturePath) + Path.DirectorySeparatorChar + "TestFix");
        Assert.Contains(paths.Completion.Values, p => p.EndsWith("TestFixture.dll"));

        var none = await _client.CompleteAsync(new PromptReference { Name = "find_feature" }, "feature", "x");
        Assert.Empty(none.Completion.Values);
    }

    [Fact]
    public async Task ProgressNotifications()
    {
        File.Copy(Env.FixturePath, _dir.File("A.dll"));
        File.Copy(Env.ConsumerPath, _dir.File("B.dll"));
        // Observe notifications with a session-wide handler: the per-call progress callback is unregistered as soon as
        // the response arrives, and the client dispatches notifications asynchronously, so it can miss ones that were
        // on the wire before the response.
        var updates = new ConcurrentQueue<ProgressNotificationParams>();
        await using var handler = _client.RegisterNotificationHandler(NotificationMethods.ProgressNotification, (n, _) =>
        {
            updates.Enqueue(n.Params.Deserialize<ProgressNotificationParams>(McpJsonUtilities.DefaultOptions)!);
            return ValueTask.CompletedTask;
        });
        var result = await _client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = _dir.Path },
            new SyncProgress(_ => { })); // gives the request a progress token
        Assert.NotEqual(true, result.IsError);
        for (int i = 0; i < 250 && updates.Count < 2; i++) await Task.Delay(20);
        Assert.True(updates.Count >= 2, $"expected progress, got {updates.Count}");
        Assert.All(updates, u => Assert.Equal(2, u.Progress.Total));
    }

    [Fact]
    public async Task ErrorsAreToolErrorsAndServerSurvives()
    {
        Assert.Contains("not found", await Call("decompile_type", new() { ["type"] = "Nope.DoesNotExist" }, expectError: true));
        Assert.Contains("File not found", await Call("load_assembly", new() { ["path"] = @"C:\definitely\missing.dll" }, expectError: true));
        Assert.Contains("Unknown kind", await Call("decompile_member", new() { ["member"] = "TakeDamage", ["kind"] = "banana" }, expectError: true));
        Assert.Contains("ambiguous", await Call("find_references", new() { ["symbol"] = "Player::TakeDamage" }, expectError: true));
        Assert.Contains("Invalid regex", await Call("search_symbols", new() { ["query"] = "(", ["regex"] = true }, expectError: true));
        Assert.Contains("compilation failed", await Call("patch_method_csharp", new() { ["method"] = "Shop::Buy", ["code"] = "return nope;" }, expectError: true));
        Assert.Contains("TakeDamage", await Call("get_type_info", new() { ["type"] = "Player" }));
    }

    [Fact]
    public async Task FileChangeNoticesRideAlongWithTheNextResult()
    {
        var path = _dir.File("Watched.dll");
        File.Copy(Env.FixturePath, path);
        await Call("load_assembly", new() { ["path"] = path });
        using (var build = new Env())
        {
            build.Edit(() => build.Edits.Rename(build.One("Shop::Describe"), "DescribeV2"));
            build.Edits.Save(build.Fixture, _dir.File("v2.dll"), false);
        }
        File.Copy(_dir.File("v2.dll"), path, overwrite: true);

        string text = "";
        for (int i = 0; i < 50 && !text.Contains("[workspace]"); i++)
        {
            await Task.Delay(200);
            text = await Call("list_namespaces", new() { ["assembly"] = "TestFixture" });
        }
        Assert.Contains("[workspace]", text);
        Assert.Contains("reloaded", text);
    }

    [Fact]
    public async Task PagingOverTheWire()
    {
        await using var client = await StartServerAsync("--load", Env.FixturePath, "--max-output", "2000");
        var first = Text(await client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Player", ["maxChars"] = 1000 }));
        var match = System.Text.RegularExpressions.Regex.Match(first, @"offset=(\d+)");
        Assert.True(match.Success, $"no truncation footer in {first.Length} chars: {first[..Math.Min(400, first.Length)]}");
        var offset = int.Parse(match.Groups[1].Value);
        var second = Text(await client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Player", ["offset"] = offset, ["maxChars"] = 1000 }));
        Assert.StartsWith($"[Continuing from offset {offset}]", second);
    }

    [Fact]
    public async Task CancellationLeavesServerUsable()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            _client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Player" }, cancellationToken: cts.Token).AsTask());
        Assert.Contains("TakeDamage", await Call("get_type_info", new() { ["type"] = "Player" }));
    }

    [Fact]
    public async Task ParallelReadsAndEditsAreSafe()
    {
        var calls = Enumerable.Range(0, 40).Select(i => (i % 5) switch
        {
            0 => _client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Player" }),
            1 => _client.CallToolAsync("search_strings", new Dictionary<string, object?> { ["query"] = "LICENSE" }),
            2 => _client.CallToolAsync("find_references", new Dictionary<string, object?> { ["symbol"] = "Player::_health" }),
            3 => _client.CallToolAsync("rename_symbol", new Dictionary<string, object?> { ["symbol"] = "Shop::Describe", ["newName"] = i % 2 == 0 ? "Describe" : "Describe" }),
            _ => _client.CallToolAsync("stub_method", new Dictionary<string, object?> { ["method"] = "Player::Score", ["value"] = i.ToString() }),
        }).Select(t => t.AsTask());
        var results = await Task.WhenAll(calls);
        Assert.All(results, r => Assert.NotEqual(true, r.IsError));
    }

    private sealed class SyncProgress(Action<ProgressNotificationValue> report) : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) => report(value);
    }
}
