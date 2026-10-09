using System.Collections.Concurrent;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Drives the real server over stdio with an MCP client; each test starts its own server. The tests are grouped in
/// nested classes so that the groups run in parallel (xUnit runs the tests of one class one after another).
/// </summary>
public abstract class McpProtocolTests : IAsyncLifetime
{
    private McpClient _client = null!;
    private readonly TempDir _dir = new();

    public async Task InitializeAsync() => _client = await StartServerAsync("--load", Env.FixturePath, "--load", Env.ConsumerPath);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private static string ServerDll => typeof(NetDecompilerMcp.Core.AssemblyWorkspace).Assembly.Location;

    /// <summary>A per-run temp folder for annotation sidecars, so tests never touch the real per-user folder.</summary>
    private static readonly string AnnotationsDir = Path.Combine(Path.GetTempPath(), "ndm-annotations-" + Guid.NewGuid().ToString("N"));

    internal static Task<McpClient> StartServerAsync(params string[] args) => StartServerInAsync(null, args);

    /// <summary>Starts a server whose working directory (where relative paths resolve) is <paramref name="workingDirectory"/>.</summary>
    internal static Task<McpClient> StartServerInAsync(string? workingDirectory, params string[] args) => StartServerAsync(workingDirectory, null, args);

    /// <summary>As above, with a client that speaks <paramref name="protocolVersion"/> (null: the SDK's newest).</summary>
    internal static async Task<McpClient> StartServerAsync(string? workingDirectory, string? protocolVersion, string[] args)
    {
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "net-decompiler",
            Command = "dotnet",
            Arguments = [ServerDll, .. args],
            WorkingDirectory = workingDirectory,
            // Keep the annotation sidecars out of the real per-user folder during tests.
            EnvironmentVariables = new Dictionary<string, string?> { ["NDM_ANNOTATIONS_DIR"] = AnnotationsDir },
            // The SDK waits this long for the server to exit before it closes the server's input, then ends it; the
            // server exits on end of input (ServerExitsWhenItsInputCloses), so waiting longer only delays each test.
            ShutdownTimeout = TimeSpan.FromMilliseconds(200),
        });
        return await McpClient.CreateAsync(transport, new McpClientOptions { ProtocolVersion = protocolVersion });
    }

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));

    private async Task<string> Call(string tool, Dictionary<string, object?> args, bool expectError = false)
    {
        var result = await _client.CallToolAsync(tool, args);
        var text = Text(result);
        Assert.True(expectError == (result.IsError == true), $"{tool} IsError={result.IsError}: {text}");
        if (!expectError) await AssertMatchesOutputSchema(_client, tool, result);
        return text;
    }

    private static readonly Dictionary<McpClient, Dictionary<string, JsonElement?>> Schemas = [];

    /// <summary>Validates structured content against the tool's advertised output schema, as clients do.</summary>
    internal static async Task AssertMatchesOutputSchema(McpClient client, string tool, CallToolResult result)
    {
        Dictionary<string, JsonElement?>? schemas;
        lock (Schemas) Schemas.TryGetValue(client, out schemas);
        if (schemas == null)
        {
            schemas = (await client.ListToolsAsync()).ToDictionary(t => t.Name, t => t.ProtocolTool.OutputSchema);
            lock (Schemas) Schemas[client] = schemas;
        }
        if (schemas.GetValueOrDefault(tool) is not { } schema) return;
        Assert.True(result.StructuredContent != null, $"{tool} has an output schema but returned no structured content");
        var value = JsonDocument.Parse(result.StructuredContent!.ToString()!).RootElement;
        var errors = OutputSchema.Validate(schema, value);
        Assert.True(errors.Count == 0, $"{tool}: structured content does not match its output schema:\n  {string.Join("\n  ", errors.Take(20))}");
    }

    /// <summary>One successful call per tool; EveryToolIsCoveredAndAnnotated fails if a tool is missing.</summary>
    /// <summary>A synthetic native DLL (imports, delay imports, exports, debug directory) written as native.dll in the temp folder.</summary>
    internal static string NativeSample(TempDir dir)
    {
        var path = dir.File("native.dll");
        if (!File.Exists(path)) File.WriteAllBytes(path, NativePeTests.KitchenSink(is64: true));
        return path;
    }

    internal static Dictionary<string, (Dictionary<string, object?> Args, string Expect)> ToolCases(TempDir dir) => new()
    {
        ["load_assembly"] = (new() { ["path"] = Env.ConsumerPath }, "TestFixture.Consumer"),
        ["list_assemblies"] = (new(), "TestFixture"),
        ["reload_assembly"] = (new() { ["assembly"] = "TestFixture.Consumer" }, "Reloaded"),
        ["add_search_directory"] = (new() { ["directory"] = Path.GetDirectoryName(Env.FixturePath) }, "Search directories"),
        ["get_assembly_info"] = (new() { ["assembly"] = "TestFixture" }, "Sections:"),
        ["list_namespaces"] = (new() { ["assembly"] = "TestFixture" }, "Fixture.Model"),
        ["list_types"] = (new() { ["namespace"] = "Fixture.Model", ["kind"] = "class" }, "Fixture.Model.Shop"),
        ["get_type_info"] = (new() { ["type"] = "Account" }, "Charge"),
        ["get_type_hierarchy"] = (new() { ["type"] = "Entity" }, "Archive"),
        ["get_attributes"] = (new() { ["symbol"] = "NativeThing::First" }, "RVA = \"0x1000\""),
        ["resolve_symbol"] = (new() { ["symbol"] = "Account::Charge" }, "2 matches"),
        ["decompile_type"] = (new() { ["type"] = "Shop" }, "public class Shop"),
        ["decompile_member"] = (new() { ["member"] = "Account::CheckLicense" }, "Secret.Validate(\"LICENSE-KEY-123\")"),
        ["get_il"] = (new() { ["symbol"] = "Account::CheckLicense" }, "ldstr"),
        ["decompile_assembly_attributes"] = (new() { ["assembly"] = "TestFixture" }, "TargetFramework"),
        ["export_project"] = (new() { ["assembly"] = "TestFixture.Consumer", ["outputDirectory"] = dir.File("export") }, "Exported"),
        ["search_symbols"] = (new() { ["query"] = "Charg*", ["kind"] = "method" }, "Charge"),
        ["search_strings"] = (new() { ["query"] = "LICENSE" }, "CheckLicense"),
        ["search_constants"] = (new() { ["value"] = "0x3E8" }, "PremiumAccount::Score"),
        ["search_il"] = (new() { ["pattern"] = "ldstr *LICENSE*; call *Validate*" }, "CheckLicense"),
        ["find_references"] = (new() { ["symbol"] = "Account::Charge(int)" }, "Consumer.Branch::Bill"),
        ["find_callees"] = (new() { ["method"] = "Account::Charge(int, string)", ["distinct"] = true }, "Log"),
        ["find_overrides"] = (new() { ["method"] = "Entity::Score" }, "PremiumAccount::Score"),
        ["list_resources"] = (new() { ["assembly"] = "TestFixture" }, "hello.txt"),
        ["get_resource"] = (new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt" }, "Hello from"),
        ["summarize_file"] = (new() { ["assembly"] = "TestFixture" }, "none (loaded assembly)"),
        ["survey_features"] = (new() { ["assembly"] = "TestFixture" }, "\"methodsScanned\""),
        ["extract_strings"] = (new() { ["assembly"] = "TestFixture", ["types"] = "url,domain" }, "\"assembly\":\"TestFixture\""),
        ["extract_embedded"] = (new() { ["assembly"] = "TestFixture" }, "\"contents\""),
        ["search_container"] = (new() { ["path"] = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"), ["query"] = "LZ4Codec", ["kind"] = "type" }, "K4os.Compression.LZ4.LZ4Codec"),
        ["unpack_container"] = (new() { ["path"] = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"), ["outputDirectory"] = dir.File("unpack"), ["load"] = false }, "NuGet package"),
        ["get_il2cpp_info"] = (new() { ["symbol"] = "NativeThing" }, "RVA=0x1100"),
        ["find_method_by_address"] = (new() { ["address"] = "1004" }, "NativeThing::First"),
        ["rename_symbol"] = (new() { ["symbol"] = "Account", ["newName"] = "Customer", ["dryRun"] = true }, "Dry run"),
        ["rename_namespace"] = (new() { ["assembly"] = "TestFixture", ["oldNamespace"] = "Fixture.Model", ["newNamespace"] = "G", ["dryRun"] = true }, "Dry run"),
        ["stub_method"] = (new() { ["method"] = "Secret::Validate", ["value"] = "true" }, "stub"),
        ["patch_method_csharp"] = (new() { ["method"] = "Shop::PriceOf(string, int)", ["code"] = "return quantity;" }, "Decompiled result"),
        ["patch_method_il"] = (new() { ["method"] = "Account::Score", ["il"] = "ldc.i4.7\nret" }, "New body"),
        ["add_members_csharp"] = (new() { ["type"] = "Shop", ["code"] = "public int Twice(int x) { return x * 2; }" }, "Twice"),
        ["simplify_methods"] = (new() { ["symbol"] = "Account", ["dryRun"] = true }, "Dry run — simplify Fixture.Model.Account"),
        ["add_types_csharp"] = (new() { ["assembly"] = "TestFixture", ["code"] = "namespace Mods { public static class M { public static int One() => 1; } }" }, "Mods.M"),
        ["list_edits"] = (new() { ["assembly"] = "TestFixture" }, "#5"),
        ["diff_edits"] = (new() { ["assembly"] = "TestFixture" }, "+public int Twice(int x)"),
        ["export_edits"] = (new() { ["assembly"] = "TestFixture", ["path"] = dir.File("edits.json") }, "Exported 5 edit(s)"),
        ["undo_edit"] = (new() { ["assembly"] = "TestFixture" }, "Undid #5"),
        ["revert_edits"] = (new() { ["assembly"] = "TestFixture" }, "4 edit(s) discarded"),
        ["apply_edits"] = (new() { ["path"] = dir.File("edits.json") }, "5 applied"),
        ["compare_assemblies"] = (new() { ["oldAssembly"] = "TestFixture", ["newAssembly"] = "TestFixture.Consumer" }, "Comparing TestFixture"),
        ["find_counterpart"] = (new() { ["symbol"] = "Shop", ["oldAssembly"] = "TestFixture", ["newAssembly"] = "TestFixture.Consumer" }, "not found"),
        ["get_call_tree"] = (new() { ["method"] = "Secret::Validate", ["direction"] = "callers" }, "Account::CheckLicense"),
        ["find_call_paths"] = (new() { ["to"] = "Account::Charge(int)", ["from"] = "Consumer.Branch::Bill" }, "1 path"),
        ["export_il2cpp_symbols"] = (new() { ["outputDirectory"] = dir.File("il2cpp"), ["assembly"] = "TestFixture" }, "Exported 2 functions"),
        ["generate_cpp_binding"] = (new() { ["type"] = "Account" }, "FindClass(api, \"TestFixture\", \"Fixture.Model\", \"Account\")"),
        ["save_assembly"] = (new() { ["assembly"] = "TestFixture", ["outputPath"] = dir.File("saved.dll") }, "Wrote"),
        ["server_status"] = (new(), "\"catalogDigest\""),
        ["get_pe_info"] = (new() { ["image"] = NativeSample(dir) }, "seed.pdb"),
        ["list_imports"] = (new() { ["image"] = NativeSample(dir) }, "KERNEL32.dll!ExitProcess"),
        ["list_exports"] = (new() { ["image"] = NativeSample(dir) }, "First"),
        ["resolve_address"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First" }, "export First"),
        ["search_bytes"] = (new() { ["image"] = NativeSample(dir), ["pattern"] = "ExitProcess", ["text"] = true }, "1 hit"),
        ["read_bytes"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["length"] = 32 }, "32 bytes"),
        ["list_cpp_classes"] = (new() { ["image"] = NativeSample(dir) }, "0 classes with RTTI"),
        ["list_functions"] = (new() { ["image"] = NativeSample(dir) }, "function"),
        ["disassemble"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First" }, "First"),
        ["get_cfg"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First" }, "block"),
        ["find_xrefs"] = (new() { ["image"] = NativeSample(dir), ["address"] = "KERNEL32!ExitProcess" }, "References to"),
        ["native_call_tree"] = (new() { ["image"] = NativeSample(dir), ["function"] = "First" }, "First"),
        ["search_native_strings"] = (new() { ["image"] = NativeSample(dir) }, "string"),
        ["decompile_native"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["engine"] = "ghidra" }, "Error (invalid_argument) in decompile_native: Unknown engine"),
        ["rename_native"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["name"] = "SweepFunc" }, "Named"),
        ["comment_native"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["text"] = "entry" }, "Commented"),
        ["export_native_annotations"] = (new() { ["image"] = NativeSample(dir), ["outputPath"] = dir.File("ann.py"), ["format"] = "ida" }, "Exported"),
        ["patch_asm"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["assembly"] = "nop", ["dryRun"] = true }, "Dry run"),
        ["patch_bytes"] = (new() { ["image"] = NativeSample(dir), ["address"] = "First", ["hex"] = "90" }, "Patched"),
        ["list_native_edits"] = (new() { ["image"] = NativeSample(dir) }, "native edit"),
        ["save_native"] = (new() { ["image"] = NativeSample(dir), ["outputPath"] = dir.File("patched.dll") }, "Wrote"),
        ["undo_native_edit"] = (new() { ["image"] = NativeSample(dir) }, "Undid"),
        ["verify_native_imports"] = (new() { ["assembly"] = "TestFixture" }, "TestFixture"),
        ["get_r2r_code"] = R2RFramework.Linq is { } linq
            ? (new() { ["method"] = "System.Linq.Enumerable::Any", ["assembly"] = linq, ["maxBodies"] = 1 }, "native code in System.Linq.dll")
            : (new() { ["method"] = "Account::Score" }, "Error (unsupported) in get_r2r_code"),
        ["find_r2r_method"] = R2RFramework.LinqEntryVa() is { } va
            ? (new() { ["assembly"] = R2RFramework.Linq, ["address"] = va }, "+0x0 into the hot code")
            : (new() { ["assembly"] = "TestFixture", ["address"] = "0x1000" }, "Error (unsupported) in find_r2r_method"),
        ["read_result"] = (new() { ["id"] = "r999" }, "Error (not_found) in read_result"),
        ["unload_assembly"] = (new() { ["assembly"] = "TestFixture.Consumer" }, "Unloaded"),
    };

    /// <summary>Every tool: listed, annotated and callable.</summary>
    public sealed class Tools : McpProtocolTests
    {
        [Fact]
        public async Task EveryToolIsCoveredAndAnnotated()
        {
            var tools = await _client.ListToolsAsync();
            Assert.Equal(ToolCases(_dir).Keys.Order(), tools.Select(t => t.Name).Order());
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

        [Trait("Speed", "Slow")]
        [Fact]
        public async Task EveryToolSucceedsWithValidInput()
        {
            foreach (var (tool, (args, expect)) in ToolCases(_dir)) // order matters: edits build on each other, unload last
            {
                var text = await Call(tool, args, expectError: expect.StartsWith("Error (", StringComparison.Ordinal));
                Assert.True(text.Contains(expect, StringComparison.Ordinal), $"{tool}: expected '{expect}' in:\n{text}");
            }
            Assert.Contains("return 7;", await Call("decompile_member", new() { ["member"] = "Account::Score" }));
            Assert.Contains("// Simplified view", await Call("decompile_member", new() { ["member"] = "Account::CheckLicense", ["simplified"] = true }));
            Assert.True(File.Exists(_dir.File("saved.dll")));
        }
    }

    /// <summary>Capabilities, resources, prompts and completions.</summary>
    public sealed class Discovery : McpProtocolTests
    {
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

        [Trait("Speed", "Slow")]
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
            Assert.Contains("public class Account", await Read("netdecomp://assembly/TestFixture/type/Fixture.Model.Account"));
            Assert.Contains("class Inventory", await Read("netdecomp://assembly/TestFixture/type/Fixture.Model.Account%2BInventory"));
            Assert.Contains("ldstr", await Read("netdecomp://assembly/TestFixture/il/Account::CheckLicense"));
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

            var types = await _client.CompleteAsync(new ResourceTemplateReference { Uri = "netdecomp://assembly/{assembly}/type/{type}" }, "type", "Fixture.Model.Acc");
            Assert.Contains("Fixture.Model.Account", types.Completion.Values);

            var shortName = await _client.CompleteAsync(new PromptReference { Name = "explain_type" }, "type", "Sho");
            Assert.Contains("Fixture.Model.Shop", shortName.Completion.Values);

            var paths = await _client.CompleteAsync(new PromptReference { Name = "analyze_assembly" }, "path", Path.GetDirectoryName(Env.FixturePath) + Path.DirectorySeparatorChar + "TestFix");
            Assert.Contains(paths.Completion.Values, p => p.EndsWith("TestFixture.dll"));

            var none = await _client.CompleteAsync(new PromptReference { Name = "find_feature" }, "feature", "x");
            Assert.Empty(none.Completion.Values);
        }
    }

    /// <summary>Notifications sent alongside results.</summary>
    public sealed class Notifications : McpProtocolTests
    {
        [Fact]
        public async Task ProgressNotifications()
        {
            File.Copy(Env.FixturePath, _dir.File("A.dll"));
            File.Copy(Env.ConsumerPath, _dir.File("B.dll"));
            // Session-wide handler: the per-call callback is removed on response and can miss in-flight notifications.
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

        [Trait("Speed", "Slow")]
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
    }

    /// <summary>Errors and cancellation leave the server usable.</summary>
    public sealed class Errors : McpProtocolTests
    {
        [Trait("Speed", "Slow")]
        [Fact]
        public async Task ErrorsAreToolErrorsAndServerSurvives()
        {
            Assert.Contains("not found", await Call("decompile_type", new() { ["type"] = "Nope.DoesNotExist" }, expectError: true));
            Assert.Contains("File not found", await Call("load_assembly", new() { ["path"] = @"C:\definitely\missing.dll" }, expectError: true));
            Assert.Contains("Unknown kind", await Call("decompile_member", new() { ["member"] = "Charge", ["kind"] = "banana" }, expectError: true));
            Assert.Contains("ambiguous", await Call("find_references", new() { ["symbol"] = "Account::Charge" }, expectError: true));
            Assert.Contains("Invalid regex", await Call("search_symbols", new() { ["query"] = "(", ["regex"] = true }, expectError: true));
            Assert.Contains("compilation failed", await Call("patch_method_csharp", new() { ["method"] = "Shop::Buy", ["code"] = "return nope;" }, expectError: true));
            Assert.Contains("Charge", await Call("get_type_info", new() { ["type"] = "Account" }));
        }

        [Fact]
        public async Task CancellationLeavesServerUsable()
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                _client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Account" }, cancellationToken: cts.Token).AsTask());
            Assert.Contains("Charge", await Call("get_type_info", new() { ["type"] = "Account" }));
        }
    }

    /// <summary>Long results over the wire.</summary>
    public sealed class Paging : McpProtocolTests
    {
        [Trait("Speed", "Slow")]
        [Fact]
        public async Task PagingOverTheWire()
        {
            await using var client = await StartServerAsync("--load", Env.FixturePath, "--max-output", "2000");
            var first = Text(await client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Account", ["maxChars"] = 1000 }));
            var match = System.Text.RegularExpressions.Regex.Match(first, @"offset=(\d+)");
            Assert.True(match.Success, $"no truncation footer in {first.Length} chars: {first[..Math.Min(400, first.Length)]}");
            var offset = int.Parse(match.Groups[1].Value);
            var second = Text(await client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Account", ["offset"] = offset, ["maxChars"] = 1000 }));
            Assert.StartsWith($"[Continuing from offset {offset}]", second);
        }
    }

    /// <summary>Concurrent calls.</summary>
    public sealed class Concurrency : McpProtocolTests
    {
        [Fact]
        public async Task ParallelReadsAndEditsAreSafe()
        {
            var calls = Enumerable.Range(0, 40).Select(i => (i % 5) switch
            {
                0 => _client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Account" }),
                1 => _client.CallToolAsync("search_strings", new Dictionary<string, object?> { ["query"] = "LICENSE" }),
                2 => _client.CallToolAsync("find_references", new Dictionary<string, object?> { ["symbol"] = "Account::_balance" }),
                3 => _client.CallToolAsync("rename_symbol", new Dictionary<string, object?> { ["symbol"] = "Shop::Describe", ["newName"] = i % 2 == 0 ? "Describe" : "Describe" }),
                _ => _client.CallToolAsync("stub_method", new Dictionary<string, object?> { ["method"] = "Account::Score", ["value"] = i.ToString() }),
            }).Select(t => t.AsTask());
            var results = await Task.WhenAll(calls);
            Assert.All(results, r => Assert.NotEqual(true, r.IsError));
        }
    }

    /// <summary>The process itself.</summary>
    public sealed class Lifetime : McpProtocolTests
    {
        /// <summary>A client that closes the server's input (ends the session) gets a server that exits, cleanly and promptly.</summary>
        [Fact]
        public void ServerExitsWhenItsInputCloses()
        {
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
            psi.ArgumentList.Add(ServerDll);
            psi.ArgumentList.Add("--load");
            psi.ArgumentList.Add(Env.FixturePath);
            using var process = System.Diagnostics.Process.Start(psi)!;
            process.OutputDataReceived += (_, _) => { };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.StandardInput.Close();
            bool exited = process.WaitForExit(30_000);
            if (!exited) process.Kill(entireProcessTree: true);
            Assert.True(exited, "the server kept running after its input closed");
            Assert.Equal(0, process.ExitCode);
        }
    }

    private sealed class SyncProgress(Action<ProgressNotificationValue> report) : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) => report(value);
    }
}
