using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// D1/D2 on real inputs over stdio: every default page within its class budget + 5% per part (text and structured content
/// each), maxTokens=24000 within 24k + 5%, no read-only size error, the same rows in both parts, one continuation, and a
/// walk of pages that equals a walk of larger pages.
/// </summary>
[Trait("Speed", "Slow")]
public sealed partial class OutputBudgetTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private const int Ceiling = 24_000;
    private readonly TempDir _dir = new();
    private McpClient _client = null!;

    private static string CoreLib => RealPackages.File("Microsoft.NETCore.App.Runtime.linux-arm64", "10.0.11", "runtimes", "linux-arm64", "lib", "net10.0", "System.Private.CoreLib.dll");
    private static string Skia => RealPackages.File("SkiaSharp.NativeAssets.Linux", "3.119.4", "runtimes", "linux-x64", "native", "libSkiaSharp.so");
    private static string PackDir(string rid) => Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(RealPackages.File(
        $"Microsoft.NETCore.App.Runtime.{rid}", "10.0.11", "runtimes", rid, "lib", "net10.0", "System.Private.CoreLib.dll")))!)!;

    public async Task InitializeAsync() => _client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch", "--load", CoreLib],
        new Dictionary<string, string?> { ["CORVUS_MAX_OUTPUT_TOKENS"] = Ceiling.ToString() });

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    /// <summary>The problems of one result, as lines (empty when it keeps the contract).</summary>
    private static List<string> Problems(string tool, Dictionary<string, object?> args, CallToolResult r)
    {
        var problems = new List<string>();
        var text = Text(r);
        string what = $"{tool}({string.Join(", ", args.Where(a => a.Key is not ("path" or "assembly" or "image")).Select(a => $"{a.Key}={a.Value}"))})";
        if (r.IsError == true) { problems.Add($"{what}: error {text[..Math.Min(300, text.Length)]}"); return problems; }
        int budget = args.TryGetValue("maxTokens", out var m) && m is int asked ? Math.Min(asked, Ceiling) : OutputClasses.Budget(ToolContract.Of(tool).Output);
        int limit = budget * 105 / 100;
        int textTokens = TokenEstimate.Of(text);
        if (textTokens > limit) problems.Add($"{what}: text {textTokens} tokens, over {limit}");
        if (r.StructuredContent is not { } s) return problems;
        var raw = s.GetRawText();
        int structuredTokens = TokenEstimate.Of(raw);
        if (structuredTokens > limit) problems.Add($"{what}: structured {structuredTokens} tokens, over {limit}");
        if (raw.Contains(":null", StringComparison.Ordinal)) problems.Add($"{what}: structured content has :null");
        if (text == raw) problems.Add($"{what}: the text block is the structured JSON");
        var json = JsonDocument.Parse(raw).RootElement;
        if (json.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array && json.TryGetProperty("offset", out var o))
        {
            int n = items.GetArrayLength(), offset = o.GetInt32();
            if (json.TryGetProperty("truncated", out _)) problems.Add($"{what}: a list record has truncated");
            bool more = json.TryGetProperty("hasMore", out var h) && h.GetBoolean();
            if (more && (!json.TryGetProperty("nextOffset", out var next) || !text.Contains($"offset={next.GetInt32()}", StringComparison.Ordinal)))
                problems.Add($"{what}: hasMore without a nextOffset named in the text");
            if (Showing().Match(text) is { Success: true } shown && int.Parse(shown.Groups[2].Value) - int.Parse(shown.Groups[1].Value) + 1 != n)
                problems.Add($"{what}: the text shows {shown.Value}, the record {n} rows from {offset}");
        }
        return problems;
    }

    [GeneratedRegex(@"\(showing (\d+)-(\d+)\)")]
    private static partial Regex Showing();

    private async Task<List<string>> Run(IEnumerable<(string Tool, Dictionary<string, object?> Args)> calls)
    {
        var problems = new List<string>();
        foreach (var (tool, args) in calls)
            foreach (var variant in new[] { args, new Dictionary<string, object?>(args) { ["maxTokens"] = Ceiling } })
            {
                if (variant.ContainsKey("maxTokens") && !HasParameter(tool, "maxTokens") && !IsList(tool)) continue;
                var watch = System.Diagnostics.Stopwatch.StartNew();
                var r = await _client.CallToolAsync(tool, variant.Where(a => a.Key != "maxTokens" || HasParameter(tool, "maxTokens")).ToDictionary());
                output.WriteLine($"{tool} {(variant.ContainsKey("maxTokens") ? "maxTokens " : "")}: text {TokenEstimate.Of(Text(r))}, structured " +
                                 $"{(r.StructuredContent is { } s ? TokenEstimate.Of(s.GetRawText()) : 0)} tokens, {watch.ElapsedMilliseconds} ms");
                problems.AddRange(Problems(tool, variant.ContainsKey("maxTokens") && !HasParameter(tool, "maxTokens") ? args : variant, r));
            }
        return problems;
    }

    private IList<McpClientTool>? _tools;

    private bool HasParameter(string tool, string parameter)
    {
        _tools ??= _client.ListToolsAsync().AsTask().GetAwaiter().GetResult();
        return _tools.Single(t => t.Name == tool).ProtocolTool.InputSchema.GetProperty("properties").TryGetProperty(parameter, out _);
    }

    private static bool IsList(string tool) => ToolContract.Of(tool).Output == OutputClass.List;

    [Fact]
    public async Task DefaultPagesOnCoreLibFitTheirBudget()
    {
        var problems = await Run(
        [
            ("list_types", new() { ["assembly"] = "System.Private.CoreLib" }),
            ("list_namespaces", new() { ["assembly"] = "System.Private.CoreLib" }),
            ("search_symbols", new() { ["query"] = "Get", ["limit"] = 5_000 }),
            ("search_strings", new() { ["query"] = "e", ["limit"] = 100_000 }),
            ("find_references", new() { ["symbol"] = "System.String::Concat(string, string)", ["limit"] = 5_000 }),
            ("search_il", new() { ["pattern"] = "call *", ["limit"] = 5_000 }),
            ("get_type_info", new() { ["type"] = "System.String" }),
            ("decompile_member", new() { ["member"] = "System.String" }),
            ("get_il", new() { ["symbol"] = "System.String" }),
            ("get_assembly_info", new() { ["assembly"] = "System.Private.CoreLib" }),
            ("verify_native_imports", new() { ["assembly"] = "System.Private.CoreLib" }),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>Two CoreLib builds compared, and a whole-assembly simplify dry run whose full report stays readable through read_result.</summary>
    [Fact]
    public async Task ACoreLibComparisonAndAWholeAssemblySimplifyFitTheirBudget()
    {
        var other = RealPackages.File("Microsoft.NETCore.App.Runtime.osx-arm64", "10.0.11", "runtimes", "osx-arm64", "lib", "net10.0", "System.Private.CoreLib.dll");
        var json = RealPackages.File("Newtonsoft.Json", "13.0.4", "lib", "net6.0", "Newtonsoft.Json.dll");
        foreach (var path in new[] { other, json })
            Assert.NotEqual(true, (await _client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path })).IsError);
        var problems = await Run(
        [
            ("compare_assemblies", new() { ["oldAssembly"] = "System.Private.CoreLib", ["newAssembly"] = "System.Private.CoreLib#2" }),
            ("simplify_methods", new() { ["assembly"] = "Newtonsoft.Json" }),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
        var cut = Text(await _client.CallToolAsync("simplify_methods", new Dictionary<string, object?> { ["assembly"] = "Newtonsoft.Json" }));
        var id = Regex.Match(cut, @"read_result id=(r-[0-9a-f]+)").Groups[1].Value;
        var whole = await _client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = id, ["outputPath"] = _dir.File("simplify.txt") });
        Assert.NotEqual(true, whole.IsError);
        Assert.True(new FileInfo(_dir.File("simplify.txt")).Length > cut.Length * 2, $"the kept report is not the whole outcome: {Text(whole)}");
    }

    [Fact]
    public async Task DefaultPagesOnANativeLibraryFitTheirBudget()
    {
        var problems = await Run(
        [
            ("list_exports", new() { ["image"] = Skia }),
            ("list_imports", new() { ["image"] = Skia }),
            ("list_functions", new() { ["image"] = Skia }),
            ("search_native_strings", new() { ["image"] = Skia, ["query"] = "a" }),
            ("get_pe_info", new() { ["image"] = Skia }),
            ("compare_folders", new() { ["oldPath"] = PackDir("linux-arm64"), ["newPath"] = PackDir("osx-arm64") }),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>
    /// Every native reading tool's default page on a C++ ELF (libSkiaSharp), a C PE and a C ELF (e_sqlite3): within its class
    /// budget per part, same rows in both parts, one continuation.
    /// </summary>
    [Theory]
    [InlineData("SkiaSharp.NativeAssets.Linux", "3.119.4", "linux-x64", "libSkiaSharp.so", "sk_canvas_draw_rect")]
    [InlineData("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "win-x64", "e_sqlite3.dll", "sqlite3_open")]
    [InlineData("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "linux-x64", "libe_sqlite3.so", "sqlite3_open")]
    public async Task DefaultNativePagesFitTheirBudget(string package, string version, string rid, string file, string function)
    {
        var image = RealPackages.File(package, version, "runtimes", rid, "native", file);
        Dictionary<string, object?> On(params (string Key, object? Value)[] more) => new[] { ("image", (object?)image) }.Concat(more).ToDictionary(p => p.Item1, p => p.Item2);
        var problems = await Run(
        [
            ("list_exports", On()), ("list_imports", On()), ("list_functions", On()), ("list_globals", On()), ("list_cpp_classes", On()),
            ("get_exception_info", On()), ("get_pe_info", On()), ("search_native_strings", On()), ("search_instructions", On(("mnemonic", "^call$"))),
            ("find_xrefs", On(("address", function))), ("disassemble", On(("address", function))), ("inspect_instruction", On(("address", function), ("limit", 64))),
            ("get_cfg", On(("address", function))), ("native_call_tree", On(("function", function))), ("analyze_native_function", On(("address", function))),
            ("get_call_arguments", On(("address", function))), ("resolve_call_targets", On(("scope", "image"))), ("trace_native_values", On(("address", function), ("argument", "1"))),
            ("find_virtual_calls", On()), ("find_similar_functions", On(("view", "duplicates"))), ("read_bytes", On(("address", function), ("length", 65536))),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>FINDINGS-4 on a real APK (CORVUS_ANDROID_PACKAGE): pages with nextOffset, not limit_exceeded.</summary>
    [RequiresRealDataFact(RealData.AndroidPackage)]
    public async Task AndroidListsArePagesNotErrors()
    {
        var apk = RealData.Path(RealData.AndroidPackage);
        var problems = await Run(
        [
            ("list_dex_classes", new() { ["path"] = apk }),
            ("list_dex_classes", new() { ["path"] = apk, ["offset"] = 200, ["limit"] = 200 }),
            ("find_dex_references", new() { ["path"] = apk, ["target"] = "Landroid/util/Log;" }),
            ("list_android_resources", new() { ["path"] = apk }),
            ("search_dex", new() { ["path"] = apk, ["kind"] = "string", ["query"] = "a" }),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
        var first = await _client.CallToolAsync("list_dex_classes", new Dictionary<string, object?> { ["path"] = apk });
        Assert.True(JsonDocument.Parse(first.StructuredContent!.Value.GetRawText()).RootElement.GetProperty("nextOffset").GetInt32() > 0);
    }

    /// <summary>An Il2Cpp game folder (GameAssembly + global-metadata.dat), loaded through the built-in metadata reader.</summary>
    public const string Il2CppGame = "CORVUS_IL2CPP_GAME";

    [RequiresRealDataFact(Il2CppGame)]
    public async Task Il2CppPagesFitTheirBudget()
    {
        var load = await _client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = RealData.Path(Il2CppGame) });
        Assert.True(load.IsError != true, Text(load));
        var problems = await Run(
        [
            ("list_assemblies", new()),
            ("list_types", new() { ["assembly"] = "Assembly-CSharp" }),
            ("search_symbols", new() { ["query"] = "Update", ["limit"] = 5_000 }),
            ("search_strings", new() { ["query"] = "a", ["limit"] = 5_000 }),
            ("get_assembly_info", new() { ["assembly"] = "Assembly-CSharp" }),
        ]);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>A walk of budget-cut pages gives the same rows, in order, without gaps or repeats, as a walk of small pages.</summary>
    [Fact]
    public async Task PagesConcatenateToTheSameRows()
    {
        async Task<List<string>> Walk(int limit)
        {
            var rows = new List<string>();
            int? offset = 0;
            while (offset is { } at)
            {
                var args = new Dictionary<string, object?> { ["assembly"] = "System.Private.CoreLib", ["offset"] = at, ["limit"] = limit };
                var r = await _client.CallToolAsync("list_types", args);
                Assert.True(r.IsError != true, Text(r));
                var json = JsonDocument.Parse(r.StructuredContent!.Value.GetRawText()).RootElement;
                rows.AddRange(json.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("token").GetString()!));
                offset = json.TryGetProperty("nextOffset", out var n) ? n.GetInt32() : null;
                Assert.True(json.GetProperty("total").GetInt32() >= rows.Count, $"total {json.GetProperty("total")} < {rows.Count} at {at}");
            }
            return rows;
        }
        var large = await Walk(5_000);
        var small = await Walk(997);
        output.WriteLine($"{small.Count} rows");
        Assert.True(small.Count > 1_000, $"{small.Count} rows");
        Assert.Equal(small.Count, small.Distinct().Count());
        Assert.Equal(large, small);
    }
}
