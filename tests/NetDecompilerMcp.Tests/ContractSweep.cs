using System.Diagnostics;
using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Contract sweep: every tool advertised by tools/list, called through a real stdio client with arguments generated from its
/// input schema (missing, wrong-typed, empty, blank, huge, out-of-range, nonexistent, path-like and invisible-character
/// values). Every call must finish within <see cref="CallLimit"/> with either a success whose structured content matches the
/// output schema or a coded tool error ("Error (code) in tool: ..."); an internal error, a protocol error, a hang or a dead
/// server fails. New tools are covered as soon as they are advertised.
/// </summary>
public static class ContractSweep
{
    public static readonly TimeSpan CallLimit = TimeSpan.FromSeconds(20);

    /// <summary>Tools that write files, and the parameters naming what they write. The sweep only passes paths inside its temp directory there.</summary>
    public static readonly Dictionary<string, string[]> FileWriters = new()
    {
        ["export_project"] = ["outputDirectory"],
        ["export_edits"] = ["path"],
        ["save_assembly"] = ["outputPath"],
        ["export_il2cpp_symbols"] = ["outputDirectory"],
        ["extract_embedded"] = ["outputDirectory"],
        ["unpack_container"] = ["outputDirectory"],
        ["get_resource"] = ["savePath"],
        ["extract_strings"] = ["savePath"],
        ["export_native_annotations"] = ["outputPath"],
        ["save_native"] = ["outputPath"],
    };

    /// <summary>Tools that can reach the network when an argument asks for it (load_pdb download=true); annotated open-world.</summary>
    public static readonly HashSet<string> OpenWorldTools = ["load_pdb"];

    /// <summary>Tools that change the loaded assemblies or the workspace (in memory).</summary>
    public static readonly HashSet<string> WorkspaceEditors =
    [
        "load_assembly", "unload_assembly", "reload_assembly", "add_search_directory", "rename_symbol", "rename_namespace", "stub_method",
        "patch_method_csharp", "patch_method_il", "add_members_csharp", "add_types_csharp", "simplify_methods", "undo_edit", "revert_edits",
        "apply_edits", "rename_native", "comment_native", "patch_bytes", "patch_asm", "undo_native_edit", "apply_il2cpp_names", "load_pdb",
        "migrate_native_names",
    ];

    /// <summary>A parameter that names a file or directory the tool writes.</summary>
    public static bool IsOutputPath(string tool, string parameter) =>
        FileWriters.TryGetValue(tool, out var outputs) && outputs.Contains(parameter)
        || parameter.Contains("output", StringComparison.OrdinalIgnoreCase)
        || parameter.Equals("savePath", StringComparison.OrdinalIgnoreCase);

    public sealed record Case(string Tool, string Label, Dictionary<string, object?> Args);

    public enum Depth { Core, Full }

    /// <summary>Starts a server with the fixtures loaded, working in <paramref name="dir"/> so relative paths resolve inside it.</summary>
    public static Task<McpClient> StartAsync(TempDir dir)
    {
        var cwd = dir.File("cwd");
        Directory.CreateDirectory(cwd);
        return McpProtocolTests.StartServerInAsync(cwd, "--load", Env.FixturePath, "--load", Env.ConsumerPath);
    }

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    private static readonly string Long = new('A', 100_000);
    private const string Invisible = "\u200B\u200E\u202EAccount\u202C\uFEFF";

    /// <summary>Malformed and edge-case symbol, token, number and list forms.</summary>
    private static readonly string[] OddSymbols =
    [
        "Account::", "::Charge", "Account::Charge(", "Account::Charge(int", "Account::Charge())", "Account::Charge(int, string, int, int, int)",
        "Account::Charge(System.Int32)", "Account::.ctor", "Account::.cctor", "Account+", "Fixture.Model.Account+Missing", "Account`1", "Account<int>",
        "Account[]", "0x06000001", "0x00000000", "0xFFFFFFFF", "0x", "-1", "18446744073709551616", "1,2,3", "a,,b", ",", "all",
    ];

    /// <summary>Bad values for a parameter of the given JSON type.</summary>
    private static IEnumerable<(string Label, object? Value)> Values(string type)
    {
        switch (type)
        {
            case "string":
                yield return ("empty", "");
                yield return ("whitespace", "  \t\n ");
                yield return ("100k chars", Long);
                yield return ("nonexistent", "No.Such.Ns.Missing::Nothing(int)");
                yield return ("traversal", @"..\..\..\..\ndm-no-such-dir\x.dll");
                yield return ("posix traversal", "../../../../ndm-no-such-dir/x.dll");
                yield return ("invalid path chars", "a<>:\"|?*\0b");
                yield return ("device name", @"C:\nul\con.dll");
                yield return ("unc", @"\\ndm-no-such-host\share\x.dll");
                yield return ("invisible chars", Invisible);
                yield return ("emoji and surrogates", "😀\uD800x");
                yield return ("wildcards", "*");
                yield return ("separators", "::");
                yield return ("regex metachars", "([{");
                foreach (var odd in OddSymbols) yield return ($"odd symbol {odd}", odd);
                yield return ("number for string", 42);
                yield return ("boolean for string", true);
                yield return ("object for string", Json("""{"a":1}"""));
                yield return ("array for string", Json("""["x"]"""));
                yield return ("null", null);
                break;
            case "integer":
                yield return ("-1", -1);
                yield return ("0", 0);
                yield return ("int.MaxValue", int.MaxValue);
                yield return ("int.MinValue", int.MinValue);
                yield return ("beyond int", 9_999_999_999L);
                yield return ("fraction", 1.5);
                yield return ("string for integer", "abc");
                yield return ("numeric string", "5");
                yield return ("object for integer", Json("{}"));
                yield return ("array for integer", Json("[1]"));
                yield return ("null", null);
                break;
            case "boolean":
                yield return ("string for boolean", "yes");
                yield return ("number for boolean", 1);
                yield return ("object for boolean", Json("{}"));
                yield return ("null", null);
                break;
            default:
                yield return ("string", "x");
                yield return ("null", null);
                break;
        }
    }

    /// <summary>Output paths: always inside the temp directory, one fresh name per call.</summary>
    private static IEnumerable<(string Label, Func<string, object?> Value)> OutputValues()
    {
        yield return ("dot segments", root => Path.Combine(root, "a", "..", "b"));
        yield return ("invisible chars", root => Path.Combine(root, Invisible));
        yield return ("number for path", _ => 42);
        yield return ("invalid chars", root => Path.Combine(root, "bad<>|?*name"));
        yield return ("long name", root => Path.Combine(root, new string('n', 300)));
        yield return ("existing directory", root => { Directory.CreateDirectory(root); File.WriteAllText(Path.Combine(root, "keep.txt"), "x"); return root; });
        yield return ("existing file", root => { Directory.CreateDirectory(root); var f = Path.Combine(root, "keep.txt"); File.WriteAllText(f, "x"); return f; });
        yield return ("trailing separator", root => root + Path.DirectorySeparatorChar);
        yield return ("object for path", _ => Json("{}"));
    }

    /// <summary>The JSON type of a property schema, ignoring "null" in a nullable union.</summary>
    private static string TypeOf(JsonElement property)
    {
        if (!property.TryGetProperty("type", out var type)) return "any";
        if (type.ValueKind == JsonValueKind.String) return type.GetString()!;
        return type.EnumerateArray().Select(t => t.GetString()!).FirstOrDefault(t => t != "null") ?? "null";
    }

    /// <summary>Plausible values by parameter name, for tools without a case in <see cref="McpProtocolTests.ToolCases"/>.</summary>
    private static object? Plausible(string parameter) => parameter switch
    {
        "assembly" or "oldAssembly" => "TestFixture",
        "newAssembly" => "TestFixture.Consumer",
        "type" => "Account",
        "symbol" or "to" => "Account::Charge(int)",
        "member" or "method" => "Account::CheckLicense",
        "path" => Env.FixturePath,
        "directory" => Path.GetDirectoryName(Env.FixturePath),
        "query" or "pattern" or "filter" => "Charge",
        _ => null,
    };

    /// <summary>
    /// The cases for every tool: a plausible call, then one bad value at a time on top of it. <see cref="Depth.Full"/> tries
    /// every value class on every parameter; <see cref="Depth.Core"/> one per parameter, taking the classes in turn so that
    /// each class still meets many tools.
    /// </summary>
    public static List<Case> Build(IList<McpClientTool> tools, TempDir dir, Depth depth)
    {
        var known = McpProtocolTests.ToolCases(dir);
        var cases = new List<Case>();
        int n = 0;
        string Fresh() => dir.File($"out{++n}");
        var turn = new Dictionary<string, int>();
        IEnumerable<T> Pick<T>(string kind, List<T> all)
        {
            if (depth == Depth.Full) return all;
            int i = turn.GetValueOrDefault(kind);
            turn[kind] = i + 1;
            return [all[i % all.Count]];
        }

        foreach (var tool in tools)
        {
            var name = tool.Name;
            var schema = tool.ProtocolTool.InputSchema;
            var properties = schema.TryGetProperty("properties", out var p) ? p.EnumerateObject().ToList() : [];
            var required = schema.TryGetProperty("required", out var r) ? r.EnumerateArray().Select(e => e.GetString()!).ToHashSet() : [];
            var outputs = properties.Where(q => IsOutputPath(name, q.Name)).Select(q => q.Name).ToList();

            var plausible = known.TryGetValue(name, out var c) ? new Dictionary<string, object?>(c.Args) : [];
            foreach (var q in properties)
                if (!plausible.ContainsKey(q.Name) && (required.Contains(q.Name) || Plausible(q.Name) != null))
                    plausible[q.Name] = Plausible(q.Name) ?? (TypeOf(q.Value) switch { "integer" => 1, "boolean" => false, _ => "x" });
            // Core: dry runs take the shared lock, so edit tools (C# compiles) run side by side instead of one after another.
            if (depth == Depth.Core && properties.Any(q => q.Name == "dryRun"))
                plausible["dryRun"] = true;
            // Default output locations can be outside the temp directory (next to the input, or under the system temp folder).
            Dictionary<string, object?> Base()
            {
                var args = new Dictionary<string, object?>(plausible);
                foreach (var o in outputs) args[o] = Fresh();
                return args;
            }
            void Add(string label, Dictionary<string, object?> args) => cases.Add(new Case(name, label, args));

            Add("plausible", Base());
            if (required.Count > 0)
                Add("no arguments", outputs.ToDictionary(o => o, o => (object?)Fresh()));
            if (depth == Depth.Full)
            {
                Add("unknown parameter", With(Base(), "ndmNoSuchParameter", 1));
                foreach (var q in required)
                    Add($"missing {q}", Without(Base(), q));
            }
            foreach (var q in properties)
            {
                if (depth == Depth.Core && q.Name == "dryRun") continue;
                if (outputs.Contains(q.Name))
                {
                    foreach (var (label, value) in Pick("output", OutputValues().ToList()))
                        Add($"{q.Name}: {label}", With(Base(), q.Name, value(Fresh())));
                    continue;
                }
                var type = TypeOf(q.Value);
                foreach (var (label, value) in Pick(type, Values(type).ToList()))
                    Add($"{q.Name}: {label}", With(Base(), q.Name, value));
            }
        }
        return cases;
    }

    private static Dictionary<string, object?> With(Dictionary<string, object?> args, string key, object? value)
    {
        args[key] = value;
        return args;
    }

    private static Dictionary<string, object?> Without(Dictionary<string, object?> args, string key)
    {
        args.Remove(key);
        return args;
    }

    /// <summary>What one call did: null <see cref="Failure"/> when it kept the contract; <see cref="Outcome"/> is "ok" or the error code.</summary>
    public sealed record Result(Case Case, string? Failure, string Outcome, TimeSpan Elapsed);

    /// <summary>
    /// Runs the cases tool by tool (calls of one tool in parallel), restoring the workspace between tools; or, when
    /// <paramref name="byTool"/> is false, in two parallel batches (faster; the contract holds whatever the workspace state
    /// is): first the read-only tools and those with a dry run, then the others, which mostly take the exclusive lock and
    /// would hold up the first batch.
    /// </summary>
    public static async Task<List<Result>> RunAsync(McpClient client, IList<McpClientTool> tools, List<Case> cases, bool byTool = true, int parallelism = 6)
    {
        var outputSchemas = tools.ToDictionary(t => t.Name, t => t.ProtocolTool.OutputSchema);
        var shared = tools.Where(t => t.ProtocolTool.Annotations?.ReadOnlyHint == true || t.ProtocolTool.InputSchema.GetProperty("properties").TryGetProperty("dryRun", out _))
            .Select(t => t.Name).ToHashSet();
        var all = new List<Result>();
        foreach (var group in cases.GroupBy(c => byTool ? c.Tool : shared.Contains(c.Tool) ? "shared" : "exclusive").OrderBy(g => g.Key != "shared"))
        {
            // Plausible calls first: they do the most work, so the slowest ones overlap the rest.
            var ordered = group.OrderBy(c => c.Label != "plausible").ToList();
            var results = new Result[ordered.Count];
            await Parallel.ForEachAsync(ordered.Select((c, i) => (c, i)), new ParallelOptions { MaxDegreeOfParallelism = parallelism },
                async (item, _) => results[item.i] = await CheckAsync(client, item.c, outputSchemas.GetValueOrDefault(item.c.Tool)));
            all.AddRange(results);
            if (results.Any(r => r.Outcome == "gone")) break;
            await RestoreAsync(client);
        }
        return all;
    }

    /// <summary>The failures, or an empty string.</summary>
    public static string Failures(List<Result> results)
    {
        var failed = results.Where(r => r.Failure != null).ToList();
        return failed.Count == 0 ? "" : $"{failed.Count} of {results.Count} calls broke the contract:\n{string.Join("\n", failed.Select(r => r.Failure))}";
    }

    /// <summary>Outcome counts and the slowest tools, for the test log.</summary>
    public static string Summary(List<Result> results) =>
        $"{results.Count} calls over {results.Select(r => r.Case.Tool).Distinct().Count()} tools; " +
        string.Join(", ", results.GroupBy(r => r.Outcome).OrderByDescending(g => g.Count()).Select(g => $"{g.Key}: {g.Count()}")) +
        "\nslowest tools (sum of call times):\n" +
        string.Join("\n", results.GroupBy(r => r.Case.Tool).Select(g => (Tool: g.Key, Ms: g.Sum(r => r.Elapsed.TotalMilliseconds), Max: g.MaxBy(r => r.Elapsed)!))
            .OrderByDescending(t => t.Ms).Take(10).Select(t => $"  {t.Tool}: {t.Ms:0} ms (slowest {t.Max.Case.Label}: {t.Max.Elapsed.TotalMilliseconds:0} ms)"));

    /// <summary>Undoes what the cases of one tool did to the workspace: edits discarded, the fixtures loaded.</summary>
    public static async Task RestoreAsync(McpClient client)
    {
        foreach (var assembly in new[] { "TestFixture", "TestFixture.Consumer" })
            await client.CallToolAsync("revert_edits", new Dictionary<string, object?> { ["assembly"] = assembly });
        foreach (var path in new[] { Env.FixturePath, Env.ConsumerPath })
            await client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path });
    }

    /// <summary>One call, checked against the contract.</summary>
    public static async Task<Result> CheckAsync(McpClient client, Case c, JsonElement? outputSchema)
    {
        var watch = Stopwatch.StartNew();
        Result Fail(string outcome, string problem) => new(c, $"{c.Tool} [{c.Label}]: {problem}", outcome, watch.Elapsed);
        using var cts = new CancellationTokenSource(CallLimit);
        CallToolResult result;
        try
        {
            result = await client.CallToolAsync(c.Tool, c.Args, cancellationToken: cts.Token);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return Fail("hang", $"no answer within {CallLimit.TotalSeconds:0} s");
        }
        catch (McpProtocolException ex)
        {
            return Fail("protocol error", $"protocol error {ex.ErrorCode}: {Clip(ex.Message)}");
        }
        catch (Exception ex)
        {
            return Fail("gone", $"server gone? {ex.GetType().Name}: {Clip(ex.Message)}");
        }

        var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text).Where(t => !t.StartsWith("[workspace]", StringComparison.Ordinal)));
        if (result.IsError == true)
        {
            var code = System.Text.RegularExpressions.Regex.Match(text, @"^Error \(([a-z_]+)");
            if (!code.Success || code.Groups[1].Value == "internal") return Fail("internal", Clip(text));
            if (McpProtocolTests.ErrorShapeProblems(result) is { Count: > 0 } shape) return Fail("bad error", $"{string.Join("; ", shape)}: {Clip(text)}");
            return new Result(c, null, code.Groups[1].Value, watch.Elapsed);
        }
        if (outputSchema is { } schema)
        {
            if (result.StructuredContent == null) return Fail("bad output", "success without the structured content its output schema promises");
            var errors = OutputSchema.Validate(schema, JsonDocument.Parse(result.StructuredContent.ToString()!).RootElement);
            if (errors.Count > 0) return Fail("bad output", $"structured content does not match the output schema: {string.Join("; ", errors.Take(5))}");
        }
        return new Result(c, null, "ok", watch.Elapsed);
    }

    private static string Clip(string s) => s.Length > 400 ? s[..400] + "..." : s;

    /// <summary>JSON Schema 2020-12 keywords; anything else in a schema position is reported.</summary>
    private static readonly HashSet<string> Keywords =
    [
        "$schema", "$id", "$ref", "$defs", "$anchor", "$dynamicRef", "$dynamicAnchor", "$comment", "$vocabulary",
        "type", "enum", "const", "properties", "patternProperties", "additionalProperties", "required", "items", "prefixItems", "contains",
        "minItems", "maxItems", "uniqueItems", "minContains", "maxContains", "minLength", "maxLength", "pattern", "format",
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "anyOf", "oneOf", "allOf", "not", "if", "then", "else",
        "dependentRequired", "dependentSchemas", "propertyNames", "unevaluatedProperties", "unevaluatedItems", "minProperties", "maxProperties",
        "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly", "contentEncoding", "contentMediaType", "contentSchema",
    ];

    private static readonly HashSet<string> Types = ["null", "boolean", "object", "array", "number", "integer", "string"];

    /// <summary>Structural problems of a schema: unknown keywords, bad types, unresolvable references, defaults that do not validate.</summary>
    public static List<string> SchemaProblems(JsonElement root)
    {
        var problems = new List<string>();
        Walk(root, root, "#", problems, 0);
        return problems;
    }

    private static void Walk(JsonElement root, JsonElement schema, string path, List<string> problems, int depth)
    {
        if (depth > 64) { problems.Add($"{path}: nested too deeply"); return; }
        if (schema.ValueKind is JsonValueKind.True or JsonValueKind.False) return;
        if (schema.ValueKind != JsonValueKind.Object) { problems.Add($"{path}: a schema must be an object or a boolean, not {schema.ValueKind}"); return; }

        foreach (var keyword in schema.EnumerateObject())
        {
            var at = $"{path}/{keyword.Name}";
            var v = keyword.Value;
            switch (keyword.Name)
            {
                case var k when !Keywords.Contains(k):
                    problems.Add($"{at}: unknown keyword");
                    break;
                case "$ref":
                    if (v.GetString() is not { } reference || OutputSchema.Resolve(root, reference) == null)
                        problems.Add($"{at}: unresolvable reference '{v}'");
                    break;
                case "type":
                    var names = v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(t => t.ValueKind == JsonValueKind.String ? t.GetString() : null).ToList() : [v.ValueKind == JsonValueKind.String ? v.GetString() : null];
                    if (names.Count == 0 || names.Any(t => t == null || !Types.Contains(t)) || names.Distinct().Count() != names.Count)
                        problems.Add($"{at}: invalid type {v}");
                    break;
                case "properties" or "patternProperties" or "$defs" or "dependentSchemas":
                    if (v.ValueKind != JsonValueKind.Object) { problems.Add($"{at}: must be an object"); break; }
                    foreach (var child in v.EnumerateObject()) Walk(root, child.Value, $"{at}/{child.Name}", problems, depth + 1);
                    break;
                case "items" or "additionalProperties" or "not" or "if" or "then" or "else" or "contains" or "propertyNames"
                    or "unevaluatedProperties" or "unevaluatedItems" or "contentSchema":
                    Walk(root, v, at, problems, depth + 1);
                    break;
                case "anyOf" or "oneOf" or "allOf" or "prefixItems":
                    if (v.ValueKind != JsonValueKind.Array || v.GetArrayLength() == 0) { problems.Add($"{at}: must be a non-empty array"); break; }
                    int i = 0;
                    foreach (var child in v.EnumerateArray()) Walk(root, child, $"{at}/{i++}", problems, depth + 1);
                    break;
                case "required":
                    if (v.ValueKind != JsonValueKind.Array || v.EnumerateArray().Any(e => e.ValueKind != JsonValueKind.String))
                    {
                        problems.Add($"{at}: must be an array of strings");
                        break;
                    }
                    var listed = v.EnumerateArray().Select(e => e.GetString()!).ToList();
                    if (listed.Distinct().Count() != listed.Count) problems.Add($"{at}: duplicate names");
                    if (schema.TryGetProperty("properties", out var props))
                        foreach (var name in listed.Where(name => !props.TryGetProperty(name, out _)))
                            problems.Add($"{at}: '{name}' is not a declared property");
                    break;
                case "enum":
                    if (v.ValueKind != JsonValueKind.Array) problems.Add($"{at}: must be an array");
                    break;
                case "default":
                    foreach (var error in OutputSchema.Validate(root, schema, v)) problems.Add($"{at}: default does not validate: {error}");
                    break;
                case "title" or "description" or "$comment" or "$schema" or "$id" or "pattern" or "format":
                    if (v.ValueKind != JsonValueKind.String) problems.Add($"{at}: must be a string");
                    break;
            }
        }
    }
}

/// <summary>Advertised schemas and annotations, and the core of the sweep (all tools, the most telling argument classes).</summary>
public sealed class ContractSweepTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    private readonly TempDir _dir = new();
    private McpClient _client = null!;
    private IList<McpClientTool> _tools = null!;

    public async Task InitializeAsync()
    {
        _client = await ContractSweep.StartAsync(_dir);
        _tools = await _client.ListToolsAsync();
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    [Fact]
    public void AdvertisedSchemasAreValid()
    {
        var problems = new List<string>();
        foreach (var tool in _tools)
        {
            var t = tool.ProtocolTool;
            if (string.IsNullOrWhiteSpace(t.Description)) problems.Add($"{t.Name}: no description");
            if (string.IsNullOrWhiteSpace(t.Title)) problems.Add($"{t.Name}: no title");
            if (!t.InputSchema.TryGetProperty("type", out var type) || type.GetString() != "object") problems.Add($"{t.Name}: input schema is not an object schema");
            problems.AddRange(ContractSweep.SchemaProblems(t.InputSchema).Select(p => $"{t.Name} input {p}"));
            if (t.OutputSchema is { } output)
            {
                if (!output.TryGetProperty("type", out var outType) || outType.GetString() != "object") problems.Add($"{t.Name}: output schema is not an object schema");
                problems.AddRange(ContractSweep.SchemaProblems(output).Select(p => $"{t.Name} output {p}"));
            }
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public void AnnotationsMatchWhatToolsDo()
    {
        var problems = new List<string>();
        var names = _tools.Select(t => t.Name).ToHashSet();
        foreach (var listed in ContractSweep.FileWriters.Keys.Concat(ContractSweep.WorkspaceEditors).Where(n => !names.Contains(n)))
            problems.Add($"{listed}: listed in the sweep's tables but not advertised");
        foreach (var tool in _tools)
        {
            var annotations = tool.ProtocolTool.Annotations;
            bool readOnly = annotations?.ReadOnlyHint == true;
            if (readOnly && ContractSweep.FileWriters.ContainsKey(tool.Name)) problems.Add($"{tool.Name}: writes files but is annotated read-only");
            if (readOnly && ContractSweep.WorkspaceEditors.Contains(tool.Name)) problems.Add($"{tool.Name}: changes the workspace but is annotated read-only");
            if ((annotations?.OpenWorldHint != false) != ContractSweep.OpenWorldTools.Contains(tool.Name))
                problems.Add($"{tool.Name}: open-world annotation does not match ContractSweep.OpenWorldTools");
            // A parameter that looks like an output path must be classified in FileWriters so the sweep keeps it in its temp directory.
            foreach (var p in tool.ProtocolTool.InputSchema.GetProperty("properties").EnumerateObject())
                if (ContractSweep.IsOutputPath(tool.Name, p.Name) && !(ContractSweep.FileWriters.TryGetValue(tool.Name, out var o) && o.Contains(p.Name)))
                    problems.Add($"{tool.Name}.{p.Name}: looks like an output path; add it to ContractSweep.FileWriters");
        }
        foreach (var destructive in new[] { "save_assembly", "revert_edits" })
            if (_tools.FirstOrDefault(t => t.Name == destructive)?.ProtocolTool.Annotations?.DestructiveHint != true)
                problems.Add($"{destructive}: not annotated destructive");
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    /// <summary>What the sweep found: wrong JSON types, paths System.IO rejects and offsets that overflowed were internal errors.</summary>
    [Fact]
    public async Task BadArgumentsAreInvalidArgumentErrors()
    {
        // The error text; the JSON block after it is checked by the sweep.
        async Task<string> Call(string tool, Dictionary<string, object?> args) =>
            (await _client.CallToolAsync(tool, args)).Content.OfType<TextContentBlock>().First(b => !b.Text.StartsWith("[workspace]", StringComparison.Ordinal)).Text;

        Assert.Equal("Error (invalid_argument) in get_type_info: parameter 'type' must be a string, not a number.",
            await Call("get_type_info", new() { ["type"] = 42 }));
        Assert.Equal("Error (invalid_argument) in list_types: parameter 'limit' must be a whole number from -2147483648 to 2147483647, not 9999999999.",
            await Call("list_types", new() { ["limit"] = 9_999_999_999L }));
        Assert.Equal("Error (invalid_argument) in get_type_info: parameter 'type' must be a string, not null.",
            await Call("get_type_info", new() { ["type"] = null }));
        // null for an optional parameter means "not given".
        Assert.Contains("Charge", await Call("get_type_info", new() { ["type"] = "Account", ["includeCompilerGenerated"] = null }));
        Assert.StartsWith("Error (invalid_argument) in load_assembly: invalid path", await Call("load_assembly", new() { ["path"] = "" }));
        Assert.Equal("Error (invalid_argument) in load_assembly: a path is too long.\nNext: Pass a shorter path.",
            await Call("load_assembly", new() { ["path"] = new string('A', 100_000) }));
        Assert.Contains("none from offset", await Call("search_strings", new() { ["query"] = "LICENSE", ["offset"] = int.MaxValue }));

        // The same errors as JSON.
        var missing = McpProtocolTests.ErrorJson(await _client.CallToolAsync("get_type_info", new Dictionary<string, object?>()));
        Assert.Equal("invalid_argument", missing.GetProperty("code").GetString());
        Assert.False(missing.GetProperty("retryable").GetBoolean());
        Assert.Equal("missing required parameter 'type'.", missing.GetProperty("message").GetString());
        Assert.Equal("type", missing.GetProperty("details").GetProperty("parameter").GetString());
        var tooLong = McpProtocolTests.ErrorJson(await _client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = new string('A', 100_000) }));
        Assert.Equal("Pass a shorter path.", tooLong.GetProperty("next").GetString());
        Assert.Equal(JsonValueKind.Null, tooLong.GetProperty("partial").ValueKind);
    }

    [Fact]
    public async Task CoreSweep()
    {
        var cases = ContractSweep.Build(_tools, _dir, ContractSweep.Depth.Core);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var results = await ContractSweep.RunAsync(_client, _tools, cases, byTool: false, parallelism: 8);
        _output.WriteLine($"{watch.Elapsed.TotalSeconds:0.0} s");
        _output.WriteLine(ContractSweep.Summary(results));
        Assert.True(ContractSweep.Failures(results) == "", ContractSweep.Failures(results));
        Assert.Contains("Charge", (await _client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Account" })).Content.OfType<TextContentBlock>().First().Text);
    }
}

/// <summary>The full argument matrix over every tool (NDM_ALL_TESTS=1).</summary>
public sealed class ContractSweepFullTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private readonly Xunit.Abstractions.ITestOutputHelper _output = output;
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task FullSweep()
    {
        using var dir = new TempDir();
        await using var client = await ContractSweep.StartAsync(dir);
        var tools = await client.ListToolsAsync();
        var cases = ContractSweep.Build(tools, dir, ContractSweep.Depth.Full);
        var results = await ContractSweep.RunAsync(client, tools, cases);
        _output.WriteLine(ContractSweep.Summary(results));
        Assert.True(ContractSweep.Failures(results) == "", ContractSweep.Failures(results));
        Assert.Contains("Charge", (await client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Account" })).Content.OfType<TextContentBlock>().First().Text);
    }
}
