using System.Text.Json;
using Corvus.Core;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// Every tool with a target parameter, through a real server: an unloaded real file there loads (never not_loaded), and a
/// missing file in any input path parameter is the one not_found text with its Next (CORVUS_ALL_TESTS=1).
/// </summary>
[Collection(SweepCollection.Name)]
public sealed class TargetSweepTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private static readonly string[] AssemblyParameters = ["assembly", "oldAssembly", "newAssembly"];

    /// <summary>Path parameters that are not input files: folders, ids-or-paths of other kinds, device-side paths.</summary>
    private static readonly HashSet<(string Tool, string Parameter)> NotInputFiles =
    [
        ("install_android_package", "path"), // refused before the file is read unless device changes are allowed
    ];

    /// <summary>The plausible arguments of each tool, as the contract sweep builds them.</summary>
    private static Dictionary<string, Dictionary<string, object?>> Plausible(IList<McpClientTool> tools, TempDir dir) =>
        ContractSweep.Build(tools, dir, ContractSweep.Depth.Core).Where(c => c.Label == "plausible").ToDictionary(c => c.Tool, c => c.Args);

    /// <summary>
    /// The plausible call with <paramref name="parameter"/> as the only target or input path: other optional ones and
    /// their alternatives dropped, engine left at auto (no engine is installed for the sweep), enum values made valid.
    /// </summary>
    private static Dictionary<string, object?> Base(McpClientTool tool, Dictionary<string, object?> plausible, string parameter)
    {
        var schema = tool.ProtocolTool.InputSchema;
        var required = schema.TryGetProperty("required", out var r) ? r.EnumerateArray().Select(e => e.GetString()!).ToHashSet() : [];
        var args = new Dictionary<string, object?>(plausible);
        foreach (var other in Parameters(tool).Where(p => p != parameter && !required.Contains(p) && (IsTarget(tool.Name, p) || p is "path" or "text" or "engine")))
            args.Remove(other);
        foreach (var property in schema.GetProperty("properties").EnumerateObject())
            if (property.Value.TryGetProperty("enum", out var values) && args.TryGetValue(property.Name, out var value)
                && !values.EnumerateArray().Any(v => v.ToString() == value?.ToString()))
                args[property.Name] = values[0].GetString();
        return args;
    }

    private static List<string> Parameters(McpClientTool tool) =>
        tool.ProtocolTool.InputSchema.TryGetProperty("properties", out var p) ? [.. p.EnumerateObject().Select(q => q.Name)] : [];

    /// <summary>The path as the parameter takes it: a one-element array for an array parameter (search_code_pattern images).</summary>
    private static object PathValue(McpClientTool tool, string parameter, string path) =>
        tool.ProtocolTool.InputSchema.GetProperty("properties").GetProperty(parameter) is var p
        && p.TryGetProperty("type", out var type)
        && (type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Any(t => t.GetString() == "array") : type.GetString() == "array")
            ? new[] { path } : path;

    private static bool IsTarget(string tool, string parameter) =>
        Targets.Parameters.Contains(parameter) && tool is not ("unload_assembly" or "reload_assembly" or "patch_asm");

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task AnUnloadedRealPathIsNeverNotLoaded()
    {
        using var dir = new TempDir();
        await using var client = await ContractSweep.StartAsync(dir);
        var tools = await client.ListToolsAsync();
        var plausible = Plausible(tools, dir);
        var native = NativePeTests.KitchenSink(is64: true);
        int n = 0;
        string Fresh(bool managed)
        {
            var folder = dir.File($"t{++n}");
            Directory.CreateDirectory(folder);
            var file = Path.Combine(folder, managed ? "TestFixture.dll" : "native.dll");
            if (managed) File.Copy(Env.FixturePath, file);
            else File.WriteAllBytes(file, native);
            return file;
        }

        var outcomes = new List<string>();
        var failures = new List<string>();
        foreach (var tool in tools)
            foreach (var parameter in Parameters(tool).Where(p => IsTarget(tool.Name, p)))
            {
                var args = Base(tool, plausible[tool.Name], parameter);
                args[parameter] = PathValue(tool, parameter, Fresh(AssemblyParameters.Contains(parameter)));
                var result = await ContractSweep.CheckAsync(client, new ContractSweep.Case(tool.Name, $"{parameter}: unloaded path", args), tool.ProtocolTool.OutputSchema);
                outcomes.Add(result.Outcome);
                if (result.Outcome != "ok") output.WriteLine($"{tool.Name} [{parameter}]: {result.Outcome}");
                if (result.Failure != null) failures.Add(result.Failure);
                else if (result.Outcome is "hang" or "internal") failures.Add($"{tool.Name} [{parameter}]: {result.Outcome}");
                else if (result.Outcome == "not_loaded") // only a workspace not_loaded fails; "no PDB is loaded" is the tool's own
                {
                    var again = await client.CallToolAsync(tool.Name, args);
                    var text = again.Content.OfType<TextContentBlock>().First(b => !b.Text.StartsWith("[workspace]", StringComparison.Ordinal)).Text;
                    if (text.Contains("load_assembly", StringComparison.Ordinal)) failures.Add($"{tool.Name} [{parameter}]: {text}");
                }
            }
        output.WriteLine($"{outcomes.Count} calls: " + string.Join(", ", outcomes.GroupBy(o => o).OrderByDescending(g => g.Count()).Select(g => $"{g.Key} {g.Count()}")));
        Assert.True(failures.Count == 0, string.Join("\n", failures));
        Assert.True(outcomes.Count > 100, $"only {outcomes.Count} target parameters");
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task AMissingFileIsOneNotFoundEverywhere()
    {
        using var dir = new TempDir();
        await using var client = await ContractSweep.StartAsync(dir);
        var tools = await client.ListToolsAsync();
        var plausible = Plausible(tools, dir);
        var missing = dir.File(Path.Combine("missing", "nope.dll"));
        var expected = $"File not found: '{missing}'\nNext: {Targets.FileNotFoundNext}";

        int calls = 0;
        var failures = new List<string>();
        foreach (var tool in tools)
            foreach (var parameter in Parameters(tool).Where(p => IsTarget(tool.Name, p)
                         || p == "path" && !ContractSweep.IsOutputPath(tool.Name, p) && !NotInputFiles.Contains((tool.Name, p))))
            {
                var args = Base(tool, plausible[tool.Name], parameter);
                args[parameter] = PathValue(tool, parameter, missing);
                calls++;
                using var cts = new CancellationTokenSource(ContractSweep.CallLimit);
                var result = await client.CallToolAsync(tool.Name, args, cancellationToken: cts.Token);
                var text = result.Content.OfType<TextContentBlock>().Select(b => b.Text).FirstOrDefault(t => !t.StartsWith("[workspace]", StringComparison.Ordinal)) ?? "";
                if (result.IsError != true || !text.StartsWith("Error (not_found)", StringComparison.Ordinal) || !text.EndsWith(": " + expected, StringComparison.Ordinal))
                    failures.Add($"{tool.Name} [{parameter}]: {(text.Length > 300 ? text[..300] : text)}");
            }
        output.WriteLine($"{calls} calls");
        Assert.True(failures.Count == 0, $"{failures.Count} of {calls}:\n" + string.Join("\n", failures));
        Assert.True(calls > 100, $"only {calls} path parameters");
    }
}
