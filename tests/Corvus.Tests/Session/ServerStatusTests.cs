using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>server_status (S14.2): the record matches its output schema and carries the status sections.</summary>
public class ServerStatusTests
{
    [Fact]
    public async Task StatusMatchesItsSchemaAndListsTheSections()
    {
        var (code, output, error) = await ToolCliTests.Run("server_status", "--json", "--no-index", "--max-output", "20000");
        Assert.True(code == 0, error);
        var structured = JsonNode.Parse(output)!["structured"]!;
        var schema = JsonSerializer.SerializeToElement(Corvus.Setup.ToolCli.FindTool("server_status")!["outputSchema"]);
        var problems = OutputSchema.Validate(schema, JsonSerializer.SerializeToElement(structured));
        Assert.True(problems.Count == 0, string.Join("; ", problems));

        var sections = structured["sections"]!.AsArray().ToDictionary(s => (string)s!["name"]!, s => s!["fields"]!.AsArray());
        Assert.Equal(["budget", "results", "caches", "calls", "workers", "run"], sections.Keys);
        string? Field(string section, string name, string part = "value") =>
            (string?)sections[section].FirstOrDefault(f => (string)f!["name"]! == name)?[part];
        Assert.StartsWith("estimated tokens per part: list 6,000", Field("budget", "page"));
        Assert.Equal("default", Field("budget", "delivery", "source"));
        Assert.Equal("9,500 tokens per result", Field("budget", "ceiling"));
        Assert.Equal("Unknown client (unknown)", Field("budget", "client"));
        Assert.Equal("default", Field("budget", "client", "source"));
        Assert.Equal("default", Field("budget", "deadline", "source"));
        Assert.Equal("full", Field("budget", "profile"));
        Assert.NotNull(Field("calls", "joined"));
        Assert.NotNull(Field("budget", "delivery"));
        Assert.NotNull(Field("results", "mode"));
        Assert.Contains("characters", Field("results", "memory"));
        Assert.NotNull(Field("calls", "leftover"));
        Assert.Equal("free", Field("calls", "workspaceLock"));
        Assert.Equal(CallLog.RunId, Field("run", "runId"));
        Assert.Equal(Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), Field("run", "pid"));
        // moved out of the record's top level into the budget section
        Assert.Null(structured["maxOutputChars"]);

        // S2: the data folder is named once, so the default status fits the report budget with room for a 260-character folder.
        var root = Corvus.Native.Providers.DataFolder.Root;
        Assert.Equal(root, Field("run", "dataDir"));
        var json = structured.ToJsonString();
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(json, System.Text.RegularExpressions.Regex.Escape(JsonEncodedText.Encode(root).ToString())));
        Assert.True(structured["warnings"] is null, structured["warnings"]?.ToJsonString());
        AssertFitsWithAFolderOf260Characters(output);
        var ghidra = structured["unavailableTools"]!.AsArray().Where(g => ((string)g!["reason"]!).StartsWith("Ghidra", StringComparison.Ordinal)).ToList();
        Assert.True(ghidra.Count <= 1, "one row per reason");
    }

    internal static void AssertFitsWithAFolderOf260Characters(string output)
    {
        int room = Corvus.Core.TokenEstimate.Of(JsonEncodedText.Encode(new string('a', 40) + string.Concat(Enumerable.Repeat(@"\Some Folder-Name", 13))).ToString());
        int budget = CallFilter.FitTokens(OutputClasses.Budget(OutputClass.Report));
        var result = JsonNode.Parse(output)!;
        var structured = result["structured"]!.AsObject();
        int json = Corvus.Core.TokenEstimate.Of(structured.ToJsonString()) + room, text = Corvus.Core.TokenEstimate.Of((string)result["text"]!) + room;
        // A runner's numbers per field, so an overrun names what grew.
        Assert.True(json <= budget && text <= budget, $"json {json}, text {text} of {budget} with {room} of folder room; by field: " +
            string.Join(", ", structured.Select(f => $"{f.Key} {Corvus.Core.TokenEstimate.Of(f.Value?.ToJsonString() ?? "null")}")) + "\n" + result["text"]);
    }

    [Fact]
    public async Task TheBudgetSection_ShowsTheClientProfileAndItsSources()
    {
        var (code, output, error) = await ToolCliTests.Run("server_status", "--json", "--no-index", "--client", "codex", "--client-timeout", "120", "--toolsets", "lean");
        Assert.True(code == 0, error);
        var budget = JsonNode.Parse(output)!["structured"]!["sections"]!.AsArray().Single(s => (string)s!["name"]! == "budget")!["fields"]!.AsArray();
        string? Field(string name, string part = "value") => (string?)budget.FirstOrDefault(f => (string)f!["name"]! == name)?[part];
        Assert.Equal(("Codex (codex)", "--client"), (Field("client"), Field("client", "source")));
        Assert.Equal("lean", Field("profile"));
        Assert.Equal(("9,500 tokens per result", "codex"), (Field("ceiling"), Field("ceiling", "source")));
        Assert.StartsWith("115 s per call: codex waits 120 s", Field("deadline"));
        Assert.Equal("--client-timeout", Field("deadline", "source"));
    }

    /// <summary>Without IDA or Ghidra the default status still fits: an engine value missing on many tools is one entry.</summary>
    [Fact]
    public void Status_sections_are_read_side_by_side_and_kept_in_order()
    {
        // Each section waits for all three to start: read one after another, the first gives up and reports an error.
        using var started = new Barrier(3);
        var sections = new[] { "c", "a", "b" }.Select(name => new WaitingSection(name, started)).ToList();
        var collected = Corvus.Core.StatusSections.Collect(null!, sections);
        Assert.Equal(["a", "b", "c"], collected.Select(s => s.Name));
        Assert.All(collected, s => Assert.Equal("met", Assert.Single(s.Fields).Value));
    }

    private sealed class WaitingSection(string name, Barrier started) : Corvus.Core.IStatusSection
    {
        public string Name => name;

        public IEnumerable<Corvus.Core.StatusField> Fields(IServiceProvider services)
        {
            if (!started.SignalAndWait(TimeSpan.FromSeconds(60))) throw new TimeoutException("the other sections did not start");
            yield return new("barrier", "met");
        }
    }

    [Fact]
    public void AMissingEngineValueOnManyToolsIsOneEntry()
    {
        var rows = new[] { "disassemble", "find_xrefs", "get_cfg", "list_functions" }
            .Select(t => new ToolAvailability.Unavailable(t, "engine=ghidra", "Ghidra was not found", "set CORVUS_GHIDRA_DIR"))
            .Append(new ToolAvailability.Unavailable("emulate_native", null, "Ghidra was not found", "set CORVUS_GHIDRA_DIR"))
            .Append(new ToolAvailability.Unavailable("find_virtual_calls", "crossCheck=true", "Ghidra was not found", "set CORVUS_GHIDRA_DIR"));
        var group = Assert.Single(Corvus.Tools.SessionTools.Group(rows));
        Assert.Equal(["emulate_native", "find_virtual_calls crossCheck=true", "engine=ghidra on the 4 tools that take engine"], group.Tools);
        // three or fewer stay listed
        var few = Assert.Single(Corvus.Tools.SessionTools.Group(rows.Take(3)));
        Assert.Equal(["disassemble engine=ghidra", "find_xrefs engine=ghidra", "get_cfg engine=ghidra"], few.Tools);
    }

    [Fact]
    public void Many_children_of_one_program_are_one_bounded_field()
    {
        var start = new DateTimeOffset(2026, 10, 21, 12, 0, 0, TimeSpan.Zero);
        var children = Enumerable.Range(1, 40).Select(i => (100 + i, "worker", start.AddSeconds(i))).ToList();
        Assert.Equal("pid 101, started 2026-10-21T12:00:01Z; pid 102, started 2026-10-21T12:00:02Z; pid 103, started 2026-10-21T12:00:03Z; 37 more",
            Corvus.Tools.WorkersStatus.Describe(children));
    }

    [Fact]
    public void AReasonInAnUnavailableRowIsNotRepeatedInItsCapability()
    {
        const string reason = "Ghidra was not found: neither CORVUS_GHIDRA_DIR nor GHIDRA_INSTALL_DIR is set.";
        var capabilities = new List<Corvus.Tools.SessionTools.Capability>
        {
            new("native decompilation (Ghidra)", false, reason, "set CORVUS_GHIDRA_DIR"),
            new("external tool: TShark", false, "not found (CORVUS_TSHARK is not set and it is not on PATH)", "set CORVUS_TSHARK"),
        };
        var trimmed = Corvus.Tools.SessionTools.PointToUnavailable(capabilities, [new(["ghidra_script"], reason, "set CORVUS_GHIDRA_DIR")]);
        Assert.Equal(("unavailable: see unavailableTools", null), (trimmed[0].Detail, trimmed[0].Remediation));
        Assert.Equal(capabilities[1], trimmed[1]);
    }
}

/// <summary>server_status with every external tool variable set: the largest default status.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
public class ServerStatusToolVariableTests
{
    [Fact]
    public async Task The_default_status_fits_with_every_external_tool_found_in_a_deep_folder()
    {
        using var fake = new FakeTool();
        fake.On("--version", stdout: "TShark (Wireshark) 4.6.9");
        var deep = Path.Combine([fake.Directory, .. Enumerable.Repeat("Some Folder-Name", 8)]);
        Directory.CreateDirectory(deep);
        string Place(string name)
        {
            var copy = fake.CopyAs(name);
            foreach (var file in Directory.GetFiles(Path.GetDirectoryName(copy)!)) File.Copy(file, Path.Combine(deep, Path.GetFileName(file)), true);
            return Path.Combine(deep, Path.GetFileName(copy));
        }
        string Jar(string name)
        {
            var path = Path.Combine(deep, name);
            File.WriteAllBytes(path, []);
            return path;
        }
        var variables = new Dictionary<string, string>
        {
            ["CORVUS_JAVA"] = Place("java"),
            ["CORVUS_JAVA_DECOMPILER"] = Jar("jadx-headless-mcp-0.7.1-all.jar"),
            ["CORVUS_JAVA_DECOMPILER2"] = Jar("vineflower-1.11.1.jar"),
            ["CORVUS_PY_DECOMPILER"] = Place("pycdc"),
            ["CORVUS_ADB"] = Place("adb"),
            ["CORVUS_TSHARK"] = Place("tshark"),
            ["CORVUS_OSV_SCANNER"] = Place("osv-scanner"),
            ["CORVUS_CAPA"] = Place("capa"),
        };
        var tools = Corvus.Native.Providers.ExternalTools.Table.Where(t => !t.TestOracle).ToList();
        Assert.Equal(tools.Select(t => t.Variable).Order(), variables.Keys.Order());
        using var scope = new EnvironmentScope().Set(FakeTool.ScriptVariable, fake.ScriptPath).Set("CORVUS_DIE", Place("diec"));
        foreach (var (name, value) in variables) scope.Set(name, value);

        var (code, output, error) = await ToolCliTests.Run("server_status", "--json", "--no-index", "--max-output", "20000");
        // A version check the status stopped waiting for still runs a copy from the folder: each ends before it is deleted.
        foreach (var tool in tools) Corvus.Native.Providers.ExternalTools.Probe(tool);
        Assert.True(code == 0, error);
        var capabilities = JsonNode.Parse(output)!["structured"]!["capabilities"]!.AsArray();
        foreach (var tool in tools)
        {
            var c = capabilities.FirstOrDefault(c => ((string)c!["name"]!).StartsWith(tool.Name, StringComparison.Ordinal));
            Assert.True(c is not null && (bool)c["available"]!, $"{tool.Name}: {c?["detail"]} {c?["remediation"]}");
        }
        ServerStatusTests.AssertFitsWithAFolderOf260Characters(output);
    }
}
