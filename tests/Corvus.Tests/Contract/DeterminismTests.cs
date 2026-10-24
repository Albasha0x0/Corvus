using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// S2.3 / S5: the same calls in two fresh server processes give byte-equal text and records, apart from a closed list of
/// lines that name the moment or the process.
/// </summary>
[Trait("Speed", "Slow")]
public class DeterminismTests
{
    /// <summary>Calls covering list, code, report and bytes results on the fixtures and a native sample.</summary>
    private static IEnumerable<(string Tool, Dictionary<string, object?> Args)> Calls(string native) =>
    [
        ("list_types", new() { ["assembly"] = "TestFixture" }),
        ("search_symbols", new() { ["query"] = "a" }),
        ("search_strings", new() { ["query"] = "e" }),
        ("get_type_info", new() { ["type"] = "Account" }),
        ("decompile_member", new() { ["member"] = "Account" }),
        ("get_il", new() { ["symbol"] = "Account::CheckPreview" }),
        ("find_references", new() { ["symbol"] = "Account::Charge(int)" }),
        ("get_call_tree", new() { ["method"] = "Account::Charge(int)" }),
        ("summarize_file", new() { ["path"] = Env.FixturePath }),
        ("get_pe_info", new() { ["image"] = native }),
        ("list_functions", new() { ["image"] = native, ["engine"] = "ours" }),
        ("disassemble", new() { ["image"] = native, ["address"] = "rva:0x1000", ["engine"] = "ours" }),
        ("read_bytes", new() { ["image"] = native, ["address"] = "rva:0x1000", ["length"] = 64 }),
        ("search_native_strings", new() { ["image"] = native }),
    ];

    /// <summary>Lines allowed to differ: none yet beyond the engine banners an engine run would add.</summary>
    private static bool Volatile(string line) => line.StartsWith("Engine: ida", StringComparison.Ordinal) || line.StartsWith("Engine: ghidra", StringComparison.Ordinal);

    [Fact]
    public async Task TwoProcessesAnswerAlike()
    {
        using var dir = new TempDir();
        var native = McpProtocolTests.NativeSample(dir);
        int run = 0;
        async Task<List<string>> RunAsync()
        {
            // A data folder and temporary folder of its own: the shared ones change under the full set's other classes,
            // and the PDB search counts the symbol caches that exist under the temporary folder.
            var temp = Directory.CreateDirectory(dir.File($"temp{++run}")).FullName;
            await using var client = await McpProtocolTests.StartServerAsync(null, null, ["--load", Env.FixturePath],
                new Dictionary<string, string?>
                {
                    [Corvus.Native.Providers.DataFolder.RootVariable] = dir.File($"data{run}"),
                    ["TEMP"] = temp, ["TMP"] = temp, ["TMPDIR"] = temp,
                });
            var answers = new List<string>();
            foreach (var (tool, args) in Calls(native))
            {
                var r = await client.CallToolAsync(tool, args);
                var text = string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));
                answers.Add($"{tool} error={r.IsError == true}\n" + string.Join("\n", text.Split('\n').Where(l => !Volatile(l))) + "\n" + r.StructuredContent?.GetRawText());
            }
            return answers;
        }
        var first = await RunAsync();
        var second = await RunAsync();
        var differing = first.Zip(second).Where(p => p.First != p.Second).Select(p => FirstDifference(p.First, p.Second)).ToList();
        Assert.True(differing.Count == 0, "answers differ between two processes: " + string.Join(", ", differing));
        Assert.All(first, a => Assert.DoesNotContain("error=True", a.Split('\n')[0]));
    }

    /// <summary>
    /// The native slice: the index-backed analysis tools on a real PE and ELF (e_sqlite3), each in two fresh processes with
    /// data folders of their own (so each builds its index), give byte-equal text and records.
    /// </summary>
    [Theory, Trait("Data", "Real")]
    [InlineData("win-x64", "e_sqlite3.dll", "rcx")]
    [InlineData("linux-x64", "libe_sqlite3.so", "rdi")]
    public async Task NativeAnalysisAnswersAlikeOnARealLibrary(string rid, string file, string firstArgument)
    {
        using var dir = new TempDir();
        var image = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", rid, "native", file);
        Dictionary<string, object?> On(params (string Key, object? Value)[] more) => new[] { ("image", (object?)image) }.Concat(more).ToDictionary(p => p.Item1, p => p.Item2);
        (string Tool, Dictionary<string, object?> Args)[] calls =
        [
            ("get_pe_info", On()), ("list_functions", On()), ("list_globals", On()), ("search_instructions", On(("mnemonic", "^call$"))),
            ("find_xrefs", On(("address", "sqlite3_free"))), ("get_cfg", On(("address", "sqlite3_open"))), ("native_call_tree", On(("function", "sqlite3_open"), ("depth", 3))),
            ("analyze_native_function", On(("address", "sqlite3_open"))), ("get_call_arguments", On(("address", "sqlite3_open"))),
            ("resolve_call_targets", On(("scope", "image"))), ("trace_native_values", On(("address", "sqlite3_open"), ("location", firstArgument))),
            ("find_virtual_calls", On()), ("find_similar_functions", On(("view", "duplicates"))), ("inspect_instruction", On(("address", "sqlite3_open"), ("limit", 8))),
            ("trace_native_feature", On(("query", "sqlite3_open"))), ("get_pe_info", On()),
        ];
        int run = 0;
        async Task<List<string>> RunAsync()
        {
            // Each process gets a temporary folder of its own: get_pe_info counts the symbol stores that exist, and an
            // engine test of this run can create one (IDA's %TEMP%\ida) in the shared folder between the two processes.
            var temp = Directory.CreateDirectory(dir.File($"temp{++run}")).FullName;
            await using var client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch"],
                new Dictionary<string, string?> { [Corvus.Native.Providers.DataFolder.RootVariable] = dir.File($"data{run}"), ["TMP"] = temp, ["TEMP"] = temp, ["TMPDIR"] = temp });
            var answers = new List<string>();
            foreach (var (tool, args) in calls)
            {
                var r = await client.CallToolAsync(tool, args);
                var text = string.Join("\n", r.Content.OfType<TextContentBlock>().Select(b => b.Text));
                answers.Add($"{tool} error={r.IsError == true}\n" + text.Replace(image, "<image>") + "\n" + r.StructuredContent?.GetRawText().Replace(image.Replace("\\", "\\\\"), "<image>"));
            }
            return answers;
        }
        var first = await RunAsync();
        var second = await RunAsync();
        var differing = first.Zip(second).Where(p => p.First != p.Second).Select(p => FirstDifference(p.First, p.Second)).ToList();
        Assert.True(differing.Count == 0, "answers differ between two processes: " + string.Join(", ", differing));
        Assert.All(first, a => Assert.DoesNotContain("error=True", a.Split('\n')[0]));
    }

    /// <summary>The call and its first differing line in each process.</summary>
    private static string FirstDifference(string a, string b)
    {
        string[] x = a.Split('\n'), y = b.Split('\n');
        int i = 0;
        while (i < x.Length && i < y.Length && x[i] == y[i]) i++;
        string Line(string[] l) => i < l.Length ? l[i][..Math.Min(l[i].Length, 300)] : "(end)";
        return $"{x[0]} line {i}: first «{Line(x)}» second «{Line(y)}»";
    }

    private static async Task<List<string>> HarnessCalls(TempDir dir)
    {
        await using var client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch"]);
        string native = McpProtocolTests.NativeSample(dir), v2 = McpProtocolTests.NativeSampleV2(dir);
        // The same file name from another folder: loaded as native.dll#2.
        var twin = dir.File("other/native.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(twin)!);
        File.Copy(v2, twin, overwrite: true);
        foreach (var path in new[] { Env.FixturePath, native, v2, twin })
            Assert.True((await client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path })).IsError != true);
        (string Tool, Dictionary<string, object?> Args)[] calls =
        [
            ("unity_overview", new() { ["path"] = UnityOverviewTests.MonoSample(dir) }),
            ("get_pe_info", new() { ["image"] = "native.dll" }),
            ("find_similar_functions", new() { ["image"] = "native.dll", ["address"] = "First", ["scope"] = "all", ["minScore"] = 0 }),
            ("list_types", new() { ["assembly"] = "TestFixture" }),
            ("search_strings", new() { ["query"] = "e" }),
            ("decompile_member", new() { ["member"] = "Account" }),
            ("list_exports", new() { ["image"] = "native.dll" }),
            ("summarize_file", new() { ["path"] = native }),
        ];
        var outputs = new List<string>();
        foreach (var (tool, args) in calls)
        {
            var r = await client.CallToolAsync(tool, args);
            Assert.True(r.IsError != true, $"{tool}: {string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text))}");
            outputs.Add($"{tool}: {string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text))}\n{r.StructuredContent?.GetRawText()}");
        }
        return outputs;
    }

    /// <summary>
    /// The harness's repeated-call cases: timings in unity_overview, get_pe_info's capability text and the image ids a
    /// scope=all similarity search names (native.dll#2). Engine banners stay out of scope.
    /// </summary>
    [Fact]
    public async Task HarnessRepeatedCallsAnswerAlike()
    {
        using var dir = new TempDir();
        var first = await HarnessCalls(dir);
        var second = await HarnessCalls(dir);
        for (int i = 0; i < first.Count; i++)
            Assert.True(first[i] == second[i], $"differs:\n{Diff(first[i], second[i])}");
    }

    private static string Diff(string a, string b)
    {
        int at = 0;
        while (at < a.Length && at < b.Length && a[at] == b[at]) at++;
        string Around(string s) => s[Math.Max(0, at - 80)..Math.Min(s.Length, at + 80)];
        return $"{a[..Math.Min(a.Length, a.IndexOf(':') + 1)]} at char {at}: '{Around(a)}' vs '{Around(b)}'";
    }
}
