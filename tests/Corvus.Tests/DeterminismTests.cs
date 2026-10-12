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
        ("get_il", new() { ["symbol"] = "Account::CheckLicense" }),
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
        async Task<List<string>> RunAsync()
        {
            await using var client = await McpProtocolTests.StartServerAsync("--load", Env.FixturePath);
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
        var differing = first.Zip(second).Where(p => p.First != p.Second).Select(p => p.First.Split('\n')[0]).ToList();
        Assert.True(differing.Count == 0, "answers differ between two processes: " + string.Join(", ", differing));
        Assert.All(first, a => Assert.DoesNotContain("error=True", a.Split('\n')[0]));
    }
}
