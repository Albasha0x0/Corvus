using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Tests;

public partial class ProtocolSampleTests
{
    [Fact]
    public void Every_action_line_of_a_recorded_sample_is_in_its_record()
    {
        var lost = new List<string>();
        foreach (var file in Directory.GetFiles(Folder, "*.json").Order(StringComparer.Ordinal))
        {
            var sample = JsonNode.Parse(File.ReadAllText(file))!;
            if (sample["isError"]?.GetValue<bool>() == true || sample["structuredContent"] is not JsonObject record) continue;
            var text = string.Join("\n", sample["content"]!.AsArray().Select(c => c!.GetValue<string>()));
            lost.AddRange(ToolOutput.ActionLines(text).Where(l => !ToolOutput.Carries(record, l)).Select(l => $"{sample["tool"]}: {l}"));
        }
        Assert.True(lost.Count == 0, "action lines the structured record does not state:\n" + string.Join("\n", lost));
    }
}
