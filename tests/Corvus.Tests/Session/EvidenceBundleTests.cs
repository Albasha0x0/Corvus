using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>read_result format=evidence / verify: the ten latest calls round-trip and verify; a changed input fails, naming each record.</summary>
public sealed class EvidenceBundleTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    [Fact]
    public async Task A_bundle_verifies_and_a_changed_input_is_named()
    {
        var input = _dir.File("sample.dll");
        File.Copy(Env.FixturePath, input);
        var bundle = _dir.File("findings.json");
        await using (var server = await InProcessServer.StartAsync())
        {
            await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = input });
            var types = await server.Client.CallToolAsync("list_types", new Dictionary<string, object?> { ["assembly"] = "sample.dll", ["limit"] = 200 });
            var names = types.StructuredContent!.Value.GetProperty("items").EnumerateArray().Select(t => t.GetProperty("name").GetString()!).ToList();
            foreach (var name in names.Take(10))
                await server.Client.CallToolAsync("decompile_member", new Dictionary<string, object?> { ["assembly"] = "sample.dll", ["member"] = name });
            var written = await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = "last:10", ["format"] = "evidence", ["outputPath"] = bundle });
            output.WriteLine(Text(written));
            var verified = Text(await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = bundle, ["format"] = "verify" }));
            output.WriteLine(verified);
            Assert.Contains("10 record(s), 10 verified, 0 differ", verified);
        }
        File.AppendAllBytes(input, [0]);
        await using (var server = await InProcessServer.StartAsync())
        {
            await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = input });
            var verified = Text(await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = bundle, ["format"] = "verify" }));
            output.WriteLine(verified);
            Assert.Contains("0 verified, 10 differ", verified);
            Assert.Matches(@"DIFFERS  c-[0-9]+ decompile_member: input sample\.dll changed", verified);
        }
    }
}
