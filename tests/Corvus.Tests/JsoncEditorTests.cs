using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Setup;

namespace Corvus.Tests;

/// <summary>In-place edits of JSON-with-comments client files, and the reserialize fallback.</summary>
public sealed class JsoncEditorTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static readonly ServerLaunch Launch = new("/opt/ndm/current/NetDecompilerMcp", []);
    private static readonly JsonDocumentOptions LenientOptions = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    private JsonTarget Target(string text, string[]? container = null, Func<ServerLaunch, JsonObject>? entry = null, bool bom = false)
    {
        var path = Path.Combine(_dir.Path, Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path, text, new UTF8Encoding(bom));
        return new JsonTarget(path, container ?? ["mcpServers"], entry ?? (l => new JsonObject { ["command"] = l.Command, ["args"] = new JsonArray() }));
    }

    private static JsonNode Lenient(string path) => JsonNode.Parse(File.ReadAllText(path), documentOptions: LenientOptions)!;

    [Fact]
    public void ZedSettings_KeepCommentsOnInstallAndUninstall()
    {
        var text = "// Zed settings\n{\n  \"ui_font_size\": 16, // trailing comment\n  /* block */\n  \"theme\": \"One Dark\"\n}\n";
        var target = Target(text, ["context_servers"], l => new JsonObject { ["command"] = l.Command, ["args"] = new JsonArray(), ["env"] = new JsonObject() });
        var change = target.Install("net-decompiler", Launch);
        Assert.Equal("registered", change.Message);
        var after = File.ReadAllText(target.Path);
        Assert.StartsWith("// Zed settings\n{\n  \"ui_font_size\": 16, // trailing comment\n  /* block */\n  \"theme\": \"One Dark\",\n  \"context_servers\": {\n    \"net-decompiler\": {\n", after);
        Assert.Equal(Launch.Command, Lenient(target.Path)["context_servers"]!["net-decompiler"]!["command"]!.GetValue<string>());
        Assert.True(target.Preview("net-decompiler", Launch).PreservesComments);
        Assert.Equal("already registered", target.Install("net-decompiler", Launch).Message);

        Assert.Equal("removed", target.Uninstall("net-decompiler").Message);
        var removed = File.ReadAllText(target.Path);
        Assert.Contains("// trailing comment", removed);
        Assert.Contains("/* block */", removed);
        Assert.Null(Lenient(target.Path)["context_servers"]!["net-decompiler"]);
    }

    [Fact]
    public void VsCodeFile_KeepsCrlfTabsBomTrailingCommasAndComments()
    {
        var text = "{\r\n\t// servers\r\n\t\"servers\": {\r\n\t\t\"other\": { \"command\": \"x\" }, /* keep */\r\n\t},\r\n}\r\n";
        var target = Target(text, ["servers"], l => new JsonObject { ["type"] = "stdio", ["command"] = l.Command, ["args"] = new JsonArray() }, bom: true);
        Assert.Equal("registered", target.Install("net-decompiler", Launch).Message);
        var bytes = File.ReadAllBytes(target.Path);
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        var after = File.ReadAllText(target.Path);
        Assert.DoesNotContain("\n", after.Replace("\r\n", ""));
        Assert.Contains("\t// servers\r\n", after);
        Assert.Contains("\"other\": { \"command\": \"x\" }, /* keep */\r\n\t\t\"net-decompiler\": {\r\n\t\t\t\"type\": \"stdio\",", after);
        Assert.EndsWith("\t},\r\n}\r\n", after);
        Assert.Equal("x", Lenient(target.Path)["servers"]!["other"]!["command"]!.GetValue<string>());
    }

    [Fact]
    public void ExistingEntry_ChangesOnlyItsChangedKeys_AndKeepsCommentsInside()
    {
        var text = """
            {
                "mcpServers": {
                    "net-decompiler": {
                        "command": "C:/old.exe", // old build
                        "args": ["--load", "x"], /* my args */
                        "env": { "A": "1" }
                    }
                }
            }

            """.Replace("\r\n", "\n");
        var target = Target(text, entry: l => new JsonObject { ["command"] = l.Command, ["args"] = new JsonArray(), ["disabled"] = false });
        Assert.Equal("registered", target.Install("net-decompiler", Launch).Message);
        var expected = text
            .Replace("\"C:/old.exe\"", JsonSerializer.Serialize(Launch.Command))
            .Replace("\"env\": { \"A\": \"1\" }", "\"env\": { \"A\": \"1\" },\n            \"disabled\": false");
        Assert.Equal(expected, File.ReadAllText(target.Path));
    }

    [Fact]
    public void StrictFiles_StayStrict_AndKeepTheirFormatting()
    {
        var text = "{\n    \"mcpServers\": {\n        \"other\": {\"command\": \"x\"}\n    },\n    \"z\": 1\n}";
        var target = Target(text);
        target.Install("net-decompiler", Launch);
        var after = File.ReadAllText(target.Path);
        JsonDocument.Parse(after).Dispose();
        Assert.StartsWith("{\n    \"mcpServers\": {\n        \"other\": {\"command\": \"x\"},\n        \"net-decompiler\": {\n            \"command\": ", after);
        Assert.EndsWith("    },\n    \"z\": 1\n}", after);

        // Removing the last entry also removes the comma before it.
        target.Uninstall("net-decompiler");
        Assert.Equal(text, File.ReadAllText(target.Path));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{ }\n")]
    [InlineData("// only a comment\n{}\n")]
    [InlineData("{ \"a\": 1 }")]
    [InlineData("{ \"mcpServers\": {} }")]
    [InlineData("{\"mcpServers\":{\"o\":{\"command\":\"x\"}}}")]
    [InlineData("{ \"a\": [1, {\"b\": 2}], \"c\": \"\\\"}\" }")]
    public void SmallShapes_EditToTheExpectedModel(string text)
    {
        var target = Target(text);
        var model = JsonNode.Parse(text, documentOptions: LenientOptions)!.AsObject();
        Assert.Equal("registered", target.Install("net-decompiler", Launch).Message);
        var servers = model["mcpServers"] as JsonObject ?? new JsonObject();
        model["mcpServers"] = servers.DeepClone();
        model["mcpServers"]!["net-decompiler"] = new JsonObject { ["command"] = Launch.Command, ["args"] = new JsonArray() };
        Assert.True(JsonNode.DeepEquals(model, Lenient(target.Path)), File.ReadAllText(target.Path));
        if (!text.Contains("//", StringComparison.Ordinal)) JsonDocument.Parse(File.ReadAllText(target.Path)).Dispose();
        if (text.Contains("only a comment", StringComparison.Ordinal)) Assert.Contains("only a comment", File.ReadAllText(target.Path));
    }

    [Fact]
    public void UnsupportedShapes_FallBackToTodaysRewrite()
    {
        // The container is not an object: replaced by one, as before, and the lost comment is reported.
        var target = Target("{\n  // note\n  \"mcpServers\": []\n}\n");
        Assert.False(target.Preview("net-decompiler", Launch).PreservesComments);
        var change = target.Install("net-decompiler", Launch);
        Assert.Contains("comments were not kept", change.Message);
        Assert.Equal(Launch.Command, Lenient(target.Path)["mcpServers"]!["net-decompiler"]!["command"]!.GetValue<string>());
        Assert.True(File.Exists(target.Path + ".netdecompiler.bak"));
    }

    [Fact]
    public void RandomEditSequences_KeepEveryComment_AndMatchTheModel()
    {
        const string text = """
            // header
            {
              /* before */ "theme": "dark", // theme
              "mcpServers": {
                // first server
                "keep": { "command": "k", "args": ["a"] }, /* after keep */
              },
              "tail": [1, 2], // end
            }

            """;
        string[] comments = ["// header", "/* before */", "// theme", "// first server", "/* after keep */", "// end"];
        string[] names = ["net-decompiler", "s1", "s-2", "s 3"];
        var random = new Random(1234);
        for (int round = 0; round < 40; round++)
        {
            var target = Target(text.Replace("\r\n", "\n"));
            var model = JsonNode.Parse(text, documentOptions: LenientOptions)!.AsObject();
            for (int step = 0; step < 12; step++)
            {
                var name = names[random.Next(names.Length)];
                var servers = model["mcpServers"]!.AsObject();
                if (random.Next(4) == 0)
                {
                    var change = target.Uninstall(name);
                    Assert.Equal(servers.Remove(name) ? "removed" : "not registered", change.Message);
                }
                else
                {
                    var entry = RandomEntry(random);
                    var change = target.Put(name, _ => (JsonObject)entry.DeepClone());
                    Assert.DoesNotContain("not kept", change.Message);
                    servers[name] = entry;
                }
                var file = File.ReadAllText(target.Path);
                Assert.True(JsonNode.DeepEquals(model, Lenient(target.Path)), $"round {round} step {step}:\n{file}");
                foreach (var comment in comments) Assert.Contains(comment, file);
            }
        }
    }

    private static JsonObject RandomEntry(Random random)
    {
        var entry = new JsonObject { ["command"] = "c" + random.Next(3) };
        if (random.Next(2) == 0) entry["args"] = new JsonArray([.. Enumerable.Range(0, random.Next(3)).Select(i => (JsonNode)JsonValue.Create("a" + i + "\"\\")!)]);
        if (random.Next(2) == 0) entry["env"] = random.Next(2) == 0 ? new JsonObject() : new JsonObject { ["K"] = "v" + random.Next(2), ["N"] = random.Next(5) };
        if (random.Next(3) == 0) entry["disabled"] = random.Next(2) == 0;
        if (random.Next(4) == 0) entry["nested"] = new JsonObject { ["list"] = new JsonArray(new JsonObject { ["x"] = 1 }, 2) };
        return entry;
    }
}
