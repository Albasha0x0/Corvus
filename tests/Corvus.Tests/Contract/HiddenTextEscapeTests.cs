using System.Text.Json;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using Corvus.Core;
using Corvus.Mcp;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>Tag characters, variation selectors, unpaired surrogates and planes 15-16 private use reach both result parts escaped.</summary>
public sealed class HiddenTextEscapeTests : IDisposable
{
    // "AB" in tag characters, invisible in an editor.
    private const string Tags = "\U000E0041\U000E0042";
    private const string TagsShown = "\\U000e0041\\U000e0042";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Theory]
    [InlineData("a\U000E0041b", "a\\U000e0041b")]
    [InlineData("a\uFE00b", "a\\ufe00b")]
    [InlineData("a\U000E0100b", "a\\U000e0100b")]
    [InlineData("a\uFE0Fb", "a\\ufe0fb")]
    [InlineData("a\U000F0000b\U0010FFFD", "a\\U000f0000b\\U0010fffd")]
    public void Hidden_code_points_are_escaped_and_read_back(string raw, string shown)
    {
        Assert.Equal(shown, Format.EscapeInvisible(raw));
        Assert.Equal(raw, Format.UnescapeInvisible(shown));
    }

    // Not theory data: the runner turns an unpaired surrogate in an argument into U+FFFD.
    [Fact]
    public void Unpaired_surrogates_are_escaped_and_read_back()
    {
        Assert.Equal("a\\ud800b\\udc00", Format.EscapeInvisible("a\uD800b\uDC00"));
        Assert.Equal("a\uD800b\uDC00", Format.UnescapeInvisible("a\\ud800b\\udc00"));
    }

    [Theory]
    [InlineData("\u2764\uFE0F")]
    [InlineData("\U0001F600\uFE0F")]
    [InlineData("1\uFE0F\u20E3")]
    [InlineData("\u2196\uFE0E")]
    public void An_emoji_with_its_presentation_selector_prints_unchanged(string text) =>
        Assert.Same(text, Format.EscapeInvisible(text));

    [Fact]
    public void A_visible_code_point_escape_is_kept_as_written() =>
        Assert.Equal("\\U0001f600\\u0041", Format.UnescapeInvisible("\\U0001f600\\u0041"));

    /// <summary>A type, a method, a resource and a string literal with tag characters in their names or text.</summary>
    private string WriteFixture()
    {
        var module = new ModuleDefUser("Tagged.dll", Guid.NewGuid(), new AssemblyRefUser("System.Runtime", new Version(8, 0, 0, 0))) { Kind = ModuleKind.Dll };
        var assembly = new AssemblyDefUser("Tagged", new Version(1, 0, 0, 0));
        assembly.Modules.Add(module);
        var objectRef = new TypeRefUser(module, "System", "Object", module.CorLibTypes.AssemblyRef);
        var type = new TypeDefUser("Lab", "Carrier" + Tags, objectRef) { Attributes = TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed };
        var run = new MethodDefUser("Run" + Tags, MethodSig.CreateStatic(module.CorLibTypes.Void), MethodAttributes.Public | MethodAttributes.Static) { Body = new CilBody() };
        run.Body.Instructions.Add(OpCodes.Ldstr.ToInstruction("marker" + Tags + "\uD800"));
        run.Body.Instructions.Add(OpCodes.Pop.ToInstruction());
        run.Body.Instructions.Add(OpCodes.Ret.ToInstruction());
        type.Methods.Add(run);
        module.Types.Add(type);
        module.Resources.Add(new EmbeddedResource("note" + Tags + ".txt", [1, 2, 3]));
        var path = _dir.File("Tagged.dll");
        module.Write(path);
        return path;
    }

    [Fact]
    public async Task Names_and_strings_with_tag_characters_print_escaped_in_text_and_record()
    {
        var path = WriteFixture();
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(path);
        await using var server = await InProcessServer.StartAsync(options: options);
        var calls = new (string Tool, Dictionary<string, object?> Args, string Expected)[]
        {
            ("search_strings", new() { ["query"] = "marker", ["assembly"] = path }, "marker" + TagsShown + "\\ud800"),
            ("search_symbols", new() { ["query"] = "Carrier", ["assembly"] = path }, "Carrier" + TagsShown),
            ("get_type_info", new() { ["type"] = "Lab.Carrier" + Tags, ["assembly"] = path }, "Run" + TagsShown),
            ("list_resources", new() { ["assembly"] = path }, "note" + TagsShown),
        };
        var failures = new List<string>();
        foreach (var (tool, args, expected) in calls)
        {
            var result = await server.Client.CallToolAsync(tool, args);
            var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
            if (result.IsError == true) { failures.Add($"{tool}: error {text}"); continue; }
            if (!text.Contains(expected, StringComparison.Ordinal)) failures.Add($"{tool}: text lacks {expected}");
            if (Raw(text)) failures.Add($"{tool}: raw hidden code point in text");
            var record = result.StructuredContent?.GetRawText();
            if (record == null) { failures.Add($"{tool}: no record"); continue; }
            var strings = Strings(JsonDocument.Parse(record).RootElement).ToList();
            if (!strings.Any(s => s.Contains(expected, StringComparison.Ordinal))) failures.Add($"{tool}: record lacks {expected}");
            if (strings.Any(Raw)) failures.Add($"{tool}: raw hidden code point in record");
        }

        var error = await server.Client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Lab.Missing" + Tags, ["assembly"] = path });
        var errorText = string.Concat(error.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (error.IsError != true) failures.Add("get_type_info: no error for a missing type");
        if (!errorText.Contains("Missing" + TagsShown, StringComparison.Ordinal)) failures.Add($"error: text lacks the escaped name: {errorText}");
        if (Raw(errorText)) failures.Add("error: raw hidden code point");
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public void An_error_record_with_tag_characters_carries_them_escaped()
    {
        var json = ToolError.ErrorJson("not_found", false, "no type", null, null, new { name = "Lab.X" + Tags });
        Assert.Contains("Lab.X" + TagsShown, JsonDocument.Parse(json).RootElement.GetProperty("details").GetProperty("name").GetString());
    }

    private static bool Raw(string s) => Format.EscapeInvisible(s) != s;

    private static IEnumerable<string> Strings(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.String:
                yield return e.GetString()!;
                break;
            case JsonValueKind.Array:
                foreach (var s in e.EnumerateArray().SelectMany(Strings)) yield return s;
                break;
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject())
                {
                    yield return p.Name;
                    foreach (var s in Strings(p.Value)) yield return s;
                }
                break;
        }
    }
}
