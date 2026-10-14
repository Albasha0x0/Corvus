using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>
/// The .NET edit and build tools end to end on Newtonsoft.Json (13.0.1, carried to 13.0.4): every edit kind for real, review,
/// undo, revert, script export and replay on the other build, save, and the comparisons; each answer within its class budget.
/// </summary>
[Trait("Data", "Real")]
[Trait("Speed", "Slow")]
public sealed class EditRealDataTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Lib(string version) => RealPackages.Lib("newtonsoft.json", version, "netstandard2.0", "Newtonsoft.Json.dll");

    private sealed record Answer(string Text, JsonElement? Record, bool IsError)
    {
        public int TextTokens => TokenEstimate.Of(Text);
        public int RecordTokens => Record is { } r ? TokenEstimate.Of(r.GetRawText()) : 0;
    }

    private static async Task<Answer> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var result = await server.Client.CallToolAsync(tool, args);
        var answer = new Answer(string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text)), result.StructuredContent, result.IsError == true);
        Assert.False(answer.IsError, $"{tool}: {answer.Text}");
        return answer;
    }

    /// <summary>Each part within the class budget plus the 5% the acceptance allows.</summary>
    private static void Within(Answer a, int tokens, string what)
    {
        Assert.True(a.TextTokens <= tokens, $"{what}: text {a.TextTokens} tokens > {tokens}");
        Assert.True(a.RecordTokens <= tokens, $"{what}: record {a.RecordTokens} tokens > {tokens}");
    }

    [Fact]
    public async Task EditReviewUndoReplayAndCompareOnNewtonsoft()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(Lib("13.0.1"));
        options.Preload.Add(Lib("13.0.4"));
        await using var server = await InProcessServer.StartAsync(options: options);
        const string Asm = "Newtonsoft.Json", Other = "Newtonsoft.Json#2", Convert = "Newtonsoft.Json.JsonConvert";

        // Previews by default: nothing changes.
        var preview = await Call(server, "rename_namespace", new() { ["assembly"] = Asm, ["oldNamespace"] = "Newtonsoft.Json.Bson", ["newNamespace"] = "Bson" });
        Assert.Contains("pass dryRun=false to apply", preview.Text);
        var whole = await Call(server, "simplify_methods", new() { ["assembly"] = Asm });
        Within(whole, 3_150, "whole-assembly simplify preview");
        Assert.StartsWith("Totals:", whole.Text.Split('\n')[1]);

        string[] edits =
        [
            (await Call(server, "stub_method", new() { ["method"] = $"{Convert}::ToString(bool)", ["value"] = "\"x\"", ["assembly"] = Asm, ["dryRun"] = false })).Text,
            (await Call(server, "patch_method_csharp", new() { ["method"] = $"{Convert}::ToString(char)", ["code"] = "return \"c\";", ["assembly"] = Asm, ["dryRun"] = false })).Text,
            (await Call(server, "patch_method_il", new() { ["method"] = $"{Convert}::ToString(byte)", ["il"] = "ldstr \"b\"\nret", ["assembly"] = Asm, ["dryRun"] = false })).Text,
            (await Call(server, "add_members_csharp", new() { ["type"] = Convert, ["code"] = "public static int Probe() { return 7; }", ["assembly"] = Asm, ["dryRun"] = false })).Text,
            (await Call(server, "add_types_csharp", new() { ["assembly"] = Asm, ["code"] = "namespace Probe { public static class P { public static int One() { return 1; } } }", ["dryRun"] = false })).Text,
            (await Call(server, "rename_symbol", new() { ["symbol"] = $"{Convert}::ToString(sbyte)", ["newName"] = "SByteText", ["assembly"] = Asm, ["dryRun"] = false })).Text,
        ];
        for (int i = 0; i < edits.Length; i++) Assert.Contains($"Edit {Asm}#{i + 1}.", edits[i]);

        var list = await Call(server, "list_edits", new() { ["assembly"] = Asm });
        Assert.Equal(6, list.Record!.Value.GetProperty("total").GetInt32());
        var diff = await Call(server, "diff_edits", new() { ["assembly"] = Asm });
        Within(diff, 8_400, "diff_edits");
        Assert.Contains("ToString(char)", diff.Text);

        var script = _dir.File("edits.json");
        await Call(server, "export_edits", new() { ["assembly"] = Asm, ["outputPath"] = script });
        var undo = await Call(server, "undo_edit", new() { ["assembly"] = Asm, ["number"] = 1 });
        Assert.Equal($"{Asm}#1", undo.Record!.Value.GetProperty("editIds")[0].GetString());
        var after = await Call(server, "list_edits", new() { ["assembly"] = Asm });
        Assert.Equal([2, 3, 4, 5, 6], after.Record!.Value.GetProperty("items").EnumerateArray().Select(e => e.GetProperty("number").GetInt32()));
        var reverted = await Call(server, "revert_edits", new() { ["assembly"] = Asm });
        Assert.True(reverted.Record!.Value.TryGetProperty("resultId", out _));

        // The script on the other build: symbols re-resolved by name, every edit applied.
        var applied = await Call(server, "apply_edits", new() { ["path"] = script, ["assembly"] = Other, ["targetBuild"] = "other", ["dryRun"] = false });
        Assert.Contains("6 applied, 0 failed", applied.Text);
        Assert.Equal(6, applied.Record!.Value.GetProperty("editIds").GetArrayLength());
        var saved = await Call(server, "save_assembly", new() { ["assembly"] = Other, ["outputPath"] = _dir.File("patched.dll") });
        Assert.True(File.Exists(saved.Record!.Value.GetProperty("outputPath").GetString()));

        var compare = await Call(server, "compare_assemblies", new() { ["oldAssembly"] = Asm, ["newAssembly"] = Other });
        Within(compare, 4_200, "compare_assemblies");
        Assert.Contains($"{compare.Record!.Value.GetProperty("total").GetInt32()} changes", compare.Text);
        var counterpart = await Call(server, "find_counterpart", new() { ["symbol"] = $"{Convert}::SerializeObject(object)", ["oldAssembly"] = Asm, ["newAssembly"] = Other });
        Within(counterpart, 4_200, "find_counterpart");
        Assert.Equal(1, counterpart.Record!.Value.GetProperty("total").GetInt32());
        var folders = await Call(server, "compare_folders", new()
        {
            ["oldPath"] = Path.GetDirectoryName(Lib("12.0.2")), ["newPath"] = Path.GetDirectoryName(Lib("13.0.1")), ["change"] = "all",
        });
        Within(folders, 4_200, "compare_folders");
    }
}
