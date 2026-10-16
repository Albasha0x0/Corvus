using System.Text.Json;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The builds-native tools by name on two real builds of one library (e_sqlite3 2.1.2 -> 2.1.11): default pages within the
/// list and code budgets, row paging, batches with a bad item, previews by default.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class NativeBuildsRealTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<OwnCopy> _copies = [];

    public void Dispose()
    {
        foreach (var c in _copies) c.Dispose();
        _dir.Dispose();
    }

    private sealed record Answer(string Text, JsonElement Record, bool IsError)
    {
        public int TextTokens => TokenEstimate.Of(Text);
        public int RecordTokens => TokenEstimate.Of(Record.GetRawText());
    }

    private string Copy(string version, string name)
    {
        var copy = new OwnCopy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", version, "runtimes", "win-x64", "native", "e_sqlite3.dll"), _dir.File(Path.Combine(version, name)));
        _copies.Add(copy);
        return copy.Path;
    }

    private async Task<Answer> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        var answer = new Answer(text, r.StructuredContent ?? default, r.IsError == true);
        output.WriteLine($"{tool}: text {answer.TextTokens} tokens, record {(r.StructuredContent != null ? answer.RecordTokens : 0)}: {text.Split('\n')[0]}");
        return answer;
    }

    [Fact]
    public async Task Build_tools_fit_their_budgets_on_a_real_pair()
    {
        var oldPath = Copy("2.1.2", "e_sqlite3.dll");
        var newPath = Copy("2.1.11", "e_sqlite3.dll");
        await using var server = await InProcessServer.StartAsync();
        var (o, n) = (oldPath, newPath);

        // compare_native_images: the default page within the list budget (6,000 + 5%), rows walk by nextOffset
        foreach (var view in new[] { "pairs", "changed" })
        {
            var page = await Call(server, "compare_native_images", new() { ["oldImage"] = o, ["newImage"] = n, ["view"] = view });
            Assert.False(page.IsError, page.Text);
            Assert.True(page.TextTokens <= 6_300 && page.RecordTokens <= 6_300, $"{view}: {page.TextTokens} / {page.RecordTokens}");
            Assert.Equal(page.Record.GetProperty("items").GetArrayLength(), page.Record.GetProperty("nextOffset").GetInt32());
        }

        // the largest changed function, found by walking the changed view
        var (largest, size) = ("", 0L);
        for (int offset = 0; ;)
        {
            var page = await Call(server, "compare_native_images", new() { ["oldImage"] = o, ["newImage"] = n, ["view"] = "changed", ["offset"] = offset, ["limit"] = 500 });
            foreach (var row in page.Record.GetProperty("items").EnumerateArray())
                if (row.GetProperty("oldSize").GetInt64() > size) (largest, size) = (row.GetProperty("old").GetString()!, row.GetProperty("oldSize").GetInt64());
            if (!page.Record.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
        }
        var diff = await Call(server, "diff_function", new() { ["oldImage"] = o, ["newImage"] = n, ["address"] = largest });
        Assert.True(diff.TextTokens <= 8_400 && diff.RecordTokens <= 8_400, $"diff_function {largest} ({size} bytes): {diff.TextTokens} / {diff.RecordTokens}");
        int rows = diff.Record.GetProperty("items").GetArrayLength();
        Assert.Equal(rows, diff.Record.GetProperty("nextOffset").GetInt32());
        var second = await Call(server, "diff_function", new() { ["oldImage"] = o, ["newImage"] = n, ["address"] = largest, ["offset"] = rows });
        Assert.Equal(rows, second.Record.GetProperty("offset").GetInt32());

        // a batch with one bad address succeeds and counts it
        var mapped = await Call(server, "map_address_between_builds", new() { ["oldImage"] = o, ["newImage"] = n, ["addresses"] = new[] { "sqlite3_open", "no_such_function", largest } });
        Assert.False(mapped.IsError, mapped.Text);
        Assert.Equal(1, mapped.Record.GetProperty("failed").GetInt32());
        Assert.Equal("function_start", mapped.Record.GetProperty("results")[0].GetProperty("reason").GetString());

        // a pattern of the old build found again in the new one
        var made = await Call(server, "make_code_pattern", new() { ["image"] = o, ["addresses"] = new[] { "sqlite3_open", "sqlite3_free" } });
        Assert.Equal(0, made.Record.GetProperty("failed").GetInt32());
        var pattern = made.Record.GetProperty("results")[0].GetProperty("pattern").GetString()!;
        var found = await Call(server, "search_code_pattern", new() { ["pattern"] = pattern, ["images"] = new[] { n } });
        Assert.Equal(1, found.Record.GetProperty("total").GetInt32());
        var common = await Call(server, "search_code_pattern", new() { ["pattern"] = "48 89 5C 24 ??", ["images"] = new[] { o, n } });
        Assert.True(common.TextTokens <= 6_300 && common.RecordTokens <= 6_300, $"search_code_pattern: {common.TextTokens} / {common.RecordTokens}");

        // migrations preview by default (D7), then apply as undoable edits
        var name = "corvus_sqlite3_libversion";
        await Call(server, "rename_native", new() { ["image"] = o, ["address"] = "sqlite3_libversion", ["name"] = name, ["dryRun"] = false });
        var preview = await Call(server, "migrate_native_names", new() { ["oldImage"] = o, ["newImage"] = n });
        Assert.True(preview.Record.GetProperty("dryRun").GetBoolean());
        Assert.Contains(preview.Record.GetProperty("items").EnumerateArray(), i => i.GetProperty("value").GetString() == name && i.GetProperty("action").GetString() == "would_set");
        var update = await Call(server, "update_to_new_build", new() { ["oldImage"] = o, ["newImage"] = n, ["include"] = new[] { "names", "patches" } });
        Assert.True(update.TextTokens <= 4_200 && update.RecordTokens <= 4_200, $"update_to_new_build: {update.TextTokens} / {update.RecordTokens}");
        var carried = await Call(server, "migrate_native_names", new() { ["oldImage"] = o, ["newImage"] = n, ["dryRun"] = false });
        var editId = carried.Record.GetProperty("editIds")[0].GetString()!;
        await Call(server, "undo_native_edit", new() { ["image"] = "e_sqlite3.dll#2", ["editId"] = editId });
        var patched = await Call(server, "patch_bytes", new() { ["image"] = o, ["address"] = "sqlite3_libversion_number", ["hex"] = "CC", ["dryRun"] = false });
        var patches = await Call(server, "migrate_native_patches", new() { ["oldImage"] = o, ["newImage"] = n });
        Assert.Equal(1, patches.Record.GetProperty("total").GetInt32());
        Assert.True(Corvus.Native.Diff.MigrationReasons.IsKnown(patches.Record.GetProperty("items")[0].GetProperty("reason").GetString()!));
        await Call(server, "undo_native_edit", new() { ["image"] = "e_sqlite3.dll", ["editId"] = patched.Record.GetProperty("editIds")[0].GetString()! });
    }
}
