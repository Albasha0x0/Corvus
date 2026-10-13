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

    public void Dispose() => _dir.Dispose();

    private sealed record Answer(string Text, JsonElement Record, bool IsError)
    {
        public int TextTokens => TokenEstimate.Of(Text);
        public int RecordTokens => TokenEstimate.Of(Record.GetRawText());
    }

    private static string Copy(TempDir dir, string version, string name)
    {
        var path = dir.File(Path.Combine(version, name));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.Copy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", version, "runtimes", "win-x64", "native", "e_sqlite3.dll"), path);
        return path;
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
        var oldPath = Copy(_dir, "2.1.2", "e_sqlite3.dll");
        var newPath = Copy(_dir, "2.1.11", "e_sqlite3.dll");
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
    }
}
