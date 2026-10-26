using System.Text;
using System.Text.Json;
using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>summarize_file view=flight: React Server Components rows from a raw response and from a page's pushes.</summary>
public sealed class FlightDataTests(Xunit.Abstractions.ITestOutputHelper output)
{
    private const string Text = "<p>text with: colon</p>";

    // React 19 rows as Next.js 15 writes them: a symbol, client modules, a server action, a hint, a text row, an error, the tree.
    private static readonly string Raw =
        "1:\"$Sreact.fragment\"\n" +
        "2:I[9766,[],\"\"]\n" +
        "4:I[5675,[\"974\",\"static/chunks/app/page-e190.js\"],\"default\"]\n" +
        "5:{\"id\":\"40dc34df82392959bf44054a60745d890e2a109691\",\"bound\":null}\n" +
        "6:HL[\"/_next/static/css/app.css\",\"style\"]\n" +
        $"7:T{Encoding.UTF8.GetByteCount(Text):x},{Text}" +
        "8:E{\"digest\":\"2361\",\"message\":\"boom\"}\n" +
        "0:{\"b\":\"build\",\"f\":[[[\"\",{\"children\":[\"__PAGE__\",{}]},\"$undefined\",\"$undefined\",true],[\"\",[\"$\",\"$1\",\"c\",{\"children\":[[\"$\",\"html\",null,{\"lang\":\"en\"," +
        "\"children\":[\"$\",\"body\",null,{\"children\":[\"$\",\"main\",null,{\"children\":[[\"$\",\"h1\",null,{\"children\":\"Notes\"}],[\"$\",\"$L4\",null,{\"start\":3}]," +
        "[\"$\",\"form\",null,{\"action\":\"$h5\",\"children\":[\"$\",\"input\",null,{\"name\":\"note\"}]}]]}]}]}]]}]]]]}\n";

    // The page form: the same stream cut inside rows into three pushes, after the bootstrap push.
    private static string Page()
    {
        var sb = new StringBuilder("<!DOCTYPE html><html><body><script>(self.__next_f=self.__next_f||[]).push([0])</script>");
        int[] cuts = [0, 30, 200, Raw.Length];
        for (int k = 0; k + 1 < cuts.Length; k++)
            sb.Append("<script>self.__next_f.push([1,").Append(JsonSerializer.Serialize(Raw[cuts[k]..cuts[k + 1]])).Append("])</script>");
        return sb.Append("</body></html>").ToString();
    }

    [Fact]
    public void A_raw_response_names_its_client_modules_actions_and_tree()
    {
        var p = FlightData.Read(Raw, default)!;
        output.WriteLine(p.Tree);
        Assert.Equal(("raw", 8), (p.Source, p.Rows));
        Assert.Equal(new Dictionary<string, int> { ["E"] = 1, ["H"] = 1, ["I"] = 2, ["T"] = 1, ["model"] = 3 }, p.Tags);
        Assert.Equal(["9766 []", "5675 [static/chunks/app/page-e190.js] default"], p.ClientModules.Select(m => $"{m.Id} [{string.Join(",", m.Chunks)}]{(m.Name.Length > 0 ? " " + m.Name : "")}"));
        Assert.Equal(["40dc34df82392959bf44054a60745d890e2a109691 (row 5)"], p.Actions);
        Assert.Equal(["preload /_next/static/css/app.css as style"], p.Hints);
        Assert.Equal(["row 8: boom (digest 2361)"], p.Errors);
        Assert.Equal(8, p.Elements);
        Assert.Equal("react.fragment(html(body(main(h1, client 5675#default, form(input)))))", p.Tree);
        Assert.Empty(p.Notes);
    }

    [Fact]
    public void A_pages_pushes_decode_to_the_same_rows()
    {
        var raw = FlightData.Read(Raw, default)!;
        var page = FlightData.Read(Page(), default)!;
        Assert.Equal("page (4 pushes)", page.Source);
        Assert.Equal((raw.Rows, raw.Elements), (page.Rows, page.Elements));
        Assert.Equal(raw.Tags, page.Tags);
        Assert.Equal(raw.ClientModules, page.ClientModules, (a, b) => a.Id == b.Id && a.Chunks.SequenceEqual(b.Chunks) && a.Name == b.Name);
        Assert.Equal(raw.Actions, page.Actions);
        Assert.Equal(raw.Tree, page.Tree);
    }

    [Fact]
    public void A_cut_stream_keeps_its_rows_and_names_the_cut()
    {
        var p = FlightData.Read(Raw[..Raw.IndexOf("8:E", StringComparison.Ordinal)].Replace("7:T17,", "7:T40,", StringComparison.Ordinal), default)!;
        Assert.Equal(6, p.Rows);
        Assert.Contains(p.Notes, n => n.StartsWith("row 7: 64 bytes announced", StringComparison.Ordinal));
        Assert.Contains("no row 0: the payload is a part of a stream, the tree is not drawn", p.Notes);
    }

    /// <summary>summarize_file lists the view for a .rsc file and returns the payload as the view's detail.</summary>
    [Fact]
    public async Task Summarize_file_view_flight_reads_a_response()
    {
        using var dir = new TempDir();
        var path = dir.File("index.rsc");
        File.WriteAllText(path, Raw);
        await using var server = await InProcessServer.StartAsync();
        var overview = await server.Client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = path });
        Assert.Contains("flight", overview.StructuredContent!.Value.GetProperty("views").EnumerateArray().Select(v => v.GetString()));
        var view = await server.Client.CallToolAsync("summarize_file", new Dictionary<string, object?> { ["path"] = path, ["view"] = "flight" });
        var detail = view.StructuredContent!.Value.GetProperty("detail");
        Assert.Equal(2, detail.GetProperty("clientModules").GetArrayLength());
        var text = string.Concat(view.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text));
        output.WriteLine(text);
        Assert.Contains("tree: react.fragment(html(body(main(h1, client 5675#default, form(input)))))", text);
        Assert.Contains("React Server Components payload (raw): 8 rows", string.Concat(overview.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text)));
    }

    /// <summary>
    /// CORVUS_NEXT_BUILD: a Next.js build folder (.next). Each prerendered page and its .rsc decode to the same rows, client
    /// modules and tree, and every chunk file a client module names exists under static.
    /// </summary>
    [RequiresRealDataFact("CORVUS_NEXT_BUILD")]
    [Trait("Speed", "Slow")]
    public void Real_pages_and_their_responses_decode_to_the_same_rows()
    {
        var build = Environment.GetEnvironmentVariable("CORVUS_NEXT_BUILD")!;
        var failures = new List<string>();
        var pages = Directory.EnumerateFiles(Path.Combine(build, "server", "app"), "*.html", SearchOption.AllDirectories).Where(f => File.Exists(Path.ChangeExtension(f, ".rsc"))).ToList();
        Assert.NotEmpty(pages);
        foreach (var html in pages)
        {
            var name = Path.GetRelativePath(build, html);
            var page = FlightData.Read(File.ReadAllText(html), default);
            var raw = FlightData.Read(File.ReadAllText(Path.ChangeExtension(html, ".rsc")), default);
            if (page == null || raw == null) { failures.Add($"{name}: not read (page {page != null}, response {raw != null})"); continue; }
            output.WriteLine($"{name}: {page.Source}, {page.Rows} rows, {page.ClientModules.Count} modules, {page.Actions.Count} actions, {page.Elements} elements");
            if (page.Notes.Concat(raw.Notes).Any()) failures.Add($"{name}: notes {string.Join("; ", page.Notes.Concat(raw.Notes))}");
            if (!page.Tags.OrderBy(t => t.Key).SequenceEqual(raw.Tags.OrderBy(t => t.Key))) failures.Add($"{name}: tags differ");
            if (!page.ClientModules.Select(m => m.Id + m.Name).SequenceEqual(raw.ClientModules.Select(m => m.Id + m.Name))) failures.Add($"{name}: client modules differ");
            if (!page.Actions.SequenceEqual(raw.Actions)) failures.Add($"{name}: actions differ");
            if (page.Tree != raw.Tree) failures.Add($"{name}: trees differ");
            foreach (var chunk in raw.ClientModules.SelectMany(m => m.Chunks).Distinct())
                if (!File.Exists(Path.Combine(build, chunk))) failures.Add($"{name}: chunk {chunk} not in the build");
        }
        Assert.True(failures.Count == 0, string.Join('\n', failures));
    }

    /// <summary>Mutated payloads, raw and in a page: a payload or null, never an exception.</summary>
    [Fact]
    [FuzzEntry(typeof(FlightData), typeof(Services.Analysis.FlightFileView))]
    public void Fuzzed_payloads_never_throw()
    {
        using var dir = new TempDir();
        var failures = new List<string>();
        foreach (var seed in new[] { Raw, Page() })
            failures.AddRange(FormatFuzz.Run(Encoding.UTF8.GetBytes(seed), b =>
            {
                FlightData.Read(Encoding.UTF8.GetString(b), default);
                new Services.Analysis.FlightFileView().Inspect(new Services.Analysis.FileInput(dir.File("index.rsc"), b, Corvus.Core.Blob.Identify(b)), default);
            }, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
