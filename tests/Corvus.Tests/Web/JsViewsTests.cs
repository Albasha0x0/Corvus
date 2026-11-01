using Corvus.Core;
using Corvus.Services.Web;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>analyze_js views: the parsed program is kept per file state, flows page by index, limits and bytecode refusals are named.</summary>
public sealed class JsViewsTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static WebTools Tools() => new(new OutputPager(new ServerOptions()));

    // Fixture: one file read twice, then rewritten with a later write time.
    [Fact]
    public void One_parse_serves_two_views_until_the_file_changes()
    {
        var js = _dir.File("app.js");
        File.WriteAllText(js, "function f(a) { return fetch(a); }\nf('/x');\n");
        var first = JsAnalysis.Program(js, default);
        Assert.Same(first, JsAnalysis.Program(js, default));
        File.WriteAllText(js, "function f(a) { return fetch(a); }\nf('/y');\n");
        File.SetLastWriteTimeUtc(js, DateTime.UtcNow.AddMinutes(1));
        Assert.NotSame(first, JsAnalysis.Program(js, default));
    }

    // Fixture: 600 eval calls, one sink flow each.
    [Fact]
    public async Task Six_hundred_flows_page_by_flow_index()
    {
        var js = SinkFile("sinks.js");
        var tools = Tools();
        var first = await tools.AnalyzeJs(js, "flow", query: "sinks", limit: 500);
        Assert.Contains("600 flow(s)", first, StringComparison.Ordinal);
        Assert.Contains("[More: offset=", first, StringComparison.Ordinal);
        var next = MoreOffset(first);
        var second = await tools.AnalyzeJs(js, "flow", query: "sinks", limit: 500, offset: next);
        Assert.Contains($"flow {next + 1} (", second, StringComparison.Ordinal);
        Assert.DoesNotContain("[More:", second, StringComparison.Ordinal);
    }

    // Fixture: 600 eval calls; a small maxTokens cuts the page below the row count.
    [Fact]
    public async Task A_small_token_budget_shortens_the_flow_page_and_names_the_next_offset()
    {
        var js = SinkFile("budget.js");
        var text = await Tools().AnalyzeJs(js, "flow", query: "sinks", limit: 500, maxTokens: 1500);
        var next = MoreOffset(text);
        Assert.InRange(next, 1, 499);
        Assert.Contains($"flow {next} (", text, StringComparison.Ordinal);
        Assert.DoesNotContain($"flow {next + 1} (", text, StringComparison.Ordinal);
    }

    // Fixture: 600 eval calls; origins of one literal read the same flow index.
    [Fact]
    public async Task Origins_page_from_the_flow_index_in_offset()
    {
        var js = SinkFile("origins.js");
        var tools = Tools();
        Assert.Contains("origins of", await tools.AnalyzeJs(js, "origins", query: "\"code7\""), StringComparison.Ordinal);
        Assert.Contains("No flow at offset 1000", await tools.AnalyzeJs(js, "origins", query: "\"code7\"", offset: 1000), StringComparison.Ordinal);
    }

    // Fixture: 600 eval calls; offset 600 is the first index past the last flow.
    [Fact]
    public async Task An_offset_past_the_last_flow_names_the_total()
    {
        var js = SinkFile("past.js");
        var text = await Tools().AnalyzeJs(js, "flow", query: "sinks", offset: 600);
        Assert.Contains("No flow at offset 600: 600 flow(s) in all.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("[More:", text, StringComparison.Ordinal);
    }

    // Fixture: a call chain of 150,000 functions exhausts the default step budget.
    [Fact]
    public async Task A_walk_cut_by_the_step_budget_names_a_narrowing_call()
    {
        var js = _dir.File("chain.js");
        File.WriteAllText(js, string.Join("\n", Enumerable.Range(0, 150_000).Select(i => $"function f{i}(x) {{ return f{i + 1}(x + 1); }}")) + "\nf0(\"/a\");");
        var text = await Tools().AnalyzeJs(js, "flow", query: "\"/a\"");
        Assert.Contains("partial: step budget", text, StringComparison.Ordinal);
        Assert.Contains("Next: analyze_js", text, StringComparison.Ordinal);
        Assert.Contains("query=", text, StringComparison.Ordinal);
    }

    // Fixture: spaces one character over the parse limit.
    [Fact]
    public async Task A_bundle_over_the_parse_limit_is_refused_with_LimitExceeded()
    {
        var js = OversizeFile();
        var tools = Tools();
        foreach (var view in new[] { "module", "refs", "modules", "search" })
            Assert.Equal(ErrorCode.LimitExceeded, (await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeJs(js, view, query: "1"))).Code);
        Assert.Equal(ErrorCode.LimitExceeded, (await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeJs(js, "secrets"))).Code);
    }

    // Fixture: spaces one character over the parse limit; the named views read it unparsed.
    [Fact]
    public async Task An_over_limit_bundle_still_answers_the_views_that_read_it_unparsed()
    {
        var js = OversizeFile();
        var tools = Tools();
        Assert.NotEmpty(await tools.AnalyzeJs(js, "summary"));
        foreach (var view in new[] { "sources", "position" })
        {
            var ex = await Record.ExceptionAsync(() => tools.AnalyzeJs(js, view, line: 1, column: 1));
            Assert.False(ex is ToolError { Code: ErrorCode.LimitExceeded }, view);
        }
    }

    // Fixture: a syntax error leaves the module table empty with parse notes.
    [Fact]
    public async Task An_unparseable_bundle_names_its_parse_notes_when_a_module_is_missing()
    {
        var js = _dir.File("broken.js");
        File.WriteAllText(js, "function ( {{{ ");
        var tools = Tools();
        foreach (var view in new[] { "module", "refs" })
        {
            var ex = await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeJs(js, view, query: "1"));
            Assert.Equal(ErrorCode.NotFound, ex.Code);
            Assert.Matches(@"in broken\.js \(.+\)\.", ex.Message);
        }
    }

    // Fixture: eight views run at once on one kept program.
    [Fact]
    public async Task Concurrent_views_of_one_bundle_agree_with_a_single_view()
    {
        var js = _dir.File("shared.js");
        File.WriteAllText(js, "var k = 'AKIAABCDEFGHIJKLMNOP';\nfunction f(a) { return fetch(a); }\nf('/x');\n");
        var tools = Tools();
        var runtime = await tools.AnalyzeJs(js, "runtime");
        var secrets = await tools.AnalyzeJs(js, "secrets");
        var all = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => Task.Run(() => tools.AnalyzeJs(js, i % 2 == 0 ? "runtime" : "secrets"))));
        for (int i = 0; i < all.Length; i++) Assert.Equal(i % 2 == 0 ? runtime : secrets, all[i]);
    }

    // Fixture: the Hermes bytecode file reads no flow view.
    [Fact]
    public async Task A_text_view_on_Hermes_bytecode_is_Unsupported()
    {
        var ex = await Assert.ThrowsAsync<ToolError>(() => Tools().AnalyzeJs(HermesTests.Fixture("metro-v96.hbc"), "flow", query: "sinks"));
        Assert.Equal(ErrorCode.Unsupported, ex.Code);
        Assert.Contains("view=search", ex.Remediation, StringComparison.Ordinal);
        Assert.Contains("xrefs", ex.Remediation, StringComparison.Ordinal);
    }

    // Fixture: the Hermes bytecode file and a view name no file reads.
    [Fact]
    public async Task An_unknown_view_on_Hermes_bytecode_is_InvalidArgument()
    {
        var ex = await Assert.ThrowsAsync<ToolError>(() => Tools().AnalyzeJs(HermesTests.Fixture("metro-v96.hbc"), "nothing"));
        Assert.Equal(ErrorCode.InvalidArgument, ex.Code);
    }

    private string SinkFile(string name)
    {
        var js = _dir.File(name);
        File.WriteAllText(js, string.Concat(Enumerable.Range(0, 600).Select(i => $"eval(\"code{i}\");\n")));
        return js;
    }

    private string OversizeFile()
    {
        var js = _dir.File("big.js");
        File.WriteAllText(js, new string(' ', JsModules.MaxParseChars + 1));
        return js;
    }

    private static int MoreOffset(string text) =>
        int.Parse(System.Text.RegularExpressions.Regex.Match(text, @"\[More: offset=(\d+)\]").Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
}
