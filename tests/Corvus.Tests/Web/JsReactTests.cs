using Corvus.Services.Web;

namespace Corvus.Tests;

/// <summary>analyze_js view=react and view=jsx: components, hooks and render edges from compiled element calls.</summary>
public sealed class JsReactTests(Xunit.Abstractions.ITestOutputHelper output)
{
    // Compiled as Babel and esbuild emit it: the automatic runtime's jsx, the classic createElement, memo and a class.
    private const string Bundle = """
        var React = { version: "18.3.1", useState: function () {}, useEffect: function () {}, createElement: function () {}, Component: function () {} };
        var r = { jsx: function () {}, jsxs: function () {}, Fragment: {} };
        function Header(props) { var _a = React.useState(0), n = _a[0]; React.useEffect(function () { document.title = n; }); return (0, r.jsx)("h1", { className: "title", children: props.title }); }
        const List = React.memo(function (e) { return (0, r.jsx)("ul", { children: e.items.map(function (i) { return (0, r.jsx)(Item, { label: i }, i); }) }); });
        const Item = e => (0, r.jsxs)("li", { children: ["#", e.label] });
        Item.displayName = "ListItem";
        class App extends React.Component { render() { return React.createElement(r.Fragment, null, React.createElement(Header, { title: "Hi" }), React.createElement(List, { items: [1, 2] }), this.props.extra && React.createElement("footer", null, "end")); } }
        function useCounter() { return React.useState(1); }
        document.createElement("div");
        var Panel = function (e) { _inherits(t, e); function t() { return e.apply(this, arguments) || this; } _createClass(t, [{ key: "render", value: function () { return (0, r.jsx)("section", { children: this.props.body }); } }]); return t; }(React.Component);
        var Badge = function (e) { function t() {} var n, o; return n = t, (o = [{ key: "label", get: function () { return "b"; } }, { key: "render", value: function () { return (0, r.jsx)("b", {}); } }]) && define(n.prototype, o), t; }(React.PureComponent);
        """;

    private static JsProgram Program(string text) => JsProgram.Build("app.js", text, [], default)!;

    [Fact]
    public void Components_hooks_and_render_edges_are_read_from_element_calls()
    {
        var r = JsReact.Read(Program(Bundle), null, 0, 100, default);
        Assert.Equal(["react 18.3.1"], r.Versions);
        // Panel is compiled by Babel: its render comes from _createClass, its class is the inner function t.
        // Badge is loose mode: the helper is inlined in the function its binding names.
        Assert.Equal(["Header function", "List memo", "ListItem function", "App class", "t class", "Badge class"], r.Components.Select(c => $"{c.Name} {c.Kind}"));
        Assert.Equal((1, 1), (r.Components[4].Elements, r.Components[5].Elements));
        Assert.Equal((10, 10), (r.Calls, r.Attributed));
        var header = r.Components[0];
        Assert.Equal(["useState", "useEffect"], header.Hooks);
        Assert.Equal((1, 3), (header.Elements, header.Line));
        Assert.Equal(["ListItem"], r.Components[1].Renders);
        Assert.Equal(2, r.Components[1].Elements);
        var app = r.Components[3];
        Assert.Equal(["Fragment", "Header", "List"], app.Renders);
        Assert.Equal(4, app.Elements);
        Assert.DoesNotContain(r.Components, c => c.Name == "useCounter");
        Assert.Equal(["List"], JsReact.Read(Program(Bundle), "lis", 0, 1, default).Components.Select(c => c.Name));
    }

    [Fact]
    public void Jsx_view_writes_a_components_element_calls_as_jsx()
    {
        var app = JsReact.Jsx(Program(Bundle), "App", default)!;
        Assert.Contains("<>\n  <Header title=\"Hi\" />\n  <List items={[1, 2]} />\n  {this.props.extra && <footer>", app);
        Assert.EndsWith("</>\n", app);
        var list = JsReact.Jsx(Program(Bundle), "List", default)!;
        Assert.Contains("<ListItem key={i} label={i} />", list);
        Assert.Contains("<li>\n  #\n  {e.label}\n</li>", JsReact.Jsx(Program(Bundle), "ListItem", default));
        Assert.Null(JsReact.Jsx(Program(Bundle), "Missing", default));
    }

    [Fact]
    public void A_script_without_element_calls_says_so()
    {
        var r = JsReact.Read(Program("function f() { return document.createElement('div'); }"), null, 0, 10, default);
        Assert.Empty(r.Components);
        Assert.Empty(r.Versions);
        Assert.StartsWith("no element factory calls", Assert.Single(r.Notes));
    }

    /// <summary>analyze_js names the views, matches its output schema and refuses an unknown component.</summary>
    [Fact]
    public async Task Analyze_js_views_react_and_jsx()
    {
        using var dir = new TempDir();
        var path = dir.File("app.js");
        File.WriteAllText(path, Bundle);
        await using var server = await InProcessServer.StartAsync();
        var react = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = path, ["view"] = "react" });
        var text = string.Concat(react.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text));
        Assert.True(text.StartsWith("React: react 18.3.1; 6 component(s), 10 of 10 element call(s) in them", StringComparison.Ordinal), text);
        Assert.Contains("App (class) 7:1: 4 element(s); renders Fragment, Header, List", text);
        Assert.Equal(6, react.StructuredContent!.Value.GetProperty("total").GetInt32());
        var jsx = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = path, ["view"] = "jsx", ["query"] = "Header" });
        Assert.Contains("<h1 className=\"title\">", string.Concat(jsx.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text)));
        var missing = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = path, ["view"] = "jsx", ["query"] = "Nope" });
        Assert.True(missing.IsError);
    }

    /// <summary>
    /// CORVUS_REACT_BUNDLES: compiled React bundles (.js). Each names the React version its text assigns, holds at least
    /// 90 % of its element calls in components, and writes every component as JSX, within 10 s per bundle.
    /// </summary>
    [RequiresRealDataFact("CORVUS_REACT_BUNDLES")]
    [Trait("Speed", "Slow")]
    public void Real_bundles_hold_their_element_calls_in_components()
    {
        var failures = new List<string>();
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_REACT_BUNDLES")!, "*.js", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var name = Path.GetFileName(file);
            var text = File.ReadAllText(file);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            var p = JsProgram.Build(name, text, [], default)!;
            var a = JsReact.Analyze(p, default);
            var r = a.Read(null, 0, JsReact.MaxComponents, default);
            foreach (var c in r.Components) a.Jsx(c.Name);
            watch.Stop();
            output.WriteLine($"{name}: {string.Join(", ", r.Versions)}; {r.Total} components, {r.Attributed}/{r.Calls} calls, {watch.Elapsed.TotalSeconds:0.0} s");
            foreach (var c in r.Components.Where(c => c.Hooks.Count > 0 || c.Renders.Count > 0).Take(10)) output.WriteLine($"  {c.Name} ({c.Kind}) {c.Elements}; hooks [{string.Join(", ", c.Hooks)}]; renders {string.Join(", ", c.Renders.Take(6))}");
            var literal = System.Text.RegularExpressions.Regex.Match(text, "version\\s*[:=]\\s*\"(1[5-9]\\.\\d+\\.\\d+)\"");
            if (literal.Success && !r.Versions.Contains("react " + literal.Groups[1].Value) && !r.Versions.Contains("react-dom " + literal.Groups[1].Value))
                failures.Add($"{name}: version {literal.Groups[1].Value} not named ({string.Join(", ", r.Versions)})");
            if (r.Calls > 0 && r.Attributed < r.Calls * 0.9) failures.Add($"{name}: {r.Attributed} of {r.Calls} element calls in components");
            if (watch.Elapsed > TimeSpan.FromSeconds(10)) failures.Add($"{name}: {watch.Elapsed.TotalSeconds:0.0} s");
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    /// <summary>Mutated bundles: components and JSX, or a parse failure, never an exception.</summary>
    [Fact]
    [FuzzEntry(typeof(JsReact))]
    public void Fuzzed_bundles_never_throw()
    {
        var failures = FormatFuzz.Run(System.Text.Encoding.UTF8.GetBytes(Bundle), b =>
        {
            var p = JsProgram.Build("app.js", System.Text.Encoding.UTF8.GetString(b), [], default);
            if (p == null) return;
            var r = JsReact.Read(p, null, 0, 50, default);
            foreach (var c in r.Components.Take(3)) JsReact.Jsx(p, c.Name, default);
        }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }
}
