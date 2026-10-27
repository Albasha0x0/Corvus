using Acornima;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services.Web;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>analyze_js view=beautify on program.min.js, terser 5.39.0 output of BeautifyFixtures/program.js.</summary>
public sealed class JsBeautifyTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Web", "BeautifyFixtures", name);

    // The source's tokens with the semicolons the parser inserted written out; identifiers mapped through rename.
    internal static List<string> Tokens(string text, Func<string, string>? rename = null)
    {
        var tokens = new List<(int Start, string Text)>();
        var inserted = new List<int>();
        var options = new ParserOptions
        {
            AllowHashBang = true,
            OnToken = (in Token t) => { if (t.Kind != TokenKind.EOF) tokens.Add((t.Start, t.Kind == TokenKind.Identifier && rename != null ? rename(text[t.Start..t.End]) : text[t.Start..t.End])); },
            OnInsertedSemicolon = (int end, Position _) => inserted.Add(end),
        };
        try { new Parser(options).ParseScript(text); }
        catch (ParseErrorException)
        {
            tokens.Clear();
            inserted.Clear();
            new Parser(options).ParseModule(text);
        }
        foreach (var end in inserted) tokens.Add((end, ";"));
        return [.. tokens.OrderBy(t => t.Start).ThenBy(t => t.Text == ";" ? 0 : 1).Select(t => t.Text)];
    }

    private static string Run(string script)
    {
        var run = ExternalTools.Run(RealData.Path("CORVUS_NODE"), [script], TimeSpan.FromMinutes(1), 1 << 20, default);
        Assert.True(run.ExitCode == 0, run.Stderr);
        return run.Text.Replace("\r", "");
    }

    // Regression: d27cda83 added the view without its parameter domain entry, so the server refused it.
    [Fact]
    public async Task Analyze_js_accepts_view_beautify()
    {
        await using var server = await InProcessServer.StartAsync();
        var r = await server.Client.CallToolAsync("analyze_js", new Dictionary<string, object?> { ["path"] = Fixture("program.min.js"), ["view"] = "beautify" });
        var text = string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(t => t.Text));
        Assert.True(r.IsError != true, text);
        Assert.StartsWith("// program.min.js: ", text);
    }

    [Fact]
    public void Minified_code_is_laid_out_with_its_tokens_unchanged()
    {
        var min = File.ReadAllText(Fixture("program.min.js"));
        var r = JsBeautify.Format(min, null, false, default);
        output.WriteLine(r.Text[..Math.Min(3000, r.Text.Length)]);
        Assert.Equal(Tokens(min), Tokens(r.Text));
        Assert.True(r.Origins.Count > 150, $"{r.Origins.Count} lines");
        Assert.Contains("function shadow(e) {\n  const t = [];\n  {\n    const e = 10;\n    t.push(e);\n  }\n", r.Text);
        Assert.Contains("  switch (e) {\n    case \"a\":\n    case \"b\": {\n", r.Text);
        Assert.Contains("  } catch (e) {\n", r.Text);
        Assert.Contains("`${e.owner}: ${e.balance.toFixed(2)} of ${Account.created}`", r.Text);
        // The original's own line breaks with no semicolon come back as written-out semicolons.
        var asi = JsBeautify.Format(File.ReadAllText(Fixture("program.js")), null, false, default).Text;
        Assert.Contains("  let x = a;\n  let y = b;\n  const z = x;\n  [x, y] = [y, x];\n  return x - y + z;\n", asi);
    }

    [Fact]
    public void Requested_renames_reach_every_site_of_one_binding_only()
    {
        const string code = "function f(a){var b=a+1;{let a=2;b+=a}return {a,b,c:a}}var a=f(1);";
        var r = JsBeautify.Format(code, "a@1:12=input,b=total", false, default);
        Assert.Equal([("a", "input"), ("b", "total")], r.Renames.Select(n => (n.From, n.To)));
        Assert.Contains("var total = input + 1;", r.Text);
        Assert.Contains("let a = 2;\n    total += a;", r.Text);
        Assert.Contains("a: input,\n    b: total,\n    c: input", r.Text);
        Assert.Contains("var a = f(1);", r.Text);
    }

    [Fact]
    public void Renames_that_would_shadow_capture_or_reach_outside_code_are_refused()
    {
        const string code = "var g=1;function f(a,b){function h(){var c=3;return c+a}return h()+b+g}" +
                            "function e(x){return eval('x')}";
        var r = JsBeautify.Format(code, "a=c,b=g,g=w,x=y,a=b,q=z,a=for", false, default);
        Assert.Empty(r.Renames);
        Assert.Contains(r.Notes, n => n.Contains("'a=c'", StringComparison.Ordinal) && n.Contains("inner scope", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'b=g'", StringComparison.Ordinal) && n.Contains("outer name", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'g=w'", StringComparison.Ordinal) && n.Contains("global of the script", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'x=y'", StringComparison.Ordinal) && n.Contains("eval", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'a=b'", StringComparison.Ordinal) && n.Contains("same scope", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'q=z'", StringComparison.Ordinal) && n.Contains("no binding", StringComparison.Ordinal));
        Assert.Contains(r.Notes, n => n.Contains("'a=for'", StringComparison.Ordinal) && n.Contains("not a usable identifier", StringComparison.Ordinal));
    }

    [Fact]
    public void Module_imports_and_exports_keep_their_external_names()
    {
        const string code = "import d,{x,y as z} from './lib.js';import * as n from 'node:path';const a=d(x)+z;export {a};export const k=1;export function m(){return n}";
        var r = JsBeautify.Format(code, "x=first,a=sum,k=one,d=main", true, default);
        Assert.Contains("import main, { x as first, y as z } from './lib.js';", r.Text);
        Assert.Contains("import * as path from 'node:path';", r.Text);
        Assert.Contains("const sum = main(first) + z;", r.Text);
        Assert.Contains("export { sum as a };", r.Text);
        Assert.Contains("return path;", r.Text);
        Assert.Contains(r.Notes, n => n.Contains("'k=one'", StringComparison.Ordinal) && n.Contains("exported", StringComparison.Ordinal));
    }

    [Fact]
    public void Minified_bindings_take_names_from_evidence()
    {
        const string code = "function f(e){const t=require('lodash/debounce'),n=new XMLHttpRequest,o=document.querySelector('#x'),r=this;" +
                            "for(let s=0;s<3;s++)for(let c=0;c<2;c++)o.push(s,c);try{e()}catch(a){return a}" +
                            "return e.map(function(u,l){return u+l}).then(i=>i).catch(d=>d)+new Promise((p,q)=>p(1))+t+n+r}";
        var r = JsBeautify.Format(code, null, true, default);
        var renamed = r.Renames.ToDictionary(n => n.From, n => n.To);
        foreach (var n in r.Renames) output.WriteLine($"{n.From} -> {n.To} ({n.Reason})");
        Assert.Equal("debounce", renamed["t"]);
        Assert.Equal("xmlHttpRequest", renamed["n"]);
        Assert.Equal("element", renamed["o"]);
        Assert.Equal("self", renamed["r"]);
        Assert.Equal("i", renamed["s"]);
        Assert.Equal("j", renamed["c"]);
        Assert.Equal("error", renamed["a"]);
        Assert.Equal(("item", "index"), (renamed["u"], renamed["l"]));
        Assert.Equal(("result", "error"), (renamed["i"], renamed["d"]));
        Assert.Equal(("resolve", "reject"), (renamed["p"], renamed["q"]));
        Assert.False(renamed.ContainsKey("e"));
        Assert.Contains("for (let i = 0; i < 3; i++) for (let j = 0; j < 2; j++) element.push(i, j);", r.Text);
    }

    // Each binding's site count in declaration order: equal before and after renaming when every site moved together.
    private static List<int> Structure(string text)
    {
        List<int>? sites = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            try
            {
                Acornima.Ast.Program tree;
                try { tree = new Parser().ParseScript(text); }
                catch (ParseErrorException) { tree = new Parser().ParseModule(text); }
                sites = [.. new JsNames(tree).Bindings.OrderBy(b => b.Declared).Select(b => b.Sites.Count)];
            }
            catch (Exception ex) { error = ex; }
        }, 256 * 1024 * 1024);
        thread.Start();
        thread.Join();
        if (error != null) throw error;
        return sites!;
    }

    // Every .js, .mjs and .cjs file under CORVUS_JS_FILES: laid out with its tokens unchanged, and with names from
    // evidence re-parsed to the same bindings with the same site counts. Files the parser rejects are counted apart.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_JS_FILES")]
    public void Real_scripts_keep_their_tokens_and_bindings()
    {
        var files = Directory.EnumerateFiles(RealData.Path("CORVUS_JS_FILES"), "*", SearchOption.AllDirectories)
            .Where(f => Path.GetExtension(f) is ".js" or ".mjs" or ".cjs").Order(StringComparer.Ordinal).ToList();
        var problems = new List<string>();
        int done = 0, rejected = 0, renames = 0;
        long bytes = 0, layout = 0, renaming = 0;
        var clock = System.Diagnostics.Stopwatch.StartNew();
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            JsBeautify.Result plain, named;
            try
            {
                long started = clock.ElapsedTicks;
                plain = JsBeautify.Format(text, null, false, default);
                layout += clock.ElapsedTicks - started;
                started = clock.ElapsedTicks;
                named = JsBeautify.Format(text, null, true, default);
                renaming += clock.ElapsedTicks - started;
            }
            catch (InvalidDataException) { rejected++; continue; }
            done++;
            bytes += text.Length;
            renames += named.Renames.Count;
            string name = Path.GetRelativePath(RealData.Path("CORVUS_JS_FILES"), file);
            try
            {
                var (before, after) = (Tokens(text), Tokens(plain.Text));
                if (!before.SequenceEqual(after))
                {
                    int i = 0;
                    while (i < before.Count && i < after.Count && before[i] == after[i]) i++;
                    string Around(List<string> t) => string.Join(" ", t.Skip(Math.Max(0, i - 4)).Take(8));
                    problems.Add($"{name}: token {i} differs: [{Around(before)}] became [{Around(after)}]");
                    continue;
                }
                if (!Structure(text).SequenceEqual(Structure(named.Text))) problems.Add($"{name}: bindings differ after {named.Renames.Count} renames");
            }
            catch (ParseErrorException ex) { problems.Add($"{name}: the output does not parse: {ex.Message}"); }
        }
        output.WriteLine($"{done} files ({bytes / 1048576.0:0.0} MB), {rejected} not parsed, {renames:N0} renames; layout {Seconds(layout):0.0} s, " +
            $"layout with names {Seconds(renaming):0.0} s, {clock.Elapsed.TotalSeconds:0.0} s with the checks");
        Assert.True(done > 0, "no script parsed");

        static double Seconds(long ticks) => ticks / (double)System.Diagnostics.Stopwatch.Frequency;
        Assert.True(problems.Count == 0, string.Join("\n", problems.Take(30)));
    }

    [Fact]
    public void Analyze_js_view_beautify_lists_the_renames_and_pages_from_an_original_position()
    {
        var js = _dir.File("app.min.js");
        File.WriteAllText(js, "function f(e){try{return e()}catch(t){return t}}\nfunction g(n){for(let r=0;r<n;r++)console.log(r)}\n");
        var tools = new Corvus.Tools.WebTools(new OutputPager(new ServerOptions()));
        var text = tools.AnalyzeJs(js, "beautify", query: "auto,e=work");
        Assert.Contains("; 3 binding(s) renamed", text, StringComparison.Ordinal);
        Assert.Contains("//   e -> work (1:12, requested)", text, StringComparison.Ordinal);
        Assert.Contains("//   t -> error (1:36, catch parameter)", text, StringComparison.Ordinal);
        Assert.Contains("    return work();\n  } catch (error) {\n    return error;\n  }", text, StringComparison.Ordinal);
        var paged = tools.AnalyzeJs(js, "beautify", line: 2, column: 15);
        Assert.Contains("]\n  for (let r = 0; r < n; r++) console.log(r);\n}", paged, StringComparison.Ordinal);
    }

    // node (CORVUS_NODE) runs the fixture, its terser output, and the terser output beautified with names from
    // evidence; all three print the same lines.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_NODE")]
    public void Beautified_and_renamed_code_prints_what_the_original_prints()
    {
        var expected = Run(Fixture("program.js"));
        Assert.Equal(expected, Run(Fixture("program.min.js")));
        var r = JsBeautify.Format(File.ReadAllText(Fixture("program.min.js")), null, true, default);
        foreach (var n in r.Renames) output.WriteLine($"{n.From} -> {n.To} ({n.Reason})");
        Assert.True(r.Renames.Count >= 10, $"{r.Renames.Count} renames");
        var file = _dir.File("program.beautified.js");
        File.WriteAllText(file, r.Text);
        Assert.Equal(expected, Run(file));
    }
}
